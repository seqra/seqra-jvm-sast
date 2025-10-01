package org.seqra.jvm.sast.project

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import mu.KLogging
import org.seqra.dataflow.ap.ifds.TaintAnalysisUnitRunnerManager
import org.seqra.dataflow.ap.ifds.access.ApMode
import org.seqra.dataflow.ap.ifds.access.FinalFactAp
import org.seqra.dataflow.ap.ifds.trace.VulnerabilityWithTrace
import org.seqra.dataflow.configuration.jvm.serialized.SerializedTaintConfig
import org.seqra.dataflow.configuration.jvm.serialized.loadSerializedTaintConfig
import org.seqra.dataflow.jvm.ap.ifds.JIRSummarySerializationContext
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.dataflow.jvm.ap.ifds.taint.applyAnalysisEndSinksForEntryPoints
import org.seqra.dataflow.jvm.util.JIRSarifTraits
import org.seqra.dataflow.sarif.SourceFileResolver
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRClasspath
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.jvm.sast.JIRSourceFileResolver
import org.seqra.jvm.sast.dataflow.JIRCombinedTaintRulesProvider
import org.seqra.jvm.sast.dataflow.JIRTaintAnalyzer
import org.seqra.jvm.sast.dataflow.JIRTaintAnalyzer.DebugOptions
import org.seqra.jvm.sast.dataflow.JIRTaintRulesProvider
import org.seqra.jvm.sast.dataflow.rules.TaintConfiguration
import org.seqra.jvm.sast.sarif.DebugFactReachabilitySarifGenerator
import org.seqra.jvm.sast.sarif.SarifGenerator
import org.seqra.jvm.sast.se.api.SastSeAnalyzer
import org.seqra.jvm.sast.util.loadDefaultConfig
import org.seqra.org.seqra.semgrep.pattern.convertToOldErrorsFormat
import org.seqra.project.Project
import org.seqra.semgrep.pattern.RuleMetadata
import org.seqra.semgrep.pattern.SemgrepLoadTrace
import org.seqra.semgrep.pattern.SemgrepRuleLoader
import org.seqra.semgrep.pattern.TaintRuleFromSemgrep
import org.seqra.semgrep.pattern.createTaintConfig
import java.io.OutputStream
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.div
import kotlin.io.path.extension
import kotlin.io.path.inputStream
import kotlin.io.path.outputStream
import kotlin.io.path.readText
import kotlin.io.path.walk
import kotlin.time.Duration

class ProjectAnalyzer(
    private val project: Project,
    private val projectPackage: String?,
    private val resultDir: Path,
    private val customConfig: Path?,
    private val semgrepRuleSet: Path?,
    private val semgrepRuleLoadErrors: Path?,
    private val semgrepRuleLoadTrace: Path?,
    private val cwe: List<Int>,
    private val useSymbolicExecution: Boolean,
    private val symbolicExecutionTimeout: Duration,
    private val ifdsAnalysisTimeout: Duration,
    private val ifdsApMode: ApMode,
    private val projectKind: ProjectKind,
    private val storeSummaries: Boolean,
    private val debugOptions: DebugOptions
) {
    private val ruleMetadatas = mutableListOf<RuleMetadata>()

    fun analyze() {
        val projectAnalysisContext = initializeProjectAnalysisContext(
            project, projectPackage, projectKind,
            summariesApMode = ifdsApMode.takeIf { storeSummaries }
        )

        projectAnalysisContext.use {
            val entryPoints = it.selectProjectEntryPoints()
            it.runAnalyzer(entryPoints)
        }
    }

    private fun loadTaintConfig(cp: JIRClasspath): TaintRulesProvider {
        if (semgrepRuleSet != null) {
            check(customConfig == null) { "Unsupported custom config" }
            return loadSemgrepRules(cp, semgrepRuleSet, semgrepRuleLoadErrors, semgrepRuleLoadTrace)
        }

        val defaultConfig = TaintConfiguration(cp)
        defaultConfig.loadConfig(loadDefaultConfig())
        val customConfig = customConfig?.let { cfg ->
            cfg.inputStream().use { cfgStream ->
                TaintConfiguration(cp).apply { loadConfig(loadSerializedTaintConfig(cfgStream)) }
            }
        }

        val defaultRules = JIRTaintRulesProvider(defaultConfig)
        if (customConfig == null) return defaultRules

        val customRules = JIRTaintRulesProvider(customConfig)

        return JIRCombinedTaintRulesProvider(defaultRules, customRules)
    }

    private fun loadSemgrepRules(
        cp: JIRClasspath,
        semgrepRulesPath: Path,
        semgrepRuleLoadErrors: Path?,
        semgrepRuleLoadTrace: Path?,
    ): TaintRulesProvider {
        val trace = SemgrepLoadTrace()
        val semgrepRules = parseSemgrepRules(semgrepRulesPath, trace)

        val compressedTrace by lazy { trace.compressed() }
        if (semgrepRuleLoadTrace != null) {
            runCatching {
                val prettyJson = Json {
                    prettyPrint = true
                }
                semgrepRuleLoadTrace.outputStream().bufferedWriter().use { writer ->
                    writer.write(prettyJson.encodeToString(compressedTrace))
                }
                logger.info { "Wrote semgrep load trace to $semgrepRuleLoadTrace" }
            }.onFailure { ex ->
                logger.error(ex) { "Failed to write semgrep load trace to $semgrepRuleLoadTrace: ${ex.message}" }
            }
        }

        // todo: remove after seqra-cli update
        if (semgrepRuleLoadErrors != null) {
            runCatching {
                val oldErrorsFormat = compressedTrace.convertToOldErrorsFormat()
                val prettyJson = Json {
                    prettyPrint = true
                }
                semgrepRuleLoadErrors.outputStream().bufferedWriter().use { writer ->
                    writer.write(prettyJson.encodeToString(oldErrorsFormat))
                }
                logger.info { "Wrote semgrep load errors to $semgrepRuleLoadErrors" }
            }.onFailure { ex ->
                logger.error(ex) { "Failed to write semgrep load errors to $semgrepRuleLoadErrors: ${ex.message}" }
            }
        }

        val defaultRules = loadDefaultConfig()
        val defaultPassRules = SerializedTaintConfig(passThrough = defaultRules.passThrough)

        val config = TaintConfiguration(cp)
        config.loadConfig(defaultPassRules)
        semgrepRules.forEach { config.loadConfig(it.createTaintConfig()) }

        return JIRTaintRulesProvider(config)
    }

    private fun parseSemgrepRules(
        semgrepRulesPath: Path,
        semgrepTrace: SemgrepLoadTrace
    ): List<TaintRuleFromSemgrep> {
        val rules = mutableListOf<TaintRuleFromSemgrep>()
        val loader = SemgrepRuleLoader()
        val ruleExtensions = arrayOf("yaml", "yml")
        semgrepRulesPath.walk().filter { it.extension in ruleExtensions }.forEach { rulePath ->
            val ruleName = semgrepRulesPath.resolve(rulePath).absolutePathString()

            val ruleText = rulePath.readText()

            val (loadedRules, loadedMetadatas) = loader.loadRuleSet(
                ruleText,
                ruleName,
                semgrepTrace.fileTrace(ruleName)
            ).unzip()
            rules += loadedRules
            ruleMetadatas += loadedMetadatas
        }

        logger.info { "Total loaded ${rules.sumOf { it.size }} rules" }

        return rules
    }

    private fun ProjectAnalysisContext.runAnalyzer(entryPoints: List<JIRMethod>) {
        val summarySerializationContext = JIRSummarySerializationContext(cp)

        JIRTaintAnalyzer(
            cp, loadTaintConfig(cp).applyAnalysisEndSinksForEntryPoints(entryPoints.toHashSet()),
            projectLocations = projectClasses.projectLocations,
            ifdsTimeout = ifdsAnalysisTimeout,
            ifdsApMode = ifdsApMode,
            symbolicExecutionEnabled = useSymbolicExecution,
            analysisCwe = cwe.takeIf { it.isNotEmpty() }?.toSet(),
            summarySerializationContext = summarySerializationContext,
            storeSummaries = storeSummaries,
            debugOptions = debugOptions
        ).use { analyzer ->
            val sourcesResolver = JIRSourceFileResolver(
                project.sourceRoot,
                projectClasses.locationProjectModules.mapValues { (_, module) -> module.moduleSourceRoot }
            )

            logger.info { "Start IFDS analysis for project: ${project.sourceRoot}" }
            val traces = analyzer.analyzeWithIfds(entryPoints)
            logger.info { "Finish IFDS analysis for project: ${project.sourceRoot}" }

            (resultDir / "report-ifds.sarif").outputStream().use {
                generateSarifReportFromTraces(it, sourcesResolver, traces)
            }

            if (debugOptions.factReachabilitySarif) {
                val stmtsWithFact = analyzer.statementsWithFacts()
                (resultDir / "debug-ifds-fact-reachability.sarif").outputStream().use {
                    generateFactReachabilityReport(it, sourcesResolver, stmtsWithFact)
                }
            }

            logger.info { "Finish IFDS analysis report for project: ${project.sourceRoot}" }

            if (!useSymbolicExecution) return

            val seAnalyzer = SastSeAnalyzer.createSeEngine<TaintAnalysisUnitRunnerManager, VulnerabilityWithTrace>()
                ?: return

            logger.info { "Start SE for project: ${project.sourceRoot}" }
            val verifiedTraces = seAnalyzer.analyzeTraces(
                cp, projectClasses.projectLocations, analyzer.ifdsEngine,
                traces, symbolicExecutionTimeout
            )
            logger.info { "Finish SE for project: ${project.sourceRoot}" }

            (resultDir / "report-se.sarif").outputStream().use {
                generateSarifReportFromTraces(it, sourcesResolver, verifiedTraces)
            }

            logger.info { "Finish SE report for project: ${project.sourceRoot}" }
        }
    }

    private fun ProjectAnalysisContext.generateSarifReportFromTraces(
        output: OutputStream,
        sourceFileResolver: SourceFileResolver<CommonInst>,
        traces: List<VulnerabilityWithTrace>
    ) {
        val generator = SarifGenerator(sourceFileResolver, JIRSarifTraits(cp))
        generator.generateSarif(output, traces.asSequence(), ruleMetadatas)
        logger.info { "Sarif trace generation stats: ${generator.traceGenerationStats}" }
    }

    private fun ProjectAnalysisContext.generateFactReachabilityReport(
        output: OutputStream,
        sourceFileResolver: SourceFileResolver<CommonInst>,
        reachableFacts: Map<CommonInst, Set<FinalFactAp>>,
    ) {
        val generator = DebugFactReachabilitySarifGenerator(sourceFileResolver, JIRSarifTraits(cp))
        generator.generateSarif(output, reachableFacts)
    }

    companion object {
        private val logger = object : KLogging() {}.logger
    }
}
