package org.seqra.jvm.sast.project

import mu.KLogging
import org.seqra.dataflow.ap.ifds.TaintAnalysisUnitRunnerManager
import org.seqra.dataflow.ap.ifds.access.FinalFactAp
import org.seqra.dataflow.ap.ifds.trace.VulnerabilityWithTrace
import org.seqra.dataflow.configuration.jvm.serialized.loadSerializedTaintConfig
import org.seqra.dataflow.jvm.ap.ifds.JIRSummarySerializationContext
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.dataflow.jvm.util.JIRSarifTraits
import org.seqra.dataflow.sarif.SourceFileResolver
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRClasspath
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.jvm.sast.dataflow.JIRCombinedTaintRulesProvider
import org.seqra.jvm.sast.dataflow.JIRTaintAnalyzer
import org.seqra.jvm.sast.dataflow.JIRTaintRulesProvider
import org.seqra.jvm.sast.dataflow.rules.TaintConfiguration
import org.seqra.jvm.sast.project.rules.analysisConfig
import org.seqra.jvm.sast.project.rules.loadSemgrepRules
import org.seqra.jvm.sast.project.rules.semgrepRulesWithDefaultConfig
import org.seqra.jvm.sast.sarif.DebugFactReachabilitySarifGenerator
import org.seqra.jvm.sast.sarif.SarifGenerator
import org.seqra.jvm.sast.se.api.SastSeAnalyzer
import org.seqra.jvm.sast.util.loadDefaultConfig
import org.seqra.project.Project
import org.seqra.semgrep.pattern.RuleMetadata
import java.io.OutputStream
import java.nio.file.Path
import kotlin.io.path.div
import kotlin.io.path.inputStream
import kotlin.io.path.outputStream

class ProjectAnalyzer(
    private val project: Project,
    private val resultDir: Path,
    private val options: ProjectAnalysisOptions,
) {
    private val ruleMetadatas = mutableListOf<RuleMetadata>()

    fun analyze() {
        val projectAnalysisContext = initializeProjectAnalysisContext(project, options)

        projectAnalysisContext.use {
            val entryPoints = it.selectProjectEntryPoints()
            it.runAnalyzer(entryPoints)
        }
    }

    private fun loadTaintConfig(cp: JIRClasspath): TaintRulesProvider {
        if (options.semgrepRuleSet.isNotEmpty()) {
            check(options.customConfig == null) { "Unsupported custom config" }
            return loadConfigFromSemgrepRules(cp)
        }

        val defaultConfig = TaintConfiguration(cp)
        defaultConfig.loadConfig(loadDefaultConfig())
        val customConfig = options.customConfig?.let { cfg ->
            cfg.inputStream().use { cfgStream ->
                TaintConfiguration(cp).apply { loadConfig(loadSerializedTaintConfig(cfgStream)) }
            }
        }

        val defaultRules = JIRTaintRulesProvider(defaultConfig)
        if (customConfig == null) return defaultRules

        val customRules = JIRTaintRulesProvider(customConfig)

        return JIRCombinedTaintRulesProvider(defaultRules, customRules)
    }

    private fun loadConfigFromSemgrepRules(cp: JIRClasspath): TaintRulesProvider {
        val (semgrepRules, semgrepRulesMeta) = options.loadSemgrepRules()
        ruleMetadatas += semgrepRulesMeta
        return semgrepRules.semgrepRulesWithDefaultConfig(cp)
    }

    private fun ProjectAnalysisContext.runAnalyzer(entryPoints: List<JIRMethod>) {
        val summarySerializationContext = JIRSummarySerializationContext(cp)

        val loadedConfig = loadTaintConfig(cp)
        val config = analysisConfig(loadedConfig)

        JIRTaintAnalyzer(
            cp, config,
            projectClasses = { projectClasses.isProjectClass(it) },
            options = options.taintAnalyzerOptions(),
            summarySerializationContext = summarySerializationContext,
        ).use { analyzer ->
            val sourcesResolver = project.sourceResolver(projectClasses)

            logger.info { "Start IFDS analysis for project: ${project.sourceRoot}" }
            val traces = analyzer.analyzeWithIfds(entryPoints)
            logger.info { "Finish IFDS analysis for project: ${project.sourceRoot}" }

            (resultDir / "report-ifds.sarif").outputStream().use {
                generateSarifReportFromTraces(it, sourcesResolver, traces)
            }

            if (options.debugOptions?.factReachabilitySarif == true) {
                val stmtsWithFact = analyzer.statementsWithFacts()
                (resultDir / "debug-ifds-fact-reachability.sarif").outputStream().use {
                    generateFactReachabilityReport(it, sourcesResolver, stmtsWithFact)
                }
            }

            logger.info { "Finish IFDS analysis report for project: ${project.sourceRoot}" }

            if (!options.useSymbolicExecution) return

            val seAnalyzer = SastSeAnalyzer.createSeEngine<TaintAnalysisUnitRunnerManager, VulnerabilityWithTrace>()
                ?: return

            logger.info { "Start SE for project: ${project.sourceRoot}" }
            val verifiedTraces = seAnalyzer.analyzeTraces(
                cp, projectClasses.projectLocationsUnsafe, analyzer.ifdsEngine,
                traces, options.symbolicExecutionTimeout
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
