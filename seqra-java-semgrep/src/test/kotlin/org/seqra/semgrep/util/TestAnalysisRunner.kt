package org.seqra.semgrep.util

import kotlinx.coroutines.runBlocking
import org.seqra.config.ConfigLoader
import org.seqra.dataflow.ap.ifds.TaintAnalysisUnitRunnerManager
import org.seqra.dataflow.ap.ifds.access.AnyAccessorUnrollStrategy
import org.seqra.dataflow.ap.ifds.access.tree.TreeApManager
import org.seqra.dataflow.ap.ifds.trace.TraceResolver
import org.seqra.dataflow.ap.ifds.trace.VulnerabilityWithTrace
import org.seqra.dataflow.configuration.jvm.serialized.SerializedTaintConfig
import org.seqra.dataflow.ifds.SingletonUnit
import org.seqra.dataflow.ifds.UnitResolver
import org.seqra.dataflow.ifds.UnknownUnit
import org.seqra.dataflow.jvm.ap.ifds.JIRSafeApplicationGraph
import org.seqra.dataflow.jvm.ap.ifds.LambdaAnonymousClassFeature
import org.seqra.dataflow.jvm.ap.ifds.LambdaExpressionToAnonymousClassTransformerFeature
import org.seqra.dataflow.jvm.ap.ifds.analysis.JIRAnalysisManager
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.dataflow.jvm.graph.MethodReturnInstNormalizerFeature
import org.seqra.dataflow.jvm.ifds.JIRUnitResolver
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRClasspath
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.ir.impl.features.classpaths.UnknownClasses
import org.seqra.ir.impl.features.usagesExt
import org.seqra.jvm.graph.JApplicationGraphImpl
import org.seqra.jvm.sast.dataflow.DummySerializationContext
import org.seqra.jvm.sast.dataflow.JIRMethodExitRuleProvider
import org.seqra.jvm.sast.dataflow.JIRTaintRulesProvider
import org.seqra.jvm.sast.dataflow.rules.TaintConfiguration
import org.seqra.jvm.transformer.JMultiDimArrayAllocationTransformer
import org.seqra.jvm.transformer.JStringConcatTransformer
import org.seqra.util.analysis.ApplicationGraph
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class TestAnalysisRunner(
    private val samples: SamplesDb,
) : AutoCloseable {
    private lateinit var cp: JIRClasspath

    init {
        initializeCp()
    }

    private fun initializeCp() = runBlocking {
        val lambdaAnonymousClass = LambdaAnonymousClassFeature()
        val lambdaTransformer = LambdaExpressionToAnonymousClassTransformerFeature(lambdaAnonymousClass)
        val methodNormalizer = MethodReturnInstNormalizerFeature

        val features = mutableListOf(
            UnknownClasses, lambdaAnonymousClass, lambdaTransformer, methodNormalizer,
            JStringConcatTransformer, JMultiDimArrayAllocationTransformer
        )

        val allCpFiles = listOf(samples.samplesJar.toFile())
        cp = samples.db.classpath(allCpFiles, features)
    }

    override fun close() {
        cp.close()
    }

    private val ifdsAnalysisGraph by lazy {
        val usages = runBlocking { cp.usagesExt() }
        val mainGraph = JApplicationGraphImpl(cp, usages)
        JIRSafeApplicationGraph(mainGraph)
    }

    @Suppress("UNCHECKED_CAST")
    private fun setupEngine(configProvider: TaintRulesProvider): TaintAnalysisUnitRunnerManager {
        return TaintAnalysisUnitRunnerManager(
            JIRAnalysisManager(cp),
            ifdsAnalysisGraph as ApplicationGraph<CommonMethod, CommonInst>,
            unitResolver = JIRUnitResolver {
                if (it.enclosingClass.declaration.location.isRuntime) UnknownUnit else SingletonUnit
            } as UnitResolver<CommonMethod>,
            apManager = TreeApManager(anyAccessorUnrollStrategy = AnyAccessorUnrollStrategy.AnyAccessorDisabled),
            summarySerializationContext = DummySerializationContext,
            taintConfig = configProvider,
            taintRulesStatsSamplingPeriod = null,
        )
    }

    fun run(
        config: SerializedTaintConfig,
        useDefaultConfig: Boolean,
        samples: Set<String>
    ): Map<String, List<VulnerabilityWithTrace>> =
        samples.associate { sample ->
            val cls = cp.findClassOrNull(sample) ?: error("No sample in CP")
            val ep = cls.declaredMethods.singleOrNull { it.name == "entrypoint" }
                ?: error("No entrypoint in $sample")

            val rulesProvider = rulesProvider(config, useDefaultConfig, hashSetOf(ep))
            setupEngine(rulesProvider).use { engine ->
                engine.runAnalysis(listOf(ep), timeout = 1.minutes, cancellationTimeout = 10.seconds)

                val allVulnerabilities = engine.getVulnerabilities()
                val vulnerabilities = engine.confirmVulnerabilities(
                    setOf(ep), allVulnerabilities,
                    timeout = 1.minutes, cancellationTimeout = 10.seconds
                )
                val traces = engine.resolveVulnerabilityTraces(
                    setOf(ep), vulnerabilities,
                    resolverParams = TraceResolver.Params(),
                    timeout = 1.minutes, cancellationTimeout = 10.seconds
                ).mapNotNull { trace ->
                    trace.takeIf { it.trace?.sourceToSinkTrace?.startNodes?.isNotEmpty() ?: false }
                }
                
                sample to traces
            }
        }

    private fun rulesProvider(
        config: SerializedTaintConfig,
        useDefaultConfig: Boolean,
        ep: Set<JIRMethod>
    ): TaintRulesProvider {
        val taintConfig = TaintConfiguration(cp)
        taintConfig.loadConfig(config)

        if (useDefaultConfig) {
            val defaultConfig = ConfigLoader.getConfig() ?: error("Error while loading default config")

            val defaultPassRules = SerializedTaintConfig(passThrough = defaultConfig.passThrough)
            taintConfig.loadConfig(defaultPassRules)
        }

        var cfg: TaintRulesProvider = JIRTaintRulesProvider(taintConfig)
        cfg = JIRMethodExitRuleProvider(cfg)
        return cfg
    }
}
