package org.seqra.jvm.sast.project.rules

import org.seqra.dataflow.configuration.jvm.serialized.SerializedTaintConfig
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.ir.api.jvm.JIRClasspath
import org.seqra.jvm.sast.dataflow.JIRMethodExitRuleProvider
import org.seqra.jvm.sast.dataflow.JIRMethodGetDefaultProvider
import org.seqra.jvm.sast.dataflow.JIRTaintRulesProvider
import org.seqra.jvm.sast.dataflow.rules.TaintConfiguration
import org.seqra.jvm.sast.project.ProjectAnalysisContext
import org.seqra.jvm.sast.project.spring.SpringRuleProvider
import org.seqra.jvm.sast.util.loadDefaultConfig
import org.seqra.semgrep.pattern.TaintRuleFromSemgrep
import org.seqra.semgrep.pattern.createTaintConfig

fun List<TaintRuleFromSemgrep>.semgrepRulesWithDefaultConfig(
    cp: JIRClasspath
): JIRTaintRulesProvider {
    val defaultRules = loadDefaultConfig()
    val defaultPassRules = SerializedTaintConfig(passThrough = defaultRules.passThrough)

    val config = TaintConfiguration(cp)
    config.loadConfig(defaultPassRules)
    this.forEach { config.loadConfig(it.createTaintConfig()) }

    return JIRTaintRulesProvider(config)
}

fun ProjectAnalysisContext.analysisConfig(initialConfig: TaintRulesProvider): TaintRulesProvider {
    var config = initialConfig
    config = JIRMethodExitRuleProvider(config)
    config = JIRMethodGetDefaultProvider(config) { projectClasses.isProjectClass(it) }
    if (springWebProjectContext != null) {
        config = SpringRuleProvider(config, springWebProjectContext)
    }
    return config
}
