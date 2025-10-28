package org.seqra.semgrep.pattern.conversion.taint

import org.seqra.dataflow.configuration.jvm.serialized.SinkMetaData
import org.seqra.semgrep.pattern.SemgrepRuleLoadStepTrace

class RuleConversionCtx(
    val ruleId: String,
    val meta: SinkMetaData,
    val semgrepRuleTrace: SemgrepRuleLoadStepTrace
)
