package org.seqra.org.seqra.semgrep.pattern

import org.seqra.dataflow.jvm.ap.ifds.taint.UserDefinedRuleInfo

data class UserRuleFromSemgrepInfo(
    val ruleId: String,
    override val relevantTaintMarks: Set<String>
) : UserDefinedRuleInfo
