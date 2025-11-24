package org.seqra.jvm.sast.dataflow

import org.seqra.dataflow.ap.ifds.access.FactAp
import org.seqra.dataflow.ap.ifds.access.InitialFactAp
import org.seqra.dataflow.configuration.jvm.TaintMethodExitSink
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst

class JIRMethodExitRuleProvider(val base: TaintRulesProvider) : TaintRulesProvider by base {
    override fun sinkRulesForMethodExit(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        initialFacts: Set<InitialFactAp>?
    ): Iterable<TaintMethodExitSink> {
        // Apply method exit rules on Z2F edges only
        if (!initialFacts.isNullOrEmpty()) return emptyList()

        return base.sinkRulesForMethodExit(method, statement, fact, initialFacts)
    }
}
