package org.seqra.jvm.sast.dataflow

import org.seqra.dataflow.ap.ifds.access.FactAp
import org.seqra.dataflow.ap.ifds.access.InitialFactAp
import org.seqra.dataflow.configuration.jvm.TaintMethodExitSink
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRuleFilter
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRField

class JIRFilteredTaintRulesProvider(
    private val provider: TaintRulesProvider,
    private val filter: TaintRuleFilter
) : TaintRulesProvider {
    override fun entryPointRulesForMethod(method: CommonMethod, fact: FactAp?, allRelevant: Boolean) =
        provider.entryPointRulesForMethod(method, fact, allRelevant)
            .filter { filter.ruleEnabled(it) }

    override fun sourceRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean) =
        provider.sourceRulesForMethod(method, statement, fact, allRelevant)
            .filter { filter.ruleEnabled(it) }

    override fun exitSourceRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        allRelevant: Boolean
    ) = provider.exitSourceRulesForMethod(method, statement, fact, allRelevant)
            .filter { filter.ruleEnabled(it) }

    override fun sinkRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean) =
        provider.sinkRulesForMethod(method, statement, fact, allRelevant)
            .filter { filter.ruleEnabled(it) }

    override fun passTroughRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        allRelevant: Boolean
    ) = provider.passTroughRulesForMethod(method, statement, fact, allRelevant)
            .filter { filter.ruleEnabled(it) }

    override fun cleanerRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean) =
        provider.cleanerRulesForMethod(method, statement, fact, allRelevant)
            .filter { filter.ruleEnabled(it) }

    override fun sinkRulesForMethodExit(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        initialFacts: Set<InitialFactAp>?,
        allRelevant: Boolean
    ): Iterable<TaintMethodExitSink> =
        provider.sinkRulesForMethodExit(method, statement, fact, initialFacts, allRelevant)
            .filter { filter.ruleEnabled(it) }

    override fun sinkRulesForMethodEntry(method: CommonMethod, fact: FactAp?, allRelevant: Boolean) =
        provider.sinkRulesForMethodEntry(method, fact, allRelevant)
            .filter { filter.ruleEnabled(it) }

    override fun sourceRulesForStaticField(field: JIRField, statement: CommonInst, fact: FactAp?, allRelevant: Boolean) =
        provider.sourceRulesForStaticField(field, statement, fact, allRelevant)
            .filter { filter.ruleEnabled(it) }
}
