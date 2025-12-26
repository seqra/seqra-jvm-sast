package org.seqra.jvm.sast.dataflow

import org.seqra.dataflow.ap.ifds.access.FactAp
import org.seqra.dataflow.ap.ifds.access.InitialFactAp
import org.seqra.dataflow.configuration.jvm.TaintConfigurationItem
import org.seqra.dataflow.configuration.jvm.TaintMethodExitSink
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRField
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.jvm.sast.dataflow.rules.TaintConfiguration

class JIRTaintRulesProvider(
    private val taintConfiguration: TaintConfiguration
) : TaintRulesProvider {
    override fun entryPointRulesForMethod(method: CommonMethod, fact: FactAp?, allRelevant: Boolean) = getRules(method) {
        taintConfiguration.entryPointForMethod(it, allRelevant)
    }

    override fun sourceRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean) = getRules(method) {
        taintConfiguration.sourceForMethod(it, allRelevant)
    }

    override fun exitSourceRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        allRelevant: Boolean
    ) = getRules(method) {
        taintConfiguration.exitSourceForMethod(it, allRelevant)
    }

    override fun sinkRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean) = getRules(method) {
        taintConfiguration.sinkForMethod(it, allRelevant)
    }

    override fun passTroughRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        allRelevant: Boolean
    ) = getRules(method) {
        taintConfiguration.passThroughForMethod(it, allRelevant)
    }

    override fun cleanerRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean) = getRules(method) {
        taintConfiguration.cleanerForMethod(it, allRelevant)
    }

    override fun sinkRulesForMethodExit(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        initialFacts: Set<InitialFactAp>?,
        allRelevant: Boolean
    ): Iterable<TaintMethodExitSink> = getRules(method) {
        taintConfiguration.methodExitSinkForMethod(it, allRelevant)
    }

    override fun sinkRulesForMethodEntry(method: CommonMethod, fact: FactAp?, allRelevant: Boolean) = getRules(method) {
        taintConfiguration.methodEntrySinkForMethod(it, allRelevant)
    }

    override fun sourceRulesForStaticField(field: JIRField, statement: CommonInst, fact: FactAp?, allRelevant: Boolean) =
        taintConfiguration.sourceForStaticField(field)

    private inline fun <T : TaintConfigurationItem> getRules(
        method: CommonMethod,
        body: (JIRMethod) -> Iterable<T>
    ): Iterable<T> {
        check(method is JIRMethod) { "Expected method to be JIRMethod" }
        return body(method)
    }
}
