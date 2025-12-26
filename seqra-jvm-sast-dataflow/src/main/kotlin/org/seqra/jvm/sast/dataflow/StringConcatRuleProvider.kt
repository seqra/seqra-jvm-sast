package org.seqra.jvm.sast.dataflow

import org.seqra.dataflow.ap.ifds.access.FactAp
import org.seqra.dataflow.configuration.jvm.Argument
import org.seqra.dataflow.configuration.jvm.ConstantTrue
import org.seqra.dataflow.configuration.jvm.CopyAllMarks
import org.seqra.dataflow.configuration.jvm.Result
import org.seqra.dataflow.configuration.jvm.TaintPassThrough
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRMethod

class StringConcatRuleProvider(private val base: TaintRulesProvider) : TaintRulesProvider by base {
    private var stringConcatPassThrough: TaintPassThrough? = null

    private fun stringConcatPassThrough(method: JIRMethod): TaintPassThrough =
        stringConcatPassThrough ?: generateRule(method).also { stringConcatPassThrough = it }

    private fun generateRule(method: JIRMethod): TaintPassThrough {
        // todo: string concat hack
        val possibleArgs = (0..20).map { Argument(it) }

        return TaintPassThrough(
            method = method,
            condition = ConstantTrue,
            actionsAfter = possibleArgs.map { CopyAllMarks(from = it, to = Result) },
            info = null
        )
    }

    override fun passTroughRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        allRelevant: Boolean
    ): Iterable<TaintPassThrough> {
        check(method is JIRMethod) { "Expected method to be JIRMethod" }
        val baseRules = base.passTroughRulesForMethod(method, statement, fact, allRelevant)

        if (method.name == "makeConcatWithConstants" && method.enclosingClass.name == "java.lang.invoke.StringConcatFactory") {
            return (sequenceOf(stringConcatPassThrough(method)) + baseRules).asIterable()
        }

        return baseRules
    }
}
