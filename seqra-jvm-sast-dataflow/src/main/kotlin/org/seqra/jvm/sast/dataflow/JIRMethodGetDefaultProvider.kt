package org.seqra.jvm.sast.dataflow

import org.seqra.dataflow.ap.ifds.access.FactAp
import org.seqra.dataflow.configuration.jvm.ConstantTrue
import org.seqra.dataflow.configuration.jvm.CopyAllMarks
import org.seqra.dataflow.configuration.jvm.Result
import org.seqra.dataflow.configuration.jvm.TaintPassThrough
import org.seqra.dataflow.configuration.jvm.This
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRMethod

class JIRMethodGetDefaultProvider(
    val base: TaintRulesProvider,
    private val projectClasses: ClassLocationChecker,
) : TaintRulesProvider by base {
    override fun passTroughRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?
    ): Iterable<TaintPassThrough> {
        val baseRules = base.passTroughRulesForMethod(method, statement, fact)

        if (method !is JIRMethod || method.isStatic) return baseRules

        if (!method.name.startsWith("get")) return baseRules

        if (projectClasses.isProjectClass(method.enclosingClass)) return baseRules

        val getDefaultRule = TaintPassThrough(method, ConstantTrue, getDefaultActions, info = null)
        return baseRules + getDefaultRule
    }

    companion object {
        private val getDefaultActions = listOf(
            CopyAllMarks(from = This, to = Result)
        )
    }
}
