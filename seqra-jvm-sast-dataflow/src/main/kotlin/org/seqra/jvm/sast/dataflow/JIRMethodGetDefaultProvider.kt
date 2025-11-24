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
import org.seqra.ir.api.jvm.RegisteredLocation

class JIRMethodGetDefaultProvider(
    val base: TaintRulesProvider,
    private val projectLocations: Set<RegisteredLocation>,
) : TaintRulesProvider by base {
    override fun passTroughRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?
    ): Iterable<TaintPassThrough> {
        val baseRules = base.passTroughRulesForMethod(method, statement, fact)

        if (method !is JIRMethod) return baseRules

        if (!method.name.startsWith("get")) return baseRules

        val location = method.enclosingClass.declaration.location
        if (location in projectLocations) return baseRules

        val getDefaultRule = TaintPassThrough(method, ConstantTrue, getDefaultActions, info = null)
        return baseRules + getDefaultRule
    }

    companion object {
        private val getDefaultActions = listOf(
            CopyAllMarks(from = This, to = Result)
        )
    }
}
