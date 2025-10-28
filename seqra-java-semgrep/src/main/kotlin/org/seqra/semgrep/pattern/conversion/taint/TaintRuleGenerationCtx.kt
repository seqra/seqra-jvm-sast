package org.seqra.semgrep.pattern.conversion.taint

import org.seqra.dataflow.configuration.jvm.serialized.PositionBase
import org.seqra.org.seqra.semgrep.pattern.Mark
import org.seqra.semgrep.pattern.MetaVarConstraints
import org.seqra.semgrep.pattern.conversion.MetavarAtom

data class TaintRuleEdge(
    val stateFrom: TaintRegisterStateAutomata.State,
    val stateTo: TaintRegisterStateAutomata.State,
    val checkGlobalState: Boolean,
    val edgeCondition: TaintRegisterStateAutomata.EdgeCondition,
    val edgeEffect: TaintRegisterStateAutomata.EdgeEffect,
    val edgeKind: Kind,
) {
    enum class Kind {
        MethodEnter,
        MethodCall,
        MethodExit,
    }
}

sealed interface MetaVarConstraintOrPlaceHolder {
    data class Constraint(val constraint: MetaVarConstraints) : MetaVarConstraintOrPlaceHolder
    data class PlaceHolder(val constraint: MetaVarConstraints?) : MetaVarConstraintOrPlaceHolder
}

data class TaintRuleGenerationMetaVarInfo(
    val constraints: Map<String, MetaVarConstraintOrPlaceHolder>
)

open class TaintRuleGenerationCtx(
    val uniqueRuleId: String,
    val automata: TaintRegisterStateAutomata,
    val metaVarInfo: TaintRuleGenerationMetaVarInfo,
    val globalStateAssignStates: Set<TaintRegisterStateAutomata.State>,
    val edges: List<TaintRuleEdge>,
    val edgesToFinalAccept: List<TaintRuleEdge>,
    val edgesToFinalDead: List<TaintRuleEdge>,
) {
    private fun allStates(): List<TaintRegisterStateAutomata.State> {
        val result = mutableListOf<TaintRegisterStateAutomata.State>()
        edges.flatMapTo(result) { listOf(it.stateFrom, it.stateTo) }
        edgesToFinalAccept.flatMapTo(result) { listOf(it.stateFrom, it.stateTo) }
        edgesToFinalDead.flatMapTo(result) { listOf(it.stateFrom, it.stateTo) }
        return result
    }

    private val metaVarValues by lazy {
        val result = hashMapOf<MetavarAtom, MutableSet<Int>>()
        allStates().forEach {
            it.register.assignedVars.forEach { (mv, value) ->
                result.getOrPut(mv, ::hashSetOf).add(value)
            }
        }
        result
    }

    open fun allMarkValues(varName: MetavarAtom): List<String> {
        val varValues = metaVarValues[varName] ?: error("MetaVar is not assigned")
        return varValues.map { stateMarkName(varName, it) }
    }

    open fun stateMarkName(varName: MetavarAtom, varValue: Int): String =
        "${uniqueRuleId}${Mark.MarkSeparator}${varName}${Mark.MarkSeparator}$varValue"

    fun globalStateMarkName(state: TaintRegisterStateAutomata.State): String {
        val stateId = automata.stateId(state)
        return "${uniqueRuleId}${Mark.ArtificialStateName}$stateId"
    }

    val stateVarPosition by lazy {
        PositionBase.ClassStatic("${uniqueRuleId}${Mark.ArtificialStateName}").base()
    }
}
