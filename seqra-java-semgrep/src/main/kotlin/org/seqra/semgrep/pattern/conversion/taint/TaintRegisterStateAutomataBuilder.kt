package org.seqra.semgrep.pattern.conversion.taint

import org.seqra.semgrep.pattern.conversion.automata.AutomataNode
import org.seqra.semgrep.pattern.conversion.automata.MethodFormulaManager
import org.seqra.semgrep.pattern.conversion.taint.TaintRegisterStateAutomata.Edge
import org.seqra.semgrep.pattern.conversion.taint.TaintRegisterStateAutomata.State

class TaintRegisterStateAutomataBuilder {
    val successors = hashMapOf<State, MutableSet<Pair<Edge, State>>>()
    val acceptStates = hashSetOf<State>()
    val deadStates = hashSetOf<State>()
    val nodeIndex = hashMapOf<AutomataNode, Int>()

    fun newState(): State {
        val node = AutomataNode()
        nodeIndex[node] = nodeIndex.size
        return State(node, TaintRegisterStateAutomata.StateRegister(emptyMap()))
    }

    fun build(manager: MethodFormulaManager, initial: State) =
        TaintRegisterStateAutomata(manager, initial, acceptStates, deadStates, successors, nodeIndex)
}
