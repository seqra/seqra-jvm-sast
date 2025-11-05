package org.seqra.semgrep.pattern.conversion.automata.operations

import org.seqra.semgrep.pattern.conversion.automata.AutomataEdgeType
import org.seqra.semgrep.pattern.conversion.automata.AutomataNode
import org.seqra.semgrep.pattern.conversion.automata.MethodFormula
import org.seqra.semgrep.pattern.conversion.automata.SemgrepRuleAutomata

fun acceptIfCurrentAutomataAcceptsSuffix(automata: SemgrepRuleAutomata) {
    check(!automata.params.hasMethodEnter) {
        "Automata contains method enter"
    }

    automata.initialNode.outEdges.add(AutomataEdgeType.MethodCall(MethodFormula.True) to automata.initialNode)
    automata.params = automata.params.copy(isDeterministic = false)
}

fun addMethodEntryLoop(automata: SemgrepRuleAutomata): SemgrepRuleAutomata {
    val newRoot = AutomataNode()
    newRoot.outEdges.add(AutomataEdgeType.MethodEnter(MethodFormula.True) to automata.initialNode)

    newRoot.outEdges.addAll(automata.initialNode.outEdges)
    if (automata.initialNode.accept) {
        newRoot.accept = true
    }

    return SemgrepRuleAutomata(
        automata.formulaManager,
        initialNodes = setOf(newRoot),
        automata.params.copy(hasMethodEnter = true),
        automata.deadNode
    )
}
