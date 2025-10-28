package org.seqra.semgrep.pattern.conversion.automata.operations

import org.seqra.semgrep.pattern.conversion.automata.AutomataEdgeType
import org.seqra.semgrep.pattern.conversion.automata.MethodFormula
import org.seqra.semgrep.pattern.conversion.automata.SemgrepRuleAutomata

fun acceptIfCurrentAutomataAcceptsSuffix(automata: SemgrepRuleAutomata) {
    check(!automata.params.hasMethodEnter) {
        "Automata contains method enter"
    }

    automata.initialNode.outEdges.add(AutomataEdgeType.MethodCall(MethodFormula.True) to automata.initialNode)
    automata.params = automata.params.copy(isDeterministic = false)
}

fun addMethodEntryLoop(automata: SemgrepRuleAutomata) {
    automata.initialNode.outEdges.add(AutomataEdgeType.MethodEnter(MethodFormula.True) to automata.initialNode)
    automata.params = automata.params.copy(hasMethodEnter = true)
}
