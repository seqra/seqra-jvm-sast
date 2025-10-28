package org.seqra.semgrep.pattern.conversion.taint

import org.seqra.semgrep.pattern.conversion.IsMetavar
import org.seqra.semgrep.pattern.conversion.MetavarAtom
import org.seqra.semgrep.pattern.conversion.SemgrepPatternAction.SignatureName
import org.seqra.semgrep.pattern.conversion.automata.MethodSignature
import org.seqra.semgrep.pattern.conversion.automata.ParamConstraint
import org.seqra.semgrep.pattern.conversion.automata.Predicate
import org.seqra.semgrep.pattern.conversion.generatedAnyValueGeneratorMethodName
import org.seqra.semgrep.pattern.conversion.generatedStringConcatMethodName
import org.seqra.semgrep.pattern.conversion.taint.TaintRegisterStateAutomata.EdgeCondition
import org.seqra.semgrep.pattern.conversion.taint.TaintRegisterStateAutomata.EdgeEffect
import org.seqra.semgrep.pattern.conversion.taint.TaintRegisterStateAutomata.MethodPredicate

fun EdgeCondition.isTrue(): Boolean = readMetaVar.isEmpty() && other.isEmpty()

fun EdgeEffect.hasNoEffect(): Boolean = assignMetaVar.isEmpty()

fun EdgeEffect.anyValueGeneratorUsed(): Boolean =
    assignMetaVar.values.any { preds -> preds.any { it.anyValueGeneratorUsed() } }

fun MethodPredicate.anyValueGeneratorUsed(): Boolean =
    predicate.signature.isGeneratedAnyValueGenerator()

fun MethodSignature.isGeneratedAnyValueGenerator(): Boolean {
    val name = methodName.name
    if (name !is SignatureName.Concrete) return false
    return name.name == generatedAnyValueGeneratorMethodName
}

fun MethodSignature.isGeneratedStringConcat(): Boolean {
    val name = methodName.name
    if (name !is SignatureName.Concrete) return false
    return name.name == generatedStringConcatMethodName
}

fun EdgeCondition.findPositivePredicate(): Predicate? =
    other.find { !it.negated }?.predicate
        ?: readMetaVar.values.firstNotNullOfOrNull { p -> p.find { !it.negated }?.predicate }

fun EdgeCondition.containsPositivePredicate(): Boolean =
    other.any { !it.negated } || readMetaVar.values.any { p -> p.any { !it.negated } }

fun MethodPredicate.findMetaVarConstraint(): MetavarAtom? {
    val constraint = predicate.constraint
    return ((constraint as? ParamConstraint)?.condition as? IsMetavar)?.metavar
}

fun EdgeCondition.containsPredicate(pred: (MethodPredicate) -> Boolean): Boolean {
    if (other.any(pred)) return true
    return readMetaVar.values.any { it.any(pred) }
}
