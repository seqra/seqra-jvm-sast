package org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.ConcreteName
import org.seqra.semgrep.pattern.MetaVarConstraint
import org.seqra.semgrep.pattern.MetaVarConstraintFormula
import org.seqra.semgrep.pattern.MetaVarConstraints
import org.seqra.semgrep.pattern.MetavarName
import org.seqra.semgrep.pattern.Name
import org.seqra.semgrep.pattern.NormalizedSemgrepRule
import org.seqra.semgrep.pattern.ResolvedMetaVarInfo
import org.seqra.semgrep.pattern.TypeName
import org.seqra.semgrep.pattern.flatMap
import org.seqra.semgrep.pattern.transform

fun rewriteTypeNameWithMetaVar(
    rule: NormalizedSemgrepRule,
    metaVarInfo: ResolvedMetaVarInfo
): Pair<List<NormalizedSemgrepRule>, ResolvedMetaVarInfo> {
    val generatedMetaVars = hashMapOf<TypeName.SimpleTypeName, String>()

    val rewriter = object : PatternRewriter {
        override fun TypeName.SimpleTypeName.rewriteSimpleTypeName(): TypeName.SimpleTypeName {
            if (dotSeparatedParts.size < 2) return this
            if (dotSeparatedParts.all { it !is MetavarName }) return this

            val metaVar = generatedMetaVars.getOrPut(this) {
                "__TYPE#${generatedMetaVars.size}__"
            }

            return TypeName.SimpleTypeName(listOf(MetavarName(metaVar)), typeArgs)
        }
    }

    val modifierRule = rewriter.safeRewrite(rule) { error("No failures expected") }

    if (generatedMetaVars.isEmpty()) {
        return listOf(rule) to metaVarInfo
    }

    val constraints = metaVarInfo.metaVarConstraints.toMutableMap()

    for ((typeName, generatedMetaVar) in generatedMetaVars) {
        val initial: MetaVarConstraintFormula<List<String>> = MetaVarConstraintFormula.Constraint(emptyList())
        val constraintParts = typeName.dotSeparatedParts.foldIndexed(initial) { idx, acc, name ->
            acc.transformNext(idx, name, typeName, constraints)
        }

        val pattern = constraintParts.transform<_, MetaVarConstraint> { parts ->
            MetaVarConstraint.RegExp(parts.joinToString("\\."))
        }

        constraints[generatedMetaVar] = MetaVarConstraints(pattern)
    }

    return modifierRule to ResolvedMetaVarInfo(metaVarInfo.focusMetaVars, constraints)
}

private fun MetaVarConstraintFormula<List<String>>.transformNext(
    i: Int, name: Name,
    typeName: TypeName.SimpleTypeName,
    constraints: Map<String, MetaVarConstraints>
): MetaVarConstraintFormula<List<String>> {
    when (name) {
        is ConcreteName -> return transform { constraintParts ->
            constraintParts + name.name
        }

        is MetavarName -> {
            val currentConstraints = constraints[name.metavarName]
            if (currentConstraints == null) {
                return transform { constraintParts ->
                    constraintParts + ".*"
                }
            }

            val constraintFormula = currentConstraints.constraint
            return constraintFormula.flatMap { constraintLit ->
                if (constraintLit is MetaVarConstraintFormula.NegatedConstraint) {
                    TODO("TypeName metavar with negated constraint")
                }

                val constraint = constraintLit.constraint
                val nextPart = when (constraint) {
                    is MetaVarConstraint.Concrete -> constraint.value
                    is MetaVarConstraint.RegExp -> {
                        val normalizedRegex = when (i) {
                            0 -> constraint.regex.trimEnd('$')
                            typeName.dotSeparatedParts.lastIndex -> constraint.regex.trimStart('^')
                            else -> constraint.regex.trimEnd('$').trimStart('^')
                        }
                        normalizedRegex
                    }
                }

                transform { constraintParts ->
                    constraintParts + nextPart
                }
            }
        }
    }
}
