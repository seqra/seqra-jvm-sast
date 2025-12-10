package org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.ConcreteName
import org.seqra.semgrep.pattern.Ellipsis
import org.seqra.semgrep.pattern.Metavar
import org.seqra.semgrep.pattern.MetavarName
import org.seqra.semgrep.pattern.Name
import org.seqra.semgrep.pattern.NormalizedSemgrepRule
import org.seqra.semgrep.pattern.PatternSequence
import org.seqra.semgrep.pattern.SemgrepJavaPattern
import org.seqra.semgrep.pattern.TypeName

// todo: for now we rewrite all catch statements as typed assign
fun rewriteCatchStatement(rule: NormalizedSemgrepRule): List<NormalizedSemgrepRule> {
    val rewriter = object : PatternRewriter {
        override fun createCatchStatement(
            exceptionTypes: List<TypeName>,
            exceptionVariable: Name,
            handlerBlock: SemgrepJavaPattern
        ): List<SemgrepJavaPattern> {
            val exceptionMetaVarName = when (exceptionVariable) {
                is ConcreteName -> return super.createCatchStatement(exceptionTypes, exceptionVariable, handlerBlock)
                is MetavarName -> exceptionVariable.metavarName
            }

            val exceptionMetaVar = Metavar(exceptionMetaVarName)

            return exceptionTypes.flatMap { type ->
                super.createVariableAssignment(type, exceptionMetaVar, value = Ellipsis).map { assign ->
                   PatternSequence(assign, handlerBlock)
                }
            }
        }
    }

    return rewriter.safeRewrite(rule) {
        error("No failures expected")
    }
}
