package org.seqra.semgrep.pattern.conversion

import org.seqra.org.seqra.semgrep.pattern.conversion.generateMethodInvocation
import org.seqra.semgrep.pattern.Ellipsis
import org.seqra.semgrep.pattern.NormalizedSemgrepRule
import org.seqra.semgrep.pattern.SemgrepJavaPattern
import org.seqra.semgrep.pattern.TypeName

const val generatedAnyValueGeneratorMethodName = "__anyValue__"

fun rewriteAssignEllipsis(rule: NormalizedSemgrepRule): List<NormalizedSemgrepRule> {
    val rewriter = object : PatternRewriter {
        override fun createVariableAssignment(
            type: TypeName?,
            variable: SemgrepJavaPattern,
            value: SemgrepJavaPattern?
        ): List<SemgrepJavaPattern> {
            if (value !is Ellipsis) {
                return super.createVariableAssignment(type, variable, value)
            }

            return super.createVariableAssignment(type, variable, anyValueCall)
        }
    }

    return rewriter.safeRewrite(rule) {
        error("No failures expected")
    }
}

private val anyValueCall by lazy {
    generateMethodInvocation(generatedAnyValueGeneratorMethodName, emptyList())
}