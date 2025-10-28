package org.seqra.semgrep.pattern.conversion

import org.seqra.org.seqra.semgrep.pattern.conversion.generateMethodInvocation
import org.seqra.org.seqra.semgrep.pattern.conversion.parseMethodArgs
import org.seqra.semgrep.pattern.ConcreteName
import org.seqra.semgrep.pattern.MetavarName
import org.seqra.semgrep.pattern.MethodInvocation
import org.seqra.semgrep.pattern.NormalizedSemgrepRule
import org.seqra.semgrep.pattern.SemgrepJavaPattern

// todo: rewrite all AddExpr as string concat for now
// we can consider split on string/non-string
// or seqra.plus utility method with special handling in engine
fun rewriteAddExpr(rule: NormalizedSemgrepRule): List<NormalizedSemgrepRule> {
    val rewriter = object : PatternRewriter {
        override fun createAddExpr(left: SemgrepJavaPattern, right: SemgrepJavaPattern): List<SemgrepJavaPattern> =
            listOf(generateStringConcat(left, right))
    }

    return rewriter.safeRewrite(rule) {
        error("No failures expected")
    }
}

const val generatedStringConcatMethodName = "__stringConcat__"

private fun generateStringConcat(first: SemgrepJavaPattern, second: SemgrepJavaPattern): SemgrepJavaPattern {
    val firstArgs = flatStringConcat(first)
    val secondArgs = flatStringConcat(second)
    return generateMethodInvocation(generatedStringConcatMethodName, firstArgs + secondArgs)
}

private fun flatStringConcat(pattern: SemgrepJavaPattern): List<SemgrepJavaPattern> {
    if (pattern !is MethodInvocation) return listOf(pattern)

    when (val mn = pattern.methodName) {
        is ConcreteName -> {
            if (mn.name == generatedStringConcatMethodName) {
                return parseMethodArgs(pattern.args)
            }
        }

        is MetavarName -> {}
    }

    return listOf(pattern)
}
