package org.seqra.org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.EllipsisArgumentPrefix
import org.seqra.semgrep.pattern.MethodArguments
import org.seqra.semgrep.pattern.NoArgs
import org.seqra.semgrep.pattern.PatternArgumentPrefix
import org.seqra.semgrep.pattern.SemgrepJavaPattern

fun createMethodArgs(args: List<SemgrepJavaPattern>): MethodArguments =
    args.foldRight(NoArgs as MethodArguments) { p, res -> PatternArgumentPrefix(p, res) }

fun parseMethodArgs(args: MethodArguments): List<SemgrepJavaPattern> = when (args) {
    is NoArgs -> emptyList()
    is EllipsisArgumentPrefix -> listOf(args) + parseMethodArgs(args.rest)
    is PatternArgumentPrefix -> listOf(args.argument) + parseMethodArgs(args.rest)
}
