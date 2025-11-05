package org.seqra.org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.ConcreteName
import org.seqra.semgrep.pattern.MethodInvocation
import org.seqra.semgrep.pattern.SemgrepJavaPattern
import org.seqra.semgrep.pattern.TypeName
import org.seqra.semgrep.pattern.TypedMetavar
import org.seqra.semgrep.pattern.conversion.mkGeneratedMethodInvocationObjMetaVar

const val generatedMethodClassName = "__.gen.__"

private var genCnt = 0
private val generatedMethodClassType by lazy { TypeName.SimpleTypeName(generatedMethodClassName.split('.').map { ConcreteName(it) }) }

fun generateMethodInvocation(methodName: String, args: List<SemgrepJavaPattern>): MethodInvocation {
    val argsPattern = createMethodArgs(args)
    val obj = TypedMetavar(mkGeneratedMethodInvocationObjMetaVar(genCnt++), generatedMethodClassType)
    return MethodInvocation(ConcreteName(methodName), obj, argsPattern)
}
