package org.seqra.jvm.sast.dataflow

import org.seqra.ir.api.jvm.JIRClassOrInterface

fun interface ClassLocationChecker {
    fun isProjectClass(cls: JIRClassOrInterface): Boolean
}
