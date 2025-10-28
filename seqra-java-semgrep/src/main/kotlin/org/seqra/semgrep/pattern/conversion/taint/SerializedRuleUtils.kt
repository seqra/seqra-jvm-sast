package org.seqra.semgrep.pattern.conversion.taint

import org.seqra.dataflow.configuration.jvm.serialized.PositionBase
import org.seqra.dataflow.configuration.jvm.serialized.PositionBaseWithModifiers
import org.seqra.dataflow.configuration.jvm.serialized.SerializedCondition
import org.seqra.dataflow.configuration.jvm.serialized.SerializedCondition.Companion.mkFalse
import org.seqra.dataflow.configuration.jvm.serialized.SerializedFunctionNameMatcher
import org.seqra.dataflow.configuration.jvm.serialized.SerializedNameMatcher

fun PositionBase.base(): PositionBaseWithModifiers =
    PositionBaseWithModifiers.BaseOnly(this)

fun anyName() = SerializedNameMatcher.Pattern(".*")

fun anyFunction() = SerializedFunctionNameMatcher.Complex(anyName(), anyName(), anyName())

fun SerializedFunctionNameMatcher.matchAnything(): Boolean =
    `class` == anyName() && `package` == anyName() && name == anyName()

fun serializedConditionOr(args: List<SerializedCondition>): SerializedCondition {
    val result = mutableListOf<SerializedCondition>()
    for (arg in args) {
        if (arg is SerializedCondition.Or) {
            result.addAll(arg.anyOf)
            continue
        }

        if (arg is SerializedCondition.True) return SerializedCondition.True

        if (arg.isFalse()) continue

        result.add(arg)
    }

    return when (result.size) {
        0 -> mkFalse()
        1 -> result.single()
        else -> SerializedCondition.Or(result)
    }
}
