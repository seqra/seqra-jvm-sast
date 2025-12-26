package org.seqra.jvm.sast.project.spring

import org.seqra.ir.api.jvm.JIRAnnotation
import org.seqra.ir.api.jvm.JIRClassOrInterface
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.ir.api.jvm.JIRParameter
import org.seqra.ir.api.jvm.ext.allSuperHierarchySequence
import org.seqra.ir.api.jvm.ext.findMethodOrNull
import org.seqra.jvm.sast.dataflow.matchedAnnotations

fun JIRMethod.isSpringControllerMethod(): Boolean =
    collectSpringControllerAnnotations() != null

fun String.isSpringMethodAnnotation(): Boolean =
    this in springControllerMethodMappingAnnotations

fun String.isSpringRequestMappingAnnotation(): Boolean =
    this == springControllerRequestMapping

fun String.isSpringControllerAnnotation(): Boolean =
    isSpringRequestMappingAnnotation() || isSpringMethodAnnotation()

fun String.isSpringControllerClassAnnotation(): Boolean =
    this in springControllerClassAnnotations

fun String.isSpringAutowiredAnnotation(): Boolean = this == SpringAutowired
fun String.isSpringValidated(): Boolean = this == JakartaValid
fun String.isSpringPathVariable(): Boolean = this == SpringPathVariable
fun String.isSpringModelAttribute(): Boolean = this == SpringModelAttribute
fun String.isSpringRequestParam(): Boolean = this == SpringRequestParam
fun String.isSpringRequestBody(): Boolean = this == SpringRequestBody
fun String.isJakartaConstraint(): Boolean = this == JakartaConstraint

fun JIRClassOrInterface.collectSpringRequestMappingAnnotation(): List<JIRAnnotation>? {
    classSpringRequestMappingAnnotation()?.let { return it }
    return allSuperHierarchySequence.firstNotNullOfOrNull { it.classSpringRequestMappingAnnotation()  }
}

fun JIRMethod.collectSpringControllerAnnotations(): List<JIRAnnotation>? {
    methodSpringControllerAnnotations()?.let { return it }

    return enclosingClass.allSuperHierarchySequence
        .mapNotNull { it.findMethodOrNull(name, description) }
        .firstNotNullOfOrNull { m -> m.methodSpringControllerAnnotations()  }
}

fun JIRClassOrInterface.classSpringRequestMappingAnnotation(): List<JIRAnnotation>? =
    matchedAnnotations(String::isSpringRequestMappingAnnotation).takeIf { it.isNotEmpty() }

fun JIRMethod.methodSpringControllerAnnotations(): List<JIRAnnotation>? =
    matchedAnnotations(String::isSpringControllerAnnotation).takeIf { it.isNotEmpty() }
