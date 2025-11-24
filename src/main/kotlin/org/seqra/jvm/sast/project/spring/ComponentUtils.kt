package org.seqra.jvm.sast.project.spring

import org.seqra.ir.api.jvm.JIRAnnotation
import org.seqra.ir.api.jvm.JIRClassOrInterface
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.ir.api.jvm.ext.allSuperHierarchySequence
import org.seqra.ir.api.jvm.ext.findMethodOrNull

fun JIRAnnotation.isSpringAutowiredAnnotation(): Boolean = jIRClass?.name == SpringAutowired

fun JIRMethod.isSpringControllerMethod(): Boolean {
    if (annotations.any { it.jIRClass?.name in springControllerMethodAnnotations }) return true

    return enclosingClass.allSuperHierarchySequence
        .mapNotNull { it.findMethodOrNull(name, description) }
        .any { m -> m.annotations.any { it.jIRClass?.name in springControllerMethodAnnotations } }
}

fun JIRAnnotation.isSpringValidated(): Boolean =
    jIRClass?.name == JakartaValid

fun JIRAnnotation.isSpringPathVariable(): Boolean =
    jIRClass?.name == SpringPathVariable

fun JIRAnnotation.isSpringModelAttribute(): Boolean =
    jIRClass?.name == SpringModelAttribute

fun JIRAnnotation.isJakartaConstraint(): Boolean =
    jIRClass?.name == JakartaConstraint

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

fun JIRClassOrInterface.classSpringRequestMappingAnnotation(): List<JIRAnnotation>? {
    val thisAnnotations = annotations.filter { it.jIRClass?.name == springControllerRequestMapping }
    if (thisAnnotations.isNotEmpty()) return thisAnnotations
    return null
}

fun JIRMethod.methodSpringControllerAnnotations(): List<JIRAnnotation>? {
    val thisAnnotations = annotations.filter { it.jIRClass?.name in springControllerMethodAnnotations }
    if (thisAnnotations.isNotEmpty()) return thisAnnotations
    return null
}
