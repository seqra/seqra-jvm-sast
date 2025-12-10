package org.seqra.jvm.sast.project

import org.seqra.ir.api.jvm.RegisteredLocation
import org.seqra.jvm.sast.JIRSourceFileResolver
import org.seqra.project.Project
import java.nio.file.Path

fun Project.sourceResolver(projectClasses: ProjectClasses): JIRSourceFileResolver {
    val locationSourceRoots = hashMapOf<RegisteredLocation, Path>()
    for ((loc, module) in projectClasses.locationProjectModules) {
        locationSourceRoots[loc] = module.moduleSourceRoot ?: continue
    }

    return JIRSourceFileResolver(sourceRoot, locationSourceRoots)
}
