package org.seqra.jvm.sast.util

import org.seqra.config.ConfigLoader
import org.seqra.dataflow.configuration.jvm.serialized.SerializedTaintConfig

fun loadDefaultConfig(): SerializedTaintConfig {
    return ConfigLoader.getConfig() ?: error("Error while loading config")
}
