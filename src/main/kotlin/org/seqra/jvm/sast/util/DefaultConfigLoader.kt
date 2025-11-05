package org.seqra.jvm.sast.util

import org.seqra.dataflow.configuration.jvm.serialized.SerializedTaintConfig
import org.seqra.dataflow.configuration.jvm.serialized.loadSerializedTaintConfig

private object DefaultConfigLoader

fun loadDefaultConfig(): SerializedTaintConfig {
    val config = DefaultConfigLoader.javaClass.classLoader.getResourceAsStream("config.yaml")
        ?: error("Default configuration not found")

    return config.use { loadSerializedTaintConfig(it) }
}
