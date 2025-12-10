package org.seqra.jvm.sast.project

import org.seqra.dataflow.ap.ifds.access.ApMode
import org.seqra.dataflow.configuration.CommonTaintConfigurationSinkMeta.Severity
import org.seqra.jvm.sast.dataflow.DebugOptions
import org.seqra.jvm.sast.dataflow.TaintAnalyzerOptions
import java.nio.file.Path
import kotlin.time.Duration

data class ProjectAnalysisOptions(
    val customConfig: Path? = null,
    val semgrepRuleSet: List<Path> = emptyList(),
    val semgrepRuleLoadErrors: Path? = null,
    val semgrepRuleLoadTrace: Path? = null,
    val semgrepMinSeverity: Severity = Severity.Note,
    val cwe: List<Int> = emptyList(),
    val useSymbolicExecution: Boolean = false,
    val symbolicExecutionTimeout: Duration = Duration.ZERO,
    val ifdsAnalysisTimeout: Duration = Duration.ZERO,
    val ifdsApMode: ApMode = ApMode.Tree,
    val projectKind: ProjectKind = ProjectKind.UNKNOWN,
    val storeSummaries: Boolean = false,
    val debugOptions: DebugOptions? = null,
) {
    val summariesApMode get() = ifdsApMode.takeIf { storeSummaries }

    fun taintAnalyzerOptions() = TaintAnalyzerOptions(
        ifdsTimeout = ifdsAnalysisTimeout,
        ifdsApMode = ifdsApMode,
        symbolicExecutionEnabled = useSymbolicExecution,
        analysisCwe = cwe.takeIf { it.isNotEmpty() }?.toSet(),
        storeSummaries = storeSummaries,
        debugOptions = debugOptions
    )
}
