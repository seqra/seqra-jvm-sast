package org.seqra.jvm.sast.sarif

import io.github.detekt.sarif4k.Message
import io.github.detekt.sarif4k.Result
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
import org.seqra.dataflow.ap.ifds.access.FinalFactAp
import org.seqra.dataflow.sarif.SourceFileResolver
import org.seqra.dataflow.util.SarifTraits
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import java.io.OutputStream

class DebugFactReachabilitySarifGenerator(
    sourceFileResolver: SourceFileResolver<CommonInst>,
    private val traits: SarifTraits<CommonMethod, CommonInst>,
) {
    private val locationResolver = LocationResolver(sourceFileResolver, traits)

    private val json = Json {
        prettyPrint = true
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun generateSarif(
        output: OutputStream,
        facts: Map<CommonInst, Set<FinalFactAp>>,
    ) {
        val locations = generateFactLocations(facts)
        val resolvedLocations = locationResolver.resolve(locations)

        val results = resolvedLocations.asSequence().mapIndexedNotNull { index, location ->
            val loc = location.location ?: return@mapIndexedNotNull null
            val ruleId = "s_$index"
            Result(ruleID = ruleId, message = Message(text = loc.message?.text), locations = listOf(loc))
        }

        val run = LazyToolRunReport(
            tool = generateSarifAnalyzerToolDescription(metadatas = emptyList()),
            results = results,
        )

        val sarifReport = LazySarifReport.fromRuns(listOf(run))
        json.encodeToStream(sarifReport, output)
    }

    private fun generateFactLocations(statementFacts: Map<CommonInst, Set<FinalFactAp>>): List<IntermediateLocation> {
        val result = mutableListOf<IntermediateLocation>()

        for ((stmt, facts) in statementFacts) {
            result += IntermediateLocation(
                inst = stmt,
                info = getInstructionInfo(stmt, rewriteLine = null),
                kind = "unknown",
                message = "$facts",
            )
        }

        return result
    }

    private fun getInstructionInfo(statement: CommonInst, rewriteLine: Int? = null): InstructionInfo = with(traits) {
        InstructionInfo(
            fullyQualified = locationFQN(statement),
            machineName = locationMachineName(statement),
            lineNumber = rewriteLine ?: lineNumber(statement),
            noExtraResolve = rewriteLine != null
        )
    }
}
