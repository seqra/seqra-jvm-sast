package org.seqra.jvm.sast.sarif

import io.github.detekt.sarif4k.ArtifactLocation
import io.github.detekt.sarif4k.Location
import io.github.detekt.sarif4k.LogicalLocation
import io.github.detekt.sarif4k.Message
import io.github.detekt.sarif4k.PhysicalLocation
import io.github.detekt.sarif4k.Region
import io.github.detekt.sarif4k.ThreadFlowLocation
import mu.KLogging
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.seqra.dataflow.sarif.SourceFileResolver
import org.seqra.dataflow.util.SarifTraits
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRClassOrInterface
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.ir.api.jvm.cfg.JIRInstList
import org.seqra.ir.api.jvm.cfg.JIRRawInst
import org.seqra.ir.api.jvm.cfg.JIRRawLabelInst
import org.seqra.ir.api.jvm.cfg.JIRRawLineNumberInst
import org.seqra.jvm.sast.mostOuterClass
import org.seqra.jvm.sast.util.DebugInfo
import org.seqra.jvm.sast.util.DebugInfoParser
import org.seqra.jvm.sast.util.SourcePosition

data class InstructionInfo(
    val fullyQualified: String, val machineName: String, var lineNumber: Int,
    val noExtraResolve: Boolean = false
)

data class IntermediateLocation(
    val inst: CommonInst,
    val info: InstructionInfo,
    val kind: String,
    val message: String?,
)

class LocationResolver(
    private val sourceFileResolver: SourceFileResolver<CommonInst>,
    private val traits: SarifTraits<CommonMethod, CommonInst>
) {
    fun resolve(locations: List<IntermediateLocation>): List<ThreadFlowLocation> {
        var currentIdx = 0
        return locations.map { loc -> resolveLocation(loc, currentIdx).also { currentIdx += it.size } }.flatten()
    }

    fun statementsLocationsAreRelative(a: CommonInst, b: CommonInst): Boolean {
        val aSource = getCachedSourceLocation(a)
        val bSource = getCachedSourceLocation(b)
        if (aSource == null || bSource == null) return false

        return traits.lineNumber(a) == traits.lineNumber(b) && aSource == bSource
    }

    fun generateSarifLocation(location: IntermediateLocation): Location {
        val realPosition = getCachedDebugInfo(location)?.findRealPosition(location.info.lineNumber)
        val source = if (realPosition != null) {
            location.info.lineNumber = realPosition.line
            getCachedSourceLocation(location.inst, realPosition.path, realPosition.file)
        }
        else {
            getCachedSourceLocation(location.inst)
        }
        return generateSarifLocation(location, source)
    }

    private val locationsCache = hashMapOf<CommonInst, String?>()
    private fun <Statement : CommonInst> getCachedSourceLocation(
        inst: Statement
    ): String? =
        locationsCache.computeIfAbsent(inst) {
            sourceFileResolver.resolveByInst(inst)
        }

    private val sourcesCache = hashMapOf<Pair<String, String>, String?>()
    private fun <Statement : CommonInst> getCachedSourceLocation(
        inst: Statement, pkg: String, name: String
    ): String? =
        sourcesCache.computeIfAbsent(pkg to name) {
            sourceFileResolver.resolveByName(inst, pkg, name)
        }

    private val debugInfoCache = hashMapOf<JIRClassOrInterface, DebugInfo?>()
    private fun getCachedDebugInfo(cls: JIRClassOrInterface): DebugInfo? =
        debugInfoCache.computeIfAbsent(cls.mostOuterClass()) {
            DebugInfoParser.parseOrNull(it.withAsmNode { it.sourceDebug })
        }

    private fun getCachedDebugInfo(location: IntermediateLocation): DebugInfo? {
        val method = location.inst.location.method
        check(method is JIRMethod)
        return getCachedDebugInfo(method.enclosingClass)
    }

    private data class InlineLocal(val insnStart: Int, val insnEnd: Int, val methodName: String)

    private fun isInlineOrLambda(name: String) =
        name.startsWith(INLINE_LOCAL_PREFIX) || name.startsWith(LAMBDA_LOCAL_PREFIX)

    private fun getInlinedName(name: String): String {
        if (name.startsWith(INLINE_LOCAL_PREFIX)) {
            return "method \"${name.drop(INLINE_LOCAL_PREFIX.length)}\""
        }
        return LAMBDA_MARKER
    }

    private val methodInfoCache = hashMapOf<JIRMethod, List<InlineLocal>>()

    private class BaseMethodVisitor : MethodVisitor(Opcodes.ASM9)
    private val mVisitor = BaseMethodVisitor()

    private fun getCachedMethodInfo(method: JIRMethod): List<InlineLocal> =
        methodInfoCache.computeIfAbsent(method) {
            method.withAsmNode { md ->
                val insts = md.instructions
                insts.accept(mVisitor)
                // filtering local variables responsible for inlined method's ranges
                val inlines = md.localVariables.filter { isInlineOrLambda(it.name) }
                inlines.map {
                    InlineLocal(
                        insts.indexOf(it.start),
                        insts.indexOf(it.end),
                        getInlinedName(it.name)
                    )
                }.sortedBy { it.insnStart }
            }
        }

    private fun JIRRawInst.isLabelOrLine(): Boolean =
        this is JIRRawLabelInst || this is JIRRawLineNumberInst

    private data class FileLocation(val lineNumber: Int, val sourceFile: String)

    private data class ResolvedInlineCall(
        val callLocation: FileLocation,
        val methodLocation: FileLocation,
        val methodName: String
    )

    private fun DebugInfo.findRealPosition(lineNumber: Int): SourcePosition? {
        val range = findRange(lineNumber) ?: return null
        return range.mapDestToSource(lineNumber)
    }

    private fun findNextLine(rawInstList: JIRInstList<JIRRawInst>, startId: Int): Int? {
        var currentId = startId
        while (currentId < rawInstList.size && rawInstList[currentId] !is JIRRawLineNumberInst)
            currentId++
        if (currentId == rawInstList.size)
            return null
        return (rawInstList[currentId] as JIRRawLineNumberInst).lineNumber
    }

    private fun getFileLocation(inst: CommonInst, sourcePosition: SourcePosition): FileLocation? {
        val sourceFile = getCachedSourceLocation(inst, sourcePosition.path, sourcePosition.file) ?: return null
        return FileLocation(
            sourcePosition.line,
            sourceFile
        )
    }

    private data class InlineEntry(val callLine: Int, val firstInlineLine: Int, val methodName: String)

    private fun resolveInlineEntry(inst: CommonInst, debugInfo: DebugInfo, entry: InlineEntry): ResolvedInlineCall? {
        val callPosition = debugInfo.findRealPosition(entry.callLine) ?: return null
        val methodPosition = debugInfo.findRealPosition(entry.firstInlineLine) ?: return null
        val callLocation = getFileLocation(inst, callPosition) ?: return null
        val methodLocation = getFileLocation(inst, methodPosition) ?: return null
        return ResolvedInlineCall(
            callLocation,
            methodLocation,
            entry.methodName
        )
    }

    private fun restoreInlineCalls(inst: CommonInst): List<InlineEntry>? {
        val methodEnters = mutableListOf<InlineEntry?>()

        var lastLineNumber: Int = -1
        var rawInstId = -1
        var instId = -1

        val method = inst.location.method as JIRMethod
        val inlines = getCachedMethodInfo(method)
        var inlineId = 0
        val inlineEnds = inlines.map { it.insnEnd }.toSet()

        val rawInsts = method.rawInstList
        val insts = method.instList
        do {
            instId++
            rawInstId++
            while (rawInstId < rawInsts.size && rawInsts[rawInstId].isLabelOrLine()) {
                val rawInst = rawInsts[rawInstId]
                if (rawInst is JIRRawLineNumberInst) {
                    lastLineNumber = rawInst.lineNumber
                }
                if (rawInst is JIRRawLabelInst && rawInst.isOriginal()) {
                    val originalLabelIndex = rawInst.getOriginalLabelIndex()!!
                    // code of a new inlined method is about to start;
                    // taking last line number label appeared as a place where the "call" happens
                    if (inlineId < inlines.size && originalLabelIndex == inlines[inlineId].insnStart) {
                        val firstMethodLine = findNextLine(rawInsts, rawInstId)
                        if (firstMethodLine != null) {
                            methodEnters.add(
                                InlineEntry(
                                    lastLineNumber,
                                    firstMethodLine,
                                    inlines[inlineId].methodName
                                )
                            )
                        } else {
                            methodEnters.add(null)
                        }
                        inlineId++
                    }
                    // end of inline reached; popping the last entry
                    if (originalLabelIndex in inlineEnds) {
                        methodEnters.removeLast()
                    }
                }
                rawInstId++
            }
            if (rawInstId == rawInsts.size) return null
        } while (instId < insts.size && insts[instId] != inst)
        if (instId == insts.size) return null

        return methodEnters.filterNotNull()
    }

    private fun generateSarifLocation(
        location: IntermediateLocation,
        sourceFile: String?
    ): Location = Location(
        physicalLocation = sourceFile?.let {
            PhysicalLocation(
                artifactLocation = ArtifactLocation(uri = it),
                region = Region(
                    startLine = location.info.lineNumber.toLong()
                )
            )
        },
        logicalLocations = listOf(
            LogicalLocation(
                fullyQualifiedName = location.info.fullyQualified,
                decoratedName = location.info.machineName
            )
        ),
        message = location.message?.let { Message(text = it.capitalize()) }
    )

    private fun generateThreadFlowLocation(
        location: IntermediateLocation,
        sourceFile: String?,
        idx: Int,
    ): ThreadFlowLocation = ThreadFlowLocation(
        index = idx.toLong(),
        executionOrder = idx.toLong(),
        kinds = listOf(location.kind),
        location = generateSarifLocation(location, sourceFile)
    )

    private fun generateLocationFromPosition(
        position: SourcePosition,
        initialLocation: IntermediateLocation,
        idx: Int
    ): ThreadFlowLocation {
        val callSource = getCachedSourceLocation(initialLocation.inst, position.path, position.file)
        val callLocation = initialLocation.copy(
            info = initialLocation.info.copy(lineNumber = position.line),
        )
        return generateThreadFlowLocation(callLocation, callSource, idx)
    }

    private fun generateInlineCallLocation(
        call: ResolvedInlineCall,
        initialLocation: IntermediateLocation,
        idx: Int
    ): List<ThreadFlowLocation> {
        val callFlow = IntermediateLocation(
            inst = initialLocation.inst,
            info = initialLocation.info.copy(lineNumber = call.callLocation.lineNumber),
            kind = "call",
            message = "Inline ${call.methodName} inserted"
        ).let { generateThreadFlowLocation(it, call.callLocation.sourceFile, idx) }
        // if it's lambda, keep the original line; otherwise, try to highlight method declaration,
        // just as with MethodEntry case
        val methodStartLineFix = if (call.methodName == LAMBDA_MARKER) 0 else -1
        val methodFlow = IntermediateLocation(
            inst = initialLocation.inst,
            info = initialLocation.info.copy(lineNumber = call.methodLocation.lineNumber + methodStartLineFix),
            kind = "unknown",
            message = "Inlined body of ${call.methodName} entered"
        ).let { generateThreadFlowLocation(it, call.methodLocation.sourceFile, idx + 1)}
        return listOf(callFlow, methodFlow)
    }

    private fun resolveLocation(location: IntermediateLocation, startIdx: Int): List<ThreadFlowLocation> {
        val debugInfo = getCachedDebugInfo(location)
        val debugRange = debugInfo?.findRange(location.info.lineNumber)
        if (debugRange == null || location.info.noExtraResolve) {
            val source = getCachedSourceLocation(location.inst)
            return listOf(generateThreadFlowLocation(location, source, startIdx))
        }
        val actualPosition = debugRange.mapDestToSource(location.info.lineNumber)
        val flowLocations = mutableListOf<ThreadFlowLocation>()
        var currentIdx = startIdx
        val restoredInlines = restoreInlineCalls(location.inst)
        if (restoredInlines == null) {
            logger.warn { "Inline restore failed for ${location.info} at ${getCachedSourceLocation(location.inst)}!" }
        }
        else {
            for (inlineCall in restoredInlines.mapNotNull { resolveInlineEntry(location.inst, debugInfo, it) }) {
                flowLocations.addAll(generateInlineCallLocation(inlineCall, location, currentIdx))
                currentIdx += 2
            }
        }
        flowLocations.add(generateLocationFromPosition(actualPosition, location, currentIdx))
        return flowLocations
    }

    companion object {
        private const val INLINE_LOCAL_PREFIX = "\$i\$f\$"
        private const val LAMBDA_LOCAL_PREFIX = "\$i\$a\$"
        private const val LAMBDA_MARKER = "lambda"

        private val logger = object : KLogging() {}.logger
    }
}
