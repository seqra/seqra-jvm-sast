package org.seqra.jvm.sast.project.spring

import org.seqra.dataflow.ap.ifds.AccessPathBase
import org.seqra.dataflow.ap.ifds.access.FactAp
import org.seqra.dataflow.ap.ifds.access.InitialFactAp
import org.seqra.dataflow.configuration.jvm.Argument
import org.seqra.dataflow.configuration.jvm.AssignMark
import org.seqra.dataflow.configuration.jvm.ClassStatic
import org.seqra.dataflow.configuration.jvm.Condition
import org.seqra.dataflow.configuration.jvm.ConstantTrue
import org.seqra.dataflow.configuration.jvm.ContainsMark
import org.seqra.dataflow.configuration.jvm.CopyAllMarks
import org.seqra.dataflow.configuration.jvm.Position
import org.seqra.dataflow.configuration.jvm.PositionAccessor
import org.seqra.dataflow.configuration.jvm.PositionWithAccess
import org.seqra.dataflow.configuration.jvm.RemoveAllMarks
import org.seqra.dataflow.configuration.jvm.Result
import org.seqra.dataflow.configuration.jvm.TaintCleaner
import org.seqra.dataflow.configuration.jvm.TaintEntryPointSource
import org.seqra.dataflow.configuration.jvm.TaintMethodEntrySink
import org.seqra.dataflow.configuration.jvm.TaintMethodExitSink
import org.seqra.dataflow.configuration.jvm.TaintMethodExitSource
import org.seqra.dataflow.configuration.jvm.TaintMethodSink
import org.seqra.dataflow.configuration.jvm.TaintMethodSource
import org.seqra.dataflow.configuration.jvm.TaintPassThrough
import org.seqra.dataflow.configuration.jvm.TaintStaticFieldSource
import org.seqra.dataflow.configuration.jvm.This
import org.seqra.dataflow.jvm.ap.ifds.taint.ConditionRewriter
import org.seqra.dataflow.jvm.ap.ifds.taint.ContainsMarkOnAnyField
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.dataflow.jvm.ap.ifds.taint.resolveBaseAp
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRField
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.ir.api.jvm.TypeName
import org.seqra.ir.impl.cfg.util.isClass

class SpringRuleProvider(
    private val base: TaintRulesProvider,
    private val springCtx: SpringWebProjectContext,
) : TaintRulesProvider by base {
    override fun entryPointRulesForMethod(method: CommonMethod, fact: FactAp?, allRelevant: Boolean): Iterable<TaintEntryPointSource> {
        if (method is SpringGeneratedMethod) return emptyList()

        val baseRules =  base.entryPointRulesForMethod(method, fact, allRelevant)
        if (method !is JIRMethod || method.isStatic || method.isPrivate || !method.isSpringControllerMethod()) {
            return baseRules
        }

        return baseRules.map { taintObjectFields(method, it) }
    }

    private fun taintObjectFields(method: JIRMethod, rule: TaintEntryPointSource): TaintEntryPointSource {
        val actions = rule.actionsAfter.flatMap { taintObjectFields(method, it) }
        return rule.copy(actionsAfter = actions)
    }

    private fun taintObjectFields(method: JIRMethod, assign: AssignMark): List<AssignMark> {
        val base = assign.position.resolveBaseAp()
        if (base !is AccessPathBase.Argument) return listOf(assign)

        val paramTypeName = method.parameters.getOrNull(base.idx)?.type
            ?: return emptyList()

        if (!paramTypeName.isClass) return listOf(assign)

        // todo: better handling of suspend functions
        if (paramTypeName.isKotlinContinuation()) return emptyList()

        val allFieldsPosition = PositionWithAccess(assign.position, PositionAccessor.AnyFieldAccessor)
        val allFieldsAssign = AssignMark(assign.mark, allFieldsPosition)

        return listOf(assign, allFieldsAssign)
    }

    override fun sourceRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean): Iterable<TaintMethodSource> {
        if (method is SpringGeneratedMethod) return emptyList()
        return base.sourceRulesForMethod(method, statement, fact, allRelevant)
    }

    override fun exitSourceRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        allRelevant: Boolean
    ): Iterable<TaintMethodExitSource> {
        if (method is SpringGeneratedMethod) return emptyList()
        return base.exitSourceRulesForMethod(method, statement, fact, allRelevant)
    }

    override fun sinkRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean): Iterable<TaintMethodSink> {
        if (method is SpringGeneratedMethod) return emptyList()
        return base.sinkRulesForMethod(method, statement, fact, allRelevant)
    }

    override fun sinkRulesForMethodEntry(method: CommonMethod, fact: FactAp?, allRelevant: Boolean): Iterable<TaintMethodEntrySink> {
        if (method is SpringGeneratedMethod) return emptyList()
        return base.sinkRulesForMethodEntry(method, fact, allRelevant)
    }

    override fun cleanerRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        allRelevant: Boolean
    ): Iterable<TaintCleaner> {
        if (method is SpringGeneratedMethod) {
            if (method.name != GeneratedSpringControllerDispatcherCleanupMethod) {
                return emptyList()
            }

            val currentFact = fact ?: return emptyList()
            val cleanupPosition = currentFact.base.cleanupPosition() ?: return emptyList()

            val cleaner = TaintCleaner(
                method, ConstantTrue,
                listOf(RemoveAllMarks(cleanupPosition)),
                info = null
            )

            return listOf(cleaner)
        }

        return base.cleanerRulesForMethod(method, statement, fact, allRelevant)
    }

    private fun AccessPathBase.cleanupPosition(): Position? {
        if (this !is AccessPathBase.ClassStatic) return toPosition()
        if (this.typeName != GeneratedSpringRegistry) return toPosition()
        return null
    }

    private fun AccessPathBase.toPosition(): Position? = when (this) {
        is AccessPathBase.Argument -> Argument(idx)
        is AccessPathBase.ClassStatic -> ClassStatic(typeName)
        is AccessPathBase.Constant -> null
        is AccessPathBase.Exception -> null
        is AccessPathBase.LocalVar -> null
        is AccessPathBase.Return -> Result
        is AccessPathBase.This -> This
    }

    override fun sourceRulesForStaticField(field: JIRField, statement: CommonInst, fact: FactAp?, allRelevant: Boolean): Iterable<TaintStaticFieldSource> {
        if (field is SpringGeneratedField) return emptyList()
        return base.sourceRulesForStaticField(field, statement, fact, allRelevant)
    }

    override fun passTroughRulesForMethod(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        allRelevant: Boolean
    ): Iterable<TaintPassThrough> {
        if (method is SpringGeneratedMethod) return emptyList()
        val rules = base.passTroughRulesForMethod(method, statement, fact, allRelevant).toList()

        val springRepoMethodInfo = springCtx.springRepositoryMethods[method]
            ?: return rules

        val repoActions = springRepoMethodInfo.actions()
            ?: return rules

        val repoRule = TaintPassThrough(method, ConstantTrue, repoActions, info = null)
        return rules + repoRule
    }

    private fun RepositoryMethodInfo.actions(): List<CopyAllMarks>? {
        val actions = mutableListOf<CopyAllMarks>()
        val repoPos = PositionWithAccess(This, repositoryContent)
        when (kind) {
            SpringRepoQueryKind.SAVE -> {
                val entityPos = Argument(0)

                when (type) {
                    // todo: support reactive types
                    is SpringRepoQueryReturn.Reactive -> return null
                    is SpringRepoQueryReturn.Unknown -> return null
                    is SpringRepoQueryReturn.Primitive,
                    is SpringRepoQueryReturn.Single -> {
                        actions += CopyAllMarks(from = entityPos, to = repoPos)
                    }

                    is SpringRepoQueryReturn.Iterable -> {
                        actions += CopyAllMarks(
                            from = PositionWithAccess(entityPos, iterableElement),
                            to = repoPos
                        )
                    }
                }

                actions += CopyAllMarks(from = entityPos, to = Result)
            }

            SpringRepoQueryKind.FIND ->
                when (type) {
                    // todo: support reactive types
                    is SpringRepoQueryReturn.Reactive -> return null
                    is SpringRepoQueryReturn.Unknown -> return null

                    // do nothing
                    is SpringRepoQueryReturn.Primitive -> {}

                    is SpringRepoQueryReturn.Entity -> {
                        actions += CopyAllMarks(from = repoPos, to = Result)
                    }

                    is SpringRepoQueryReturn.Iterable -> {
                        actions += CopyAllMarks(
                            from = repoPos,
                            to = PositionWithAccess(Result, iterableElement)
                        )
                    }

                    is SpringRepoQueryReturn.Optional -> {
                        actions += CopyAllMarks(
                            from = repoPos,
                            to = PositionWithAccess(Result, optionalElement)
                        )
                    }
                }

            SpringRepoQueryKind.OTHER -> return null
        }

        return actions.takeIf { it.isNotEmpty() }
    }

    override fun sinkRulesForMethodExit(
        method: CommonMethod,
        statement: CommonInst,
        fact: FactAp?,
        initialFacts: Set<InitialFactAp>?,
        allRelevant: Boolean
    ): Iterable<TaintMethodExitSink> {
        if (method !is JIRMethod || !method.isSpringControllerMethod()) {
            return base.sinkRulesForMethodExit(method, statement, fact, initialFacts, allRelevant)
        }

        val allBaseRules = base.sinkRulesForMethodExit(method, statement, fact, initialFacts = null, allRelevant)
        return allBaseRules.map { unfoldSpringExitObject(it) }
    }

    private fun unfoldSpringExitObject(rule: TaintMethodExitSink): TaintMethodExitSink =
        rule.copy(condition = unfoldObjectContainsMark(position = Result, rule.condition))

    private fun unfoldObjectContainsMark(position: Position, condition: Condition): Condition =
        condition.accept(ContainsMarkRewriter(position))

    private class ContainsMarkRewriter(val position: Position) : ConditionRewriter {
        override fun visit(condition: ContainsMark): Condition {
            if (condition.position != position) return condition

            return ContainsMarkOnAnyField(position, condition.mark)
        }
    }

    private fun TypeName.isKotlinContinuation(): Boolean = typeName == kotlinContinuation

    companion object {
        private const val javaObject = "java.lang.Object"
        private const val kotlinContinuation = "kotlin.coroutines.Continuation"

        private val iterableElement = PositionAccessor.FieldAccessor(
            className = "java.lang.Iterable",
            fieldName = "Element",
            fieldType = javaObject,
        )

        private val optionalElement = PositionAccessor.FieldAccessor(
            className = "java.util.Optional",
            fieldName = "Element",
            fieldType = javaObject,
        )

        private val repositoryContent = PositionAccessor.FieldAccessor(
            className = javaObject,
            fieldName = "__repo__",
            fieldType = javaObject,
        )
    }
}
