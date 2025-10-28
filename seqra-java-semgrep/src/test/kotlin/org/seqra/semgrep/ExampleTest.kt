package org.seqra.semgrep

import example.RuleRequiringCarefulCleaners
import example.RuleRequiringCarefulCleanersInTaint
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS
import org.seqra.dataflow.configuration.jvm.serialized.PositionBase
import org.seqra.dataflow.configuration.jvm.serialized.SerializedNameMatcher
import org.seqra.dataflow.configuration.jvm.serialized.SerializedRule
import org.seqra.dataflow.configuration.jvm.serialized.SerializedTaintPassAction
import org.seqra.semgrep.pattern.conversion.taint.anyFunction
import org.seqra.semgrep.pattern.conversion.taint.base
import org.seqra.semgrep.util.SampleBasedTest
import kotlin.test.Test

@TestInstance(PER_CLASS)
class ExampleTest : SampleBasedTest() {
    @Test
    fun `test rule`() = runTest<example.Rule>()

    @Test
    fun `test nd rule`() = runTest<example.NDRule>(EXPECT_STATE_VAR)

    @Test
    fun `test rule with pattern-inside`() = runTest<example.RuleWithPatternInside>()

    @Test
    fun `test rule with allowed constant`() = runTest<example.RuleWithAllowedConstant>()

    @Test
    fun `test rule with signature`() = runTest<example.RuleWithSignature>()

    @Test
    fun `test rule with pattern-not-inside prefix`() = runTest<example.RuleWithNotInsidePrefix>()

    @Test
    fun `test rule with intersection`() = runTest<example.RuleWithIntersection>()

    @Test
    fun `test rule with pattern-not-inside suffix`() = runTest<example.RuleWithNotInsideSuffix>()

    @Test
    fun `test rule pattern-not with signature`() = runTest<example.RulePatternNotWithSignature>()

    @Test
    fun `test rule with real pattern-inside sequence`() = runTest<example.RuleWithRealInsideSequence>()

    @Test
    fun `test rule with artificial pattern-inside sequence`() = runTest<example.RuleWithArtificialInsideSequence>()

    @Test
    fun `test rule with ellipsis method invocation`() = runTest<example.RuleWithEllipsisMethodInvocation>()

    @Test
    fun `test rule with ellipsis method invocation and pattern not`() = runTest<example.RuleWithEllipsisInvocationAndPatternNot>(EXPECT_STATE_VAR)

    @Test
    fun `test rule requiring careful cleaners`() = runTest<RuleRequiringCarefulCleaners>()

    @Test
    @Disabled // todo: pattern-sanitizers?
    fun `test rule requiring careful cleaners in taint`() = runTest<RuleRequiringCarefulCleanersInTaint>()

    @Test
    fun `test rule with artificial reverse pattern-inside sequence`() = runTest<example.RuleWithArtificialInsideSequenceReverse>()

    @Test
    fun `test simple pass`() = runTest<example.RuleWithSimplePass>(EXPECT_STATE_VAR)

    @Test
    fun `test rule with several suffix cleaners`() = runTest<example.RuleWithSeveralSuffixCleaners>()

    @Test
    fun `test rule cookie`() = runTest<example.RuleCookie>()

    @Test
    fun `test rule with static field`() = runTest<example.RuleWithStaticField>()

    @Test
    fun `test rule with state`() = runTest<example.RuleWithState>(EXPECT_STATE_VAR)

    @Test
    fun `test rule with any pattern`() = runTest<example.RuleWithAnyPattern>()

    @Test
    fun `test rule without pattern`() = runTest<example.RuleWithoutPattern>()

    @Test
    fun `test rule with type`() = runTest<example.RuleWithType>()

    @Test
    fun `test rule with interface type`() = runTest<example.RuleWithInterfaceType>()

    @Test
    fun `test patterns simple`() = runTest<example.RuleWithPatternsSimple>()

    @Test
    fun `test patterns signature`() = runTest<example.RuleWithPatternsSignature>()

    @Test
    fun `test rule with multiple patterns`() = runTest<example.RuleWithMultiplePatterns>(EXPECT_STATE_VAR)

    @Test
    fun `test rule with multiple patterns unification`() = runTest<example.RuleWithMultiplePatternsUnification>(EXPECT_STATE_VAR)

    @Test
    fun `test rule with multiple patterns ellipsis unification`() = runTest<example.RuleWithMultiplePatternsEllipsisUnification>(EXPECT_STATE_VAR)

    @Test
    fun `test rule return simple`() = runTest<example.RuleReturnSimple>()

    @Test
    fun `test rule return chained`() = runTest<example.RuleReturnChained>(EXPECT_STATE_VAR)

    @Test
    fun `test rule return conditional`() = runTest<example.RuleReturnConditional>()

    @Test
    fun `test rule return 1`() = runTest<example.RuleReturn1>()

    @Test
    fun `test rule return 2`() = runTest<example.RuleReturn2>()

    @Test
    @Disabled // todo: unconditional exit sink
    fun `test rule return 3`() = runTest<example.RuleReturn3>()

    @Test
    fun `test rule return 4`() = runTest<example.RuleReturn4>()

    @Test
    fun `test rule return 5`() = runTest<example.RuleReturn5>()

    @Test
    fun `test rule return 6`() = runTest<example.RuleReturn6>()

    @Test
    fun `test cleaner after sink 0`() = runTest<example.CleanerAfterSink0>(EXPECT_STATE_VAR)

    @Test
    fun `test cleaner after sink 1`() = runTest<example.CleanerAfterSink1>()

    @Test
    fun `test cleaner after sink 2`() = runTest<example.CleanerAfterSink2>()

    @Test
    fun `test rule return not inside`() = runTest<example.RuleReturnNotInside>()

    @Test
    fun `test rule return not inside prefix`() = runTest<example.RuleReturnNotInsidePrefix>(EXPECT_STATE_VAR)

    @Test
    fun `test rule return multi A`() = runTest<example.RuleReturnMultiInsideNotInsideA>()

    @Test
    fun `test rule return multi C`() = runTest<example.RuleReturnMultiInsideNotInsideC>()

    @Test
    fun `test not-inside signature`() = runTest<example.RulePatternNotInsideWithSignature>(EXPECT_STATE_VAR)

    @Test
    fun `test return inside signature`() = runTest<example.RuleReturnInsideSignature>()

    @Test
    fun `test return inside signature 2`() = runTest<example.RuleReturnInsideSignature2>()

    @Test
    @Disabled // todo: incorrect pattern-inside processing
    fun `test r1`() = runTest<example.R1>()

    @Test
    fun `test r2`() = runTest<example.R2>()

    @Test
    fun `test r3`() = runTest<example.R3>()

    @Test
    fun `test RuleReturnWithNotInsideSignature`() = runTest<example.RuleReturnWithNotInsideSignature>()

    @Test
    fun `test RuleReturnWithNotInsideSignature with pass`() =
        runTest<example.RuleReturnWithNotInsideSignatureWithPass> { cfg ->
            val function = anyFunction().copy(name = SerializedNameMatcher.Simple("clean"))
            val action = SerializedTaintPassAction(
                from = PositionBase.Argument(0).base(), to = PositionBase.Result.base()
            )
            val rule = SerializedRule.PassThrough(function, copy = listOf(action))
            cfg.copy(passThrough = cfg.passThrough.orEmpty() + rule)
        }

    @AfterAll
    fun close() {
        closeRunner()
    }
}
