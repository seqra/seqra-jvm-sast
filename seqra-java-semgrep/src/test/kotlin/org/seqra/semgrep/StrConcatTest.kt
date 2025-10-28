package org.seqra.semgrep

import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS
import org.seqra.semgrep.util.SampleBasedTest
import kotlin.test.Test

@TestInstance(PER_CLASS)
class StrConcatTest : SampleBasedTest(configurationRequired = true) {
    @Test
    fun `test rule with ellipsis string concat`() = runTest<strconcat.RuleWithEllipsisStringConcat>(EXPECT_STATE_VAR)

    @Test
    fun `test rule with ellipsis concat`() = runTest<strconcat.RuleWithEllipsisConcat>(EXPECT_STATE_VAR)

    @Test
    @Disabled // TODO: support string concat with concrete string
    fun `test rule with concrete string concat`() = runTest<strconcat.RuleWithConcreteStringConcat>()

    @Test
    fun `test rule with metavar concat`() = runTest<strconcat.RuleWithMetavarConcat>(EXPECT_STATE_VAR)

    @Test
    fun `test rule with multiple metavar concat`() = runTest<strconcat.RuleWithMultipleMetavarConcat>(EXPECT_STATE_VAR)

    @Test
    fun `test rule with unbound concat`() = runTest<strconcat.RuleWithUnboundConcat>(EXPECT_STATE_VAR)

    @AfterAll
    fun close() {
        closeRunner()
    }
}