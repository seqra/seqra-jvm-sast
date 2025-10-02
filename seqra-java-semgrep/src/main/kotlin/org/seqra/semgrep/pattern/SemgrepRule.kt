package org.seqra.semgrep.pattern

sealed interface SemgrepRule<PatternsRepr> {
    fun <NewRepr> transform(block: (PatternsRepr) -> NewRepr): SemgrepRule<NewRepr>
    fun <NewRepr> flatMap(block: (PatternsRepr) -> List<NewRepr>): SemgrepRule<NewRepr>
}

data class SemgrepTaintPropagator<PatternsRepr>(
    val from: String,
    val to: String,
    val bySideEffect: Boolean?,
    val pattern: PatternsRepr,
) {
    fun <NP> updatePattern(pattern: NP) = SemgrepTaintPropagator(from, to, bySideEffect, pattern)
}

data class SemgrepTaintSanitizer<PatternsRepr>(
    val exact: Boolean?,
    val bySideEffect: Boolean?,
    val pattern: PatternsRepr,
) {
    fun <NP> updatePattern(pattern: NP) = SemgrepTaintSanitizer(exact, bySideEffect, pattern)
}

data class SemgrepTaintSource<PatternsRepr>(
    val exact: Boolean?,
    val control: Boolean?,
    val bySideEffect: Boolean?,
    val label: SemgrepTaintLabel?,
    val requires: SemgrepTaintRequires?,
    val pattern: PatternsRepr,
) {
    fun <NP> updatePattern(pattern: NP) = SemgrepTaintSource(exact, control, bySideEffect, label, requires, pattern)
}

data class SemgrepTaintSink<PatternsRepr>(
    val requires: SemgrepSinkTaintRequirement?,
    val pattern: PatternsRepr,
) {
    fun <NP> updatePattern(pattern: NP) = SemgrepTaintSink(requires, pattern)
}

sealed interface SemgrepTaintRequires

data class SemgrepTaintLabel(val label: String): SemgrepTaintRequires

sealed interface SemgrepSinkTaintRequirement {
    data class Simple(val requirement: SemgrepTaintRequires) : SemgrepSinkTaintRequirement
    data class MetaVarRequirement(val requirement: Map<String, SemgrepTaintRequires>) : SemgrepSinkTaintRequirement
}

data class SemgrepTaintRule<PatternsRepr>(
    val sources: List<SemgrepTaintSource<PatternsRepr>>,
    val sinks: List<SemgrepTaintSink<PatternsRepr>>,
    val propagators: List<SemgrepTaintPropagator<PatternsRepr>>,
    val sanitizers: List<SemgrepTaintSanitizer<PatternsRepr>>,
) : SemgrepRule<PatternsRepr> {
    override fun <NewRepr> transform(block: (PatternsRepr) -> NewRepr) =
        SemgrepTaintRule(
            sources = sources.map { it.updatePattern(block(it.pattern)) },
            sinks = sinks.map { it.updatePattern(block(it.pattern)) },
            propagators = propagators.map { it.updatePattern(block(it.pattern)) },
            sanitizers = sanitizers.map { it.updatePattern(block(it.pattern)) },
        )

    override fun <NewRepr> flatMap(block: (PatternsRepr) -> List<NewRepr>) = SemgrepTaintRule(
        sources = sources.flatMap { p -> block(p.pattern).map { p.updatePattern(it) } },
        sinks = sinks.flatMap { p -> block(p.pattern).map { p.updatePattern(it) } },
        propagators = propagators.flatMap { p -> block(p.pattern).map { p.updatePattern(it) } },
        sanitizers = sanitizers.flatMap { p -> block(p.pattern).map { p.updatePattern(it) } },
    )
}

data class SemgrepMatchingRule<PatternsRepr>(
    val rules: List<PatternsRepr>,
) : SemgrepRule<PatternsRepr> {
    override fun <NewRepr> transform(block: (PatternsRepr) -> NewRepr) =
        SemgrepMatchingRule(rules.map(block))

    override fun <NewRepr> flatMap(block: (PatternsRepr) -> List<NewRepr>) =
        SemgrepMatchingRule(rules.flatMap(block))
}
