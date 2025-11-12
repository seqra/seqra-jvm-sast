## 2025.11.12
### feat: Improve rules loading, add controller path resolving, and fix SARIF generation
- Safe load for semgrep yaml rules
- Fix exit sink bases
- Fix controller name
- Fix recursion in sarif traits
- Add spring controller info
- Don't reset heap alias on calls without heap access
## 2025.11.08
### feat: Improve automata, config loading, and analysis handling
- Fix a bunch of automata generation issues
- Load default config from resources
- Handle loop-vars more correctly
- Better handling for loop-assign vars
- Publish analyzer jar
- Try to match taints to path starts
- Initial support for arrays
- Generate at least one trace for each entry point
- Enable alias analysis by default
- Update rules on CI
- Annotate all rules with rule-info
- Fix signature patterns
## 2025.10.28
### feat: Enhance string concat, add propagators, refactor and fix issues
- N-ary string concat
- Drop summary fact with rule conflict
- Add check for StateVar creation to rule tests
- Refactor taint edge generation
- Add `Base64.Decoder` and `ByteArrayInputStream` propagators to config
- Fix merge issues
- Remove edges to cleaners with unassigned metavariables
- Rework return stmt
- Replace analysis-end with vulnerability verification phase
- Add propagators for `String.replace` methods
- Enable a bunch of disabled tests
- Use `edgesAfter` for clearer message generation
- Introduce return statement sources
- Add a test for sanitizer in `pattern-not-inside` form
- Update core
- Fixes
## 2025.10.10
### fix: Resolve taint issues, update core, and enhance tests
- Add fixes for missing traces and wrong taint flow
- Remove value marks
- Add test for parallel `patterns` usage
- Small fixes for sarif message generation
- Fix rules with patterns and signatures
## 2025.10.02
### feat: Add taint labels, tests, and optimize automata
- Initial support for taint labels
- Add test for `label` and `requires` keywords
- Fix null pointer bug for first line retrieval
- Remove redundant automata edges
## 2025.10.01
### feat: Publish release
- feat: Publish release
