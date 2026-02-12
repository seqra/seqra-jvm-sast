## 2026.02.12
### feat: Add inter-procedural alias analysis
- Resolved an edge-case cause affecting the non-user cleaner
- Corrected Spring component initialization order
- Added a Spring test example
- Renamed `thread-flow-limit` to `code-flow-limit`
- Improved config rule matching for inner classes containing .
- Fixed configuration loading on Windows
- Disabled aliases for method summaries with no memory impact
- Enabled inter-procedural AA
## 2026.02.06
### feat: Bump version
- feat: Bump version
## 2026.02.06
### fix: Resolve config issues, vulnerabilities, and update CI setup
- Fix inner calls resolving
- Fix SpringRuleProvider and several config rules
- Annotate Servlet controllers
- Handle vulnerabilities with generated locations
- Fix tree summary storage with Any accessor
## 2026.02.01
### feat: Add Path#of config, update IR, and add resolve transformer
- Add java.nio.file.Path#of config
- Update ir
- Add properties resolve transformer
## 2026.01.21
### feat: Add JDK support, model params, and fix trace/config issues
- Fix trace resolver
- Update ir: add support for newer jdk
- Support model attribute controller params
- Fix config types
## 2026.01.15
### feat: Enhance Kotlin support, fix controllers, update IR, remove Docker
- Fix kotlin suspend spring controllers handling
- Improve span resolution for assignments
- Remove docker
- Skip inlined locations with no source
- Update ir
- Better kotlin support
- Use package name in class name resolver
- Add option to generate sarif fingerprints
- Fix Sarif tool description messages
- Fix method summaries selector in trace resolver
## 2025.12.26
### fix: Correct SARIF for simple traces and MapKey/MapValue issues
- Fix SARIF for simple traces
- Fix MapKey/MapValue
## 2025.12.26
### fix: resolve trace issues, optimize span resolver, and update SARIF handling
- Remove unreachable trace roots
- Fix trace resolver
- Drop traces with unresolved inner calls
- Add tags to spring related locations
- Filter out reports with invalid traces
- Update core
- Fix semgrep style id
- Fix join rules
- Sarif uri base
- Fix method entry span resolution for simple traces
- Fix string literal matcher
- Add fallback for unresolved spans
- Fix arrays and phi assigns
- Fix unchanged handling with alias
- Fix span resolver
- Optimize AST span resolver
- Better SARIF generation progress reporting
- Fix remove from complex position
- Use type checker in accessor unroller
- Set trace resolver limit
- Sarif options
- Rewrite source file resolver
- Fix column resolution for fields, method declarations and method ends
- Fix rule types
- Fix vararg and method resolutions
- Improve assign message folding and readability
- Rule overrides
- Use severity list instead of min severity
- Fix spring controller paths
- Fix transitive accept after end edge removal
- Add snakeyaml and fastjson propagators
## 2025.12.11
### fix: Apply multiple bug fixes from issue #155
- More fixes
## 2025.12.11
### fix: Resolve ambiguous source files issue
- Fixes
- Ambiguous source files
## 2025.12.10
### feat: Update CI, core, and project model; enhance dependency handling
- Use dependencies from infra
- Update project model
- Consider project package
- Test project analyzer
- Update core
- AST-based column resolver
- Add dependencies version on CI
- Fix ci container
- Publish with dependencies image
- Publish workflow dispatch
- Dependencies image
- Fix tree any accessor
- Fix rule ids
- More on annotations & is-null 
- Spring annotation inheritance & minor fixes
- Update core
- Remove absolute paths from rule ids
- Rewrite taint mark name generation
- Minor fixes
- Add lambda captures resolution
- Add apache FilenameUtils
- Support join with taint rules
- Initial join rules support
## 2025.11.27
### fix: Resolve cfg performance issues
- Fix cfg performance issues
## 2025.11.27
### feat: Rewrite rule composition and avoid split on metavar constraints
- Rewrite rule composition
- Avoid split on metavar constraints
## 2025.11.24
### feat: Enhance path reporting, fix trace gen
- Fix spring controller rules
- Add inner paths of calls to path reporting
- Fix trace generation
- Taint spring controller args
- Support Spring cross-controller analysis
## 2025.11.19
### feat: Bump version
- feat: Bump version
## 2025.11.13
### fix: Correct spring paths and add complex taint support
- Fix spring paths
- Support complex taint requires
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
