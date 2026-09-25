# W7-C13 keyed-memory security repair

## Decisions

- Keyed claims remain ordinary CLAIM storage. No new record kind, global raw ACL,
  or privileged Vault/BatchBuilder restriction was added.
- `claim_generic_readable` excludes the exact keyed predicate from generic
  projection even for the owner. `claim_surfaceable` composes this exclusion;
  pipeline status/authority filters also conjoin it outside `include_stale`.
  Memory's entity/hydrate/list/history, BM25 and neighbor projections apply the
  same rule. ScopedRead's get, short-id hydrate, timeline, PPR and context-pack
  filters already use those admission predicates. Code-run and HTTP core readers
  delegate to ScopedRead. Context-pack neighbor hydration uses claim_surfaceable;
  cached result bodies can only arrive after the pipeline's admission filter.
- Imported claim admission checks both the incoming predicate and the existing
  stored predicate under the original batch commit writer transaction. The
  crate-private `commit_with_target_guard` executes before policy preflight. It
  preserves batch commit's denial receipts, gate/source-trust decisions and VAD
  postcommit behavior. Erased IDs/shells cannot be reused by import.
- Duplicate actor/class evidence stamps never establish ownership, including
  duplicates with identical values. Lookup is exact-one via single_map_value.
- Malformed rows are not heads. Key scans skip erased shells, invalid CLAIM
  frames, malformed keyed payloads/addresses/scopes and invalid demotion stamps.
  They never walk backwards to superseded values. Valid competing heads still
  fail loudly. Actual storage errors and scan overflow still propagate.
  A replay whose deterministic ID already stores an erased/malformed revision
  refuses and does not overwrite it. A fresh request may create a new revision;
  this does not restore or rewrite the erased ID or its history.
- Replacement keeps the canonical source-trust guard. KV calls it in the same
  writer snapshot to return INVALID_STATE with useful advice, then still calls
  canonical supersession. No retract-before-put, source relabel, or permit bypass.
  Generated output belongs at a separate key when existing user truth is protected.
- The shared SDK no longer caps the entire keyed request at 64 KiB. Engine
  address/value/filter limits are authoritative on both backends; the general
  64 MiB HTTP transport cap remains intact.
- JavaScript omits explicit undefined only for known top-level optional request
  fields. Undefined nested in JSON data (including filter values and arrays)
  still refuses rather than silently changing user data.
- Exact numeric equality is serde_json value equality. Integer 2 differs from
  floating 2.0; integer precision is not lost through f64 normalization. Host JSON
  encoder limits still apply, especially JavaScript's single Number representation.

## Canon / public guidance corrections

The applied keyed-memory description implied generic actor-private reads and
source-independent replacement. It must say that only the actor/class-bound
exact doors read these bodies; generic reads exclude them for everyone. It must
also state the source-trust replacement refusal, malformed-row exclusion,
undefined-envelope behavior and JSON-number equality rules above. Engine SDK and
LangGraph READMEs and Rust request docs carry those corrections. No docs mirror
or external docs repository was edited.

## Evidence and integration

This is an unvalidated proposal, not test evidence. The delegated security seat
ran no Cargo, builds, tests, formatting, dependency installs, git operations, or
tracked-source writes. Root must apply guarded files, format, regenerate the
code map, and run the selected native tests and compile/lint lanes serially.

Added adversarial tests cover owner/non-owner generic readers, indexed and graph
candidates, ScopedRead hydration/history/search, direct context-pack results and
neighbors, include_stale, exact-store read preservation, imported creation and
disguised overwrites, duplicate evidence, erased/malformed rows and no replay or
history fallback, conflicting valid heads, mixed-source rollback and same-source
replacement, large integer/float equality, SDK filter-cap transport parity, and
undefined request options versus nested JSON data.
