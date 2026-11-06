# Native HTML parser and node arena snapshots

`html5ever-0.39.0/` is the html5ever 0.39.0 crates.io archive, licensed
MIT OR Apache-2.0. The archive SHA-256 is
`46a1761807faccc9a19e86944bbf40610014066306f96edcdedc2fb714bcb7b8`.
`LICENSE-MIT`, `LICENSE-APACHE`, the upstream README and source copyright
notices are retained. The original manifest and VCS record are also retained.

Only production sources and provenance are packaged. The archive's tests,
examples, benchmarks, benchmark data, lockfile and development dependencies
are omitted. Its three trailing test modules in `src/encoding.rs`,
`src/tokenizer/mod.rs` and `src/util/str.rs` are not imported. Existing engine
tests are unchanged. The production manifest keeps the same package version,
library, dependencies and features, with automatic auxiliary targets disabled.

Local production changes (FIX 9615):

- `tokenizer::TokenSink::checkpoint` defaults to true. The existing tokenizer
  latches the first false result before a state step or token delivery and
  returns from its feed/EOF loops without further sink delivery. It does not
  mint a failed handle or reinterpret script/encoding indicators as errors.
- `driver::parse_document_with_checkpoint` constructs the original tree builder
  and tokenizer behind a private checkpoint sink. It retains the first typed
  callback failure and returns it only after dropping the partial parser/DOM.
  Successful parsing uses the ordinary sink output and supplied parse options.
- `TokenSink::process_token_with_checkpoint` defaults to the original token
  method. Native dispatch forwards the same borrowed checkpoint into the
  existing tree-builder reprocess/split-whitespace loop, before its next
  insertion-mode step. The ordinary token API uses an always-true callback.
  The original token conversion and grammar bodies remain shared and unchanged.
- The checked driver can install a native tree-sink checkpoint. It admits an
  operation before a node handle is created, or before appending text that may
  need an arena slot. An internal stopped result propagates through creation,
  reconstruction, adoption, foreign insertion and both table-text drain paths.
  The first typed refusal uses the same checked-driver error and partial-DOM drop.
- The ordinary driver and checked driver share the existing feed loop. The
  ordinary `Parser`, `parse_document`, fragment APIs and `Document::from` keep
  their signatures and algorithms. The new checked API is re-exported at root.

The root and Cargo-config path patches both redirect only html5ever 0.39.0.
The separately locked html5ever 0.38.0 and both markup5ever versions are
unchanged. The engine's direct edge is the same exact `=0.39.0` pin already
used by dom_query 0.28.0; no new codec family is introduced.

`dom-query-0.28.0/` is the exact dom_query 0.28.0 production snapshot. Its
archive hash, retained licence and production exclusions are recorded in that
snapshot's `PROVENANCE.md`. Root/config patches redirect only that version;
dom_query 0.27.0 remains on the registry. The added native arena API admits a
whole replacement Vec<TreeNode> before allocation, settles reported capacity,
and frees the old storage before returning the replacement reservation. The
parser caller keeps that reservation with its returned Document through rendering.
Text that coalesces with an existing node does not reserve a new arena slot.

Callbacks use the caller's memory and work deadline, not a node-count/content
limit or a new timer. Attribute, atom/tendril, parser-stack, input and error
allocations remain unadmitted. One tokenizer step, character-reference work,
allocator surplus before settlement and opaque codec calls still prevent a
global heap or hard wall-time bound. This snapshot does not complete FIX 9615.
