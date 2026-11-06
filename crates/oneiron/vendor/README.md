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
- `CheckedParser::one_str` feeds borrowed UTF-8 as inline, single-scalar
  tendrils instead of copying the entire input into a heap tendril before the
  first checkpoint. In this scalar-input mode, adjacent table text with the
  same split status coalesces before buffering, so a long run does not retain
  one pending-vector entry per scalar. Ordinary input mode is unchanged.
  It stops producing input on the first failure and uses
  the existing finish/error path. Tokenizer lookahead and retained payloads
  can still allocate separately; this is not a bound on all parser memory.
- `CheckedParser::with_open_elements_reservation`, installed before input,
  lets the caller reserve the actual private open-element Vec before a push
  or insertion. The same first typed error stops root, ordinary, foreign,
  script, head-reentry and adoption paths. Its owned callback is the last
  tree-builder field, so the stack frees before the reservation is released
  at parser completion, rather than retaining that charge during rendering.
- `CheckedParser::with_temporary_buffer_reservation` uses a caller-reserved
  UTF-8 String for the spec temporary buffer only. Each push admits a whole
  replacement while the old allocation remains live, then settles actual
  capacity. The String drops before its owned callback releases admission.
  Taking text copies it into a native tendril, then clears the retained,
  still-admitted scratch capacity. The output tendril has separate unadmitted
  backing; no reservation is transferred to it or to DOM payload. The ordinary
  tokenizer keeps its original StrTendril operations and take/clear behavior.
- `CheckedParser::with_tag_name_reservation` uses the same private text-buffer
  backing for the current tag name, with its own caller reservation. Tag
  creation's first character and subsequent tag-name pushes stop on the same
  first typed error. Native case folding, LocalName construction and appropriate
  end-tag matching are retained. Interned atom storage is separate and unadmitted.
- `CheckedParser::with_attribute_name_reservation` reserves current attribute
  name scratch through the same primitive and its own parser-owned callback.
  Attribute creation's first character and later name pushes stop on refusal.
  Duplicate-name checks, native LocalName construction, namespace handling and
  attribute-value moves keep their original behavior. Attribute values, the
  attribute vector and interned atoms remain separate, unadmitted allocations.
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
The sink-operation callback also covers native diagnostic recording. The actual
Document.errors Vec<Cow<str>> uses the existing caller-backed replacement
algorithm before its push, with a separate guard kept after the Document. All
successful messages and their order remain unchanged. Owned diagnostic strings
are separate, unadmitted allocations. On refusal the failed push is skipped and
the first typed error is retained; the current parser step, including private
unadmitted work, may continue until the next checkpoint or guarded node operation.

`tendril-0.5.1/` is the matching same-version production snapshot, with both
upstream licences and archive hash in its `PROVENANCE.md`. Additive fallible
slice construction and reserve APIs admit real native backing before allocation
and settle its reported capacity before copying. A `Send + Sync` reservation
lives in the native shared header. Last-owner drop extracts it, frees the header
and backing, then returns admission. Ordinary unadmitted APIs remain available;
ordinary allocating copies/growth can create separate unadmitted backing.
The checked parser's optional comment reservation runs before every actual UTF-8
char/slice append. Native comment emission moves the admitted tendril through
the existing token/sink into DOM comment storage, including the owned atomic
wrapper conversion. Its reservation follows that backing, not parser completion.
Other payloads, the boxed guard's metadata and allocator-private overhead remain
outside this backing admission.
The optional attribute-value reservation covers every character or slice append,
including decoded character references. Moves and native shares keep its
allocation header; later allocating copies, including shared-value atomic
wrapping, have separate unadmitted backing. Attribute-vector backing and
interned names remain outside that initial value reservation.

Callbacks use the caller's memory and work deadline, not a node-count/content
limit or a new timer. Attribute-vector backing, allocating attribute copies,
retained atoms and other tendril payloads, other
parser stacks, lookahead and owned diagnostic payload allocations remain unadmitted. One tokenizer step, character-reference work,
allocator surplus before settlement and opaque codec calls still prevent a
global heap or hard wall-time bound. This snapshot does not complete FIX 9615.
