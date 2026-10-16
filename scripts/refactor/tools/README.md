# scripts/refactor/tools — move-only refactor checks

Two checkers prove that a Rust refactor moved code without changing it.
`split_check.py` covers the common one-file split and needs no manifest.
`../conformance.sh` checks moves declared in a stage manifest under `../moves/`.
Both are specialised tools, not the merge bar: that is
`cargo check --workspace --all-features` on the head (see `AGENTS.md`).
Run either with `RUSTFMT_BIN=$(rustup which rustfmt)` or any `rustfmt` on PATH.

## `split_check.py` — manifest-free move-only split check

`split_check.py <base-rev> <old-file>[,<old-file>…] <new-dir | new-file>` (paths
relative to the cwd; deps: `python3` + `git` + `rustfmt`/`RUSTFMT_BIN`). The little
sibling of `conformance.sh` for the common campaign case — `foo.rs` → `foo/mod.rs` +
children — with no manifest: the old file at `<base-rev>` IS the manifest. Exit 0 =
pure move, 1 = drift (one `FAIL …` line per problem, then
`SPLIT-CHECK OK <old> -> <n> children (<m> items)` /
`SPLIT-CHECK FAIL <old>: <k> problem(s)`); any exception fails closed with
`SPLIT-CHECK-ERROR` + exit 1. Modes: several comma-separated old files feed one
directory; a child module the old file mounted at `<base-rev>` (top-level `mod x;` or
`#[path = "…"] mod y;`) whose file is gone from the tree is absorbed as a source
automatically (`INFO absorbed …`); when the last argument is a `.rs` file the old file
is compared against that one file (single-file mode: no mod.rs / sibling checks).

What it checks (new side = working tree, every `*.rs` under `<new-dir>`, nested
directory modules followed):

- `<old-file>` no longer exists; `<new-dir>/mod.rs` exists; every child `x.rs` and
  every nested module directory `x/` is declared — by a `mod x;` or a
  `#[path = "x.rs"] mod y;` in ANY file of that directory level (mod.rs or a child
  such as `tests.rs`), resolved the way rustc does (a child's plain `mod x;` looks in
  `<child>/` first, then, leniently, next to it).
- Pre-existing children. A new-side file that already exists at `<base-rev>` at the
  same path is not part of the split: byte-identical → `INFO skipped <path>
  (pre-existing, unchanged)` and exempt from the declaration check; modified → its
  items are compared against ITS OWN base version with the normal machinery
  (`use`/`mod` plumbing allowed, vis → INFO): `INFO pre-existing child re-plumbed:
  <path>` when nothing else changed, `FAIL body …` / `FAIL missing …` otherwise. Items
  it gained are matched against the split's base like any other child (`(+N items
  moved in)` on the INFO line).
- Directory layouts. A subdirectory holding a `mod.rs` is a nested module (below). A
  subdirectory WITHOUT `mod.rs` whose sibling `D.rs` exists (Rust-2018 layout,
  `tests.rs` + `tests/regressions.rs`) holds children of `D.rs`'s module: same scope
  as `D.rs` (`…::tests` for a tests file inside), declared from `D.rs`. A subdirectory
  with Rust files but neither → `FAIL orphan directory …`.
- Nested modules. A base `mod X { … }` (X ≠ `tests`) is not one opaque item: its
  body is walked with scope `X` (`X::tests`, `X::Y` for mods nested inside it) and
  the mod itself becomes a *mod record* (name, cfgs, vis, `///` doc + non-cfg
  attributes). On the new side a subdirectory `X/` holding a `mod.rs` is the nested
  module `X`: its parent `mod.rs` must declare `mod X;`, `X/mod.rs` + `X/*.rs` are
  collected with scope `<parent>::X`, and it is walked recursively; a flat child
  `X.rs` whose stem matches a base mod record at that level is the module `X`
  flattened into one file; a bodied `mod Y { … }` inside any new-side file is scope
  `<file scope>::Y`.
- Mod records are compared 1:1: a base `mod X` at scope S needs exactly one
  counterpart — a bodied `mod X` in S or a `mod X;` decl in S's `mod.rs`
  (`FAIL missing mod X (in S)` / `FAIL duplicate mod X`); the cfg tuples must be equal
  (`FAIL cfg on mod X differs: … -> …`); a visibility change is `INFO vis mod X`; the
  `///` doc + non-cfg attributes must sit on the decl verbatim OR as `//!` / `#![…]`
  lines at the top of `X/mod.rs` / `X.rs`, otherwise `INFO doc on mod X
  moved/changed`. A new-side bodied mod or `mod.rs` decl with no base record is
  `FAIL extra mod Y` unless it is a `tests` / `*_tests` mount or a decl for a sibling
  `y.rs` child (plumbing).
- Base file and each child are rustfmt-normalised whole (`rustlex.rustfmt`, edition
  2024, comment options off, no repo `rustfmt.toml`), then `rustlex.enumerate_items`
  on both. Items match by `(scope, kind, name | impl-header canon, cfgs)` and every
  base item must land in exactly one child: missing / duplicate / extra = FAIL.
- Bodies (doc comments + attributes included) must be byte-identical after the
  leading visibility keyword is stripped; a `pub`↔`pub(crate)`↔`pub(super)`↔private
  change is an `INFO vis …` line, never a failure. A mismatch prints a unified diff of
  the two normalised fragments (capped at 60 lines); an item that only reflows because
  it moved between an inline `mod tests` body and a file top level is re-formatted
  standalone before it is called a mismatch.
- String literals are compared byte-for-byte. Every whitespace normalisation the
  checker applies to compared text — the dedent of an inline mod body or impl method,
  the per-line visibility strip, the standalone rustfmt pass with its de-wrap, the
  canon tokenisation of residue chunks — runs with each literal (normal, byte, C, raw
  with any number of `#`) swapped for a one-line placeholder string and put back
  byte-exact afterwards. So a multi-line raw string re-indented along with the code
  (a YAML / JSON fixture whose test left an inline `mod tests`) is `FAIL body …
  differs` with the literal lines in the diff, even though the dedent would have
  equalised both sides. The one run the compiler itself discards — the leading
  whitespace of the line after a `\`-newline continuation in a non-raw string — is
  compared as skipped, so re-indenting that continuation line is not a change
  (`literal_compare_form`; return the literal unchanged there for the strict form).
  Indentation inside a macro invocation rustfmt cannot parse (`matches!` with a
  guard, `json!`) is code, not literal: it is dedented with the mod body and must
  otherwise move byte-exact.
- Scope is a `::`-joined module path: `top` = the file body; `tests` = the base
  file's inline `mod tests { … }` body; `seam`, `seam::tests`, `seam::inner` for
  bodied mods and what nests inside them. On the new side `tests.rs` / `*_tests.rs`
  children at any level and an inline `mod tests` in any file are that level's
  `…::tests` scope, so moved tests are still 1:1. `tests.rs` / `*_tests.rs` are
  skipped (INFO) when the base file (or the base mod at that level) had no inline
  `mod tests`. Item labels print `(in <scope>)` for every non-`top` scope.
- An impl header that lands in more than one child (the usual way a 6k-line
  `impl Vault {}` gets split), or that the base already carried more than once, is
  compared per associated item (`method` / `const` / `type`) instead; each part's
  residue — header, attributes, docs, anything that is not an associated item — must
  equal the base's. Headers pair with impl lifetimes elided: a lifetime parameter
  declared on the impl and used exactly once after the parameter list is read as
  `'_` on both sides, so `impl<'a> S<'a>` and `impl S<'_>` are one header (the
  workspace `single_use_lifetimes` lint forces the elided spelling on a part that uses
  the lifetime nowhere else); a respelled part is `INFO impl header lifetime elided: …`,
  never a FAIL.
- Allowed new-side extras (module plumbing, also ignored on the base side): `use` at
  any visibility incl. `#[cfg(test)] use …` seams, `mod x;` declarations for child
  files (a decl that mounts a directory the base never had is `FAIL extra mod`; a
  dangling decl is left to rustc), `#![…]` inner attributes, `//!` docs,
  `extern crate`, free comments and blank lines. The `<n> children` count in the OK
  line is every `*.rs` file walked, nested levels and skipped pre-existing files
  included.
- Anything `enumerate_items` does not recognise (a top-level macro invocation such as
  `thread_local! { … }`, an `extern "C" { … }` block) is compared as an opaque
  canon-tokenised residue chunk, also 1:1. Reported line numbers are those of the
  rustfmt-normalised text, not the file on disk.

Cost: whole-file rustfmt once per side plus a byte-equality fast path; an 18k-line
file checks in ~0.5 s, so no per-fragment batching is needed. Tests:
`python3 -m pytest scripts/tests/test_split_check.py -q` (throwaway git repo + fixture).

## `../conformance.sh <stage-id> <base-rev>` — manifest-based conformance

`<base-rev>` is the commit the stage branch was cut from. The script refuses a
stage with no `../moves/<stage-id>.tsv`. It runs the manifest checks in
`driver.py` (1–8 plus E/F/X) from an embedded Python payload (deps: `python3`,
`rustfmt`, `git`), then the full cargo gate: `cargo fmt --check`, workspace
clippy, the full nextest profile, doctests, strict `cargo doc` and the sync
nextest lane. The first failure exits non-zero; there is no override flag. The
cargo step builds and tests the whole workspace, so this is not a cheap
manifest inspection. Run it only where `AGENTS.md` allows Cargo builds.

`conformance.sh` embeds `rustlex.py` and `driver.py` as a payload. After any
edit to either, re-run `build_conformance.py`, or the script runs the old code.
`build_conformance.py --check` exits 1 when the script is stale.

### Manifests: `../moves/<stage-id>.{tsv,decls}`

`<stage>.tsv` — one row per moved item:
`kind<TAB>container<TAB>item_name<TAB>cfg<TAB>src_file<TAB>dst_file<TAB>header_change`.
`container` is the impl header for `method` rows or `mod tests` for
test-distribution rows; `item_name` is the full normalised header for `kind=impl`
rows; `cfg` disambiguates cfg-gated duplicates.

`<stage>.decls` — labelled sections: `## crate`, `## allowed`, `## forbid`, `## anchors`
(`kind<TAB>container<TAB>item<TAB>cfg<TAB>file`), `## uniqueness`,
`## error-literal`, `## decl` (`±` declaration heads, check 2a), `## impl-delta`
(`±` `file<TAB>header`, check 2b), `## edit` (`file<TAB>old<TAB>new`),
`## frag-edit` (`src<TAB>old<TAB>new`, moved-item internal edits), `## comment`
(`src:start-end<TAB>dst`), `## add` (`file<TAB>exact-line`, non-item additions for
check 8), `## filemove` (`src<TAB>dst`), `## exhaust` + `## exhaust-stages`.

Manifests carry no line numbers: items are located by identity.

### Files

| file | purpose |
|---|---|
| `rustlex.py` | Rust structural extractor shared by both checkers (masks strings and comments, enumerates items, canon-tokenises heads, rustfmt byte-compare). CLI: `rustlex.py enumerate <file>` / `find <file> <kind> <container> <name> <cfg>` / `inventory` / `impls`. |
| `driver.py` | Manifest checks 1–8 plus E/F/X: `driver.py checks <root> <stage> <base> <movesdir>`. |
| `build_conformance.py` | Assembles `../conformance.sh` from `rustlex.py` and `driver.py`; `--check` reports a stale script. |
| `consumer_complete.py` | Asserts that the file of every cross-module consumer of a moved `pub`/`pub(crate)` item appears in the stage's `## allowed`. |
| `v2_selftest.py` | Synthetic self-test of the manifest checks, including the freshness check. |
