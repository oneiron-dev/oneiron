# scripts/refactor — GPS refactor-wave conformance

Machinery for the ratified `vault.rs` / `api.rs` split + test-split wave
(pin: `REFACTOR-MOVE-MAP-DESIGN.md`, §D6 = this gate's spec, §D5 = the PR
slicing, §D1–D3 = the move lists).

## `conformance.sh <stage-id> <base-rev>`

The move-PR gate. `<base-rev>` is the commit the stage branch was cut from.
Runs, in order — first failure exits non-zero, **no override flag**:

1. **forbidden-zone + allowed-files** — every changed file is in the stage's
   allowed list and none is in the global forbidden zone (`batch.rs`,
   `outbound.rs`, `anchored_annotation.rs`, `agent_def[.rs/]`, `edit_settle[.rs/]`).
2. **surface inventory** — the multiset of `pub…` declaration heads (2a,
   file-agnostic) and `impl …` headers (2b, file-attributed) changes by exactly
   the stage's declared `## decl` / `## impl-delta` deltas. Widened per critique
   F3 so `pub(super)`/`pub(in …)` and impl blocks are visible.
3. **moved-block byte-equivalence** — each manifest row's item is located in
   `git show <base>:<src>` and in HEAD `<dst>` by `(kind, container, item_name,
   cfg)` with an **exactly-one-match** invariant (F2), rustfmt-normalised, and
   byte-compared. Doc comments are byte-compared, not stripped (F5). An added
   `pub(crate)` (header_change=yes) is stripped from the signature before
   formatting.
4. **frozen anchors** — stage-declared stay-put items (`struct Vault` / `open` /
   `impl ActorBound<'_>` for vault; `api_routes` / `ApiDoc` for api) are
   unchanged.
5. **name-uniqueness** — no duplicate top-level item names across `api/*.rs`
   (glob re-export ambiguity guard; api stages only).
6. **error-literal inventory** — codec stages only (unused by PR-1..8).
7. **the WORKFLOW.md gate** — `cargo fmt/clippy/nextest/doctest/doc/nextest-sync`.

`conformance.sh` is self-contained: checks 1–6 are an embedded python program
(no deps beyond `python3` + `rustfmt` + `git`); check 7 shells out to `cargo`.

## `moves/<stage-id>.{tsv,decls}`

One pair per stage `vault-A vault-B api-A api-B tests-w1 tests-w2 tests-w3 tests-w4`.

`<stage>.tsv` — one row per moved item:
`kind<TAB>container<TAB>item_name<TAB>cfg<TAB>src_file<TAB>dst_file<TAB>header_change`.
`container` is the impl header for `method` rows (`-` otherwise); `item_name` is
the full normalised header for `kind=impl` rows; `cfg` disambiguates cfg-gated
duplicates; `header_change=yes` means the move bumps the item to `pub(crate)`.

`<stage>.decls` — labelled sections: `## allowed`, `## forbid`, `## anchors`,
`## uniqueness`, `## error-literal`, `## decl` (`+`/`-` declaration heads for
check 2a), `## impl-delta` (`+`/`-` `<file><TAB>header` for check 2b).

Line numbers are **not** stored in manifests — items are located by identity, so
the gate is line-number-independent (critique F7). The per-stage Codex handoff
packages carry the advisory line numbers, re-derived from base at cut time.
