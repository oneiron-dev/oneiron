# scripts/refactor — GPS refactor-wave conformance (v2)

Machinery for the ratified endgame-first refactor wave. Governing pins:
`REFACTOR-TARGET-STATE-DESIGN.md` (TS — one-home entity modules, no `vault/`
directory, no shims, fence removed; §D6 = this gate's spec) and
`REFACTOR-TYPES-DISSOLUTION-DESIGN.md` (D9 — stage T dissolves `types.rs`).
Where pins conflict: D9 > TS > MM/CONV.

## `conformance.sh <stage-id> <base-rev>`

The move-PR gate. `<base-rev>` is the commit the stage branch was cut from.
Runs, in order — first failure exits non-zero, **no override flag**:

1. **forbidden-zone + allowed-files** — every changed file is in the stage's
   allowed list; the global forbidden zone is the **liftable guard**
   (`agent_def[.rs/]`, `edit_settle[.rs/]`). The guard is **lifted** (owner,
   2026-07-08 — ONE-1443/ONE-1554 landed): guarded files are allowed iff a stage
   lists them. The old batch/outbound/anchored_annotation fence is gone.
2. **surface inventory** — the multiset of `pub…` declaration heads (2a) and
   `impl…` headers (2b) changes by exactly the stage's `## decl` / `## impl-delta`
   deltas. When lib.rs is touched, the **flat-name façade SET must diff empty**
   (CONV D3.2 / TS D6 #6).
3. *(check E)* **declared-edit validation** — each `## edit` row (`file<TAB>old<TAB>new`)
   must be a legal delta (token-identical except one contiguous `::`-path region,
   or the single `pub(crate)` visibility exception), old present at BASE, new
   present + old absent at HEAD.
4. **moved-block byte-equivalence** — each row's item located in `git show
   <base>:<src>` and HEAD `<dst>` by `(kind, container, item_name, cfg)`,
   exactly-one-match, **plus ZERO matches in src at HEAD** (removal assertion,
   TS D6 #2). Declared `## edit` / `## frag-edit` substitutions are applied to the
   BASE fragment before the rustfmt byte-compare. `container = mod tests` locates
   test-distribution items inside the tests module.
5. **frozen anchors** — stage-declared stay-put items (edits applied to base).
6. **name-uniqueness** — across `api/*.rs` (api stages).
7. **error-literal inventory** — codec / trio / T stages (multiset unchanged).
8. **insertion integrity** (NEW, TS D6 #5) — for every dst file, excise each
   moved item **individually** (brace/bracket-matched extent, never span
   deletion), subtract declared `## add` boilerplate + moved `## comment` blocks,
   and require the remaining stripped lines to equal the BASE dst (edits applied).
   This is the designated detector for **private** additions/mutations (check 2 is
   `pub`-only).
   - *(check F)* **file relocation** — `## filemove` rows (B1 `git mv`): base:src
     byte-identical to HEAD:dst, src absent at HEAD.
   - *(check X)* **src-exhaustion** — T12 finale: reconstruct BASE `types.rs`,
     excise every union-stage item + declared decl/comment, residue must be
     whitespace-only (mechanically re-proves the D9.1.2 census).
9. **the WORKFLOW.md gate** — `cargo fmt/clippy/nextest/doctest/doc/nextest-sync`.

Checks 1–8 (+E/F/X) are a self-contained embedded python program (deps: `python3`
+ `rustfmt` + `git`); the gate shells out to `cargo`. A rustfmt-normalised
bracket-matched extractor handles the 257-line `ENTITY_TYPE_REGISTRY` const
(D9.4 #6 acceptance — verified).

## `moves/<stage-id>.{tsv,decls}`

`<stage>.tsv` — one row per moved item:
`kind<TAB>container<TAB>item_name<TAB>cfg<TAB>src_file<TAB>dst_file<TAB>header_change`.
`container` is the impl header for `method` rows or `mod tests` for
test-distribution rows; `item_name` is the full normalised header for `kind=impl`
rows; `cfg` disambiguates cfg-gated duplicates.

`<stage>.decls` — labelled sections: `## allowed`, `## forbid`, `## anchors`
(`kind<TAB>container<TAB>item<TAB>cfg<TAB>file`), `## uniqueness`,
`## error-literal`, `## decl` (`±` declaration heads, check 2a), `## impl-delta`
(`±` `file<TAB>header`, check 2b), `## edit` (`file<TAB>old<TAB>new`),
`## frag-edit` (`src<TAB>old<TAB>new`, moved-item internal edits), `## comment`
(`src:start-end<TAB>dst`), `## add` (`file<TAB>exact-line`, non-item additions for
check 8), `## filemove` (`src<TAB>dst`), `## exhaust` + `## exhaust-stages` (T12).

Manifests carry no line numbers — items are located by identity, so the gate is
line-number-independent (MM F7). The per-stage Codex handoff packages carry the
advisory line numbers, re-derived from base at cut time.
