# WORKLOG — ONE-1737-fix · manifest `@` delimiter (owner ruling R-20260807-04)

Micro fix leg. Branch `ONE-1737-fix`, base `origin/main` `47ac63070`.

## The ruling (verbatim)

> Split `manifest@version` on the FIRST `@`. Refs may not contain `@`; versions
> may (`s@1@beta` parses to ref `s`, version `1@beta`). Reject `@` in refs at
> parse. One regression test.

Banked as a known hole on 2026-08-06 (`decisions.jsonl`, `wf_aad7b48f-8b4`
verdict items): `rsplit_once('@')` misparsed multi-`@` wire forms.

## DEVIATION from the dispatch brief's prime suspect

The brief named `crates/oneiron/src/llm.rs` `ModelId` (`name()` :150-157,
`revision()` :162-166, `from_str` :177-185) as the prime suspect and told me to
fix the real site if it lay elsewhere. **It lies elsewhere.**

`ModelId` parses `provider/name@revision` — a DIFFERENT grammar, minted only by
`llm.rs:761` `ModelId::new(format!("{provider}/{name}@{revision}"))` and
`booking/constraint.rs:385`, neither of which is a manifest. The ruling's
`manifest@version` grammar is `ManifestEntry::wire_form()` in
`crates/oneiron/src/attempt_queue.rs:266` — `format!("{}@{}", reference, version)`
— the ARCH-0053 §2 pack-manifest row ONE-1737 introduced, which is exactly what
the banked hole was raised against. **`llm.rs` is untouched**, as is the
URL-authority strip at `llm.rs:798` (correctly `rsplit`, unrelated).

## Site census (`rg "rsplit_once\('@'\)|split_once\('@'\)"`, whole workspace)

| Site | Grammar | Verdict |
|---|---|---|
| `attempt_queue.rs:266` `wire_form()` | manifest producer | in scope |
| `skill_attribution.rs:757` | manifest parse | **FIXED** |
| `skill_reliability.rs:468` | manifest parse | **FIXED** |
| `llm.rs:160/168/188` `ModelId` | `provider/name@revision` | out of scope — different grammar |
| `llm.rs:798` | URL authority strip | out of scope — `rsplit` is correct there |
| `channel_identity_provider.rs:1705` + `tests.rs:252` | email `local@domain` | out of scope, already `split_once` |
| `pkix-chain-0.4.1` (vendored) | mailbox matcher | out of scope — vendored |

Two consumers, both writing the same grammar independently, both from the RIGHT
— which is how the bug survived review twice. Neither imported the producing
module; each restated the split in its own doc comment.

## The fix (4 files, chokepoint not call-site)

**`crates/oneiron/src/attempt_queue.rs`** — the grammar now lives in one place:

1. `ManifestEntry::parse_wire_form(&str) -> Option<(&str, &str)>` — the inverse
   of `wire_form()`, sited next to it, splitting on the FIRST `@`. Returns
   `None` for a string carrying no `@` (not a wire form).
2. `validate_manifest_entry` rejects `@` in a REFERENCE
   (`ERR_MANIFEST_REFERENCE_HAS_AT`). This is the "reject at parse" half and it
   is what makes the first-`@` split lossless: with the reference constrained,
   everything past the delimiter is unambiguously the version. A VERSION may
   hold `@` freely.

**`crates/oneiron/src/skill_attribution.rs`** and
**`crates/oneiron/src/skill_reliability.rs`** — both `manifest_entry_names_skill`
helpers delegate to `ManifestEntry::parse_wire_form`; their behaviour comments
about splitting direction are deleted rather than corrected, since the split is
no longer theirs to describe. Each gains one `use crate::attempt_queue::ManifestEntry;`.

`skill_reliability.rs` is ONE-1738's file. Fixing only one of the two would have
left the reliability posterior parsing the same rows the opposite way — the same
grammar, two answers. Not a scope expansion: no new behaviour, no API beyond the
one inverse function, no skill-system reshaping (that redesign stays noted and
out of this leg).

## Callers verified against the old last-`@` behaviour

`pack_manifest_skills()` / `pack_manifest_actor_claims()` have exactly the two
parse consumers above (plus assert-only reads in
`receipt/tests.rs`, `attempt_queue/tests.rs`, `skills_epic_oracle.rs:945`).
Every `ManifestEntry::new` call site in the tree (17, all tests/oracles) passes
an `@`-free reference, so nothing existing trips the new rejection and no
fixture moved. Behaviour is identical for every wire form with ≤1 `@` — the
change is observable only on the multi-`@` rows that were misparsed.

## The regression test (one, as ruled)

`attempt_queue::tests::a_manifest_wire_form_splits_on_the_first_at_and_refs_may_not_hold_one`
— appends `("s", "1@beta")` through the real door, asserts the wire form is
`s@1@beta` and parses back to `("s", "1@beta")`; asserts the door REFUSES
reference `s@1` with `ERR_MANIFEST_REFERENCE_HAS_AT`; asserts a delimiter-free
string is not a wire form; asserts the refused row never landed.

The existing `manifest_entries_are_validated` table was left untouched
(fixture-sync law).

### Mutation verification

| Mutation | Failure |
|---|---|
| `parse_wire_form` back to `rsplit_once` | `left: Some(("s@1", "beta")) / right: Some(("s", "1@beta"))` |
| drop the `@` rejection from `validate_manifest_entry` | `expect_err` panicked — and the resulting manifest held BOTH `s`/`1@beta` and `s@1`/`beta`, two rows with the identical wire form: the ambiguity, demonstrated |

Both mutations restored; the committed tree is the unmutated code.

## Gates

- `cargo fmt -p oneiron --check` — clean
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean
- `cargo test -p oneiron --all-features --lib` — **3979 passed, 0 failed, 8 ignored** (144.67s)
- `cargo test -p oneiron --all-features --test skills_epic_oracle` — 16 passed, 0 failed

`Cargo.lock` was regenerated by the `--all-features` runs and restored
(`git checkout -- Cargo.lock`); it is not in the commit. Porcelain clean apart
from this packet's four source files plus this worklog.
