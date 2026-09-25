# Forked dependencies

Two third-party crates carry changes of ours. Neither is vendored: each is a git dependency on a
fork under `github.com/oneiron-dev`, pinned by a full commit `rev`, never by a branch or a tag.
The fork branch holds upstream's release commit plus our commits, one per change, each message
saying what it changes and why. Upstream licence files and copyright notices stay untouched on
the fork.

| crate | upstream base | fork branch | pinned rev | licence |
|---|---|---|---|---|
| `sudachi` 0.6.11 | [WorksApplications/sudachi.rs](https://github.com/WorksApplications/sudachi.rs) tag `v0.6.11`, `90fd6068c80c2fc3b63e0dbab0e341475bad4d8f` | [`oneiron/v0.6.11`](https://github.com/oneiron-dev/sudachi.rs/tree/oneiron/v0.6.11) | `d8cba3609521805ebf35bfc2b71d8099a13befef` | Apache-2.0 |
| `formualizer-common`, `-parse` 3.1.2; `formualizer-eval`, `-macros`, `-workbook` 0.9.3 | [psu3d0/formualizer](https://github.com/psu3d0/formualizer) `362becffa029d8f77349c2c477fc39eff7fc52d5` (the commit the five crates.io archives name; tag `v0.9.3` is an annotated tag on it) | [`oneiron/0.9.3`](https://github.com/oneiron-dev/formualizer/tree/oneiron/0.9.3) | `adc4743f909ccbe54a6a590fe1a0b0f1bdad9e95` | MIT OR Apache-2.0 |

## Changing a forked crate

1. Commit the change on the fork branch (or on a new `oneiron/<upstream version>` branch cut from
   the next upstream release), with a message that names the change and the reason.
2. Push the branch and move the `rev` in the manifest to the new branch head.
3. Update the table above. `deny.toml` allows each fork URL in `[sources] allow-git`;
   `unknown-git` stays `deny`.
4. `python3 -m unittest discover -s scripts/ci -p 'test_vendor_pins.py'` and
   `cargo-deny --locked check` must pass.

## sudachi

`crates/oneiron/Cargo.toml`:

```toml
sudachi = { git = "https://github.com/oneiron-dev/sudachi.rs", rev = "d8cba3609521805ebf35bfc2b71d8099a13befef" }
```

Fork commits on `oneiron/v0.6.11`, over upstream `v0.6.11`:

- `baa525f0` names Android plugins `lib<name>.so`: `target_os = "android"` joins the
  Linux/FreeBSD branch of `make_system_specific_name` in `sudachi/src/plugin/loader.rs`. Without
  it the crate does not build for Android (E0425). The Android embedded workflow depends on it.
- `d8cba360` gives each bare `#[allow]` in `sudachi/src` and `sudachi/tests` a `reason` (24),
  removes two that no lint needed, and raises the workspace `rust-version` to 1.81, the release
  that stabilised lint reasons.

The earlier vendored snapshot also trimmed the CLI, fuzz and Python members from the root
workspace. The fork does not: Cargo reads the full upstream workspace as a git dependency, as
it did when main pinned upstream `v0.6.11` by tag.

## formualizer

Not a dependency on main yet. The Office-documents lane (PR #947, `crates/oneiron-xlsx-formula`)
replaces its vendored copy with these five root `Cargo.toml` lines; its manifest keeps the exact
`=0.9.3` and `=3.1.2` requirements, and `deny.toml` then allows
`https://github.com/oneiron-dev/formualizer`:

```toml
[patch.crates-io]
formualizer-common = { git = "https://github.com/oneiron-dev/formualizer", rev = "adc4743f909ccbe54a6a590fe1a0b0f1bdad9e95" }
formualizer-eval = { git = "https://github.com/oneiron-dev/formualizer", rev = "adc4743f909ccbe54a6a590fe1a0b0f1bdad9e95" }
formualizer-macros = { git = "https://github.com/oneiron-dev/formualizer", rev = "adc4743f909ccbe54a6a590fe1a0b0f1bdad9e95" }
formualizer-parse = { git = "https://github.com/oneiron-dev/formualizer", rev = "adc4743f909ccbe54a6a590fe1a0b0f1bdad9e95" }
formualizer-workbook = { git = "https://github.com/oneiron-dev/formualizer", rev = "adc4743f909ccbe54a6a590fe1a0b0f1bdad9e95" }
```

Fork commit on `oneiron/0.9.3`, over `362becff`:

- `adc4743f` "Owned evaluator patch 0.9.3-oneiron.1": `formualizer-eval/src/interpreter.rs`
  propagates a typed error on either side of `&`, in both the AST and the arena paths, before
  text coercion. Literal text `"#N/A"` stays text.

Proved against #947 (`1e76293d`) with the five lines above in place of its vendor paths: the
lockfile changes only the five `source` entries, and `tests/error_concat.rs` passes on the fork
rev. With the fork in `allow-git`, `cargo-deny` passes `sources` but `licenses` rejects
`tiny-keccak` 2.0.2 (CC0-1.0), which `formualizer-eval` pulls in through `arrow` → `ahash` →
`const-random`. The vendored graph on #947 has the same edge, so landing formualizer needs a
`deny.toml` decision on CC0-1.0 as well.

## Licences and attribution

No source of either project is copied into this repository; the upstream licence texts ship in
the forks and in every Cargo checkout of them.

- sudachi.rs: Apache License 2.0, `LICENSE` at the repository root. Copyright (c) 2021 Works
  Applications Co., Ltd.
- formualizer: MIT OR Apache-2.0, `LICENSE-MIT` and `LICENSE-APACHE` at the repository root.
  Copyright (c) 2025-2026 Frank Colson and Formualizer contributors.
