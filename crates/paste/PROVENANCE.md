# Vendored `paste` 1.0.15 — provenance and exit condition

`crates/paste/vendor/paste-1.0.15` is a **byte-for-byte local vendor of the published
paste 1.0.15 crate**, with no code changes. The repository root manifest substitutes it
for the registry copy with

```toml
[patch.crates-io]
paste = { path = "crates/paste/vendor/paste-1.0.15" }
```

and excludes it from the workspace. The dependency graph is otherwise untouched: the
package keeps name `paste`, version `1.0.15`, its edition and its (empty) dependency
list, so no version moves and no dependency is added.

## Why this vendor exists

`paste` is a compile-time proc-macro that concatenates identifiers. Its author archived
the upstream repository in 2024, so RustSec carries the informational advisory
RUSTSEC-2024-0436 ("no longer maintained"). There is no vulnerability. The crate ships
zero bytes in any binary; it runs inside the compiler only.

The embedder lane (ONE-1979 / ONE-1980, candle 0.11) pulls it in transitively through
`gemm-c32`, `gemm-c64`, `gemm-common`, `gemm-f16`, `gemm-f32`, `gemm-f64`, `gemm`, `metal`, `pulp`, `tokenizers`. The repository's advisory policy
(`scripts/advisory-policy/`, ONE-335) accepts maintenance risks only as exact, expiring,
owner-named entries. The owner's ruling (2026-09-12) is to own the crate instead: the
vendored copy is maintained here, so the "unmaintained" status no longer describes it,
and the advisory scanner (which matches registry-sourced crates only) stops reporting it.

## Upstream pin

| Fact | Value |
| --- | --- |
| Upstream source root | `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/paste-1.0.15` |
| Registry source | `registry+https://github.com/rust-lang/crates.io-index` |
| crates.io checksum (unpatched lock entry) | `57c0d7b74b563b49d38dae00a0c37d4d6de9b432382b2892f0574ddcae73fd0a` |
| Upstream VCS commit (`.cargo_vcs_info.json`) | `a2c7e27875277450ed28147623ba5218dd23e732` |
| `src/lib.rs` SHA-256 | `12a0578bb1d011ae759a94aa4850e970fc1c74102d1ede62b9f405675d7e182e` |
| License | MIT OR Apache-2.0 (both license files vendored) |

## Inventory

Every file is byte-for-byte the pinned registry crate (`diff -r` against the source root
above is empty): `Cargo.toml`, `Cargo.toml.orig`, `.cargo_vcs_info.json`, `build.rs`,
`LICENSE-APACHE`, `LICENSE-MIT`, `README.md`, `src/`, `tests/`. Nothing is edited here;
`typos.toml` and the code map skip the tree like they skip `crates/heed/vendor`.

## Exit condition

Delete this directory and the `[patch.crates-io]` line when no crate in `Cargo.lock`
depends on `paste` any more (the upstreams are expected to move to the maintained fork
`pastey`). Check with `grep -c 'name = "paste"' Cargo.lock` after a dependency bump.
