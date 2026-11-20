# Changelog

All notable changes to `pkix-path-builder` are documented here. The
crate follows [Keep a Changelog](https://keepachangelog.com/) headings
and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Optional `serde` feature gating `Serialize`/`Deserialize` derives on
  the public `Error` enum. All fields (`tried: usize`,
  `last_error: String`) are already serde-compatible; the derive
  passes through unchanged. Enables consumers like `pkix-chain` that
  carry `Error` in their own serde-supporting result types (AGENTS.md
  non-negotiable #6). (PKIX-zkjb.7)

## [1.0.0] — TBD

First stable release.

### Added

- BetterTLS `pathbuilding` fixtures imported under `tests/` with a
  characterization-test harness (PKIX-lwr9.1). 23 of 25 picked fixtures
  pass; `tc41` is a corpus-expected `FAILURE` correctly rejected, and
  `tc60` is the sole genuine path-builder divergence remaining at 1.0
  (depth-6 wrong-intermediate selection in a cross-signed pool). The
  `tc60` resolution is the post-validation `build_first_valid_path`
  helper shipped in `0.3.1`.

## [0.3.1] — 2026-05-11

### Added

- `build_first_valid_path<V>` and `build_first_valid_path_with_config<V>`
  helpers (PKIX-lwr9.4.2). Iterate `build_path_candidates` until the
  first candidate chain passes `pkix_path::validate_path`. Closes the
  consumer-ergonomics gap surfaced by PKIX-lwr9.4 / BetterTLS `tc60`:
  `build_path` is single-shot and has no `SignatureVerifier`
  dependency, so it cannot pre-filter candidates by algorithm
  support. Cross-signed pools containing intermediates signed under
  algorithms the verifier does not dispatch (e.g. `ecdsa-with-SHA1`)
  now route through the helper to find a valid SHA-256-only path.
- `Error::NoValidPath { tried: usize, last_error: String }` variant
  on the `#[non_exhaustive]` `Error` enum. The inner `pkix_path::Error`
  is rendered to `String` rather than carried verbatim so the builder's
  `Error` retains its `Hash` derive (`pkix_path::Error` is not `Hash`).
  Consumers needing programmatic match on inner errors should drop to
  `build_path_candidates` and call `validate_path` per candidate
  themselves. Zero-yield exhaustion still surfaces as
  `Error::NoPathFound` (unchanged `build_path` contract).
- Three new integration tests in `tests/build_first_valid_path.rs`:
  positive (BetterTLS `tc60` cross-signed pool), `NoValidPath`
  (PKITS §4.1.1 chain + `AlwaysRejectVerifier`), and `NoPathFound`
  passthrough (empty pool).
- Dev-dependencies on workspace-pinned `spki` and `signature` so the
  `AlwaysRejectVerifier` test impl can spell out the
  `SignatureVerifier` trait's argument types.

## [0.3.0] — 2026-05-11

### Changed (breaking)

- Dep major bump on `pkix-path` (0.2 → 0.3); the `pkix-path-builder`
  public API is otherwise unchanged. Bump `pkix-path-builder = "0.2"`
  to `pkix-path-builder = "0.3"` in your `Cargo.toml`.

### Changed (non-breaking, behavior)

- `build_path`, `build_path_with_config`, and the `PathCandidates`
  iterator now silently **skip** candidate intermediates whose
  `BasicConstraints` extension is present but cannot be DER-decoded,
  rather than aborting the search with `Error::MalformedIntermediate`.
  Matches the existing treatment of candidates with `cA = FALSE` or
  no `BasicConstraints` at all (PKIX-qgw1).

  Rationale: real-world certificate pools (notably CMS
  `SignedData.certificates` bags) routinely include unsolicited or
  corrupt certs the verifier did not request — intermediates for
  other recipients in a multi-recipient encrypted message, certs
  from unrelated CAs that rode along, or expired / corrupt artefacts
  from someone's pipeline. One bad cert in the bag must not poison
  verification of an otherwise-valid chain.

  When skipping all malformed candidates would leave no path to a
  trust anchor, `build_path` returns `Error::NoPathFound` (as it
  would for any other no-path scenario). The
  `Error::MalformedIntermediate` variant is retained because `Error`
  is `#[non_exhaustive]` and may be repurposed by a future
  diagnostic mode.

## [0.2.1] — 2026-05-07

### Added

- `PathCandidates` iterator API (PKIX-mszo) — exposes the lazy
  candidate-enumeration surface that `build_path` consumes internally.
  Callers driving differential testing, fixture diff, or other
  enumeration use cases can iterate candidates directly without the
  single-shot wrapper's first-success-wins semantics.
- AKI-based candidate selection in the search (PKIX-yn3e). When a
  candidate intermediate's `authorityKeyIdentifier.keyIdentifier` is
  present, the builder prefers issuers whose `subjectKeyIdentifier`
  matches, falling back to issuer-DN matching when AKI is absent or
  no SKI match exists. Substantially reduces backtracking on
  large pools with multiple same-DN issuers.
- `PathBuilderConfig` and `build_path_with_config` (originally landed
  in earlier 0.2 work; full surface stable in 0.2.1).

### Changed (non-breaking)

- `cert_is_ca` is now a thin wrapper over `pkix_path::cert_is_ca` with
  `.map_err(|_| Error::MalformedIntermediate)`. Behavior unchanged.
- `Error::DepthExceeded` doc and `Display` no longer hardcode `"(10)"`;
  reference `PathBuilderConfig::max_depth` and `DEFAULT_MAX_DEPTH`
  instead.

## [0.2.0] — 2026-05-06

Initial 0.2 release alongside the workspace stabilization. RFC 4158
path discovery: DFS over a caller-supplied `CertPool` rooted at a
target leaf and resolved against caller-supplied trust anchors.
Subject-DN issuer matching with SPKI-fingerprint cycle detection;
basic `BasicConstraints` cA / `KeyUsage::keyCertSign` filtering on
candidate intermediates. Output is a positional chain ready to feed
into `pkix_path::validate_path`.

## Pre-history

Initial scaffold landed under `9b0995eb` (`feat: add stub crates,
specs, and READMEs`) alongside the other workspace stub crates. The
substantive RFC 4158 path-discovery implementation landed in
`3f922ad2` (`feat: path builder, policy scaffolding, CRL OIDs, PKITS
CRL fixtures`) and stabilized through the `0.2.x` cycle.
