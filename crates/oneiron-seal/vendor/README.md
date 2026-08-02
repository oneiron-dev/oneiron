# Vendored crates (ONE-1837 amendment A7)

## pkix-chain-0.4.1

- Source: `https://static.crates.io/crates/pkix-chain/pkix-chain-0.4.1.crate`
- Recorded SHA-256 of the `.crate` archive:
  `bb5a98d9c03b29aa0512bc8c22287a3af2d4152ef546fceddbbacde0c1e82337`
  (matches the `checksum` recorded for pkix-chain 0.4.1 in the pre-vendor
  `Cargo.lock`)
- Contents: the unpacked archive, unmodified. The crate's test fixtures are
  public X.509 certificates only; the archive contains no private key
  material (verified by scan at vendor time).
- Wiring: root `.cargo/config.toml` `[patch.crates-io]` redirects the exact
  `=0.4.1` pin to this snapshot, so a yanked crates.io release cannot break
  the build. A directory `[source]` replacement was rejected: it would
  require vendoring the entire crates.io graph.
- A7 open item resolved: no direct `pkix-path-builder` dependency is
  needed. The lane calls only `pkix_chain::verify_chain`; path building
  from the certificate bag runs inside pkix-chain via its re-exported
  `pkix_path_builder`.
- License: Apache-2.0 OR MIT (both on the deny.toml allow list; no
  deny.toml allowance change required).
