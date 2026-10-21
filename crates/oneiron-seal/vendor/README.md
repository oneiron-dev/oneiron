# Vendored crates

## pkix-chain-0.4.1 (ONE-1837 amendment A7)

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

## lopdf-0.44.0 (FIX 7654: decode memory admission)

- Source: `https://static.crates.io/crates/lopdf/lopdf-0.44.0.crate`
- Recorded SHA-256 of the `.crate` archive:
  `5e2ec995d822e05cabc3f06d196ee43650af3fe4fe38012cacb35e0c3d113b68`
  (matches the `checksum` recorded for lopdf 0.44.0 in the pre-vendor
  `Cargo.lock`, and the archive in the Cargo cache)
- Upstream VCS: `.cargo_vcs_info.json` names commit
  `8c454dd93d9c37e608c552a2b304d1d31d1cb2e1` of `J-F-Liu/lopdf` with
  `"dirty": true`. The archive was packaged from a tree with uncommitted
  changes, so that commit alone does not reproduce it; the archive and its
  checksum are the provenance.
- License: MIT, `LICENSE` kept unmodified ("Copyright (c) 2016 Junfeng
  Liu"). MIT is on the deny.toml allow list; no allowance change.
- Contents: not the unmodified archive. Copied: all of `src/`, the
  normalized `Cargo.toml`, `Cargo.toml.orig`, `.cargo_vcs_info.json`,
  `LICENSE`, `README.md` (the crate docs include it), `CHANGELOG.md`,
  `.gitattributes`, `.gitignore`, `.editorconfig` and `rustfmt.toml`. Left
  out: `.cargo-ok` (Cargo's extraction marker), the archive's own
  `Cargo.lock`, `examples/` and `tests/`. The active `Cargo.toml` drops the
  `[[example]]` and `[[test]]` tables and every dev-dependency table,
  including the `cfg(not(target_family="wasm"))` criterion one; `[package]`,
  `[features]`, `[lib]` and the dependency tables are the archive's, byte for
  byte. `Cargo.toml.orig` is kept as provenance only. The inline
  `#[cfg(test)]` modules in `src/` are upstream's and untouched; some read
  `assets/` files the archive does not ship.
- Wiring: a `[patch.crates-io]` path entry in both the root `Cargo.toml`
  and `.cargo/config.toml` (as for pkix-chain: trybuild copies only the
  manifest's patches), the directory in the root workspace `exclude`, and
  the `Cargo.lock` lopdf entry without its `source` and `checksum` lines
  (dependency list unchanged). `crates/oneiron` and `crates/oneiron-seal`
  keep their `=0.44.0`, `default-features = false` pins; no lopdf feature
  is enabled.
- Formatting: these files keep upstream formatting; the local patch is
  written in it. Never run the workspace formatter over this directory.
- Local patch list (the first vendor commit is the unmodified sources plus
  the manifest strip, so `git log -p` on this directory shows each change).
  All of it is additive: without a `DecodeAdmission` every load and decode
  runs upstream's code.
  - `src/decode_admission.rs` (new): the `DecodeAdmission` trait (`admit`
    before each allocation, `decoded` to observe an output length),
    `DecodeAdmissionError` (`MemoryFloor { needed, available }`, `Deadline`,
    `Cancelled`), the admitted growth helper, the codec working-state charge
    and the `BTreeMap` node charge. `src/lib.rs` exports both types.
  - `src/error.rs`: `Error::DecodeAdmission`.
  - `src/load_options.rs`: `LoadOptions::decode_admission` (default `None`;
    `Debug` shows only whether one is set).
  - `src/object.rs`: `Stream::decompressed_content_admitted`; admitted
    Flate (flate2 `bufread` decoders over the input, the raw-deflate
    fallback included), LZW (weezl `decode_bytes` into admitted output),
    ASCII85 and the copy of unfiltered content. `decompressed_content` and
    `decompressed_content_with_limit` go through a dispatcher whose `None`
    arm is upstream's `decode_filters`.
  - `src/filters/png.rs`: `decode_frame_admitted` for the PNG predictor.
  - `src/object_stream.rs`: `ObjectStream::new_admitted`.
  - `src/parser_aux.rs`: `decode_xref_stream_admitted`; it reads each field
    a byte at a time instead of through a buffer as wide as `/W` says.
  - `src/parser/mod.rs`: the admitted stream content copy, and a refusal
    while resolving an indirect `/Length`, inside an indirect object or in
    an xref stream is carried out of nom instead of becoming an unknown
    length, `IndirectObject` or `InvalidTrailer`.
  - `src/reader.rs`: `Reader::decode_admission`, set by every constructor
    (`None` for the metadata and incremental loaders); object streams, the
    delayed stream copies and the encrypted loader's raw object copies use
    it, and a refusal ends the load. The encrypted loader's object-stream
    members and `get_compressed_object`'s container move instead of being
    cloned; the result is the same, with or without an admission.
