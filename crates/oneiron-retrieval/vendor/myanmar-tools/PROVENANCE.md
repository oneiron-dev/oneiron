# Provenance: `zawgyiUnicodeModel.dat`

What this file is: the pre-trained Zawgyi/Unicode Markov model from
google/myanmar-tools. It holds the transition log-odds that
`crates/oneiron-retrieval/src/analyzer/zawgyi.rs` reads to score
P(Zawgyi) for an input string.

Source: <https://github.com/google/myanmar-tools>, path
`clients/cpp/resources/zawgyiUnicodeModel.dat` (byte-identical copies live
under `clients/js` and `clients/python`). Fetched at master
`13e4af6aaac63849fa122374f93bc77a42674027`; the file last changed upstream
in `7d7f7316bd5f` (2020-07-20).

SHA-256: `7df7bdf7c7bf2dbc83ebbbb6f75ce7b6a1886cc64147b778176a03a803241b8a`.

Licence: Apache-2.0, Copyright 2017 Google LLC. The upstream header is in
`LICENSE.md` here; the full licence text is in the repo root `LICENSE`; the
project entry is in the repo root `THIRD-PARTY-NOTICES.md`.

The one reader is `include_bytes!` in
`crates/oneiron-retrieval/src/analyzer/zawgyi.rs`.

How to update it: replace the bytes, update the sha256 above, and rerun the
compatibility test (`detector_matches_the_myanmar_tools_compatibility_vectors`
in `crates/oneiron-retrieval/src/analyzer/zawgyi/tests.rs`, 50 rows from
myanmar-tools).
