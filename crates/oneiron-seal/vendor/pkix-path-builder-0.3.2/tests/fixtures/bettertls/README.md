# bettertls::pathbuilding fixtures

Offline fixtures for `pkix-path-builder` integration testing against the
BetterTLS `pathbuilding` suite, imported from the x509-limbo Tier-2
corpus.

## Provenance

- **Upstream corpus**: <https://github.com/C2SP/x509-limbo>
- **Commit pinned**: `5669a4d8097f7f9ecd871a5fbe87fe81e1f0235e` (2026-05-04)
- **Source manifest**: `limbo.json` at the repo root.
- **Source suite**: `bettertls::pathbuilding::tc*` (81 testcases upstream).
- **Original test corpus**: <https://github.com/Netflix/bettertls>
  (BetterTLS by Netflix). x509-limbo curates a Limbo-format JSON port.

## What is committed

25 representative testcases from the 47 `bettertls::pathbuilding::*`
cases that previously appeared in
`pkix-difftest/baseline-limbo.json` with class `StricterThanWild`
(pkix-path Fail, OpenSSL+pyca Pass).

Distribution across the five failure-mode buckets identified in
`pkix-difftest/baseline-limbo-analysis.md`:

| Bucket | Testcases | Count |
|---|---|---:|
| `no-path-to-anchor` (cross-signed candidate selection) | tc1, tc16, tc20, tc24, tc28, tc41 | 6 |
| `sig-invalid-at-1` (cross-signed depth-1) | tc2, tc30, tc31, tc33, tc34, tc35 | 6 |
| `sig-invalid-at-5-or-6` (depth-6 chains) | tc48, tc51, tc54, tc57, tc60 | 5 |
| `cert-not-ca-at-6` (depth-6 not-a-CA at boundary) | tc58, tc59 | 2 |
| `path-len-exceeds` (pathLenConstraint backtracking) | tc61, tc62, tc64, tc66, tc67, tc68 | 6 |

Each `tcN/` subdirectory contains:

- `peer.pem` — the leaf certificate
- `intermediates.pem` — concatenated untrusted intermediates
- `anchors.pem` — concatenated trusted certs (anchors)
- `testcase.json` — metadata extracted from `limbo.json`:
  `id`, `bucket`, `validation_time` (RFC 3339), `expected_result`
  (`SUCCESS` or `FAILURE` per the corpus), plus a description.

`baseline-pkix-path.json` at this directory's root records the observed
`pkix_path_builder::build_path` + `pkix_path::validate_path` status for
each fixture (one of `built_and_valid`, `validation_failed`, or
`build_failed`). The integration test `tests/bettertls.rs` walks the
fixtures and asserts the observed status matches this baseline.

## Empirical baseline (filed under PKIX-lwr9.1, 2026-05-11)

When the harness was first run against these 25 fixtures, **23 of 25
already pass** end-to-end (`build_path` builds a chain and
`validate_path` accepts it). The two non-passing fixtures are:

- **tc41** (corpus-expected FAILURE): `build_path` succeeds and
  `validate_path` correctly rejects the chain with `SignatureInvalid`.
  This is the **correct** outcome for a corpus-expected-failure case.
- **tc60** (corpus-expected SUCCESS): `build_path` builds a chain that
  `validate_path` then rejects with `SignatureInvalid` at chain index
  3. This is a genuine path-selection issue — the builder picked a
  wrong-key intermediate in a 6-deep chain.

This contradicts the framing in the parent epic PKIX-lwr9, which
states pkix-path-builder fails on 47 cases. The 47-case figure comes
from `pkix-difftest/baseline-limbo.json` — but the limbo corpus loader
(`pkix-difftest/src/corpus/limbo.rs::build_item`) builds positional
chains `[peer, ..intermediates, anchor]` and feeds them directly to
`pkix_path::validate_path`, **bypassing pkix-path-builder entirely**.
The 47 StricterThanWild cases are therefore positional-chain-walk
failures in `pkix-path`, not path-discovery failures in
`pkix-path-builder`. See the PKIX-lwr9 comment thread for the
follow-up plan.

The standing fixture set is sized to also cover the path-builder
behaviour PKIX-lwr9.2/.3/.4 will land: even though the current baseline
is mostly green, the fixtures remain useful as regression coverage
against future path-builder refactors.

## Regenerating fixtures

`extract.py` regenerates all 25 fixtures from a local x509-limbo
checkout. Run from this directory:

```sh
python3 extract.py [path/to/limbo.json]
```

The default limbo.json path is `~/GIT/x509-limbo/limbo.json`.
The script uses only the Python 3 standard library. To pick different
testcases (e.g., expand coverage of one bucket), edit the `SELECTED`
mapping near the top of `extract.py` and re-run.

## Regenerating the baseline

After deliberate pkix-path-builder behavioural changes, regenerate
`baseline-pkix-path.json`:

```sh
BETTERTLS_BASELINE_DISCOVER=1 cargo test \
  -p pkix-path-builder --test bettertls -- --nocapture \
  | awk '/^\{$/,/^\}$/' > tests/fixtures/bettertls/baseline-pkix-path.json
```

Then `cargo test -p pkix-path-builder --test bettertls` must pass. Do
**not** regenerate without reviewing the diff — a regression in
pkix-path-builder will look like an "intentional" rebaseline if the diff
is not scrutinized.
