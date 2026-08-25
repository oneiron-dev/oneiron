# seal-oracle — CI-only differential oracle

pyHanko is a **CI oracle only** (ONE-1837 §9, amendment A6). Nothing here is
referenced by the shipped crate, release images, or server startup: no
runtime Python, no sidecar, no credential configuration.

Cadence (A6, amended 2026-08-24): the oracle workflow is event-based only —
merges to main that touch the seal crate (or the workflow file), plus manual
dispatch. The `v*` release-tag trigger A6 called for was removed by the
2026-08-24 amendment: a tag carries no seal-crate content the main merge
behind it did not already run, so it only bought a duplicate run. Never
`pull_request`, never a schedule.

## Layout

- `pyproject.toml` / `uv.lock` — exact pin: `pyhanko == 0.35.2`.
- `run.py` — `validate <sealed.pdf>` prints a normalized JSON verdict
  (`{valid, validator, version}`) with no credential references and no full
  fetch URLs.

## Local use

The `seal-oracle` cargo test target skips cleanly when pyHanko is absent.
To run it for real:

```bash
uv run --project crates/oneiron-seal/oracle python crates/oneiron-seal/oracle/run.py validate <sealed.pdf>
cargo test -p oneiron-seal --features seal-oracle --test oracle
```
