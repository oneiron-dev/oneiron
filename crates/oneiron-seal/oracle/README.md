# seal-oracle — CI-only differential oracle

pyHanko is a **CI oracle only** (ONE-1837 §9, amendment A6). Nothing here is
referenced by the shipped crate, release images, or server startup: no
runtime Python, no sidecar, no credential configuration.

Cadence (A6): the oracle workflow is event-based only — merges to main that
touch the seal crate, `v*` release tags (EU-DSS rides the tags), and manual
dispatch while the lane is built. Never `pull_request`, never a schedule.

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
