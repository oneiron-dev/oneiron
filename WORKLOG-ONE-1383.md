# ONE-1383 Fix Cycle 2b

- Added cross-manifest chain order-independence and revoke-dominance regression coverage.
- Added delegated gate binding coverage for exact, mismatched, unknown, revoked, and proposed ceilings.
- Validation: cargo fmt; cargo clippy -p oneiron --all-targets --all-features -- -D warnings; focused tests passed.
