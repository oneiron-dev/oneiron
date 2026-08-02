# Agent guidance

General rules: `CLAUDE.md` (consumer boundary, build/test). Deep guidance: `oneiron.skills.md`.

## Code Review Rules

- Pre-release, no deployed vaults: don't flag missing migrations or legacy decoders for
  persisted formats whose version counters have never shipped. Full posture: `REVIEW.md`.
- Don't review `crates/*/vendor/**` (vendored upstream snapshots) — unless a PR modifies them.
- Prioritize: invariants missing at any door (admission / replay / rematerialization / export /
  batch), validator-vs-writer-promise gaps, hostile-peer-reachable paths, fail-open errors,
  and regressions in code introduced by earlier review fixes.
- Doc/comment/naming findings are informational, never blocking.
