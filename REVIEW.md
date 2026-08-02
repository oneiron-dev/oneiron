# Review guidance

Standing posture for reviewing this repo, human or bot.

## Release state: pre-release, no deployed data

No vault created by a shipped build exists anywhere. A persisted format whose version
counter has never shipped may change shape in place — do not request legacy decoders,
migrations, or version bumps whose only beneficiaries are rows that cannot exist outside
dev vaults (they are wiped as debris). Flag compatibility only when a format has actually
shipped, or the change breaks data written by this same build. This posture expires at GA.

## Out of scope

`crates/*/vendor/**` — vendored third-party snapshots, upstream's text. Do not review it.
Exception: a PR that *modifies* vendored files — flag that loudly.

## What matters most here

- A new invariant enforced at one door but not all of them (admission, replay,
  rematerialization, export, generic batch writes).
- Validators that merely trust what writers promise not to write.
- Anything reachable by a hostile sync peer or caller-chosen IDs; fail-open error paths.
- Code introduced by a previous review fix — freshly patched seams regress most.

Consumer boundary (no product names or prompt text in engine code) is in CLAUDE.md and
binds first-party code only. Doc/comment/naming findings are informational, never blocking.
