# Review guidance

Standing posture for reviewing this repo, human or bot.

## Reviews do not block merges

The vibe build rules in `AGENTS.md` apply. A change merges as soon as
`cargo check --workspace --all-features` passes on its head. No review blocks a merge, and bot
comments need no answer. Flag real defects; the author fixes them or puts them on the fix list.
Do not ask for new tests.

## No backward compatibility

No vault exists anywhere yet. Formats change freely. Do not ask for migrations, legacy decoders,
upgrade code, old-format readers or version bumps.

## What matters most here

- A new invariant enforced at one door but not all of them (admission, replay,
  rematerialization, export, generic batch writes).
- Validators that merely trust what writers promise not to write.
- Anything reachable by a hostile sync peer or caller-chosen IDs; fail-open error paths.
- Code introduced by a previous review fix — freshly patched seams regress most.

The consumer boundary (no product names or prompt text in engine code) is in `CLAUDE.md` and
binds first-party code only.
