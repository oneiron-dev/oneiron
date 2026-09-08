# Post-wave maintenance-risk policy record (ONE-335)

## 2026-09-07 exact3 extension

**Accepted maintenance risk, not a dependency fix or vulnerability remediation.**
The original 16 exact acceptances remain unchanged. This extension adds only:

| Advisory | Exact locked package | Exact direct parents |
| --- | --- | --- |
| RUSTSEC-2026-0247 | bitmaps 2.1.0 | im 15.1.0; sized-chunks 0.6.5 |
| RUSTSEC-2026-0248 | im 15.1.0 | loro-internal 1.13.9 |
| RUSTSEC-2026-0251 | sized-chunks 0.6.5 | im 15.1.0 |

The required dependency chain in the inspected current lock is:

```text
loro 1.13.9 -> loro-internal 1.13.9 -> im 15.1.0 -> bitmaps 2.1.0
                                             -> sized-chunks 0.6.5 -> bitmaps 2.1.0
```

`exceptions.json` records both upstream links as version/source-checked context
and every direct parent of the three accepted packages. All five chain packages
use the crates.io registry source. Changed versions, sources, missing packages,
changed direct parents, or broken recorded upstream links require re-evaluation.
The current lock SHA-256 is
`1d31f3cdb3ac79e9fb610c8a76cb7349949caba096cb9a7918018ecfadc84ad6`.
The lock was read, not regenerated; this hash records inspection, not a new
whole-lock pin.

## Fresh evidence and rationale

The inspected fresh disposition reports all three as **informational
unmaintained**, affecting all versions, with no supported safe upgrade in the
required chain. It records repositories archived on 2026-05-03 and asserts no
known vulnerability here. This is not a guarantee that the dependencies are safe.

- `bitmaps`: `fixedbitset` or `bitvec` are alternatives, not same-package safe
  version pins.
- `im`: `imbl` is a maintained fork; adopting it is not authorized by this grant.
- `sized-chunks`: `imbl-sized-chunks` is a fork, not an authorized dependency
  replacement.

Use an ordinary supported upgrade/fix when available. No speculative architecture
change or fork adoption is authorized merely to remove maintenance warnings.
Keep Linux support, source custody, and the existing review/affected-test pipeline.
The total is now **19 explicit temporary acceptances**. The four pre-existing
atomic-polyfill, bincode, smallstr, and rsa decisions stay separate and are not
renewed or broadened; no new vulnerability waiver is granted.

Evidence provenance (external owner records, not runtime policy inputs;
`<harness-report-dir>` is the dispatch harness's report directory on the worker
host, not part of this repo):

- Authority: `<harness-report-dir>/factory-wave6-launch-20260906/v11/mass-coverage/supervision-correction/owner-exact-maintenance-exception-20260907/OWNER-STANDING-EXTENSION-AUTHORITY.json`.
  Recorded at `2026-09-07T10:34:58.159134+00:00`; it preserves the original16 grant
  in `OWNER-AUTHORITY.json` in the same directory.
- Fresh disposition: `<harness-report-dir>/factory-wave6-launch-20260906/v11/mass-coverage/front-dispatch/ONE-335/FRESH-THREE-ADVISORY-DISPOSITION.json`.
  Its candidate is `738846849279acdadd98f873fae1b5606963d926`; its source is
  `OWNER-EXCEPTION-FRESH-CHECK.log` in the same directory. That check blocked
  these then-unlisted advisories. The later standing authority explicitly adds
  the exact three; it does not turn the earlier failure into a passing check.

## Standing delegation and review boundary

The owner stated: "Hey, sure, you can extend and don't ask going forward".
SoleCEO through the existing lane/ticket owners (CEO -> PERF-QA / appropriate
existing ticket owner) may add equivalent cases without per-ID Board/owner
approval or ACK. No new manager or evaluation lane is needed.

The current owner must inspect each case and record its exact advisory ID,
package/version, required dependency chain, informational-unmaintained
classification, and why no supported safe upgrade is available. Add a narrow,
explicit entry to `check.py`'s `AUTHORIZED` set and `exceptions.json`, with exact
current-lock context, count-sensitive tests, fresh-DB/effective-policy validation,
and a banked rationale for post-wave review. **Standing delegation is not runtime
blanket autoallow.** Fresh unlisted notices still block until an inspected narrow
entry is added. Vulnerabilities, changed classifications, and other nonqualifying
findings remain blocking. Escalate only materially different risk outside scope;
do not interrupt the Board for routine equivalent additions.

All 19 acceptances end at **2026-10-07T00:00:00Z**, or the post-wave context-pack
discussion, whichever comes first. Record that event in `review.post_wave_at`
when scheduled or when it starts. Review is not complete merely because this
record exists. New additions do not extend expiry. **No automatic renewal**, no
date bump, and no clearing a completed review timestamp to continue acceptance.
Retire/review the exceptions at that boundary; renewal needs new authority.

## Validation handoff

No tests, builds, Git commands, or network checks were executed for this extension.
The old offline DB lacks the three new IDs and must fail closed. Missing records
must not be skipped, and classification checks must not be weakened. A later
fresh DB check on the exact current candidate is required; the earlier candidate's
diagnostic and the authored synthetic fixtures are not that validation.
See [README.md](README.md#inspection-and-validation-handoff) for exact commands.
