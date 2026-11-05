# Shared proactivity-policy proposals

The nightly `dreamer.digest.policy` facet can propose a change to the shared
proactivity digest's `cadence.period_secs`. It reuses the existing closed-form
Weave digest verdict for the embedded owner's own opens, dismissals and feedback.
It honors `keep_current` and the steps declined or undone under that owner's
current settings generation. It does not change a per-owner Weave schedule.

Only a cadence verdict is copied. Grouping, urgency and every presentation field
stay as they were in the shared rows read for the proposal. Daily and weekly use
the existing Weave cadence durations; no separate tuning thresholds are added.
A proposal needs live `weave.digest` notification witnesses for that owner's
periods. The engagement side rows themselves are not entity evidence. Without a
cadence change or a live witness, the facet files nothing.

## Review and confirm

A new request is a Proposed `dreamer.proactivity.policy_request` claim in its
attempt's run tray, with a finding notice. It changes no setting on its own.
These routes use the normal authenticated vault-owner HTTP door:

- `GET /v1/owner/proactivity/policy?proposal=<32-hex claim id>` returns the
  `proposal`, its exact `revision` (64 hex), and the typed `request`.
- `POST /v1/owner/proactivity/policy/confirm` takes
  `{"proposal":"<claim id>","revision":"<reviewed revision>"}`. Both shared
  settings rows and the replay marker commit in one writer. Changed, inactive,
  stale or already-confirmed proposals do not confirm again.

The ordinary run-tray Approve also applies a pending policy request. The live
owner, reviewed bundle, claim and consent binding are rechecked first; settings,
replay marker, Approved claim, tray closure and bundle receipt then share one
transaction. A failure rolls the whole approval back. There is no settings hook
after the approval commits. If the exact-confirm route already applied the same
revision, run-tray Approve closes the claim without applying its settings again.
Decline keeps the ordinary rejection behavior and applies no settings.

The exact-confirm route retains the existing proposal lifecycle: it writes the
settings and marker but leaves the claim Proposed. Run-tray approval can settle
that claim later without a second settings write. Neither route changes past
digests. This feature needs the normal engine/server deployment; no migration or
new configuration is needed.

## Owner-stated intent timing

`POST /v1/owner/intents` takes the owner's actual `text` (required), an
optional `message` (32 hex, the MESSAGE the words came from), and an optional
`needed_before` (u64 Unix seconds). Omitting the time keeps the original
untimed intent; stating it keeps the same Approved `profile.intent` words
with the time as factual evidence under the same intent hash, for example
`{"text":"...","needed_before":1770000000}` (placeholder number, no default).
The time adds no urgency gate and bypasses no quiet hours, grant, or outbound
rule. This feature needs the normal matching engine/server rollout; no
migration or new configuration is needed.
