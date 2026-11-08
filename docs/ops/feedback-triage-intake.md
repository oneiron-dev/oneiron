# Feedback triage on intake

Feedback normally stays in the inbox until a manual or nightly sweep. The
owner can opt in to queueing the ordinary sweep as each new inbox note lands.
This setting does not start a separate worker or timer, promise immediate
execution, or change the sweep's skill, budgets or admission.

Read `GET /v1/owner/feedback/triage/binding` with the authenticated owner. The
response includes `skill`, `enqueue_on_intake`, `revision` and `set_at`.
`enqueue_on_intake` defaults to false while the binding has never been set.
Write the existing `PUT /v1/owner/feedback/triage/binding` with all desired
settings and the revision read, for example:

```json
{"skill": null, "enqueue_on_intake": true, "seen": 0}
```

`skill: null` leaves no skill bound; such a sweep retains the existing
`skill_unbound` no-work result and does not consume the pending notes. A real
skill change still requires the same live, active, approved shared skill.
Changing only the intake policy keeps the current skill binding. Keeping both
settings unchanged keeps the revision; any real setting change increments it.
A stale `seen` still refuses the whole change.

The boolean is required in the current stored and request formats. Deploy
matching clients and engine/server together; there is no old-format reader
or migration.

With the setting enabled, every native intake kind uses the same landing
transaction. It writes the note and reads the owner's standing binding there,
then queues the ordinary fixed-key sweep. Anonymous feedback cannot enable
the setting or supply scheduling authority. A queued sweep covers new notes.
If a sweep is already running, one durable pending request queues a later
ordinary sweep after terminal settlement releases its dedupe key. Multiple
intakes coalesce; there is no per-note queue key or parallel sweep.

Note storage and enqueue commit together. An enqueue error rolls the note
back too, so the caller receives the existing storage error rather than a
false accepted response. A committed note has its queued sweep or durable
pending request. Existing continuation and terminal redrive behavior remain
in use.

Turning the setting off stops future intake-triggered requests. It never
cancels admitted work or erases a pending manual or policy request. Manual
run-now, nightly scheduling, quoting permissions, parsing and intake flood
limits are unchanged. The setting applies to this vault's inbox; it neither
sends feedback nor authorizes data to leave a vault.
