# Ordinary outbound connector approvals

A keyed ordinary dispatch with a frozen communication, calendar or feedback
HTTP-bundle target, a native Linear target (including a verified mirrored
TASK mutation), or a native campaign leg observes the owner's current `always ask` setting on replay. Common and Linear
calls keep their live and hostless replay paths. Campaign sends keep the
existing enrollment driver; this adds no hostless campaign recovery worker.
`never allow` keeps its existing terminal behavior. Other ordinary payload
families remain on their existing path; this is not whole FIX 990 completion.

## Review and release

The held result carries the Gate's `approval_digest` and the actual admitting
actor when that admission named one. For an actual actor, the ordinary replay
also queues a normal owner decision ask. Its structured state contains only
`intent_id`, `server`, `tool` and `approval_digest`, not the frozen request body.
The question text carries those machine identifiers; hosts render their own
localized words. Repeated sweeps reuse the same question. Answering a question
creates no standing grant and does not send the request.

The existing owner SDK verb `vault.consent.approve_once` accepts the emitted
effect digest. Native hosts can use the more specific
`Vault::approve_outbound_intent_once(owner, intent_id, approval_digest)` to
revalidate the owner, current Pending row, frozen target and current `always
ask` setting in the marker's writer. A stale or stopped target is not approved.
The next normal retry or recovery pass consumes the exact marker and keeps its
proof beside the same ledger row. No new external verb is required.

A bare admission honestly names no actor. It still returns its exact approval
digest and accepts the authenticated owner's native release, but it does not
invent a principal to put in the decision-ask queue.

## Frozen identity and retries

The common dispatcher now retains the already selected logical send reference
in its existing `approval_send_ref` field for these targets. Its selection is
unchanged: ordinary sends keep their original intent reference; e-sign and
failure-signal sends keep their existing stable-reference rule. Recomposition
uses the actual frozen actor, sender, thread, content, calendar payload and
brief. The stored admission envelope must name that same actor. The charged
connector key selects the tool setting; it never supplies the actor.

A new typed `ConnectorSlate` kept-proof family is used only for these ordinary
targets. Its target pin is the original pin, unchanged. First-admission spend,
Pending insertion and retention of that family's proof share one writer.
Send-boundary spend and proof retention also share one writer. A live retry
reuses the proof only for the same ledger intent, frozen request and actor,
and the same target recomposed by the current Gate. It does not spend again.

Native-mail, e-sign, failure-signal and scoped-MCP proof paths are retained.
Linear mirrors retain their native two-principal proof family and checks. Campaign legs retain their native family and target.
Keyless and no-slate defaults, issuer
holds, charters, current policy and permissions, budget accounting, retry permits, idempotency,
delivery certainty and transport outcomes remain in their existing paths.
There is no new table, ledger schema, standing grant, timeout, numeric limit,
configuration default, migration or old-format reader.

## Ordinary Linear sends

The common dispatcher freezes `linear_approval_send_ref` only for a normalized
Linear request whose native `linear_mirror` is absent. It carries the stable
reference that the Linear target already selected: the approval identity,
otherwise the ledger identity, otherwise the intent reference. Its presence
also identifies this as a non-mirror request; absence of mirror fields in a
stored payload alone is not enough to reconstruct that target.

Recomposition keeps the existing `LinearDispatch` proof family and target pin.
It binds the canonical verb, original target, content reference, stable send
reference and digest of the entire frozen payload, with `mirror: None`.
It uses the same owner question, authenticated native release and exact retry
proof checks described above. First-admission spend, Pending insertion and
retention of this normal Linear proof share one writer; the old post-commit
retention path does not run for that same proof. A retry spends no second tap.

Mirrored requests use their separate original native request metadata, not
`linear_approval_send_ref`. Both existing policy-risk values are preserved;
non-mirror is not a new risk classification or permission. There is no new
proof family or numeric tag.

## Native mirrored Linear sends

The frozen payload retains the original operation ID, TASK, scheduler, issue,
mutation kind, full fields and logical send reference. These are request data,
not either actor's authority. Recomposition checks the original stored ledger
actor and full payload, then previews the already bound native operation without
writing a binding or spending a press. It never replaces the original request
with today's TASK fields or guesses its writer class.

At an `always ask` send boundary, one writer validates the original operation
against the current TASK revision, dirty state, link, verified writer and both
actors' liveness. It runs the existing current-policy pair for scheduler and
writer, without charging the original mutation's budgets again. A held pair
spends neither actor's unadmitted tap. Both pending actor/digest questions are
queued separately; the single result uses the native scheduler-first selection.
The specific intent approval door still releases only its scheduler's exact
ask. The writer's independent digest uses the existing authenticated
`vault.consent.approve_once` door. One answer never approves both principals.

The first send also carries the actual co-actor input and press from its own
committed admission. Only that exact input and digest can reuse the co-actor's
press at the current pair check; neither the payload nor a primary press can
supply it. The original best-effort post-commit keeper contract stays intact:
a failed keeper does not cancel the already admitted first send. Later replay
uses only the native kept proofs and current checks. New boundary taps and both
of their native proof writes share the same writer and commit only on joint
Allow. These checks are last-observed state, not network-atomic authorization.

The stored payload envelope is current-only version 3. It also names the native
admission's verified co-actor and copied TASK source. Their erase uses the same
full payload wipe, custody-key retirement, remote-handle removal and budget
settlement as the existing actor/recipient erase. A source erase reports the
existing binding-invalid outcome; no new erase authority, table, migration or
old-format reader is added. No whole-vault privacy or runtime proof is implied.
Unsupported mirror payloads retain their old path; this is not full FIX 990.

## Native campaign legs

The native transport envelope retains the actual query, member, epoch,
campaign, program, step, body digest and sender beside its transport fields.
The strict sender decoder and replay recomposer share this current-only shape;
there is no old-envelope reader. The Gate actor is the sender. The transport's
actor field names the event owner and is not substituted for the sender.
The raw ledger admission must name the same sender as the reconstructed Gate.

Recomposition keeps the original `CampaignLeg` family, consequence identity,
call sequence and target pin. A live retry must match the current prepared
actor and target digest, the entire frozen request and the proof kept for that
same intent. First-admission spend, Pending insertion and proof retention share
one writer. The old post-commit keeper does not keep that proof a second time.

The native driver's actual local-node ID travels only in live transport
context. It is never guessed from the designation, key or sender, and never
enters the frozen request, intent or approval digest. New admission, live retry
and send-boundary press spending check native home, lifecycle, membership and
exact filed body in their writer. The final pre-wire read is a last observed
snapshot, not an atomic lock with a remote provider. A home handoff returns the
existing lease-preserving driver outcome, not an attempt failure or a send.
Membership and body no-send results keep the driver's existing settlement.
Absent context in other transports creates no new unknown-node refusal.

Owner question inspection and authenticated approve-once release do not require
the owner to be on the designated home node. The send writer rereads the current
Pending row and reconstructs the candidate before spending and keeping a tap.
A settled row returns its actual current state; a missing row is not reported as
a stale Pending ask. The same native owner question and approve-once doors serve
this family. No new queue, grant, table, public verb, timer or default is added.
