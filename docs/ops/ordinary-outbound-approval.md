# Ordinary outbound connector approvals

A keyed ordinary dispatch with a frozen communication, calendar or feedback
HTTP-bundle target, or a native non-mirror Linear target, now observes the
owner's current `always ask` setting on both a live retry and a hostless replay. `never allow` keeps its existing
terminal behavior. Other ordinary payload families remain on their existing
path; this is not whole FIX 990 completion.

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

Native-mail, e-sign, failure-signal, mirror-present Linear, campaign and
scoped-MCP proof paths are retained. Keyless and no-slate defaults, issuer
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

Mirror-present requests freeze no new reference and remain in their existing
path. Both existing policy-risk values are preserved; non-mirror is not a new
risk classification or permission. There is no new proof family or numeric tag.
