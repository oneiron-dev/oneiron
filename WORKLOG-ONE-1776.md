# WORKLOG — ONE-1776 [CA-05] send hygiene

Worktree: `/Volumes/Cinema/w5-lt/ca-1773` · branch `ONE-1776` off `origin/main` 30bd4d020.
Blueprint: `/Users/olety/.claude-wave5/blueprints/CA/ONE-1776.md`.

## Packet — exact, no amendments

CREATE
- `crates/oneiron/src/campaign/send_hygiene.rs`
- `crates/oneiron/tests/campaign_send_hygiene_oracle.rs`

MODIFY
- `crates/oneiron/src/campaign.rs` (expose the submodule)
- `crates/oneiron/src/campaign/claims.rs` (writer order 1772 -> 1776)
- `crates/oneiron/src/identity_reputation.rs`
- `crates/oneiron/src/outbound.rs` (collision order 1868 -> 1776; 1868 merged)
- `crates/oneiron/src/outbound_chokepoint.rs`

`git diff --name-only HEAD~1` is exactly those seven paths plus this worklog.
No `registry.rs`, no entity/type byte, no `comm.rs`, no `attempt_queue.rs`, no
`receipt.rs`, no `gate.rs`, no `counterparty_contact.rs`, no `Cargo.toml`, no
sequencer / recurrence / retry primitive.

`Cargo.lock` was ALREADY dirty in the worktree on arrival; it was never staged
and is not in any commit.

**PACKET_AMEND candidates: none.**

## Gates

- `cargo fmt --all` clean.
- `cargo clippy -p oneiron --all-features --all-targets` clean (zero warnings).
- `cargo check --workspace --all-features` clean.
- `cargo test -p oneiron --all-features`: **3862 lib + every integration binary
  green, 0 failed** (including `identity_reputation`, `outbound`,
  `outbound_intent_ledger`, `campaign_*`, `counterparty_opt_out_shipping_paths_oracle`).
- `cargo test -p oneiron --test campaign_send_hygiene_oracle`: 11 passed.

## Done-means checklist

| Blueprint bullet | Test |
|---|---|
| oracle exists and passes | `campaign_send_hygiene_oracle` — 11 tests |
| `hard_bounce_writes_bounce_and_suppression_same_turn` | present |
| `soft_bounce_updates_health_without_permanent_suppression` | present |
| `unsubscribe_is_honored_before_handler_returns` | present |
| `campaign_email_payload_contains_rfc8058_headers` | present |
| `retry_reuses_identical_unsubscribe_headers` | present |
| `sender_health_uses_existing_boundary_constants` | present |
| `degraded_identity_clamps_and_rest_reenters_warmup` | present |
| `sticky_sender_is_reused_for_followups` | present |
| `dead_sticky_sender_requires_visible_restart` | present |
| existing identity-reputation + outbound/gate suites | green |
| no registry/byte/comm/attempt_queue/sequencer in the diff | verified |

## Blueprint deviations — every one declared

### D-1 · signature: `store: &Store` -> `vault: &Vault`
`apply_suppression_in_txn` and `bind_sticky_sender_in_txn` take `&Vault`, not
`&Store`. `Store` cannot write a validated CLAIM or a supersession edge —
`put_claim_in_txn` and `supersede_claim_in_txn` are `Vault` methods. CA-01's own
`supersede_crm_stage_in_txn` takes `&Vault` for exactly this reason. The
skeleton is declared "compilable-shaped, not full impls"; every type, name, and
field is otherwise verbatim.

### D-2 · same, for `project_campaign_email_webhook_in_txn`
It calls the suppression door, so it needs the same handle.

### D-3 · addition: public self-transaction doors
The skeleton's three write functions are `pub(crate)`, but
`tests/campaign_send_hygiene_oracle.rs` is an INTEGRATION binary and sees only
`pub` items. Added `apply_suppression`, `bind_sticky_sender`, and
`project_campaign_email_webhook` — the crate's standard public/`_in_txn` pair
(`put_claim`/`put_claim_in_txn`, `supersede_claim`/`supersede_claim_in_txn`).
No new semantics: each opens one write txn, calls the `_in_txn` form, commits.

### D-4 · additions to the CA-01-owned `campaign/claims.rs`
Inside the ratified `1772 -> 1776` writer order, and required by the
"constants/codecs/validators stay there — import, never redefine" law:
- `encode_do_not_contact_value`, `encode_comm_bounce_value` — the write halves
  of two codecs that shipped with decode halves only. Without them the
  suppression writer would re-spell CA-01's private MessagePack key literals.
- `normalize_campaign_pack_token` — `pub` wrapper over the private
  `normalize_token`, so a writer normalizes through the same rule the validator
  enforces.
- `live_campaign_member_head_in_txn`, `identical_live_head_in_txn` —
  `pub(crate)` store-aware head lookups. The first is the membership
  counterpart of the existing `other_live_crm_stage_heads_in_txn`; the second is
  the redelivery door (see D-12).

### D-5 · interpretation: a soft bounce writes NO `comm.bounce` claim
Blueprint text: "A soft bounce changes health statistics only". Read strictly —
only reputation counters and the clamp move; no claim of any predicate is
written. `BounceKind::Soft` stays available in the CA-01 family for a future
writer; CA-05 never emits it, and `SuppressionCause` is a closed two-variant
enum so a soft bounce cannot reach the suppression door at all.
**Screen note:** if the ratified intent was "record the soft-bounce FACT, just
never suppress", that is a one-line addition — but it needs a non-suppressing
cause variant, which the current enum deliberately refuses.

### D-6 · interpretation: `campaign_ref: None` runs no membership leg
`SuppressionReceipt.member_claim_ref` is a singular `Option<EntityId>`
(content-ratified), so the shape cannot fan out across every campaign a person
belongs to. When the inbound signal names no campaign, only
`comm.do_not_contact` is written — which is campaign-independent by
construction and is the claim the external-effect gate actually reads, so the
send is refused everywhere regardless. Asserted in
`unsubscribe_is_honored_before_handler_returns`.

### D-7 · interpretation: two live member heads for one `(person, campaign)` is an ERROR
`live_campaign_member_head_in_txn` rejects rather than merging, mirroring the
ratified `crm.stage` head law ("first head is not the only head"). Choosing one
of two heads would silently discard the other's derivation. This is also what
makes the atomicity test possible (D-11).

### D-8 · mechanism: List-Unsubscribe rides the FROZEN outbound payload
The blueprint's `inject_campaign_email_hygiene_headers(channel, headers,
unsubscribe)` presumes a header map at payload assembly. **No such map exists at
HEAD**: `outbound.rs` freezes `serde_json::to_vec(&request.intent)` and
`outbound_chokepoint.rs` sees opaque bytes. Implemented, verbatim signature
kept, as:
- `outbound.rs` derives the headers ONCE at payload assembly (before the gate,
  long before any connector) and freezes them into the payload under
  `hygiene_headers`, elided when empty;
- `outbound_chokepoint.rs::frozen_call_hygiene_headers` reads them back at the
  last in-process boundary before `transport.send`;
- `OutboundExecutionRequest` gains `hygiene_headers` so the connector is handed
  exactly the frozen set and cannot invent a different target per attempt.

This is what makes retries byte-identical rather than merely equivalent. It also
makes `retry_reuses_identical_unsubscribe_headers` a stronger test than it
looks: the chokepoint's `validate_new_replay` REJECTS a replay whose payload
bytes differ, so the replay being accepted at all proves the derivation is
deterministic down to the byte.

New public surface, both on claimed files: `OutboundDispatchRequest.campaign_unsubscribe`
(+ builder) and `OutboundExecutionRequest.hygiene_headers`. The only in-repo
construction site of `OutboundExecutionRequest` is `DispatchChokepointTransport`.

### D-9 · addition: `EMAIL_CHANNEL` and `HYGIENE_HEADERS_PAYLOAD_FIELD`
The sketch compares `channel != "email"` inline. The value is verbatim; it is
named once so the payload-assembly caller and the header injector cannot drift.
`inject_campaign_email_hygiene_headers` takes an ALREADY-NORMALIZED channel —
the caller in `outbound.rs` holds the connector-class spelling and normalizes
with the existing `normalize_key`, so no second normalization rule is minted.

### D-10 · interpretation: the projector does not persist reputation claims
`SenderHealthProjection` carries no claim refs, in deliberate contrast to
`SuppressionReceipt`, which does. `claim_bodies` and `clamp_send_rate` have
always been pure producers whose callers own persistence; writing them from the
projector would make it a second authority deciding when reputation claims land.
The projection returns them; the caller persists. The `wtxn` exists for the
suppression leg.

### D-11 · two tests beyond the named list
- `hard_bounce_suppression_rolls_back_whole` — the "same write turn" half of leg
  1, measured the only way it can be: make the LAST leg fail (a torn cohort) and
  prove the bounce fact and the suppression are not on disk. Three separate
  transactions would have left the person permanently suppressed by a write turn
  that reported failure.
- `unsubscribe_headers_are_deterministic_and_framed` — repeat-determinism, the
  mailto-optional shape, and refusal of targets carrying `<`, `>`, `,`,
  whitespace, CRLF, or a non-HTTPS scheme.

### D-12 · addition: redelivery is idempotent
Provider webhooks and unsubscribe callbacks redeliver. A leg whose exact fact is
already live reuses that head instead of appending a second, so
`SuppressionReceipt` is stable across replays and suppression heads do not grow
without bound. Equality is on the ENCODED value, i.e. the same identity test the
decoder enforces — not a hand-written field comparison that can drift.

## Notes for the screen

- `Complaint` and `Delivered` dispositions move health only; only `HardBounce`
  suppresses. Asserted in `degraded_identity_clamps_and_rest_reenters_warmup`.
- The four sender-health thresholds are unchanged in VALUE; only their
  visibility was raised to `pub`, exactly as the blueprint specifies. The oracle
  pins all four literals plus the five boundary cases, including
  `complaint = 0.003` staying constrained (the ARCH-0059 bench maps onto the
  existing tier; no fifth constant).
- Suppression preserves the member row's channel basis, sticky `sender_ref`, and
  CA-01 derivation `{source_query, evidence_hash, epoch}` — asserted by
  comparing against `encode_campaign_member_value` of the expected struct, so a
  CA-01 schema change breaks the codec's tests rather than this file's guesses.
- Sticky sender binds a channel row onto an EXISTING `campaign.member` head and
  never mints membership (CA-03's door); a missing head is `EntityNotFound`.
