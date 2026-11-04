//! CA-05 send hygiene: suppression, unsubscribe headers, and sticky senders.
//!
//! Four ratified legs live here, and nothing else. There is no sequencer, no
//! retry primitive, no new entity kind, and no second reputation model:
//!
//! 1. **Hard bounce → suppression in ONE write turn.** A hard bounce writes the
//!    evidence-linked `comm.bounce` fact, the channel-scoped enforcement
//!    suppression `comm.do_not_contact`, and supersedes any matching
//!    `campaign.member` head to `state = suppressed` — all inside the caller's
//!    transaction. A SOFT bounce never reaches this module's suppression door:
//!    it moves health statistics only.
//! 2. **Deterministic `List-Unsubscribe` / RFC 8058 `List-Unsubscribe-Post`.**
//!    Derived from frozen send metadata and folded into the frozen outbound
//!    payload, so a replayed intent reproduces byte-identical headers from the
//!    bytes the ledger already holds rather than re-deriving them.
//! 3. **Immediate unsubscribe honor.** The same one-transaction door, with
//!    `SuppressionCause::Unsubscribe`. No grace period, no deferred cleanup
//!    job, no projector to wait for.
//! 4. **Sticky sender.** First touch on a member-channel binds the proposed
//!    identity into `campaign.member.channels[].sender_ref`; later touches reuse
//!    it. A dead mailbox returns a human-visible restart, never a silent
//!    rotation.
//!
//! Ownership is deliberately thin. Every predicate constant, value codec, and
//! exact-predicate validator this module writes through belongs to
//! [`crate::campaign::claims`] (CA-01) and is IMPORTED, never re-spelled. Sender
//! health belongs to [`crate::identity_reputation`] (OF-347): its thresholds,
//! warm-up stages, and send-rate clamp are the live dial, and this module wires
//! the campaign webhook into that existing flow instead of growing a parallel
//! one. `comm.rs` is SPINE-COMM's projector hot zone and is never edited — the
//! states-only/restrictive claim-write shape is mirrored, not moved.

use rmpv::Value;

use crate::Vault;
use crate::campaign::claims::{
    BounceKind, CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, CommBounceValue,
    CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_BOUNCE,
    PREDICATE_COMM_DO_NOT_CONTACT, encode_comm_bounce_value, encode_do_not_contact_value,
    identical_live_head_in_txn, live_campaign_member_head_in_txn,
    live_campaign_member_heads_in_txn, member_replacement_body, normalize_campaign_pack_token,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

// ---------------------------------------------------------------------------
// Suppression
// ---------------------------------------------------------------------------

pub use crate::write_envelope::cohort_claims::suppression::{
    SuppressionCause, SuppressionInput, SuppressionReceipt,
};

/// Suppresses one person on one channel, atomically.
///
/// The public door: it opens ONE write transaction, runs
/// `apply_suppression_in_txn`, and commits. An inbound unsubscribe handler
/// that persists its evidence first calls the `_in_txn` form with its own
/// transaction so evidence and suppression commit together; a handler with
/// nothing else to write calls this.
///
/// # Errors
///
/// See `apply_suppression_in_txn`; storage errors propagate.
pub fn apply_suppression(
    vault: &Vault,
    cause: SuppressionCause,
    input: &SuppressionInput,
) -> Result<SuppressionReceipt> {
    vault.with_write_txn_grouped(|wtxn| apply_suppression_in_txn(vault, wtxn, cause, input))
}

/// Writes one suppression's restrictive claims into the CALLER's transaction.
///
/// [`SuppressionCause::HardBounce`] writes `comm.bounce` first; both causes
/// write `comm.do_not_contact` and, when the input names a campaign, supersede
/// each live `campaign.member` head for it to `state = suppressed` while
/// preserving its channel rows and any CA-01 derivation
/// `{ source_query, evidence_hash, epoch }`.
///
/// One transaction is the whole point. A suppression that commits its evidence
/// and loses its enforcement claim is a send that goes out after the person
/// asked it to stop, so every leg below commits with the caller's txn or rolls
/// back with it. There is no grace period, no deferred cleanup job, and no
/// projector to wait for: the moment this returns, the gate refuses.
///
/// Redelivery-safe. Provider webhooks and unsubscribe callbacks redeliver, so a
/// leg whose exact fact is already live reuses that head instead of appending a
/// second one; the receipt is therefore stable across replays.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when a hard bounce names no sender or when the
/// channel token is not storable. Claim-validation and storage errors
/// propagate.
pub(crate) fn apply_suppression_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    cause: SuppressionCause,
    input: &SuppressionInput,
) -> Result<SuppressionReceipt> {
    let channel = storable_channel(&input.channel)?;
    let bounce_claim_ref = match cause {
        SuppressionCause::HardBounce => Some(write_hard_bounce_in_txn(
            vault,
            wtxn,
            input,
            channel.clone(),
        )?),
        SuppressionCause::Unsubscribe => None,
    };
    let do_not_contact_claim_ref = put_hygiene_claim_in_txn(
        vault,
        wtxn,
        PREDICATE_COMM_DO_NOT_CONTACT,
        input,
        encode_do_not_contact_value(&CommDoNotContactValue {
            channel: Some(channel),
            scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
        }),
    )?;
    let member_claim_refs = match input.campaign_ref {
        Some(campaign_ref) => suppress_membership_in_txn(vault, wtxn, input, campaign_ref)?,
        None => Vec::new(),
    };
    Ok(SuppressionReceipt {
        bounce_claim_ref,
        do_not_contact_claim_ref,
        member_claim_refs,
    })
}

/// The `comm.bounce` leg. A bounce is a fact about a SENDER, so a hard bounce
/// with no sending identity is not recordable and is rejected before anything
/// is written.
fn write_hard_bounce_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: &SuppressionInput,
    channel: String,
) -> Result<EntityId> {
    let sender_ref = input.sender_ref.ok_or(Error::InvalidClaimBody(
        "hard bounce suppression requires the observing sender identity",
    ))?;
    put_hygiene_claim_in_txn(
        vault,
        wtxn,
        PREDICATE_COMM_BOUNCE,
        input,
        encode_comm_bounce_value(&CommBounceValue {
            channel,
            bounce: BounceKind::Hard,
            sender_ref,
            occurred_at: input.occurred_at,
        }),
    )
}

/// Supersedes every live `campaign.member` head for the campaign to
/// `suppressed`.
///
/// Each replacement is built from the head it replaces, so the channel rows
/// (each with its consent basis and sticky sender) and any derivation survive
/// the transition — suppression removes a person from a cohort, it does not
/// erase how they got there or what authorized the contact. Two live heads are
/// a torn cohort, but a restriction need not pick between them: each is
/// suppressed on its own, so the tear can never veto the do-not-contact claim
/// this turn already wrote (F06 H195).
fn suppress_membership_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: &SuppressionInput,
    campaign_ref: EntityId,
) -> Result<Vec<EntityId>> {
    let heads =
        live_campaign_member_heads_in_txn(&vault.store, wtxn, input.person_ref, campaign_ref)?;
    let mut suppressed_ids = Vec::with_capacity(heads.len());
    for (old_id, old_value) in heads {
        if old_value.state == CampaignMemberState::Suppressed {
            suppressed_ids.push(old_id);
            continue;
        }
        let suppressed = CampaignMemberValue {
            state: CampaignMemberState::Suppressed,
            ..old_value
        };
        suppressed_ids.push(replace_member_head_in_txn(
            vault,
            wtxn,
            MemberHeadReplacement {
                value: &suppressed,
                evidence_ref: input.evidence_ref,
                occurred: input.occurred_at,
                old_id,
            },
        )?);
    }
    // Ordered by the heads' own ids, so a redelivery that reuses them returns
    // the same receipt.
    suppressed_ids.sort_unstable();
    Ok(suppressed_ids)
}

/// One replacement of a live `campaign.member` head.
struct MemberHeadReplacement<'a> {
    value: &'a CampaignMemberValue,
    evidence_ref: EntityId,
    occurred: u64,
    old_id: EntityId,
}

/// Writes a replacement `campaign.member` head and supersedes the old head with
/// it in the same txn, so a rejected supersession rolls the replacement back
/// with it rather than leaving two live memberships.
///
/// The replacement is the predecessor's own body, read in this txn, with only
/// its value and evidence changed (FIX 9656): its world, relationship, facet,
/// project and approval stamps carry over, so a suppression or a sender binding
/// never widens who may read the membership.
fn replace_member_head_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    replacement: MemberHeadReplacement<'_>,
) -> Result<EntityId> {
    let old =
        vault
            .get_claim_in_txn(wtxn, &replacement.old_id)?
            .ok_or(Error::InvariantViolation(
                "a scanned campaign.member head is absent in its own txn",
            ))?;
    let new_id = vault.store.clock.entity_id()?;
    let body = member_replacement_body(&old, replacement.value, replacement.evidence_ref);
    vault.put_claim_in_txn(
        wtxn,
        &new_id,
        &body,
        occurred_at(replacement.occurred),
        replacement.occurred,
    )?;
    vault.supersede_claim_in_txn(wtxn, &new_id, &replacement.old_id, replacement.occurred)?;
    Ok(new_id)
}

/// Writes one evidence-linked hygiene claim, or returns the live head that
/// already carries exactly this fact.
fn put_hygiene_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    predicate: &str,
    input: &SuppressionInput,
    value: Value,
) -> Result<EntityId> {
    if let Some(existing) =
        identical_live_head_in_txn(&vault.store, wtxn, input.person_ref, predicate, &value)?
    {
        return Ok(existing);
    }
    let id = vault.store.clock.entity_id()?;
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(input.person_ref),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    body.evidence = Some(evidence_value(input.evidence_ref));
    vault.put_claim_in_txn(
        wtxn,
        &id,
        &body,
        occurred_at(input.occurred_at),
        input.occurred_at,
    )?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// List-Unsubscribe (RFC 2369 + RFC 8058)
// ---------------------------------------------------------------------------

pub use crate::outbound_intent_ledger::email_headers::EMAIL_CHANNEL;
pub use crate::outbound_intent_ledger::email_headers::HYGIENE_HEADERS_PAYLOAD_FIELD;
pub use crate::outbound_intent_ledger::email_headers::LIST_UNSUBSCRIBE;
pub use crate::outbound_intent_ledger::email_headers::LIST_UNSUBSCRIBE_POST;
pub use crate::outbound_intent_ledger::email_headers::LIST_UNSUBSCRIBE_POST_ONE_CLICK;
pub use crate::outbound_intent_ledger::email_headers::ListUnsubscribeTarget;
pub(crate) use crate::outbound_intent_ledger::email_headers::frozen_payload_hygiene_headers;
pub(crate) use crate::outbound_intent_ledger::email_headers::inject_campaign_email_hygiene_headers;
pub use crate::outbound_intent_ledger::email_headers::list_unsubscribe_headers;

// ---------------------------------------------------------------------------
// Sticky sender
// ---------------------------------------------------------------------------

/// What one sticky-sender binding attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StickySenderOutcome {
    /// First touch on this member-channel; the proposed identity is now stored.
    Bound {
        /// The identity that was bound.
        sender_ref: EntityId,
    },
    /// A live binding already existed and was reused.
    Reused {
        /// The stored identity.
        sender_ref: EntityId,
    },
    /// The stored identity is dead. Nothing was written.
    RestartRequired {
        /// The dead stored identity.
        previous_sender_ref: EntityId,
        /// The identity a rotation would have used.
        proposed_sender_ref: EntityId,
    },
}

/// Binds or reuses the sticky sender for one member-channel.
///
/// The public door; see `bind_sticky_sender_in_txn` for the contract.
///
/// # Errors
///
/// See `bind_sticky_sender_in_txn`.
#[expect(
    clippy::too_many_arguments,
    reason = "the member-channel coordinate, the proposal, and its liveness are each independent facts"
)]
pub fn bind_sticky_sender(
    vault: &Vault,
    person_ref: EntityId,
    campaign_ref: EntityId,
    channel: &str,
    proposed_sender_ref: EntityId,
    existing_sender_live: bool,
    basis_evidence: EntityId,
    occurred_at: u64,
) -> Result<StickySenderOutcome> {
    vault.with_write_txn_grouped(|wtxn| {
        bind_sticky_sender_in_txn(
            vault,
            wtxn,
            person_ref,
            campaign_ref,
            channel,
            proposed_sender_ref,
            existing_sender_live,
            basis_evidence,
            occurred_at,
        )
    })
}

/// Binds or reuses the sticky sender for one member-channel, inside the
/// caller's transaction.
///
/// Health-aware selection happens ONCE, at first assignment: the caller picks
/// the proposal. After that the stored `sender_ref` wins, because a campaign
/// that re-picks its "healthiest" sender on every touch presents a different
/// From address to the same person every time — which is the deliverability
/// problem sender health exists to avoid, not a fix for it.
///
/// So a live existing binding is always [`StickySenderOutcome::Reused`], even
/// when a healthier identity is proposed; and a DEAD existing binding is
/// [`StickySenderOutcome::RestartRequired`] with nothing written, because a
/// silent rotation is exactly the invisible identity change a human needs to
/// see and rule on.
///
/// Membership itself is CA-03's door. This binds a channel row onto an existing
/// `campaign.member` head; it never mints one.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the channel token is not storable or the
/// person carries more than one live head for the campaign;
/// [`Error::EntityNotFound`] when no live membership exists. Claim-validation
/// and storage errors propagate.
#[expect(
    clippy::too_many_arguments,
    reason = "the member-channel coordinate, the proposal, and its liveness are each independent facts"
)]
pub(crate) fn bind_sticky_sender_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    person_ref: EntityId,
    campaign_ref: EntityId,
    channel: &str,
    proposed_sender_ref: EntityId,
    existing_sender_live: bool,
    basis_evidence: EntityId,
    occurred_at: u64,
) -> Result<StickySenderOutcome> {
    let channel = storable_channel(channel)?;
    let (old_id, old_value) =
        live_campaign_member_head_in_txn(&vault.store, wtxn, person_ref, campaign_ref)?
            .ok_or(Error::EntityNotFound)?;

    if let Some(bound) = old_value.channels.iter().find(|row| row.channel == channel) {
        return Ok(if existing_sender_live {
            StickySenderOutcome::Reused {
                sender_ref: bound.sender_ref,
            }
        } else {
            StickySenderOutcome::RestartRequired {
                previous_sender_ref: bound.sender_ref,
                proposed_sender_ref,
            }
        });
    }

    let mut value = old_value;
    value.channels.push(CampaignMemberChannel {
        channel,
        basis_evidence,
        sender_ref: proposed_sender_ref,
    });
    replace_member_head_in_txn(
        vault,
        wtxn,
        MemberHeadReplacement {
            value: &value,
            evidence_ref: basis_evidence,
            occurred: occurred_at,
            old_id,
        },
    )?;
    Ok(StickySenderOutcome::Bound {
        sender_ref: proposed_sender_ref,
    })
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Normalizes a channel token through the CA-01 rule and rejects one that the
/// claim write door would refuse anyway, so a bad token fails at this door with
/// a reason naming the channel rather than deep inside claim validation.
fn storable_channel(channel: &str) -> Result<String> {
    let channel = normalize_campaign_pack_token(channel);
    if channel.is_empty() {
        return Err(Error::InvalidClaimBody(
            "send hygiene channel must not be empty",
        ));
    }
    Ok(channel)
}

/// Evidence is a reference list, matching the crate's claim-evidence shape.
fn evidence_value(evidence_ref: EntityId) -> Value {
    Value::Array(vec![Value::from(evidence_ref.to_hex())])
}

fn occurred_at(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

use crate::outbound_intent_ledger::email_headers::invalid_payload;
