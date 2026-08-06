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
//!    [`SuppressionCause::Unsubscribe`]. No grace period, no deferred cleanup
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

use std::collections::BTreeMap;

use rmpv::Value;

use crate::Vault;
use crate::campaign::claims::{
    BounceKind, CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, CommBounceValue,
    CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_CAMPAIGN_MEMBER,
    PREDICATE_COMM_BOUNCE, PREDICATE_COMM_DO_NOT_CONTACT, encode_campaign_member_value,
    encode_comm_bounce_value, encode_do_not_contact_value, identical_live_head_in_txn,
    live_campaign_member_head_in_txn, normalize_campaign_pack_token,
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

/// Why a suppression is being written.
///
/// Closed on purpose: these are the two facts that permanently stop contact. A
/// soft bounce, a complaint, and a delivery are health signals and have no
/// variant here, because giving them one would make "does this suppress?" a
/// property of the call site rather than of the cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionCause {
    /// A permanent delivery failure observed by the sending identity.
    HardBounce,
    /// The counterparty asked to stop.
    Unsubscribe,
}

/// Everything one suppression write turn needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionInput {
    /// PERSON being suppressed.
    pub person_ref: EntityId,
    /// Campaign whose membership is superseded.
    ///
    /// Absent for an inbound signal that names no campaign. The enforcement
    /// claim still lands: `comm.do_not_contact` carries no campaign field by
    /// construction, so a suppression can never be scoped away by moving the
    /// person to another campaign.
    pub campaign_ref: Option<EntityId>,
    /// Channel the suppression is scoped to; normalized here.
    pub channel: String,
    /// Sending identity that observed the failure. Required for
    /// [`SuppressionCause::HardBounce`], which is a fact ABOUT a sender.
    pub sender_ref: Option<EntityId>,
    /// The persisted inbound evidence this suppression derives from.
    pub evidence_ref: EntityId,
    /// When the suppressing event occurred.
    pub occurred_at: u64,
}

/// What one suppression write turn landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionReceipt {
    /// The `comm.bounce` head, for [`SuppressionCause::HardBounce`] only.
    pub bounce_claim_ref: Option<EntityId>,
    /// The `comm.do_not_contact` head. Always present — this is the claim the
    /// external-effect gate reads.
    pub do_not_contact_claim_ref: EntityId,
    /// The replacement `campaign.member` head, when a membership matched.
    pub member_claim_ref: Option<EntityId>,
}

/// Suppresses one person on one channel, atomically.
///
/// The public door: it opens ONE write transaction, runs
/// [`apply_suppression_in_txn`], and commits. An inbound unsubscribe handler
/// that persists its evidence first calls the `_in_txn` form with its own
/// transaction so evidence and suppression commit together; a handler with
/// nothing else to write calls this.
///
/// # Errors
///
/// See [`apply_suppression_in_txn`]; storage errors propagate.
pub fn apply_suppression(
    vault: &Vault,
    cause: SuppressionCause,
    input: &SuppressionInput,
) -> Result<SuppressionReceipt> {
    vault.with_write_txn(|wtxn| apply_suppression_in_txn(vault, wtxn, cause, input))
}

/// Writes one suppression's restrictive claims into the CALLER's transaction.
///
/// [`SuppressionCause::HardBounce`] writes `comm.bounce` first; both causes
/// write `comm.do_not_contact` and, when the input names a campaign, supersede
/// that `campaign.member` head to `state = suppressed` while preserving its
/// channel rows and any CA-01 derivation `{ source_query, evidence_hash, epoch }`.
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
/// [`Error::InvalidClaimBody`] when a hard bounce names no sender, when the
/// channel token is not storable, or when the person carries more than one live
/// `campaign.member` head for the campaign. Claim-validation and storage errors
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
    let member_claim_ref = match input.campaign_ref {
        Some(campaign_ref) => suppress_membership_in_txn(vault, wtxn, input, campaign_ref)?,
        None => None,
    };
    Ok(SuppressionReceipt {
        bounce_claim_ref,
        do_not_contact_claim_ref,
        member_claim_ref,
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

/// Supersedes the matching `campaign.member` head to `suppressed`.
///
/// The replacement is built from the head it replaces, so the channel rows
/// (each with its consent basis and sticky sender) and any derivation survive
/// the transition — suppression removes a person from a cohort, it does not
/// erase how they got there or what authorized the contact.
fn suppress_membership_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: &SuppressionInput,
    campaign_ref: EntityId,
) -> Result<Option<EntityId>> {
    let Some((old_id, old_value)) =
        live_campaign_member_head_in_txn(&vault.store, wtxn, input.person_ref, campaign_ref)?
    else {
        return Ok(None);
    };
    if old_value.state == CampaignMemberState::Suppressed {
        return Ok(Some(old_id));
    }
    let suppressed = CampaignMemberValue {
        state: CampaignMemberState::Suppressed,
        ..old_value
    };
    let new_id = replace_member_head_in_txn(
        vault,
        wtxn,
        MemberHeadReplacement {
            person_ref: input.person_ref,
            value: &suppressed,
            evidence_ref: input.evidence_ref,
            occurred: input.occurred_at,
            old_id,
        },
    )?;
    Ok(Some(new_id))
}

/// One replacement of a live `campaign.member` head.
struct MemberHeadReplacement<'a> {
    person_ref: EntityId,
    value: &'a CampaignMemberValue,
    evidence_ref: EntityId,
    occurred: u64,
    old_id: EntityId,
}

/// Writes a replacement `campaign.member` head and supersedes the old head with
/// it in the same txn, so a rejected supersession rolls the replacement back
/// with it rather than leaving two live memberships.
fn replace_member_head_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    replacement: MemberHeadReplacement<'_>,
) -> Result<EntityId> {
    let new_id = EntityId::now();
    let mut body = ClaimBody::new(
        PREDICATE_CAMPAIGN_MEMBER,
        ClaimSubject::Entity(replacement.person_ref),
        encode_campaign_member_value(replacement.value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.evidence = Some(evidence_value(replacement.evidence_ref));
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
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(input.person_ref),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
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

/// RFC 2369 unsubscribe header name.
pub const LIST_UNSUBSCRIBE: &str = "List-Unsubscribe";
/// RFC 8058 one-click header name.
pub const LIST_UNSUBSCRIBE_POST: &str = "List-Unsubscribe-Post";
/// The one RFC 8058 one-click header value.
pub const LIST_UNSUBSCRIBE_POST_ONE_CLICK: &str = "List-Unsubscribe=One-Click";

/// The only channel these headers exist for.
pub const EMAIL_CHANNEL: &str = "email";

/// Field the frozen outbound payload carries hygiene headers under.
///
/// Public because it is wire shape: the frozen bytes are the retry contract, and
/// a connector adapter reading them back needs the same name the writer used.
pub const HYGIENE_HEADERS_PAYLOAD_FIELD: &str = "hygiene_headers";

/// Upper bound for one unsubscribe URI.
const MAX_UNSUBSCRIBE_URI_BYTES: usize = 998;

/// Where an unsubscribe lands, frozen with the send it belongs to.
///
/// The HTTPS one-click target is mandatory and the mailto is optional, which is
/// exactly RFC 8058's shape: one-click needs an HTTPS endpoint, and a mailto
/// alone cannot satisfy it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListUnsubscribeTarget {
    /// Optional RFC 2369 mailto target.
    pub mailto_uri: Option<String>,
    /// Mandatory RFC 8058 one-click HTTPS target.
    pub https_one_click_uri: String,
}

/// Builds the deterministic unsubscribe headers for one frozen target.
///
/// Determinism is the contract, not a nicety: the same frozen intent must
/// produce byte-identical header names, values, and ordering on every retry, or
/// a mailbox provider sees two different unsubscribe surfaces for one message.
/// Two things pin it — a [`BTreeMap`] fixes header ordering, and the URI list
/// order is fixed as HTTPS-then-mailto rather than following the input.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when a URI carries the wrong scheme, is empty past
/// its scheme, exceeds [`MAX_UNSUBSCRIBE_URI_BYTES`], or contains a character
/// that would break header framing.
pub fn list_unsubscribe_headers(
    target: &ListUnsubscribeTarget,
) -> Result<BTreeMap<String, String>> {
    validate_unsubscribe_uri(&target.https_one_click_uri, "https://")?;
    let mut value = format!("<{}>", target.https_one_click_uri);
    if let Some(mailto_uri) = &target.mailto_uri {
        validate_unsubscribe_uri(mailto_uri, "mailto:")?;
        value.push_str(", <");
        value.push_str(mailto_uri);
        value.push('>');
    }
    Ok(BTreeMap::from([
        (LIST_UNSUBSCRIBE.to_owned(), value),
        (
            LIST_UNSUBSCRIBE_POST.to_owned(),
            LIST_UNSUBSCRIBE_POST_ONE_CLICK.to_owned(),
        ),
    ]))
}

/// Folds the unsubscribe headers into an email payload's header map.
///
/// A small pre-send transformation, deliberately: it is not a transport layer,
/// it never invents a target, and a non-email channel or a send with no frozen
/// target passes through untouched.
///
/// `channel` is expected already normalized; the caller owns normalization
/// because it already holds the connector-class spelling.
///
/// # Errors
///
/// Propagates [`list_unsubscribe_headers`].
pub(crate) fn inject_campaign_email_hygiene_headers(
    channel: &str,
    headers: &mut BTreeMap<String, String>,
    unsubscribe: Option<&ListUnsubscribeTarget>,
) -> Result<()> {
    if channel != EMAIL_CHANNEL {
        return Ok(());
    }
    let Some(target) = unsubscribe else {
        return Ok(());
    };
    headers.extend(list_unsubscribe_headers(target)?);
    Ok(())
}

/// Reads hygiene headers back out of a frozen outbound payload.
///
/// Tolerant by construction: most frozen payloads are opaque connector bytes
/// that were never JSON and carry no hygiene headers at all. Only a payload that
/// DOES carry the field and carries it malformed is an error — a send whose
/// unsubscribe header cannot be reproduced from the frozen bytes must not reach
/// the wire under a header the ledger cannot vouch for.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the field is present but is not a flat map of
/// strings.
pub(crate) fn frozen_payload_hygiene_headers(payload: &[u8]) -> Result<BTreeMap<String, String>> {
    let Ok(serde_json::Value::Object(fields)) =
        serde_json::from_slice::<serde_json::Value>(payload)
    else {
        return Ok(BTreeMap::new());
    };
    let Some(headers) = fields.get(HYGIENE_HEADERS_PAYLOAD_FIELD) else {
        return Ok(BTreeMap::new());
    };
    let serde_json::Value::Object(headers) = headers else {
        return Err(invalid_payload("outbound hygiene headers must be a map"));
    };
    headers
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_owned()))
                .ok_or_else(|| invalid_payload("outbound hygiene header value must be a string"))
        })
        .collect()
}

/// Rejects a URI that carries the wrong scheme, is empty past it, is too long,
/// or would break header framing.
fn validate_unsubscribe_uri(uri: &str, scheme: &str) -> Result<()> {
    if !uri.starts_with(scheme) || uri.len() == scheme.len() {
        return Err(invalid_payload("unsubscribe URI scheme is invalid"));
    }
    if uri.len() > MAX_UNSUBSCRIBE_URI_BYTES {
        return Err(invalid_payload("unsubscribe URI is too long"));
    }
    // `<`, `>`, and `,` frame the RFC 2369 list; whitespace and controls fold
    // the header. Any of them would let a target rewrite the header around it.
    if uri
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '<' | '>' | ','))
    {
        return Err(invalid_payload(
            "unsubscribe URI contains a framing character",
        ));
    }
    Ok(())
}

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
/// The public door; see [`bind_sticky_sender_in_txn`] for the contract.
///
/// # Errors
///
/// See [`bind_sticky_sender_in_txn`].
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
    vault.with_write_txn(|wtxn| {
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
            person_ref,
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

fn invalid_payload(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
