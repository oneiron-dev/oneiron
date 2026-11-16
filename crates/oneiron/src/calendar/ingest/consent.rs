//! CAL-02 standing import consent for an installed ICS feed (ruling
//! CAL-02-FEED-CONSENT = A, Engine 12:04 Sun 15 Nov): one consent per
//! installed feed.
//!
//! * The first completed poll's imported claims become the feed's one
//!   review, and the feed polls no more until the owner decides it. The
//!   claims that poll's property continuations admit from its archived
//!   version join the same review.
//! * The owner approves or declines the review whole, with one consent
//!   receipt over the exact claim set; each claim settles in that same
//!   transaction.
//! * An approval is the feed's standing consent: every later poll's claims
//!   land Approved under it, settled as the owner, their source still
//!   `Imported`. A declined feed does not poll again.
//! * The standing consent never settles a claim whose body the inbound
//!   screen flagged (CAL-02-FLAGGED-UNDER-CONSENT = B, Engine 16:57 Mon 16
//!   Nov): it stays Proposed at the imported tier until the owner settles it
//!   (`vault.claims.settle`), and the feed's status counts it. The owner's
//!   own review decision covers every claim it names, flagged or not, and
//!   an indeterminate verdict settles like a clear one.
//! * A provider reset pauses the feed (`poll.rs`) and leaves the consent as
//!   it is.
//!
//! Each record binds the feed's configuration digest, so a feed installed
//! again under its system with another configuration starts with no consent.

use oneiron_contracts::fingerprint::{LegacyDigest, purposes};
use serde::{Deserialize, Serialize};

use super::IcsFeedPollConfig;
use super::admission::FLAGGED_VERDICT;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus};
use crate::consent::bundle_projection::GateConsentBundleAction;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ComposedEffect, EffectFacts,
    GrantBound,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::gate::RecordedClaimGateDecision;
use crate::memory::{MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

/// The consent action an owner's review decision is bound to.
const FEED_REVIEW_ACTION: &str = "calendar.ics.review";

const CONSENT: SideTable<String, IcsFeedConsentRecord, Named> =
    SideTable::new(&side_table::CALENDAR_ICS_FEED_CONSENT);

/// One installed feed's import consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct IcsFeedConsentRecord {
    /// The digest of the feed configuration this record belongs to.
    config_digest: String,
    state: IcsFeedConsentState,
    /// When the review opened, or when the owner decided it.
    at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum IcsFeedConsentState {
    /// The first completed poll's imported claims (and its property
    /// continuations'), waiting on the owner's one review.
    AwaitingReview { claim_ids: Vec<String> },
    /// The owner approved the review: the feed's standing consent.
    Granted {
        receipt: String,
        /// The claims the standing consent left Proposed because the inbound
        /// screen flagged their body, by id. A record written before this
        /// field reads with none.
        #[serde(default)]
        held_claim_ids: Vec<String>,
    },
    /// The owner declined the review.
    Declined { receipt: String },
}

/// The owner-visible consent state of an installed feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CalendarIcsFeedConsent {
    /// No poll has completed: the first completed poll opens the review.
    AwaitingFirstPoll,
    /// The first poll's claims wait on the owner's one review. A decision
    /// names `review_ref`; a review that moved since refuses.
    AwaitingReview { claims: u32, review_ref: String },
    /// The owner approved the review; later polls land under it. A claim
    /// whose body the inbound screen flagged waits Proposed for the owner's
    /// own settlement instead; `held_claims` counts those still waiting.
    Granted {
        receipt: String,
        decided_at: u64,
        held_claims: u32,
    },
    /// The owner declined the review; the feed does not poll again.
    Declined { receipt: String, decided_at: u64 },
}

/// What a completed poll's admitted claims became under the feed's consent.
pub(super) enum CompletedPollConsent {
    /// They opened the feed's review: the poll chain ends here.
    OpenedReview { claims: u32 },
    /// They landed Approved under the standing consent.
    Standing,
}

/// How a settlement covers the claims still waiting.
#[derive(Clone, Copy)]
enum Settlement {
    /// The owner's own review decision, or a declined feed: every waiting
    /// claim settles with this action.
    Every(GateConsentBundleAction),
    /// The feed's standing consent: every waiting claim lands Approved except
    /// one whose body the inbound screen flagged, which stays Proposed.
    Standing,
}

/// What a settlement did: the gate decisions to record once its transaction
/// commits, and the flagged claims a standing settlement left waiting.
struct Settled {
    metrics: Vec<RecordedClaimGateDecision>,
    held: Vec<EntityId>,
}

fn config_digest(config: &IcsFeedPollConfig) -> crate::Result<String> {
    let bytes = serde_json::to_vec(config)
        .map_err(|_| crate::Error::InvariantViolation("ICS feed config did not encode"))?;
    let digest = LegacyDigest::new(purposes::calendar::ICS_FEED_CONFIG_DIGEST)
        .raw(&bytes)
        .finish();
    Ok(oneiron_hex::encode(&digest))
}

/// The ref of one exact review: the feed's configuration and its claim set.
fn review_ref(config_digest: &str, claim_ids: &[String]) -> crate::Result<String> {
    let bytes = serde_json::to_vec(&(config_digest, claim_ids))
        .map_err(|_| crate::Error::InvariantViolation("ICS feed review did not encode"))?;
    let digest = LegacyDigest::new(purposes::calendar::ICS_FEED_REVIEW_REF)
        .raw(&bytes)
        .finish();
    Ok(oneiron_hex::encode(&digest))
}

/// The feed's consent record, when it belongs to `config`.
fn read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    config: &IcsFeedPollConfig,
) -> crate::Result<Option<IcsFeedConsentRecord>> {
    let digest = config_digest(config)?;
    Ok(CONSENT
        .get(&vault.store, txn, &config.system)?
        .filter(|record| record.config_digest == digest))
}

/// Why the feed's next poll waits on its owner, if it does: its review is
/// open, or the owner declined it.
pub(super) fn poll_hold(
    vault: &Vault,
    config: &IcsFeedPollConfig,
) -> crate::Result<Option<&'static str>> {
    let txn = vault.store.env.read_txn()?;
    Ok(
        match read_in_txn(vault, &txn, config)?.map(|record| record.state) {
            Some(IcsFeedConsentState::AwaitingReview { .. }) => {
                Some("ICS feed waits on the owner's review of its first poll")
            }
            Some(IcsFeedConsentState::Declined { .. }) => {
                Some("the owner declined this ICS feed's import")
            }
            Some(IcsFeedConsentState::Granted { .. }) | None => None,
        },
    )
}

/// The feed's consent as its owner reads it.
pub(super) fn consent_view(
    vault: &Vault,
    config: &IcsFeedPollConfig,
) -> crate::Result<CalendarIcsFeedConsent> {
    let txn = vault.store.env.read_txn()?;
    match read_in_txn(vault, &txn, config)? {
        Some(record) => view(vault, &txn, &record),
        None => Ok(CalendarIcsFeedConsent::AwaitingFirstPoll),
    }
}

fn view(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &IcsFeedConsentRecord,
) -> crate::Result<CalendarIcsFeedConsent> {
    Ok(match &record.state {
        IcsFeedConsentState::AwaitingReview { claim_ids } => {
            CalendarIcsFeedConsent::AwaitingReview {
                claims: u32::try_from(claim_ids.len()).unwrap_or(u32::MAX),
                review_ref: review_ref(&record.config_digest, claim_ids)?,
            }
        }
        IcsFeedConsentState::Granted {
            receipt,
            held_claim_ids,
        } => {
            let mut held_claims = 0_u32;
            for id in claim_ids_from_hex(held_claim_ids)? {
                if waiting_in_txn(vault, txn, &id)?.is_some() {
                    held_claims = held_claims.saturating_add(1);
                }
            }
            CalendarIcsFeedConsent::Granted {
                receipt: receipt.clone(),
                decided_at: record.at,
                held_claims,
            }
        }
        IcsFeedConsentState::Declined { receipt } => CalendarIcsFeedConsent::Declined {
            receipt: receipt.clone(),
            decided_at: record.at,
        },
    })
}

/// Settles the imported claims an installed feed's completed poll admitted,
/// as `owner`, under the consent record read again in this transaction: with
/// no record they open the feed's review, and under the standing consent each
/// lands Approved, except a flagged one, which joins the held claims.
///
/// # Errors
/// The owner no longer holds, the review is open or declined (the poll was
/// held before its admissions, so this is a race), or a settlement refused.
pub(super) fn settle_completed_poll(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    config: &IcsFeedPollConfig,
    admitted: &[EntityId],
    now: u64,
) -> crate::Result<CompletedPollConsent> {
    let (outcome, metrics) = vault.with_write_txn_grouped(|txn| {
        let actor = WriteActor::new(owner.revalidate_in_txn(vault, txn)?, EdgeActorClass::Human);
        let Some(record) = read_in_txn(vault, txn, config)? else {
            let record = IcsFeedConsentRecord {
                config_digest: config_digest(config)?,
                state: IcsFeedConsentState::AwaitingReview {
                    claim_ids: admitted.iter().map(|id| id.to_hex()).collect(),
                },
                at: now,
            };
            CONSENT.put(&vault.store, txn, &config.system, &record)?;
            let claims = u32::try_from(admitted.len()).unwrap_or(u32::MAX);
            return Ok((CompletedPollConsent::OpenedReview { claims }, Vec::new()));
        };
        if !matches!(record.state, IcsFeedConsentState::Granted { .. }) {
            return Err(crate::Error::InvalidConfig(
                "ICS feed poll completed while its import waits on the owner".into(),
            ));
        }
        let settled = settle_claims_in_txn(
            vault,
            txn,
            owner,
            actor,
            admitted,
            Settlement::Standing,
            now,
        )?;
        hold_in_txn(vault, txn, config, record, &settled.held)?;
        Ok((CompletedPollConsent::Standing, settled.metrics))
    })?;
    record_metrics(vault, metrics);
    Ok(outcome)
}

/// Settles the imported claims one of an installed feed's property
/// continuations admitted, as `owner`: they join the feed's open review, land
/// Approved under its standing consent (a flagged one joins the held claims),
/// or are declined with a declined feed. A feed with no record (no poll of it
/// completed) leaves them as they are.
///
/// A held feed polls no more, so a continuation that runs while its review
/// is open reads the version the first poll archived: its claims are the
/// rest of that poll's diff, held Proposed like the rest. Joining them moves
/// the review, so a decision named on the earlier `review_ref` refuses.
///
/// # Errors
/// The owner no longer holds, or a settlement refused.
pub(super) fn settle_continuation(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    config: &IcsFeedPollConfig,
    admitted: &[EntityId],
    now: u64,
) -> crate::Result<()> {
    if admitted.is_empty() {
        return Ok(());
    }
    let metrics = vault.with_write_txn_grouped(|txn| {
        let actor = WriteActor::new(owner.revalidate_in_txn(vault, txn)?, EdgeActorClass::Human);
        let Some(mut record) = read_in_txn(vault, txn, config)? else {
            return Ok(Vec::new());
        };
        let settlement = match &mut record.state {
            IcsFeedConsentState::AwaitingReview { claim_ids } => {
                for id in admitted {
                    let hex = id.to_hex();
                    if !claim_ids.contains(&hex) {
                        claim_ids.push(hex);
                    }
                }
                CONSENT.put(&vault.store, txn, &config.system, &record)?;
                return Ok(Vec::new());
            }
            IcsFeedConsentState::Granted { .. } => Settlement::Standing,
            IcsFeedConsentState::Declined { .. } => {
                Settlement::Every(GateConsentBundleAction::Decline)
            }
        };
        let settled = settle_claims_in_txn(vault, txn, owner, actor, admitted, settlement, now)?;
        hold_in_txn(vault, txn, config, record, &settled.held)?;
        Ok(settled.metrics)
    })?;
    record_metrics(vault, metrics);
    Ok(())
}

/// The owner's one decision on the feed's open review, in `txn`: one consent
/// receipt over the exact claim set (an approve-once act, spent here, or a
/// denial), each claim still waiting settled the same way, flagged or not (the
/// owner reviewed it), and the decision recorded as the feed's consent.
/// Answers the decided consent and the gate decisions to record once `txn`
/// commits.
///
/// # Errors
/// No open review, a review that moved since `expected_review_ref` was read,
/// or a refused settlement; nothing changes.
pub(super) fn decide_review_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    config: &IcsFeedPollConfig,
    expected_review_ref: &str,
    approve: bool,
    now: u64,
) -> MemoryResult<(CalendarIcsFeedConsent, Vec<RecordedClaimGateDecision>)> {
    let record = read_in_txn(vault, txn, config)?
        .ok_or_else(|| MemoryError::bad_request("ICS feed has no completed poll to review"))?;
    let IcsFeedConsentState::AwaitingReview { claim_ids } = &record.state else {
        return Err(MemoryError::bad_request(
            "ICS feed's import review is already decided",
        ));
    };
    let current_ref = review_ref(&record.config_digest, claim_ids)?;
    if current_ref != expected_review_ref {
        return Err(MemoryError::bad_request(
            "ICS feed's import review moved; read its status again",
        ));
    }
    let ids = claim_ids_from_hex(claim_ids)?;
    let actor_ref = owner.revalidate_in_txn(vault, txn)?;
    let digest = review_effect(actor_ref, &record.config_digest, &current_ref, ids.len())?.digest();
    let (receipt, action) = if approve {
        let receipt = vault.approve_once_in_txn(txn, owner, digest)?;
        let authorization =
            crate::consent::approve_once_authorization_in_txn(&vault.store, txn, &digest)?
                .ok_or(crate::Error::CorruptedIndex("consent approve-once marker"))?;
        crate::consent::spend_approve_once_in_txn(&vault.store, txn, &authorization)?;
        (receipt, GateConsentBundleAction::Approve)
    } else {
        (
            vault.deny_consent_in_txn(txn, owner, digest)?,
            GateConsentBundleAction::Decline,
        )
    };
    let actor = WriteActor::new(actor_ref, EdgeActorClass::Human);
    let settled = settle_claims_in_txn(
        vault,
        txn,
        owner,
        actor,
        &ids,
        Settlement::Every(action),
        now,
    )?;
    let receipt = receipt.decision_id().to_hex();
    let decided = IcsFeedConsentRecord {
        config_digest: record.config_digest,
        state: if approve {
            IcsFeedConsentState::Granted {
                receipt,
                held_claim_ids: Vec::new(),
            }
        } else {
            IcsFeedConsentState::Declined { receipt }
        },
        at: now,
    };
    CONSENT.put(&vault.store, txn, &config.system, &decided)?;
    Ok((view(vault, txn, &decided)?, settled.metrics))
}

/// The exact effect the owner's review decision is bound to.
fn review_effect(
    owner: EntityId,
    config_digest: &str,
    review_ref: &str,
    claims: usize,
) -> crate::Result<ComposedEffect> {
    let bound = GrantBound::action(
        ActorBound::new(owner.to_hex())?,
        ActionClass::new(FEED_REVIEW_ACTION)?,
        ActionEnvelope::new([
            format!("config:{config_digest}"),
            format!("claims:{claims}"),
            format!("review:{review_ref}"),
        ])?,
    )?;
    ComposedEffect::new(EffectFacts::new(FEED_REVIEW_ACTION)?).with_action_requirement(bound)
}

/// Settles each claim in `ids` that is still an active proposal as `actor`,
/// the owner. A claim the owner settled on its own, or one gone since, is
/// past this decision and is skipped. Under the standing consent a claim whose
/// body the inbound screen flagged is not settled: it is answered as held.
fn settle_claims_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    actor: WriteActor,
    ids: &[EntityId],
    settlement: Settlement,
    now: u64,
) -> crate::Result<Settled> {
    let (action, hold_flagged) = match settlement {
        Settlement::Every(action) => (action, false),
        Settlement::Standing => (GateConsentBundleAction::Approve, true),
    };
    let mut settled = Settled {
        metrics: Vec::new(),
        held: Vec::new(),
    };
    for id in ids {
        let Some(body) = waiting_in_txn(vault, txn, id)? else {
            continue;
        };
        if hold_flagged && screen_flagged(&body) {
            settled.held.push(*id);
            continue;
        }
        // Each settlement spends its own owner-tier answer, revalidated in
        // this transaction, as a run review's members do.
        let owner_answer = owner.owner_answer_in_txn(vault, txn)?;
        let done =
            vault.settle_proposed_claim_in_txn(txn, *id, action, actor, owner_answer, now)?;
        settled.metrics.extend(done.recorded);
    }
    Ok(settled)
}

/// Adds `held` to the standing consent's held claims, beside each earlier one
/// still waiting on the owner, and writes the record back. Nothing to hold
/// writes nothing.
fn hold_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    config: &IcsFeedPollConfig,
    mut record: IcsFeedConsentRecord,
    held: &[EntityId],
) -> crate::Result<()> {
    if held.is_empty() {
        return Ok(());
    }
    let IcsFeedConsentState::Granted { held_claim_ids, .. } = &mut record.state else {
        return Err(crate::Error::InvariantViolation(
            "ICS feed holds claims without its standing consent",
        ));
    };
    let mut kept = Vec::with_capacity(held_claim_ids.len() + held.len());
    for id in claim_ids_from_hex(held_claim_ids)? {
        if waiting_in_txn(vault, txn, &id)?.is_some() {
            kept.push(id.to_hex());
        }
    }
    for id in held {
        let hex = id.to_hex();
        if !kept.contains(&hex) {
            kept.push(hex);
        }
    }
    *held_claim_ids = kept;
    CONSENT.put(&vault.store, txn, &config.system, &record)?;
    Ok(())
}

/// The claim's body while it is still an active proposal.
fn waiting_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> crate::Result<Option<ClaimBody>> {
    Ok(vault.get_claim_in_txn(txn, id)?.filter(|body| {
        body.approval == ClaimApprovalStatus::Proposed
            && body.lifecycle == ClaimLifecycleStatus::Active
    }))
}

/// Whether the inbound screen flagged the body this claim was admitted on, by
/// the verdict its admission keeps on the claim's evidence (CAL-09).
fn screen_flagged(body: &ClaimBody) -> bool {
    body.evidence
        .as_ref()
        .and_then(crate::ingest::imported_screen_verdict)
        == Some(FLAGGED_VERDICT)
}

fn claim_ids_from_hex(hexes: &[String]) -> crate::Result<Vec<EntityId>> {
    hexes
        .iter()
        .map(|hex| EntityId::from_hex(hex))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            crate::Error::InvariantViolation("ICS feed consent holds a malformed claim id")
        })
}

pub(super) fn record_metrics(vault: &Vault, metrics: Vec<RecordedClaimGateDecision>) {
    for decision in metrics {
        decision.record_metrics(&vault.store.diagnostics.gate);
    }
}
