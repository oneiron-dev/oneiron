//! An agent's review and settlement of a Dreamer consent bundle, beside the
//! owner's (restriction census C29; Engine RULING RESTRICTION-WAVE-9-CANON
//! C29 = A, canon's settlement policy row of DEC-0006).
//!
//! With the owner's `gate.consent_bundle.delegate_resolution` row on for it,
//! an agent reviews a run's bundle (`vault.gate.consent_bundle.review_as`)
//! and approves or declines it as a unit
//! (`vault.gate.consent_bundle.resolve_as`), each under its own live Grant
//! listing the verb, and only a bundle whose every member its read lane
//! admits. The review names each member's claim and never its body: the
//! agent reads each claim through its own lane. Whatever the key says:
//! - the opener's lineage and its forks never settle their bundle (DEC-0006):
//!   each member's writer and every try of the run open it, and two lineages
//!   that share an actor are one ([`settling_lineage_in_txn`]);
//! - a bundle that holds a proactivity policy request waits for the owner,
//!   whose own policy it asks to change;
//! - an agent's answer is never the owner's, so every member's owner-answer
//!   obligation stays open and the owner is shown a fresh item for it, as
//!   for a narrowed owner proof; and a Coach heal it answers is not counted
//!   as the owner's review.
//!
//! The members replay through the live gate as the agent's own writes, and
//! the unit's ledger row names the agent and its Grant.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    BundleDigestMember, BundleSettler, gate_consent_bundle_id, gate_consent_bundle_members_in_txn,
    require_gate_consent_bundle_run_id,
};
use crate::agent_dispatch::{LineageStart, settling_lineage_in_txn};
use crate::attempt_queue::AttemptQueue;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::consent::bundle_projection::{GateConsentBundleAction, GateConsentBundleReceipt};
use crate::dreamer_runner::maintenance::digest::PROACTIVITY_POLICY_REQUEST_PREDICATE;
use crate::edge::EdgeActorClass;
use crate::gate::setting_keys::CONSENT_BUNDLE_DELEGATE_RESOLVE;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::setting::SettingScope;
use crate::{EntityId, Error, Vault};

/// `vault.gate.consent_bundle.review_as`, the name a Grant lists to name an
/// agent's bundle review.
const REVIEW_AS_VERB: &str = "vault.gate.consent_bundle.review_as";
/// `vault.gate.consent_bundle.resolve_as`, the name a Grant lists to name an
/// agent's bundle settlement.
const RESOLVE_AS_VERB: &str = "vault.gate.consent_bundle.resolve_as";

/// `vault.gate.consent_bundle.review_as`'s input: the run whose bundle the
/// agent reviews.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GateConsentBundleReviewRequest {
    /// The Dreamer run id the bundle's pending rows are stamped with.
    pub dreamer_run_id: String,
}

/// One member as an agent's review names it: the claim to read through the
/// agent's own lane, never its body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GateConsentBundleMemberView {
    /// The member claim's id, 32 lowercase hex.
    pub claim_id: String,
    pub predicate: String,
    /// Why the gate parked it.
    pub reason_codes: Vec<String>,
    pub created_at: u64,
}

/// `vault.gate.consent_bundle.review_as`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GateConsentBundleReview {
    /// The id `vault.gate.consent_bundle.resolve_as` takes back, 64
    /// lowercase hex: it binds every member's live body and consent binding,
    /// so a member that moves after the review makes it stale.
    pub bundle_id: String,
    pub dreamer_run_id: String,
    pub members: Vec<GateConsentBundleMemberView>,
}

/// `vault.gate.consent_bundle.resolve_as`'s input: the reviewed bundle and
/// the one action over all its members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GateConsentBundleResolveRequest {
    /// The `bundle_id` the agent's review returned, 64 lowercase hex.
    pub bundle_id: String,
    pub dreamer_run_id: String,
    pub action: GateConsentBundleAction,
}

/// `vault.gate.consent_bundle.resolve_as`'s answer: the unit's receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GateConsentBundleResolution {
    /// The unit's gate ledger row, 32 lowercase hex.
    pub receipt_id: String,
    pub bundle_id: String,
    pub dreamer_run_id: String,
    pub action: GateConsentBundleAction,
    /// The members settled, 32 lowercase hex each.
    pub member_claim_ids: Vec<String>,
    pub created_at: u64,
}

impl From<GateConsentBundleReceipt> for GateConsentBundleResolution {
    fn from(receipt: GateConsentBundleReceipt) -> Self {
        Self {
            receipt_id: receipt.receipt_id.to_hex(),
            bundle_id: crate::entity_id::bytes_to_hex_lower(&receipt.bundle_id),
            dreamer_run_id: receipt.dreamer_run_id,
            action: receipt.action,
            member_claim_ids: receipt
                .member_claim_ids
                .iter()
                .map(EntityId::to_hex)
                .collect(),
            created_at: receipt.created_at,
        }
    }
}

/// The handle's own agent, or the refusal of any other caller: these doors
/// are an agent's; the owner reviews and settles through the owner's routes.
fn bundle_agent(memory: &Memory<'_>, verb: &str) -> MemoryResult<EntityId> {
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is an agent's door: the caller is no agent"),
            &["Settle the bundle through the owner's route with the owner's own credential."],
        ));
    }
    Ok(memory.actor())
}

/// `agent`'s admitting Grant for `verb` in `txn`: its live Grant listing
/// `verb`, then the owner's `CONSENT_BUNDLE_DELEGATE_RESOLVE` row for it.
/// With the key off the bundle stays the owner's, as at the owner's door.
fn admit_bundle_agent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    verb: &str,
) -> MemoryResult<EntityId> {
    let grant = crate::authority::principal_standing_in_txn(
        vault,
        txn,
        agent,
        EdgeActorClass::Agent,
        verb,
    )?
    .and_then(|standing| standing.grant);
    let Some(grant) = grant else {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "{verb} takes a live Grant listing {verb}: no live Grant from a live owner names this caller and lists the verb"
            ),
            &["Have the owner grant this caller the verb by name."],
        ));
    };
    let delegated = CONSENT_BUNDLE_DELEGATE_RESOLVE
        .read_in_txn(vault, txn, &[SettingScope::Agent(agent)], None)?
        .value;
    if !delegated {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "{verb} is the vault owner's: the owner has not turned on {} for this agent",
                CONSENT_BUNDLE_DELEGATE_RESOLVE.spec.name
            ),
            &["Ask the owner to turn the setting on for this agent."],
        ));
    }
    Ok(grant)
}

/// The run's live group, when `lane` reads every member claim in `txn`;
/// `None` for an empty group and for one with a member the lane withholds:
/// such a bundle reads, to the agent, as no bundle.
fn agent_bundle_members_in_txn(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    dreamer_run_id: &str,
) -> crate::Result<Option<Vec<BundleDigestMember>>> {
    let members = gate_consent_bundle_members_in_txn(&vault.store, txn, dreamer_run_id)?;
    if members.is_empty() {
        return Ok(None);
    }
    let claims: Vec<EntityId> = members.iter().map(|entry| entry.member.claim_id).collect();
    if lane
        .entities_readable_in_txn(txn, &claims)?
        .contains(&false)
    {
        return Ok(None);
    }
    Ok(Some(members))
}

/// Refuses `agent`'s settlement of a bundle its own lineage or a fork of it
/// opened (DEC-0006), whatever the key says. The opener is each member's
/// writer, as its pending gate decision names it, and every try of the run.
/// A member whose decision no longer names its writer, or a lineage the
/// engine cannot read whole, counts as the agent's own.
fn refuse_opener_lineage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    dreamer_run_id: &str,
    members: &[BundleDigestMember],
) -> MemoryResult<()> {
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "{RESOLVE_AS_VERB} never settles a bundle the settling agent's own lineage or its forks opened"
            ),
            &["Ask the owner, or an agent outside the opener's lineage, to settle it."],
        )
    };
    let mut opener = Vec::with_capacity(members.len());
    for entry in members {
        let writer = vault
            .store
            .gate_decision_in_txn(txn, entry.member.decision_id)?
            .and_then(|record| record.actor_ref)
            .and_then(|hex| EntityId::from_hex(&hex).ok());
        let Some(writer) = writer else {
            return Err(refused());
        };
        opener.push(LineageStart::Actor(writer));
    }
    opener.extend(
        AttemptQueue::new(vault)
            .list_run_in_txn(txn, dreamer_run_id)?
            .into_iter()
            .map(|attempt| LineageStart::Attempt(attempt.id)),
    );
    let settler = settling_lineage_in_txn(vault, txn, &[LineageStart::Actor(agent)])?;
    let opener = settling_lineage_in_txn(vault, txn, &opener)?;
    match (settler, opener) {
        (Some(settler), Some(opener)) if settler.is_disjoint(&opener) => Ok(()),
        _ => Err(refused()),
    }
}

/// `vault.gate.consent_bundle.review_as`: the run's bundle as the owner's
/// review binds it, for the handle's own agent under its live Grant listing
/// the verb and the owner's `gate.consent_bundle.delegate_resolution` row
/// for it, judged in one snapshot of the agent's read lane. It names each
/// member's claim, predicate and reasons, never its body. A bundle with a
/// member the lane withholds answers not found, as no bundle does.
///
/// # Errors
/// `FORBIDDEN` for a caller that is no agent, an agent with no such Grant,
/// and an agent the owner has not turned the key on for; `NOT_FOUND` for no
/// bundle the agent may read; a credential that no longer holds; storage
/// faults.
pub fn review_gate_consent_bundle_as_agent(
    memory: &Memory<'_>,
    input: GateConsentBundleReviewRequest,
) -> MemoryResult<GateConsentBundleReview> {
    bundle_agent(memory, REVIEW_AS_VERB)?;
    require_gate_consent_bundle_run_id(&input.dreamer_run_id)?;
    let agent = memory.actor();
    let vault = memory.vault();
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let read = lane.read_projected(&[], None, |txn, _| {
        memory.prove_read_authority_in_txn(txn)?;
        admit_bundle_agent_in_txn(vault, txn, agent, REVIEW_AS_VERB)?;
        let Some(members) = agent_bundle_members_in_txn(vault, &lane, txn, &input.dreamer_run_id)?
        else {
            return Err(Error::EntityNotFound.into());
        };
        let bundle_id = gate_consent_bundle_id(&input.dreamer_run_id, &members);
        let claims: Vec<EntityId> = members.iter().map(|entry| entry.member.claim_id).collect();
        let review = GateConsentBundleReview {
            bundle_id: crate::entity_id::bytes_to_hex_lower(&bundle_id),
            dreamer_run_id: input.dreamer_run_id.clone(),
            members: members
                .into_iter()
                .map(|entry| GateConsentBundleMemberView {
                    claim_id: entry.member.claim_id.to_hex(),
                    predicate: entry.body.predicate,
                    reason_codes: entry.member.reason_codes,
                    created_at: entry.member.created_at,
                })
                .collect(),
        };
        Ok::<_, MemoryError>((review, claims))
    })?;
    let (review, claims) = read.value;
    memory.produced_from(claims);
    Ok(review)
}

/// `vault.gate.consent_bundle.resolve_as`: [`Vault::resolve_gate_consent_bundle`]
/// for the handle's own agent, admitted as
/// [`review_gate_consent_bundle_as_agent`] admits, in the settlement's own
/// write: the bundle must read whole to the agent's lane and still hash to
/// `bundle_id`. The opener's lineage is refused, and a bundle holding a
/// proactivity policy request waits for the owner, whatever the key says.
/// No member's owner-answer obligation closes. An approval's curator
/// findings apply after the commit, as at the owner's route.
///
/// # Errors
/// As [`review_gate_consent_bundle_as_agent`]; `FORBIDDEN` for the opener's
/// lineage and for a proactivity policy request; the owner door's
/// refusals: a stale bundle id, a member the live gate refuses for this
/// agent's write, a malformed member.
pub fn resolve_gate_consent_bundle_as_agent(
    memory: &Memory<'_>,
    input: GateConsentBundleResolveRequest,
) -> MemoryResult<GateConsentBundleResolution> {
    let agent = bundle_agent(memory, RESOLVE_AS_VERB)?;
    let expected = parse_bundle_id(&input.bundle_id)?;
    let vault = memory.vault();
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let now = vault.now_recorded_at();
    let receipt = vault.settle_gate_consent_bundle(
        BundleSettler::Agent(agent),
        expected,
        &input.dreamer_run_id,
        input.action,
        now,
        |wtxn| {
            memory.verify_actor_write_in_txn(wtxn)?;
            memory.prove_read_authority_in_txn(wtxn)?;
            let grant = admit_bundle_agent_in_txn(vault, wtxn, agent, RESOLVE_AS_VERB)?;
            let Some(members) =
                agent_bundle_members_in_txn(vault, &lane, wtxn, &input.dreamer_run_id)?
            else {
                return Err(Error::EntityNotFound.into());
            };
            if members
                .iter()
                .any(|entry| entry.body.predicate == PROACTIVITY_POLICY_REQUEST_PREDICATE)
            {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    format!(
                        "{RESOLVE_AS_VERB} never settles a bundle that holds a proactivity policy request: it waits for the owner"
                    ),
                    &["Ask the owner to settle this bundle."],
                ));
            }
            refuse_opener_lineage_in_txn(vault, wtxn, agent, &input.dreamer_run_id, &members)?;
            Ok(Some(grant))
        },
    )?;
    // An approved curator rung applies now, after the approval committed,
    // not at the next nightly pass (FIX 470), as at the owner's route.
    if receipt.action == GateConsentBundleAction::Approve {
        crate::dreamer_runner::maintenance::apply_curator_after_consent(
            vault,
            receipt.member_claim_ids.iter().copied(),
            now,
        );
    }
    memory.produced_from(receipt.member_claim_ids.clone());
    Ok(receipt.into())
}

/// `bundle_id` as 32 bytes: exactly 64 lowercase hex characters.
fn parse_bundle_id(value: &str) -> MemoryResult<[u8; 32]> {
    let invalid = || MemoryError::bad_request("bundle_id must be 64 lowercase hex characters");
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let mut id = [0_u8; 32];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(id)
}
