//! CA-03 enrollment consequence writer: the leader-only MACRO job that turns a
//! detected SAVED_QUERY membership transition into the CA-01 `campaign.member`
//! claim and, when the campaign program declares one, an outward call.
//!
//! Four mechanisms carry correctness here, and the queue dedupe key is NOT one
//! of them:
//!
//! 1. the campaign-local home-node designation, re-checked immediately before
//!    the consequence write so a node that lost leadership after claiming its
//!    attempt cannot still write;
//! 2. the attempt lease plus LMDB's single-writer transaction;
//! 3. ONE-1773's monotonic per-`(query, entity)` epoch watermark, compare-and-set
//!    inside the commit txn;
//! 4. ONE-1691's outbound intent ledger, which freezes the outward payload
//!    before transport and replays the same frozen bytes after a crash.
//!
//! Disable or corrupt the advisory dedupe key and every one of those still
//! holds. That asymmetry is the design.
//!
//! The attempt payload carries REFS ONLY. Nothing authority-bearing — cause,
//! evidence hash, epoch, timestamps, an "enrolled" flag, an outbound request —
//! travels through the queue, because a queue row is the one thing a replay or a
//! confused caller can hand us verbatim. Execution resolves the refs against
//! persisted rows and re-derives everything else through ONE-1773 under the
//! saved query's own owner actor.
//!
//! Home-node election is a deliberate local copy of the `dreamer_runner.rs`
//! candidate/designation shape rather than a shared abstraction: the Dreamer's
//! pure selector is private and its public method persists to a Dreamer-private
//! key. CA-03 keeps its own `campaign:home_node_macro:v1` row and never touches
//! the Dreamer's.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, EnqueueAttempt,
    EnqueueOutcome,
};
use crate::campaign::claims::{CampaignMemberChannel, CampaignMemberState};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundEffectError, OutboundTransport, PreparedAuthorization,
    PreparedEffect, execute_outbound_effect,
};
use crate::outbound_consent::OutboundBindingAuthority;
use crate::outbound_intent_ledger::{
    BudgetClass, IntentDispatchResult, IntentId, OutboundCallRequest, derive_intent_id,
};
use crate::saved_query::{
    EVIDENCE_HASH_LEN, EvaluationRequest, MatchVerdict, MembershipCause, MembershipCommitOutcome,
    MembershipEvent, MembershipTransition, MembershipWritePlan, QueryScope, SavedQueryEvaluator,
    commit_membership_plan, derived_member_value, membership_events, next_membership_epoch,
    read_saved_query,
};

/// The ONE attempt kind this ticket introduces. No queue enum, no recurrence
/// primitive, no second kind for the outward leg.
pub const CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND: &str = "campaign.enrollment.macro";

/// Schema version shared by every campaign-local row this module persists.
pub const CAMPAIGN_ENROLLMENT_SCHEMA_VERSION: u32 = 1;

/// Campaign-local home-node designation key. Deliberately NOT the Dreamer's
/// `dreamer:home_node_macro:v1`.
const CAMPAIGN_HOME_NODE_META_KEY: &[u8] = b"campaign:home_node_macro:v1";
const ENROLLMENT_EVENT_PREFIX: &[u8] = b"campaign:enrollment_event:v1:";
const ENROLLMENT_CONTEXT_PREFIX: &[u8] = b"campaign:enrollment_context:v1:";
const CAMPAIGN_PROGRAM_PREFIX: &[u8] = b"campaign:program:v1:";
const CAMPAIGN_PROGRAM_STEP_PREFIX: &[u8] = b"campaign:program_step:v1:";

// ---------------------------------------------------------------------------
// Home-node designation
// ---------------------------------------------------------------------------

/// Candidate node signals for the campaign MACRO home-node election.
///
/// `attached` is authority-bearing only for cloud candidates: a detached cloud
/// node is not eligible at all, while local candidates are elected from the
/// caller-supplied current candidate set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CampaignHomeNodeCandidate {
    /// Stable node identity; zero is rejected.
    pub node_id: u64,
    /// Whether this candidate is the attached cloud node.
    pub cloud: bool,
    /// Sync attachment signal.
    pub attached: bool,
    /// Whether this candidate is an always-on local node.
    pub always_on_local: bool,
    /// Whether this candidate is the owner's primary device.
    pub primary_device: bool,
}

impl CampaignHomeNodeCandidate {
    /// Cloud candidate; eligible only while attached.
    #[must_use]
    pub const fn cloud(node_id: u64, attached: bool) -> Self {
        Self {
            node_id,
            cloud: true,
            attached,
            always_on_local: false,
            primary_device: false,
        }
    }

    /// Always-on local candidate.
    #[must_use]
    pub const fn always_on_local(node_id: u64) -> Self {
        Self {
            node_id,
            cloud: false,
            attached: true,
            always_on_local: true,
            primary_device: false,
        }
    }

    /// Primary-device candidate.
    #[must_use]
    pub const fn primary_device(node_id: u64) -> Self {
        Self {
            node_id,
            cloud: false,
            attached: true,
            always_on_local: false,
            primary_device: true,
        }
    }

    const fn designation_class(self) -> Option<CampaignHomeNodeClass> {
        if self.cloud {
            // A detached cloud node is INELIGIBLE, not demoted: it cannot be a
            // local or primary device, so it simply drops out of the election.
            if self.attached {
                Some(CampaignHomeNodeClass::CloudAttached)
            } else {
                None
            }
        } else if self.always_on_local {
            Some(CampaignHomeNodeClass::AlwaysOnLocal)
        } else if self.primary_device {
            Some(CampaignHomeNodeClass::PrimaryDevice)
        } else {
            None
        }
    }
}

/// Election class that made a node the campaign MACRO home node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CampaignHomeNodeClass {
    /// Attached cloud node — the strongest tier.
    CloudAttached,
    /// Always-on local node.
    AlwaysOnLocal,
    /// The owner's primary device — the weakest eligible tier.
    PrimaryDevice,
}

impl CampaignHomeNodeClass {
    /// Stable wire token persisted in the designation row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudAttached => "cloud_attached",
            Self::AlwaysOnLocal => "always_on_local",
            Self::PrimaryDevice => "primary_device",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "cloud_attached" => Some(Self::CloudAttached),
            "always_on_local" => Some(Self::AlwaysOnLocal),
            "primary_device" => Some(Self::PrimaryDevice),
            _ => None,
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::CloudAttached => 0,
            Self::AlwaysOnLocal => 1,
            Self::PrimaryDevice => 2,
        }
    }
}

/// The single persisted campaign MACRO home-node designation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CampaignHomeNodeDesignation {
    /// Row schema version.
    pub schema_version: u32,
    /// Designated node.
    pub node_id: u64,
    /// Tier that won the election.
    pub class: CampaignHomeNodeClass,
    /// Election instant supplied by the caller.
    pub elected_at: u64,
}

/// Whether the local node may act as the campaign home node right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignHomeNodeAdmission {
    /// The local node holds the designation.
    Designated(CampaignHomeNodeDesignation),
    /// Another node holds it.
    NotHomeNode(CampaignHomeNodeDesignation),
    /// No node holds it.
    NoHomeNode,
}

/// Builds a local candidate from the vault's stable sync device identity.
///
/// # Errors
///
/// Storage errors propagate from the device-identity read.
pub fn local_campaign_home_node_candidate(
    vault: &Vault,
    attached: bool,
    always_on_local: bool,
    primary_device: bool,
) -> Result<CampaignHomeNodeCandidate> {
    Ok(CampaignHomeNodeCandidate {
        node_id: crate::identity::load_or_mint_client_id(vault)?,
        cloud: false,
        attached,
        always_on_local,
        primary_device,
    })
}

/// Elects and persists the campaign home-node designation.
///
/// Deterministic over the CURRENT candidate set: attached cloud beats always-on
/// local beats primary device, with the lowest stable node id resolving ties
/// inside a tier. An empty or all-ineligible set CLEARS the designation rather
/// than leaving a stale leader behind.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a zero or duplicated node id; storage errors
/// propagate.
pub fn elect_campaign_home_node_designation(
    vault: &Vault,
    candidates: &[CampaignHomeNodeCandidate],
    now: u64,
) -> Result<Option<CampaignHomeNodeDesignation>> {
    let designation = select_campaign_home_node(candidates, now)?;
    let encoded = designation.map(encode_designation).transpose()?;
    vault.with_write_txn(|wtxn| {
        match encoded.as_ref() {
            Some(bytes) => vault
                .store
                .vault_meta
                .put(wtxn, CAMPAIGN_HOME_NODE_META_KEY, bytes)?,
            None => {
                vault
                    .store
                    .vault_meta
                    .delete(wtxn, CAMPAIGN_HOME_NODE_META_KEY)?;
            }
        }
        Ok(())
    })?;
    Ok(designation)
}

/// Reads the persisted campaign home-node designation, if one exists.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_home_node_designation(vault: &Vault) -> Result<Option<CampaignHomeNodeDesignation>> {
    read_meta(vault, CAMPAIGN_HOME_NODE_META_KEY)?
        .map(|raw| decode_designation(&raw))
        .transpose()
}

/// Admission check for the local node.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a zero node id; storage errors propagate.
pub fn require_campaign_home_node(
    vault: &Vault,
    local_node_id: u64,
) -> Result<CampaignHomeNodeAdmission> {
    if local_node_id == 0 {
        return Err(invalid("campaign home node_id must be nonzero"));
    }
    Ok(match campaign_home_node_designation(vault)? {
        None => CampaignHomeNodeAdmission::NoHomeNode,
        Some(designation) if designation.node_id == local_node_id => {
            CampaignHomeNodeAdmission::Designated(designation)
        }
        Some(designation) => CampaignHomeNodeAdmission::NotHomeNode(designation),
    })
}

/// Pure selector. Kept separate from persistence so the ordering law is
/// testable without a vault, and so the write path has exactly one decision.
fn select_campaign_home_node(
    candidates: &[CampaignHomeNodeCandidate],
    now: u64,
) -> Result<Option<CampaignHomeNodeDesignation>> {
    let mut best: Option<(u8, u64, CampaignHomeNodeClass)> = None;
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.node_id == 0 {
            return Err(invalid("campaign home node_id must be nonzero"));
        }
        if candidates[..index]
            .iter()
            .any(|seen| seen.node_id == candidate.node_id)
        {
            return Err(invalid("duplicate campaign home node candidate"));
        }
        let Some(class) = candidate.designation_class() else {
            continue;
        };
        let rank = class.rank();
        let better = best.is_none_or(|(best_rank, best_node_id, _)| {
            rank < best_rank || (rank == best_rank && candidate.node_id < best_node_id)
        });
        if better {
            best = Some((rank, candidate.node_id, class));
        }
    }
    Ok(best.map(|(_, node_id, class)| CampaignHomeNodeDesignation {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        node_id,
        class,
        elected_at: now,
    }))
}

// ---------------------------------------------------------------------------
// The persisted enrollment (membership) event
// ---------------------------------------------------------------------------

/// One detected, PERSISTED membership transition awaiting its consequence.
///
/// This is the row an attempt payload points at. Everything authority-bearing
/// about the transition lives here, written by the engine at detection time, so
/// no caller and no queue replay can present a different cause, epoch, or
/// evidence hash to the write path.
///
/// `definition_version` and `scope_digest` are the derivation CONTEXT the next
/// detection compares against: they are what makes "the definition moved" and
/// "the owner's reach moved" decidable without re-deriving ONE-1773's evidence
/// machinery here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignEnrollmentEvent {
    /// Durable identity of this row; the attempt payload's only membership ref.
    pub event_ref: EntityId,
    /// Query that derived the transition.
    pub query_ref: EntityId,
    /// Campaign the consequence is scoped to.
    pub campaign_ref: EntityId,
    /// Entity whose membership moved.
    pub entity_ref: EntityId,
    /// Owner actor the re-derivation must run under.
    pub owner_actor: EntityId,
    /// Monotonic per-`(query, entity)` epoch minted at detection.
    pub epoch: u64,
    /// When the transition became true.
    pub valid_at: u64,
    /// When the engine detected it.
    pub detected_at: u64,
    /// Direction.
    pub transition: MembershipTransition,
    /// Engine-derived cause. The routing dial reads THIS, never a payload field.
    pub cause: MembershipCause,
    /// Evidence the detection verdict was derived from.
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
    /// Definition version the detection ran against.
    pub definition_version: u64,
    /// Digest of the effective (declared ∩ granted) scope at detection.
    pub scope_digest: [u8; 32],
}

impl CampaignEnrollmentEvent {
    /// Projection onto ONE-1773's event type. The commit boundary owns the
    /// event shape; this module owns only the durable row that carries it.
    #[must_use]
    pub fn membership_event(&self) -> MembershipEvent {
        MembershipEvent {
            query_ref: self.query_ref,
            campaign_ref: self.campaign_ref,
            entity_ref: self.entity_ref,
            epoch: self.epoch,
            valid_at: self.valid_at,
            detected_at: self.detected_at,
            transition: self.transition,
            cause: self.cause,
            evidence_hash: self.evidence_hash,
        }
    }
}

/// Reads one persisted enrollment event.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_enrollment_event(
    vault: &Vault,
    event_ref: EntityId,
) -> Result<Option<CampaignEnrollmentEvent>> {
    read_meta(vault, &keyed(ENROLLMENT_EVENT_PREFIX, &[event_ref.as_bytes()]))?
        .map(|raw| decode_event(event_ref, &raw))
        .transpose()
}

/// What a detection pass concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentDetection {
    /// A transition was recorded and is ready to be enqueued.
    Recorded(Box<CampaignEnrollmentEvent>),
    /// Nothing to do: the entity does not match, or already holds the cohort
    /// row this evidence would write.
    NoTransition,
}

/// Detection-door input. Refs and a clock — no cause, epoch, evidence hash,
/// enrolled flag, or outbound request, because none of those is a caller's to
/// assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectEnrollment {
    /// The saved query.
    pub query_ref: EntityId,
    /// The campaign the consequence is scoped to.
    pub campaign_ref: EntityId,
    /// The entity being considered.
    pub entity_ref: EntityId,
    /// Detection instant.
    pub now: u64,
}

/// Runs one detection pass and, on a real transition, PERSISTS the event.
///
/// The epoch is minted here, once, and pinned to the row — not re-minted at
/// execution. That is what makes a retry of the same attempt land on the same
/// epoch and content, and therefore report `AlreadyApplied` instead of writing
/// a second cohort row one epoch later.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the query is absent or `owner_actor` does not
/// own it; evaluation and storage errors propagate.
pub async fn detect_enrollment(
    evaluator: &SavedQueryEvaluator<'_>,
    owner_actor: EntityId,
    input: &DetectEnrollment,
) -> Result<EnrollmentDetection> {
    let vault = evaluator.vault;
    let record =
        read_saved_query(vault, owner_actor, input.query_ref)?.ok_or(Error::EntityNotFound)?;
    let scope_digest =
        effective_scope_digest(&record.definition.scope, evaluator.owner_grants);
    let definition_version = record.definition.definition_version;
    let cause = derive_cause(
        vault,
        input.query_ref,
        input.entity_ref,
        definition_version,
        &scope_digest,
    )?;
    let outcome = evaluator
        .evaluate_entity(&EvaluationRequest {
            query_ref: input.query_ref,
            campaign_ref: input.campaign_ref,
            entity_ref: input.entity_ref,
            definition: &record.definition,
            cause,
            valid_at: input.now,
            detected_at: input.now,
        })
        .await?;
    if outcome.decision.verdict != MatchVerdict::Match {
        return Ok(EnrollmentDetection::NoTransition);
    }
    // A transition is a CHANGE. An entity already entered on exactly this
    // evidence has nothing to transition into, and minting an epoch for it
    // would churn the cohort head on every wake.
    if membership_events(vault, input.query_ref, input.entity_ref)?
        .last()
        .is_some_and(|last| {
            last.transition == MembershipTransition::Entered
                && last.evidence_hash == outcome.evidence_hash
        })
    {
        return Ok(EnrollmentDetection::NoTransition);
    }
    let event = CampaignEnrollmentEvent {
        event_ref: EntityId::now(),
        query_ref: input.query_ref,
        campaign_ref: input.campaign_ref,
        entity_ref: input.entity_ref,
        owner_actor,
        epoch: next_membership_epoch(vault, input.query_ref, input.entity_ref)?,
        valid_at: input.now,
        detected_at: input.now,
        transition: MembershipTransition::Entered,
        cause,
        evidence_hash: outcome.evidence_hash,
        definition_version,
        scope_digest,
    };
    put_event_with_context(vault, &event)?;
    Ok(EnrollmentDetection::Recorded(Box::new(event)))
}

/// Routes the transition onto ONE of the three closed causes.
///
/// Precedence is definition > scope > data, because a definition move can also
/// move the effective scope and the more specific explanation is the honest
/// one. With no prior context the only mover that can be evidenced is the
/// entity's own data.
fn derive_cause(
    vault: &Vault,
    query_ref: EntityId,
    entity_ref: EntityId,
    definition_version: u64,
    scope_digest: &[u8; 32],
) -> Result<MembershipCause> {
    let Some(prior) = read_context(vault, query_ref, entity_ref)? else {
        return Ok(MembershipCause::DataChange);
    };
    Ok(if prior.definition_version != definition_version {
        MembershipCause::DefinitionChange
    } else if &prior.scope_digest != scope_digest {
        MembershipCause::ScopeChange
    } else {
        MembershipCause::DataChange
    })
}

/// Digest of the scope the query will ACTUALLY run under: declared ∩ granted.
/// A closed intersection gets its own tag so "the owner lost all reach" is
/// distinguishable from "the owner's reach is unrestricted".
fn effective_scope_digest(declared: &QueryScope, grants: &QueryScope) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.campaign.enrollment.scope.v1");
    match declared.intersect(grants) {
        None => hasher.update([0u8]),
        Some(scope) => {
            hasher.update([1u8]);
            let mut worlds: Vec<[u8; 16]> =
                scope.worlds.iter().map(|world| *world.as_bytes()).collect();
            worlds.sort_unstable();
            hasher.update((worlds.len() as u64).to_be_bytes());
            for world in &worlds {
                hasher.update(world);
            }
            let mut facets = scope.facets.clone();
            facets.sort_unstable();
            hasher.update((facets.len() as u64).to_be_bytes());
            for facet in &facets {
                hasher.update((facet.len() as u64).to_be_bytes());
                hasher.update(facet.as_bytes());
            }
        }
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Campaign program state (the outward leg's persisted authority)
// ---------------------------------------------------------------------------

/// A campaign program: the persisted binding between a campaign and the steps
/// its enrollments execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CampaignProgram {
    /// Row schema version.
    pub schema_version: u32,
    /// Program identity.
    pub program_ref: EntityId,
    /// Campaign this program belongs to.
    pub campaign_ref: EntityId,
}

/// The outward half of a program step.
///
/// `call_seq` is DURABLE program state, never a clock or a process counter:
/// ONE-1691 derives the intent id from `(attempt_id, call_seq, server, tool,
/// payload_hash)`, so a process-local counter would mint a fresh intent — and a
/// second send — on every restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignProgramOutbound {
    /// Durable call sequence within the program.
    pub call_seq: u64,
    /// Outbound verb.
    pub verb: String,
    /// Frozen program-authored body.
    pub payload: Vec<u8>,
    /// Whether the channel honors the ledger's idempotency key. Persisted
    /// rather than assumed: getting this wrong turns an ambiguous send into a
    /// duplicate one.
    pub idempotency_supported: bool,
}

/// One step of a campaign program.
///
/// The step is the single persisted source for BOTH halves of the consequence:
/// the `campaign.member` channel row (channel, consent basis, sticky sender)
/// and, when present, the outward call. A cohort row with no channel would be
/// an unauthorized send waiting to happen, which is why CA-01 rejects one — so
/// enrollment without a resolvable step fails closed rather than writing a
/// channel-less member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignProgramStep {
    /// Row schema version.
    pub schema_version: u32,
    /// Owning program.
    pub program_ref: EntityId,
    /// Step identity.
    pub step_ref: EntityId,
    /// Normalized channel token.
    pub channel: String,
    /// Sticky sender identity for this channel.
    pub sender_ref: EntityId,
    /// Evidence entity authorizing contact on this channel.
    pub basis_evidence: EntityId,
    /// Outward leg; absent means "enroll, send nothing".
    pub outbound: Option<CampaignProgramOutbound>,
}

impl CampaignProgramStep {
    /// The CA-01 channel row this step authorizes.
    #[must_use]
    pub fn member_channel(&self) -> CampaignMemberChannel {
        CampaignMemberChannel {
            channel: self.channel.clone(),
            basis_evidence: self.basis_evidence,
            sender_ref: self.sender_ref,
        }
    }
}

/// Persists a campaign program row.
///
/// # Errors
///
/// Storage errors propagate.
pub fn put_campaign_program(vault: &Vault, program: &CampaignProgram) -> Result<()> {
    put_meta(
        vault,
        &keyed(CAMPAIGN_PROGRAM_PREFIX, &[program.program_ref.as_bytes()]),
        &encode_program(program)?,
    )
}

/// Reads a campaign program row.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_program(vault: &Vault, program_ref: EntityId) -> Result<Option<CampaignProgram>> {
    read_meta(
        vault,
        &keyed(CAMPAIGN_PROGRAM_PREFIX, &[program_ref.as_bytes()]),
    )?
    .map(|raw| decode_program(program_ref, &raw))
    .transpose()
}

/// Persists a campaign program step.
///
/// # Errors
///
/// Storage errors propagate.
pub fn put_campaign_program_step(vault: &Vault, step: &CampaignProgramStep) -> Result<()> {
    put_meta(
        vault,
        &keyed(
            CAMPAIGN_PROGRAM_STEP_PREFIX,
            &[step.program_ref.as_bytes(), step.step_ref.as_bytes()],
        ),
        &encode_program_step(step)?,
    )
}

/// Reads a campaign program step.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_program_step(
    vault: &Vault,
    program_ref: EntityId,
    step_ref: EntityId,
) -> Result<Option<CampaignProgramStep>> {
    read_meta(
        vault,
        &keyed(
            CAMPAIGN_PROGRAM_STEP_PREFIX,
            &[program_ref.as_bytes(), step_ref.as_bytes()],
        ),
    )?
    .map(|raw| decode_program_step(program_ref, step_ref, &raw))
    .transpose()
}

// ---------------------------------------------------------------------------
// The attempt payload
// ---------------------------------------------------------------------------

/// The whole queue payload: three refs.
///
/// Resolving them is a CROSS-BINDING, not a lookup — the program must belong to
/// the event's campaign and the step must belong to that program, or execution
/// fails closed. Refs a caller can shuffle are refs a caller can misuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CampaignEnrollmentAttemptPayload {
    /// The persisted [`CampaignEnrollmentEvent`].
    pub membership_event_ref: EntityId,
    /// The persisted [`CampaignProgram`].
    pub campaign_program_ref: EntityId,
    /// The persisted [`CampaignProgramStep`].
    pub program_step_ref: EntityId,
}

/// Encodes the refs-only payload.
///
/// # Errors
///
/// Serialization errors surface as [`Error::InvalidConfig`].
pub fn encode_enrollment_attempt_payload(
    payload: &CampaignEnrollmentAttemptPayload,
) -> Result<Vec<u8>> {
    to_row(&AttemptPayloadRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        membership_event_ref: payload.membership_event_ref.to_hex(),
        campaign_program_ref: payload.campaign_program_ref.to_hex(),
        program_step_ref: payload.program_step_ref.to_hex(),
    })
}

/// Decodes the refs-only payload, rejecting unknown, duplicated, or
/// wrong-version keys.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for any malformed payload.
pub fn decode_enrollment_attempt_payload(
    bytes: &[u8],
) -> Result<CampaignEnrollmentAttemptPayload> {
    const CONTEXT: &str = "campaign enrollment attempt payload";
    let row: AttemptPayloadRow = from_row(bytes, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    Ok(CampaignEnrollmentAttemptPayload {
        membership_event_ref: id_from_hex(&row.membership_event_ref, CONTEXT)?,
        campaign_program_ref: id_from_hex(&row.campaign_program_ref, CONTEXT)?,
        program_step_ref: id_from_hex(&row.program_step_ref, CONTEXT)?,
    })
}

/// Advisory queue-hygiene key over the persisted `(query, entity, epoch)`.
///
/// It coalesces duplicate enqueues and nothing more. Every correctness property
/// this module claims survives this key being wrong, absent, or hostile.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the membership event ref does not resolve.
pub fn enrollment_dedupe_key(
    vault: &Vault,
    payload: &CampaignEnrollmentAttemptPayload,
) -> Result<String> {
    let event = campaign_enrollment_event(vault, payload.membership_event_ref)?
        .ok_or(Error::EntityNotFound)?;
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.campaign.enrollment.dedupe.v1");
    hasher.update(event.query_ref.as_bytes());
    hasher.update(event.entity_ref.as_bytes());
    hasher.update(event.epoch.to_be_bytes());
    Ok(bytes_to_hex_lower(&hasher.finalize()))
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/// Outcome of a home-gated claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CampaignEnrollmentClaim {
    /// The local node took (or found nothing to take from) the queue.
    Queue(ClaimOutcome),
    /// Another node is the home node; the row stays available to it.
    NotHomeNode(CampaignHomeNodeDesignation),
    /// No home node is designated; the row stays queued.
    NoHomeNode,
}

/// What one execution of a claimed enrollment attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentExecution {
    /// The cohort row landed. `outbound_intent` is the stable identity the
    /// outward leg will use, derived from the durable attempt id and the
    /// program step's `call_seq` — it is not evidence that a send happened.
    Applied {
        /// Stable outward-leg identity, when the step declares one.
        outbound_intent: Option<IntentId>,
    },
    /// This exact epoch and content had already landed.
    AlreadyApplied {
        /// Stable outward-leg identity, when the step declares one.
        outbound_intent: Option<IntentId>,
    },
    /// The event's epoch is behind the watermark. Distinct from
    /// `AlreadyApplied`: a replayed `Entered` from before an exit must never be
    /// reported as success.
    RejectedStaleEpoch {
        /// Watermark that rejected the plan.
        current_epoch: u64,
    },
    /// The transition no longer describes reality; nothing was written or sent.
    SkippedStale,
    /// A bulk cause needs an owner ruling before it may write.
    ReviewRequired {
        /// The persisted cause that routed here.
        cause: MembershipCause,
    },
    /// Leadership moved between claim and write.
    NotHomeNode(CampaignHomeNodeDesignation),
    /// Leadership vanished between claim and write.
    NoHomeNode,
}

/// Leader-only enrollment runner over the existing attempt queue.
pub struct CampaignEnrollmentRunner<'a> {
    vault: &'a Vault,
    attempts: AttemptQueue<'a>,
}

impl<'a> CampaignEnrollmentRunner<'a> {
    /// Opens a runner over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            attempts: AttemptQueue::new(vault),
        }
    }

    /// Enqueues one enrollment attempt.
    ///
    /// The membership ref must already resolve: a queue row pointing at nothing
    /// is a row whose consequence can never be derived.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for an unresolvable membership ref; queue and
    /// storage errors propagate.
    pub fn enqueue(
        &self,
        payload: &CampaignEnrollmentAttemptPayload,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueOutcome> {
        let dedupe_key = enrollment_dedupe_key(self.vault, payload)?;
        self.attempts.enqueue(EnqueueAttempt {
            kind: CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND.to_owned(),
            payload: encode_enrollment_attempt_payload(payload)?,
            dedupe_key: Some(dedupe_key),
            run_id,
            now,
        })
    }

    /// Claims the oldest queued enrollment attempt, but only on the home node.
    ///
    /// The designation check runs BEFORE the queue is touched, so a non-home
    /// node never leases a row it would not be allowed to finish.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a zero node id; queue errors propagate.
    pub fn claim_if_home(
        &self,
        local_node_id: u64,
        lease_owner: String,
        now: u64,
    ) -> Result<CampaignEnrollmentClaim> {
        match require_campaign_home_node(self.vault, local_node_id)? {
            CampaignHomeNodeAdmission::NoHomeNode => Ok(CampaignEnrollmentClaim::NoHomeNode),
            CampaignHomeNodeAdmission::NotHomeNode(designation) => {
                Ok(CampaignEnrollmentClaim::NotHomeNode(designation))
            }
            CampaignHomeNodeAdmission::Designated(_) => self
                .attempts
                .claim_kind(
                    CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND,
                    ClaimAttempt { lease_owner, now },
                )
                .map(CampaignEnrollmentClaim::Queue),
        }
    }

    /// Executes one claimed attempt: the membership consequence leg.
    ///
    /// Outward firing is deliberately a SECOND leg
    /// ([`run_enrollment_outbound_leg`]): a crash between the cohort write and
    /// the intent record must resume the send, not redo the write.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a foreign attempt kind or a payload whose
    /// refs do not cross-bind; [`Error::EntityNotFound`] for unresolvable refs;
    /// evaluation, claim-validation, and storage errors propagate.
    pub async fn execute_claimed(
        &self,
        local_node_id: u64,
        record: &AttemptRecord,
        evaluator: &SavedQueryEvaluator<'_>,
        now: u64,
    ) -> Result<EnrollmentExecution> {
        if record.kind != CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND {
            return Err(invalid("attempt kind is not campaign.enrollment.macro"));
        }
        if let Some(refused) = home_node_refusal(self.vault, local_node_id)? {
            return Ok(refused);
        }
        let payload = decode_enrollment_attempt_payload(&record.payload)?;
        let event = campaign_enrollment_event(self.vault, payload.membership_event_ref)?
            .ok_or(Error::EntityNotFound)?;
        let step = resolve_program_step(self.vault, &payload, &event)?;

        // The ratified routing dial: only ordinary data movement auto-applies.
        // A bulk scope or definition move is the owner's call, and no payload
        // field can reach this decision.
        if event.cause != MembershipCause::DataChange {
            return Ok(EnrollmentExecution::ReviewRequired { cause: event.cause });
        }
        if event.transition != MembershipTransition::Entered {
            return Ok(EnrollmentExecution::SkippedStale);
        }
        if !self.evidence_still_holds(evaluator, &event, now).await? {
            return Ok(EnrollmentExecution::SkippedStale);
        }

        // Re-checked HERE, immediately before the write: a lease proves this
        // node claimed the work, not that it is still allowed to finish it.
        if let Some(refused) = home_node_refusal(self.vault, local_node_id)? {
            return Ok(refused);
        }
        let plan = MembershipWritePlan {
            event: event.membership_event(),
            value: derived_member_value(
                &event.membership_event(),
                CampaignMemberState::Enrolled,
                vec![step.member_channel()],
            ),
        };
        let outbound_intent = enrollment_intent_id(record.id, &step)?;
        Ok(
            match commit_membership_plan(self.vault, &plan, now)? {
                MembershipCommitOutcome::Applied => {
                    EnrollmentExecution::Applied { outbound_intent }
                }
                MembershipCommitOutcome::AlreadyApplied => {
                    EnrollmentExecution::AlreadyApplied { outbound_intent }
                }
                MembershipCommitOutcome::RejectedStaleEpoch { current_epoch } => {
                    EnrollmentExecution::RejectedStaleEpoch { current_epoch }
                }
            },
        )
    }

    /// Re-derives the saved-query result under the query's OWN owner actor and
    /// the evaluator's current grants, and reports whether the persisted event
    /// still describes reality.
    async fn evidence_still_holds(
        &self,
        evaluator: &SavedQueryEvaluator<'_>,
        event: &CampaignEnrollmentEvent,
        now: u64,
    ) -> Result<bool> {
        let record = read_saved_query(self.vault, event.owner_actor, event.query_ref)?
            .ok_or(Error::EntityNotFound)?;
        let outcome = evaluator
            .evaluate_entity(&EvaluationRequest {
                query_ref: event.query_ref,
                campaign_ref: event.campaign_ref,
                entity_ref: event.entity_ref,
                definition: &record.definition,
                cause: event.cause,
                valid_at: event.valid_at,
                detected_at: now,
            })
            .await?;
        Ok(outcome.decision.verdict == MatchVerdict::Match
            && outcome.evidence_hash == event.evidence_hash)
    }
}

fn home_node_refusal(vault: &Vault, local_node_id: u64) -> Result<Option<EnrollmentExecution>> {
    Ok(match require_campaign_home_node(vault, local_node_id)? {
        CampaignHomeNodeAdmission::Designated(_) => None,
        CampaignHomeNodeAdmission::NotHomeNode(designation) => {
            Some(EnrollmentExecution::NotHomeNode(designation))
        }
        CampaignHomeNodeAdmission::NoHomeNode => Some(EnrollmentExecution::NoHomeNode),
    })
}

/// Resolves the program step and proves it belongs to the event's campaign.
fn resolve_program_step(
    vault: &Vault,
    payload: &CampaignEnrollmentAttemptPayload,
    event: &CampaignEnrollmentEvent,
) -> Result<CampaignProgramStep> {
    let program =
        campaign_program(vault, payload.campaign_program_ref)?.ok_or(Error::EntityNotFound)?;
    if program.campaign_ref != event.campaign_ref {
        return Err(invalid(
            "campaign program does not belong to the event's campaign",
        ));
    }
    campaign_program_step(vault, program.program_ref, payload.program_step_ref)?
        .ok_or(Error::EntityNotFound)
}

/// The stable outward-leg identity for this attempt, derived exactly the way
/// ONE-1691 will derive it at dispatch.
fn enrollment_intent_id(
    attempt_id: AttemptId,
    step: &CampaignProgramStep,
) -> Result<Option<IntentId>> {
    let Some(outbound) = step.outbound.as_ref() else {
        return Ok(None);
    };
    derive_intent_id(
        attempt_id,
        outbound.call_seq,
        &step.channel,
        &outbound.verb,
        &crate::outbound_intent_ledger::hash_frozen_payload(&outbound.payload),
    )
    .map(Some)
    .map_err(|_| invalid("campaign enrollment outbound identity is not derivable"))
}

/// Derives the outward call from PERSISTED program state plus the durable
/// attempt id. No caller supplies any of it.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the refs do not cross-bind;
/// [`Error::EntityNotFound`] when they do not resolve.
pub fn derive_enrollment_outbound_request(
    vault: &Vault,
    record: &AttemptRecord,
    payload: &CampaignEnrollmentAttemptPayload,
    event: &CampaignEnrollmentEvent,
    now_ms: u64,
) -> Result<Option<OutboundCallRequest>> {
    let step = resolve_program_step(vault, payload, event)?;
    Ok(step.outbound.map(|outbound| {
        OutboundCallRequest::new(
            record.id,
            outbound.call_seq,
            step.channel,
            outbound.verb,
            outbound.payload,
            now_ms,
        )
    }))
}

/// Runs the outward leg for a claimed enrollment attempt.
///
/// A thin bridge, on purpose. It resolves the same persisted refs the
/// membership leg used, derives the call, and hands it to
/// `outbound_chokepoint::execute_outbound_effect` — the one production lane
/// that combines governance, budget, the ONE-1691 ledger, and transport. It
/// never touches a connector, never opens a second ledger, and never mints a
/// second idempotency scheme.
///
/// The leg is SELF-CONTAINED: it takes only the attempt record, so a process
/// that crashed after the cohort write and before the intent record resumes by
/// calling exactly this, and one that crashed after the send replays the frozen
/// bytes the ledger already holds. `Ok(None)` means the program step declares no
/// outward leg.
///
/// # Errors
///
/// Gate, budget, ledger, and storage failures surface as
/// [`OutboundEffectError`].
// The host driver that pumps this queue is ONE-1778 surface work; until it
// lands the leg has only its oracle. Same posture `gate.rs` takes for the
// crate-visible effect surfaces it exposes ahead of their call sites.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn run_enrollment_outbound_leg<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    attempt: &AttemptRecord,
    transport: &mut T,
    now_ms: u64,
) -> std::result::Result<Option<IntentDispatchResult>, OutboundEffectError> {
    if attempt.kind != CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND {
        return Err(OutboundEffectError::InvalidInput(
            "attempt kind is not campaign.enrollment.macro",
        ));
    }
    let payload = decode_enrollment_attempt_payload(&attempt.payload)?;
    let event = campaign_enrollment_event(vault, payload.membership_event_ref)?
        .ok_or(Error::EntityNotFound)?;
    let step = resolve_program_step(vault, &payload, &event)?;
    let Some(outbound) = step.outbound.as_ref() else {
        return Ok(None);
    };
    let prepared = PreparedEffect {
        attempt_id: attempt.id,
        call_seq: outbound.call_seq,
        server: step.channel.clone(),
        tool: outbound.verb.clone(),
        payload: outbound.payload.clone(),
        idempotency_supported: outbound.idempotency_supported,
        resolved_endpoint: None,
        gate: enrollment_gate_input(&step, outbound, &event),
        budget_class: BudgetClass::Send,
        authorization: PreparedAuthorization::None,
        verified_actor: None,
    };
    let result = execute_outbound_effect(
        vault,
        authority,
        OutboundEffectCommand::New(prepared),
        now_ms,
        transport,
    )?;
    Ok(Some(result.dispatch))
}

/// Gate facts assembled from persisted rows only.
///
/// `has_opted_in`/`has_permission` report the program step's own consent basis
/// and sticky sender — a step cannot exist without both. They are ASSERTIONS
/// about persisted state, not a decision: the gate is still the authority, and
/// CA-06 owns tightening this posture.
#[cfg_attr(not(test), allow(dead_code))]
fn enrollment_gate_input(
    step: &CampaignProgramStep,
    outbound: &CampaignProgramOutbound,
    event: &CampaignEnrollmentEvent,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "agent".to_owned(),
            actor_ref: Some(step.sender_ref.to_hex()),
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(step.sender_ref),
            ..GateProvenanceHandles::default()
        },
        verb: outbound.verb.clone(),
        channel: step.channel.clone(),
        channel_identity_ref: None,
        counterparty: Some(event.entity_ref.to_hex()),
        brief_ref: Some(event.campaign_ref.to_hex()),
        send_ref: Some(event.event_ref.to_hex()),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
    }
}

// ---------------------------------------------------------------------------
// Codecs and small storage helpers
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptPayloadRow {
    schema_version: u32,
    membership_event_ref: String,
    campaign_program_ref: String,
    program_step_ref: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesignationRow {
    schema_version: u32,
    node_id: u64,
    class: String,
    elected_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventRow {
    schema_version: u32,
    query_ref: String,
    campaign_ref: String,
    entity_ref: String,
    owner_actor: String,
    epoch: u64,
    valid_at: u64,
    detected_at: u64,
    transition: String,
    cause: String,
    evidence_hash: String,
    definition_version: u64,
    scope_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextRow {
    schema_version: u32,
    definition_version: u64,
    scope_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramRow {
    schema_version: u32,
    campaign_ref: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramStepRow {
    schema_version: u32,
    channel: String,
    sender_ref: String,
    basis_evidence: String,
    outbound: Option<ProgramOutboundRow>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramOutboundRow {
    call_seq: u64,
    verb: String,
    payload: String,
    idempotency_supported: bool,
}

struct EnrollmentContext {
    definition_version: u64,
    scope_digest: [u8; 32],
}

fn encode_designation(record: CampaignHomeNodeDesignation) -> Result<Vec<u8>> {
    to_row(&DesignationRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        node_id: record.node_id,
        class: record.class.as_str().to_owned(),
        elected_at: record.elected_at,
    })
}

fn decode_designation(raw: &[u8]) -> Result<CampaignHomeNodeDesignation> {
    const CONTEXT: &str = "campaign home-node designation";
    let row: DesignationRow = from_row(raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    if row.node_id == 0 {
        return Err(Error::CorruptedIndex(CONTEXT));
    }
    Ok(CampaignHomeNodeDesignation {
        schema_version: row.schema_version,
        node_id: row.node_id,
        class: CampaignHomeNodeClass::parse(&row.class).ok_or(Error::CorruptedIndex(CONTEXT))?,
        elected_at: row.elected_at,
    })
}

/// Writes the event and the derivation context it establishes in ONE txn: a
/// context row without its event would misroute the next cause, and an event
/// without its context would re-derive `data_change` forever.
fn put_event_with_context(vault: &Vault, event: &CampaignEnrollmentEvent) -> Result<()> {
    let event_bytes = to_row(&EventRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        query_ref: event.query_ref.to_hex(),
        campaign_ref: event.campaign_ref.to_hex(),
        entity_ref: event.entity_ref.to_hex(),
        owner_actor: event.owner_actor.to_hex(),
        epoch: event.epoch,
        valid_at: event.valid_at,
        detected_at: event.detected_at,
        transition: event.transition.as_str().to_owned(),
        cause: event.cause.as_str().to_owned(),
        evidence_hash: hex_lower(&event.evidence_hash),
        definition_version: event.definition_version,
        scope_digest: hex_lower(&event.scope_digest),
    })?;
    let context_bytes = to_row(&ContextRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        definition_version: event.definition_version,
        scope_digest: hex_lower(&event.scope_digest),
    })?;
    let event_key = keyed(ENROLLMENT_EVENT_PREFIX, &[event.event_ref.as_bytes()]);
    let context_key = context_key(event.query_ref, event.entity_ref);
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, &event_key, &event_bytes)
            .map_err(Error::from)?;
        vault
            .store
            .vault_meta
            .put(wtxn, &context_key, &context_bytes)
            .map_err(Error::from)
    })
}

fn decode_event(event_ref: EntityId, raw: &[u8]) -> Result<CampaignEnrollmentEvent> {
    const CONTEXT: &str = "campaign enrollment event";
    let row: EventRow = from_row(raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    Ok(CampaignEnrollmentEvent {
        event_ref,
        query_ref: id_from_hex(&row.query_ref, CONTEXT)?,
        campaign_ref: id_from_hex(&row.campaign_ref, CONTEXT)?,
        entity_ref: id_from_hex(&row.entity_ref, CONTEXT)?,
        owner_actor: id_from_hex(&row.owner_actor, CONTEXT)?,
        epoch: row.epoch,
        valid_at: row.valid_at,
        detected_at: row.detected_at,
        transition: MembershipTransition::parse(&row.transition)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        cause: MembershipCause::parse(&row.cause).ok_or(Error::CorruptedIndex(CONTEXT))?,
        evidence_hash: hash_from_hex(&row.evidence_hash, CONTEXT)?,
        definition_version: row.definition_version,
        scope_digest: hash_from_hex(&row.scope_digest, CONTEXT)?,
    })
}

fn read_context(
    vault: &Vault,
    query_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Option<EnrollmentContext>> {
    const CONTEXT: &str = "campaign enrollment context";
    let Some(raw) = read_meta(vault, &context_key(query_ref, entity_ref))? else {
        return Ok(None);
    };
    let row: ContextRow = from_row(&raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    Ok(Some(EnrollmentContext {
        definition_version: row.definition_version,
        scope_digest: hash_from_hex(&row.scope_digest, CONTEXT)?,
    }))
}

fn encode_program(program: &CampaignProgram) -> Result<Vec<u8>> {
    to_row(&ProgramRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        campaign_ref: program.campaign_ref.to_hex(),
    })
}

fn decode_program(program_ref: EntityId, raw: &[u8]) -> Result<CampaignProgram> {
    const CONTEXT: &str = "campaign program";
    let row: ProgramRow = from_row(raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    Ok(CampaignProgram {
        schema_version: row.schema_version,
        program_ref,
        campaign_ref: id_from_hex(&row.campaign_ref, CONTEXT)?,
    })
}

fn encode_program_step(step: &CampaignProgramStep) -> Result<Vec<u8>> {
    to_row(&ProgramStepRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        channel: step.channel.clone(),
        sender_ref: step.sender_ref.to_hex(),
        basis_evidence: step.basis_evidence.to_hex(),
        outbound: step
            .outbound
            .as_ref()
            .map(|outbound| ProgramOutboundRow {
                call_seq: outbound.call_seq,
                verb: outbound.verb.clone(),
                payload: hex_lower(&outbound.payload),
                idempotency_supported: outbound.idempotency_supported,
            }),
    })
}

fn decode_program_step(
    program_ref: EntityId,
    step_ref: EntityId,
    raw: &[u8],
) -> Result<CampaignProgramStep> {
    const CONTEXT: &str = "campaign program step";
    let row: ProgramStepRow = from_row(raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    let outbound = row
        .outbound
        .map(|outbound| {
            Ok::<_, Error>(CampaignProgramOutbound {
                call_seq: outbound.call_seq,
                verb: outbound.verb,
                payload: bytes_from_hex(&outbound.payload, CONTEXT)?,
                idempotency_supported: outbound.idempotency_supported,
            })
        })
        .transpose()?;
    Ok(CampaignProgramStep {
        schema_version: row.schema_version,
        program_ref,
        step_ref,
        channel: row.channel,
        sender_ref: id_from_hex(&row.sender_ref, CONTEXT)?,
        basis_evidence: id_from_hex(&row.basis_evidence, CONTEXT)?,
        outbound,
    })
}

fn context_key(query_ref: EntityId, entity_ref: EntityId) -> Vec<u8> {
    keyed(
        ENROLLMENT_CONTEXT_PREFIX,
        &[query_ref.as_bytes(), entity_ref.as_bytes()],
    )
}

fn keyed(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + parts.iter().map(|part| part.len()).sum::<usize>());
    key.extend_from_slice(prefix);
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

fn to_row<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| invalid("campaign enrollment row encode failed"))
}

fn from_row<T: serde::de::DeserializeOwned>(raw: &[u8], context: &'static str) -> Result<T> {
    serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex(context))
}

fn pin_schema(schema_version: u32, context: &'static str) -> Result<()> {
    if schema_version == CAMPAIGN_ENROLLMENT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(Error::CorruptedIndex(context))
    }
}

fn id_from_hex(value: &str, context: &'static str) -> Result<EntityId> {
    EntityId::from_hex(value).map_err(|_| Error::CorruptedIndex(context))
}

fn hash_from_hex(value: &str, context: &'static str) -> Result<[u8; 32]> {
    bytes_from_hex(value, context)?
        .try_into()
        .map_err(|_| Error::CorruptedIndex(context))
}

fn bytes_from_hex(value: &str, context: &'static str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::CorruptedIndex(context));
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or(Error::CorruptedIndex(context))?;
        let lo = hex_nibble(pair[1]).ok_or(Error::CorruptedIndex(context))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn read_meta(vault: &Vault, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&rtxn, key)?
        .map(|bytes| bytes.to_vec()))
}

fn put_meta(vault: &Vault, key: &[u8], value: &[u8]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, key, value)
            .map_err(Error::from)
    })
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attempt_queue::AttemptState;
    use crate::config::VaultConfig;
    use crate::outbound_intent_ledger::{
        FrozenOutboundCall, IntentState, OutboundSendOutcome, intent_ledger_records,
    };
    use crate::test_util::{entity, put_policy_manifest_bytes};

    const CHANNEL: &str = "email";
    const VERB: &str = "send";

    fn vault_fixture() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
        (dir, vault)
    }

    /// The host's ordinary policy posture for this sender/channel/verb. The
    /// outward-leg tests must prove the ledger fires INSIDE the existing gate,
    /// so they install a real manifest rather than bypassing governance.
    fn install_send_policy(vault: &Vault, sender_ref: EntityId) {
        vault
            .put_entity(
                &sender_ref,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                b"campaign enrollment sender",
            )
            .expect("seed sender actor");
        let scoped_grant = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("actor_ref"),
                rmpv::Value::from(sender_ref.to_hex()),
            ),
            (
                rmpv::Value::from("effector"),
                rmpv::Value::from(format!("external:{VERB}")),
            ),
            (
                rmpv::Value::from("scope"),
                rmpv::Value::Map(vec![(
                    rmpv::Value::from("channel"),
                    rmpv::Value::from(CHANNEL),
                )]),
            ),
        ]);
        let manifest = rmpv::Value::Map(vec![
            (rmpv::Value::from("schema_version"), rmpv::Value::from("1.1")),
            (
                rmpv::Value::from("pack_id"),
                rmpv::Value::from("campaign-enrollment-test"),
            ),
            (rmpv::Value::from("pack_version"), rmpv::Value::from("v1")),
            (
                rmpv::Value::from("min_engine_version"),
                rmpv::Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                rmpv::Value::from("defaults"),
                rmpv::Value::Map(vec![
                    (
                        rmpv::Value::from("criticality"),
                        rmpv::Value::from("normal"),
                    ),
                    (rmpv::Value::from("sensitivity"), rmpv::Value::from("normal")),
                ]),
            ),
            (rmpv::Value::from("rules"), rmpv::Value::Array(Vec::new())),
            (
                rmpv::Value::from("actor_ceilings"),
                rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                    (
                        rmpv::Value::from("actor_class"),
                        rmpv::Value::from("agent"),
                    ),
                    (
                        rmpv::Value::from("actor_ref"),
                        rmpv::Value::from(sender_ref.to_hex()),
                    ),
                    (rmpv::Value::from("ceiling"), rmpv::Value::from("auto")),
                ])]),
            ),
            (
                rmpv::Value::from("scoped_grants"),
                rmpv::Value::Array(vec![scoped_grant]),
            ),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &manifest).expect("manifest encode");
        put_policy_manifest_bytes(vault, entity(0xD0), &bytes).expect("policy manifest");
    }

    /// Transport that reads the ledger AT SEND TIME. That is the only way to
    /// prove the record exists BEFORE the bytes leave, rather than after.
    struct LedgerWitnessTransport<'a> {
        vault: &'a Vault,
        outcome: OutboundSendOutcome,
        sent_intents: Vec<[u8; 32]>,
        sent_payload_hashes: Vec<[u8; 32]>,
        ledger_rows_at_send: Vec<usize>,
    }

    impl<'a> LedgerWitnessTransport<'a> {
        fn new(vault: &'a Vault, outcome: OutboundSendOutcome) -> Self {
            Self {
                vault,
                outcome,
                sent_intents: Vec::new(),
                sent_payload_hashes: Vec::new(),
                ledger_rows_at_send: Vec::new(),
            }
        }
    }

    impl OutboundTransport for LedgerWitnessTransport<'_> {
        fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
            self.ledger_rows_at_send.push(
                intent_ledger_records(self.vault)
                    .expect("ledger is readable at send time")
                    .len(),
            );
            self.sent_intents.push(
                *call
                    .intent_id()
                    .expect("an effectful frozen call carries its ledger identity"),
            );
            self.sent_payload_hashes.push(*call.payload_hash());
            self.outcome
        }
    }

    struct Fixture {
        event: CampaignEnrollmentEvent,
        payload: CampaignEnrollmentAttemptPayload,
    }

    fn install_fixture(vault: &Vault, outbound: Option<CampaignProgramOutbound>) -> Fixture {
        let campaign_ref = entity(0x41);
        let program_ref = entity(0x51);
        let step_ref = entity(0x52);
        let sender_ref = entity(0x57);
        install_send_policy(vault, sender_ref);
        let event = CampaignEnrollmentEvent {
            event_ref: entity(0x53),
            query_ref: entity(0x54),
            campaign_ref,
            entity_ref: entity(0x55),
            owner_actor: entity(0x56),
            epoch: 1,
            valid_at: 1_000,
            detected_at: 1_000,
            transition: MembershipTransition::Entered,
            cause: MembershipCause::DataChange,
            evidence_hash: [0x11; EVIDENCE_HASH_LEN],
            definition_version: 1,
            scope_digest: [0x22; 32],
        };
        put_event_with_context(vault, &event).expect("event row");
        put_campaign_program(
            vault,
            &CampaignProgram {
                schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
                program_ref,
                campaign_ref,
            },
        )
        .expect("program row");
        put_campaign_program_step(
            vault,
            &CampaignProgramStep {
                schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
                program_ref,
                step_ref,
                channel: CHANNEL.to_owned(),
                sender_ref,
                basis_evidence: entity(0x58),
                outbound,
            },
        )
        .expect("step row");
        Fixture {
            event,
            payload: CampaignEnrollmentAttemptPayload {
                membership_event_ref: entity(0x53),
                campaign_program_ref: program_ref,
                program_step_ref: step_ref,
            },
        }
    }

    fn outbound_step() -> CampaignProgramOutbound {
        CampaignProgramOutbound {
            call_seq: 7,
            verb: VERB.to_owned(),
            payload: b"enrollment-body".to_vec(),
            idempotency_supported: true,
        }
    }

    fn queued_attempt(vault: &Vault, fixture: &Fixture) -> AttemptRecord {
        let runner = CampaignEnrollmentRunner::new(vault);
        match runner
            .enqueue(&fixture.payload, None, 10)
            .expect("enqueue succeeds")
        {
            EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record,
        }
    }

    // -----------------------------------------------------------------------
    // Home-node election
    // -----------------------------------------------------------------------

    #[test]
    fn campaign_home_node_election_matches_preference_order() {
        let designation = select_campaign_home_node(
            &[
                CampaignHomeNodeCandidate::primary_device(2),
                CampaignHomeNodeCandidate::always_on_local(9),
                CampaignHomeNodeCandidate::cloud(7, true),
            ],
            5,
        )
        .expect("election")
        .expect("an eligible candidate exists");
        assert_eq!(designation.class, CampaignHomeNodeClass::CloudAttached);
        assert_eq!(designation.node_id, 7);
        assert_eq!(designation.elected_at, 5);

        // A DETACHED cloud node is ineligible, not demoted: it does not become
        // a local candidate just because the cloud link dropped.
        let without_cloud = select_campaign_home_node(
            &[
                CampaignHomeNodeCandidate::cloud(7, false),
                CampaignHomeNodeCandidate::primary_device(2),
                CampaignHomeNodeCandidate::always_on_local(9),
            ],
            5,
        )
        .expect("election")
        .expect("an eligible candidate exists");
        assert_eq!(without_cloud.class, CampaignHomeNodeClass::AlwaysOnLocal);
        assert_eq!(without_cloud.node_id, 9);

        // Lowest stable node id wins inside a tier, whatever the input order.
        let tie = select_campaign_home_node(
            &[
                CampaignHomeNodeCandidate::always_on_local(9),
                CampaignHomeNodeCandidate::always_on_local(3),
                CampaignHomeNodeCandidate::always_on_local(6),
            ],
            5,
        )
        .expect("election")
        .expect("an eligible candidate exists");
        assert_eq!(tie.node_id, 3);

        assert_eq!(
            select_campaign_home_node(&[CampaignHomeNodeCandidate::cloud(7, false)], 5)
                .expect("election"),
            None,
            "an all-ineligible set clears the designation"
        );
    }

    #[test]
    fn campaign_home_node_election_rejects_unusable_candidate_sets() {
        assert!(matches!(
            select_campaign_home_node(&[CampaignHomeNodeCandidate::always_on_local(0)], 1),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            select_campaign_home_node(
                &[
                    CampaignHomeNodeCandidate::always_on_local(4),
                    CampaignHomeNodeCandidate::primary_device(4),
                ],
                1
            ),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn campaign_designation_persists_under_the_campaign_key_only() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        let elected = elect_campaign_home_node_designation(
            &vault,
            &[CampaignHomeNodeCandidate::always_on_local(11)],
            42,
        )?
        .expect("a candidate is eligible");

        assert_eq!(campaign_home_node_designation(&vault)?, Some(elected));
        assert!(
            read_meta(&vault, b"dreamer:home_node_macro:v1")?.is_none(),
            "the Dreamer's private designation key must be untouched"
        );

        // An empty candidate set clears the row rather than freezing a leader
        // that no longer exists.
        assert_eq!(
            elect_campaign_home_node_designation(&vault, &[], 43)?,
            None
        );
        assert_eq!(campaign_home_node_designation(&vault)?, None);
        Ok(())
    }

    #[test]
    fn campaign_designation_row_fails_closed_on_malformed_input() {
        assert!(matches!(
            decode_designation(br#"{"schema_version":1,"node_id":3,"class":"always_on_local","elected_at":1,"extra":true}"#),
            Err(Error::CorruptedIndex(_))
        ));
        assert!(matches!(
            decode_designation(
                br#"{"schema_version":2,"node_id":3,"class":"always_on_local","elected_at":1}"#
            ),
            Err(Error::CorruptedIndex(_))
        ));
        assert!(matches!(
            decode_designation(
                br#"{"schema_version":1,"node_id":3,"class":"tertiary_toaster","elected_at":1}"#
            ),
            Err(Error::CorruptedIndex(_))
        ));
        assert!(matches!(
            decode_designation(br#"{"schema_version":1,"node_id":0,"class":"cloud_attached","elected_at":1}"#),
            Err(Error::CorruptedIndex(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Payload
    // -----------------------------------------------------------------------

    #[test]
    fn enrollment_attempt_payload_is_three_refs_and_nothing_else() -> Result<()> {
        let payload = CampaignEnrollmentAttemptPayload {
            membership_event_ref: entity(0x81),
            campaign_program_ref: entity(0x82),
            program_step_ref: entity(0x83),
        };
        let encoded = encode_enrollment_attempt_payload(&payload)?;
        assert_eq!(decode_enrollment_attempt_payload(&encoded)?, payload);

        let wire: serde_json::Value = serde_json::from_slice(&encoded).expect("payload is json");
        let keys: Vec<&str> = wire
            .as_object()
            .expect("payload is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "schema_version",
                "membership_event_ref",
                "campaign_program_ref",
                "program_step_ref"
            ],
            "no cause, epoch, evidence hash, timestamp, enrolled flag, or \
             outbound request may ride the queue"
        );

        // A payload that smuggles a cause is rejected outright, not ignored.
        assert!(matches!(
            decode_enrollment_attempt_payload(
                br#"{"schema_version":1,"membership_event_ref":"00","campaign_program_ref":"00","program_step_ref":"00","cause":"data_change"}"#
            ),
            Err(Error::CorruptedIndex(_))
        ));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Outward leg
    // -----------------------------------------------------------------------

    #[test]
    fn outward_enrollment_records_intent_before_transport() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        let fixture = install_fixture(&vault, Some(outbound_step()));
        let attempt = queued_attempt(&vault, &fixture);
        let authority = OutboundBindingAuthority::for_vault(&vault)?;
        let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);

        let dispatch = run_enrollment_outbound_leg(&vault, &authority, &attempt, &mut transport, 50)
            .expect("outbound leg")
            .expect("the step declares an outward leg");

        assert_eq!(transport.ledger_rows_at_send, vec![1]);
        assert_eq!(dispatch.state, Some(IntentState::Done));
        assert!(!dispatch.replayed);
        let records = intent_ledger_records(&vault).expect("ledger");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].attempt_id, attempt.id);
        assert_eq!(records[0].call_seq, 7);
        assert_eq!(transport.sent_intents, vec![records[0].id]);
        Ok(())
    }

    #[test]
    fn outward_intent_uses_durable_attempt_and_call_sequence() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        let fixture = install_fixture(&vault, Some(outbound_step()));
        let attempt = queued_attempt(&vault, &fixture);

        let step = resolve_program_step(&vault, &fixture.payload, &fixture.event)?;
        let derived = enrollment_intent_id(attempt.id, &step)?.expect("an outward leg exists");

        // Clock-free and process-free: recomputing from the same durable inputs
        // reproduces the identity a restarted process would use.
        assert_eq!(
            derived,
            derive_intent_id(
                attempt.id,
                7,
                CHANNEL,
                VERB,
                &crate::outbound_intent_ledger::hash_frozen_payload(b"enrollment-body"),
            )
            .expect("intent id")
        );

        let authority = OutboundBindingAuthority::for_vault(&vault)?;
        let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);
        let dispatch = run_enrollment_outbound_leg(&vault, &authority, &attempt, &mut transport, 50)
            .expect("outbound leg")
            .expect("the step declares an outward leg");
        assert_eq!(dispatch.intent_id, Some(derived));

        let request = derive_enrollment_outbound_request(
            &vault,
            &attempt,
            &fixture.payload,
            &fixture.event,
            50,
        )?
        .expect("an outward leg exists");
        assert_eq!(request.attempt_id, attempt.id);
        assert_eq!(request.call_seq, 7);
        Ok(())
    }

    #[test]
    fn crash_after_send_before_queue_complete_reuses_the_frozen_intent() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        let fixture = install_fixture(&vault, Some(outbound_step()));
        let attempt = queued_attempt(&vault, &fixture);
        let authority = OutboundBindingAuthority::for_vault(&vault)?;

        let mut first = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Ambiguous);
        let ambiguous =
            run_enrollment_outbound_leg(&vault, &authority, &attempt, &mut first, 50)
                .expect("outbound leg")
                .expect("the step declares an outward leg");
        assert_eq!(ambiguous.state, Some(IntentState::Pending));

        // The recovery path re-enters with the SAME attempt row. It must reuse
        // the frozen bytes and identity, never mint a fresh send.
        let mut second = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);
        let replay = run_enrollment_outbound_leg(&vault, &authority, &attempt, &mut second, 60)
            .expect("outbound leg")
            .expect("the step declares an outward leg");
        assert!(replay.replayed);
        assert_eq!(replay.intent_id, ambiguous.intent_id);
        assert_eq!(second.sent_intents, first.sent_intents);
        assert_eq!(second.sent_payload_hashes, first.sent_payload_hashes);
        assert_eq!(
            intent_ledger_records(&vault).expect("ledger").len(),
            1,
            "recovery must not open a second intent"
        );
        Ok(())
    }

    #[test]
    fn outward_leg_is_absent_when_the_program_step_declares_none() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        let fixture = install_fixture(&vault, None);
        let attempt = queued_attempt(&vault, &fixture);
        let authority = OutboundBindingAuthority::for_vault(&vault)?;
        let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);

        assert!(
            run_enrollment_outbound_leg(&vault, &authority, &attempt, &mut transport, 50)
                .expect("outbound leg")
                .is_none()
        );
        assert!(transport.sent_intents.is_empty());
        assert!(intent_ledger_records(&vault).expect("ledger").is_empty());
        Ok(())
    }

    #[test]
    fn gate_rejection_prevents_a_direct_send() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        // The installed policy grants `external:send` on this channel and
        // nothing else. A step declaring an UNGRANTED verb must be stopped by
        // the ordinary gate — not by a campaign-local check, and not at all.
        let fixture = install_fixture(
            &vault,
            Some(CampaignProgramOutbound {
                call_seq: 7,
                verb: "call".to_owned(),
                payload: b"enrollment-body".to_vec(),
                idempotency_supported: true,
            }),
        );
        let attempt = queued_attempt(&vault, &fixture);
        let authority = OutboundBindingAuthority::for_vault(&vault)?;
        let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);

        let dispatch = run_enrollment_outbound_leg(&vault, &authority, &attempt, &mut transport, 50)
            .expect("outbound leg")
            .expect("the step declares an outward leg");

        assert_eq!(dispatch.state, None);
        assert_eq!(dispatch.send_outcome, None);
        assert!(transport.sent_intents.is_empty(), "no connector was reached");
        assert!(
            intent_ledger_records(&vault).expect("ledger").is_empty(),
            "a refused effect leaves no frozen intent behind"
        );
        Ok(())
    }

    #[test]
    fn outward_leg_refuses_a_foreign_attempt_kind() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        let fixture = install_fixture(&vault, Some(outbound_step()));
        let mut attempt = queued_attempt(&vault, &fixture);
        attempt.kind = "dreamer.consolidation.macro".to_owned();
        let authority = OutboundBindingAuthority::for_vault(&vault)?;
        let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);

        assert!(
            run_enrollment_outbound_leg(&vault, &authority, &attempt, &mut transport, 50).is_err()
        );
        assert!(transport.sent_intents.is_empty());
        Ok(())
    }

    #[test]
    fn mismatched_program_refs_fail_closed() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        let fixture = install_fixture(&vault, Some(outbound_step()));

        // A program belonging to a DIFFERENT campaign must not be usable just
        // because the caller pointed the payload at it.
        let foreign_program = entity(0x61);
        put_campaign_program(
            &vault,
            &CampaignProgram {
                schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
                program_ref: foreign_program,
                campaign_ref: entity(0x62),
            },
        )?;
        let crossed = CampaignEnrollmentAttemptPayload {
            campaign_program_ref: foreign_program,
            ..fixture.payload
        };
        assert!(matches!(
            resolve_program_step(&vault, &crossed, &fixture.event),
            Err(Error::InvalidConfig(_))
        ));

        // A step ref that does not resolve under the program is not silently
        // skipped either.
        let dangling = CampaignEnrollmentAttemptPayload {
            program_step_ref: entity(0x63),
            ..fixture.payload
        };
        assert!(matches!(
            resolve_program_step(&vault, &dangling, &fixture.event),
            Err(Error::EntityNotFound)
        ));
        Ok(())
    }

    #[test]
    fn enqueue_refuses_an_unresolvable_membership_ref() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        let runner = CampaignEnrollmentRunner::new(&vault);
        assert!(matches!(
            runner.enqueue(
                &CampaignEnrollmentAttemptPayload {
                    membership_event_ref: entity(0x71),
                    campaign_program_ref: entity(0x72),
                    program_step_ref: entity(0x73),
                },
                None,
                1,
            ),
            Err(Error::EntityNotFound)
        ));
        Ok(())
    }

    #[test]
    fn enqueued_attempt_uses_exactly_the_one_kind() -> Result<()> {
        let (_dir, vault) = vault_fixture();
        let fixture = install_fixture(&vault, Some(outbound_step()));
        let attempt = queued_attempt(&vault, &fixture);
        assert_eq!(attempt.kind, "campaign.enrollment.macro");
        assert_eq!(attempt.kind, CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND);
        assert_eq!(attempt.state, AttemptState::Queued);
        assert_eq!(
            decode_enrollment_attempt_payload(&attempt.payload)?,
            fixture.payload
        );
        Ok(())
    }
}
