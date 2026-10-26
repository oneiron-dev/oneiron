use crate::ports::EntityStoreRead;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::campaign::claims::{
    CampaignMemberDerivation, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    decode_campaign_member_value, decode_member_recorded_exit, encode_campaign_member_value,
    encode_member_recorded_exit,
};
use crate::campaign::enrollment::{
    IntakeSource, Reconciled, effective_member_in_txn, keep_isolation_stamps, reconcile,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, decode_claim_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;

use super::evidence::EVIDENCE_HASH_LEN;
use super::storage::{
    MEMBERSHIP_EVENTS, WATERMARK, Watermark, encode_event, encode_member_value_bytes,
    event_pair_prefix, read_watermark,
};
use super::support::hash_bytes;

/// Why a membership transition happened. A CLOSED set: an unknown cause fails
/// decoding rather than becoming an opaque token nobody can route on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipCause {
    /// The entity's own evidence moved.
    DataChange,
    /// The owner's effective reach moved.
    ScopeChange,
    /// The query definition moved.
    DefinitionChange,
}

impl MembershipCause {
    /// Every cause, in wire order.
    pub const ALL: [Self; 3] = [Self::DataChange, Self::ScopeChange, Self::DefinitionChange];

    /// Wire token for this cause.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DataChange => "data_change",
            Self::ScopeChange => "scope_change",
            Self::DefinitionChange => "definition_change",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|cause| cause.as_str() == value)
    }
}

/// Direction of a membership transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipTransition {
    /// The entity joined the cohort.
    Entered,
    /// The entity left the cohort.
    Exited,
}

impl MembershipTransition {
    /// Wire token for this transition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entered => "entered",
            Self::Exited => "exited",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "entered" => Some(Self::Entered),
            "exited" => Some(Self::Exited),
            _ => None,
        }
    }
}

/// One entered/exited event row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEvent {
    /// Query that derived the transition.
    pub query_ref: EntityId,
    /// Campaign the membership is scoped to.
    pub campaign_ref: EntityId,
    /// Entity whose membership changed.
    pub entity_ref: EntityId,
    /// Monotonic per-(query, campaign, entity) epoch.
    pub epoch: u64,
    /// When the transition became true.
    pub valid_at: u64,
    /// When the engine detected it.
    pub detected_at: u64,
    /// Direction.
    pub transition: MembershipTransition,
    /// Cause.
    pub cause: MembershipCause,
    /// Evidence the verdict was derived from.
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
}

/// An event plus the CA-01 claim value it must be written with.
///
/// ONE-1774 builds this after home-node admission and hands it to
/// [`commit_membership_plan`]; the two halves travel together so the commit can
/// prove they agree before either lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipWritePlan {
    /// The event row.
    pub event: MembershipEvent,
    /// The `campaign.member` value, carrying the matching derivation.
    pub value: CampaignMemberValue,
}

/// What a commit did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipCommitOutcome {
    /// The plan landed.
    Applied,
    /// The exact same plan had already landed at this epoch.
    AlreadyApplied,
    /// The plan's epoch is behind the watermark, or conflicts with it.
    RejectedStaleEpoch {
        /// Watermark that rejected the plan.
        current_epoch: u64,
    },
    /// The event, its epoch and its new channels landed on the person's one
    /// membership, whose own paused, suppressed or exited state holds
    /// (FIX 9664): nothing outward is owed.
    RecordedOnly,
    /// As [`Self::RecordedOnly`], for a saved pause whose wake falls due at
    /// `until` (FIX 9662).
    DeferredUntil {
        /// When the saved wake falls due.
        until: u64,
    },
}

/// The next epoch a transition on this `(query, entity)` pair may claim in
/// `campaign_ref`. Each campaign a query feeds holds its own sequence.
///
/// Re-entry after exit is a NEW epoch, never a resurrection of the old one, and
/// this is the only door that mints one. The floor is
/// `current_watermark`-derived, so a node that was promoted to home after a
/// failover continues the sequence its peers already replicated instead of
/// restarting at 1 against `campaign.member` claims that carry later epochs.
///
/// # Errors
///
/// Storage errors propagate; [`Error::ArithmeticOverflow`] at `u64::MAX`.
pub fn next_membership_epoch(
    vault: &Vault,
    query_ref: EntityId,
    campaign_ref: EntityId,
    entity_ref: EntityId,
) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let current = current_watermark(vault, &rtxn, query_ref, campaign_ref, entity_ref)?;
    current.map_or(Ok(1), |(epoch, _)| {
        epoch
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("membership epoch"))
    })
}

/// Commits one membership transition atomically.
///
/// Watermark-guarded, not dedupe-guarded. The distinction is the whole point:
/// a queue that de-duplicates by payload would report a REPLAYED `Entered` from
/// before an exit as "already applied" and leave the cohort holding a
/// resurrected member. Here the compare is against a monotonic watermark inside
/// the same transaction as the write, so a stale `Entered` after exit/re-entry
/// is [`MembershipCommitOutcome::RejectedStaleEpoch`], never `AlreadyApplied`.
///
/// The watermark and the epoch are per query; the membership is per person
/// and campaign (FIX 9664, 10221). The writer reads every admitted live head
/// of the person in the campaign, whatever its source (another query, a
/// manual enrollment, a re-entry), reconciles the plan into one value and
/// supersedes them all in the same transaction, keeping the replaced head's
/// isolation stamps, each held channel with its basis and sticky sender, and
/// the person's own pause, suppression or exit (FIX 9662, 9663). The event and
/// the watermark land whenever the epoch is new, also when the membership's
/// state holds ([`MembershipCommitOutcome::RecordedOnly`],
/// [`MembershipCommitOutcome::DeferredUntil`]): evidence left unrecorded
/// would be detected again after a pause and read as a new trigger.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the event and the claim value disagree;
/// claim-validation and storage errors propagate.
pub fn commit_membership_plan(
    vault: &Vault,
    plan: &MembershipWritePlan,
    now: u64,
) -> Result<MembershipCommitOutcome> {
    validate_plan_coherence(plan)?;
    let content = plan_content_digest(plan)?;
    let event = &plan.event;
    let source = IntakeSource::Query {
        query_ref: event.query_ref,
        transition: event.transition,
        detected_at: event.detected_at,
    };
    vault.with_write_txn_grouped(|wtxn| {
        let watermark = current_watermark(
            vault,
            wtxn,
            event.query_ref,
            event.campaign_ref,
            event.entity_ref,
        )?;
        if let Some(outcome) = watermark_verdict(watermark, event.epoch, &content) {
            return Ok(outcome);
        }
        // Every admitted head, from every source, is read BEFORE the
        // replacement lands, so the replacement is never its own competition
        // and one effective head remains.
        let effective = effective_member_in_txn(vault, wtxn, event.entity_ref, event.campaign_ref)?;
        let reconciled = reconcile(effective.as_ref(), &plan.value, &source, now);
        let mut claim_body = ClaimBody::new(
            PREDICATE_CAMPAIGN_MEMBER,
            ClaimSubject::Entity(event.entity_ref),
            encode_campaign_member_value(&reconciled.value),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?;
        if let Some(effective) = &effective {
            keep_isolation_stamps(&mut claim_body, &effective.body);
        }
        // A foreign exit recorded on another source's membership rides as
        // the head's evidence, so its spent epoch still replicates.
        claim_body.evidence = reconciled
            .recorded_exit
            .as_ref()
            .map(encode_member_recorded_exit);
        WATERMARK.put(
            &vault.store,
            wtxn,
            &(event.query_ref, event.entity_ref, event.campaign_ref),
            &Watermark {
                epoch: event.epoch,
                content,
            },
        )?;
        MEMBERSHIP_EVENTS.put(
            &vault.store,
            wtxn,
            &(
                event.query_ref,
                event.entity_ref,
                (event.campaign_ref, event.epoch),
            ),
            event,
        )?;
        let claim_id = vault.store.clock.entity_id()?;
        // A kept state keeps the instant it began, so a pause still knows
        // which events came after it.
        let start = reconciled.kept_since.unwrap_or(event.valid_at);
        vault.put_claim_in_txn(
            wtxn,
            &claim_id,
            &claim_body,
            TimeRange { start, end: start },
            now,
        )?;
        // A transition REPLACES the cohort head; it does not add a second one.
        // Without this, Entered(1) -> Exited(2) -> Entered(3) would leave three
        // live `campaign.member` claims on the person carrying mutually
        // incompatible states, and `claims_for_subject` would expose all three
        // as current truth. Same-txn supersession is the CA-01 `crm.stage`
        // pattern: a rejection rolls the replacement back with it.
        for old_id in effective.iter().flat_map(|member| &member.heads) {
            vault.supersede_claim_in_txn(wtxn, &claim_id, old_id, now)?;
        }
        Ok(match reconciled.outcome {
            Reconciled::Applied => MembershipCommitOutcome::Applied,
            Reconciled::RecordedOnly => MembershipCommitOutcome::RecordedOnly,
            Reconciled::DeferredUntil(until) => MembershipCommitOutcome::DeferredUntil { until },
        })
    })
}

/// `None` means "proceed"; `Some` is the terminal outcome.
///
/// `stored` is the content digest of the plan the watermark records, and is
/// absent when the watermark came from the replicated claim chain rather than
/// this node's own row. An unprovable retry is a stale epoch, never
/// `AlreadyApplied`: reporting success for a plan this node cannot show it
/// applied is the one answer the watermark exists to prevent.
pub(super) fn watermark_verdict(
    watermark: Option<(u64, Option<[u8; EVIDENCE_HASH_LEN]>)>,
    epoch: u64,
    content: &[u8; EVIDENCE_HASH_LEN],
) -> Option<MembershipCommitOutcome> {
    let (current_epoch, stored) = watermark?;
    if epoch > current_epoch {
        return None;
    }
    if epoch == current_epoch && stored == Some(*content) {
        return Some(MembershipCommitOutcome::AlreadyApplied);
    }
    Some(MembershipCommitOutcome::RejectedStaleEpoch { current_epoch })
}

/// Decodes the `campaign.member` claim at `claim_id`, or `None` when the row is
/// absent, is not a CLAIM, or carries another predicate.
fn member_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
) -> Result<Option<(ClaimBody, CampaignMemberValue)>> {
    let Some(raw) = vault
        .store
        .port_entity_record(txn, claim_id)?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("saved query member claim header"));
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.predicate != PREDICATE_CAMPAIGN_MEMBER {
        return Ok(None);
    }
    let value = decode_campaign_member_value(&body.value)?;
    Ok(Some((body, value)))
}

/// Proves the event and the CA-01 claim value describe the same transition.
fn validate_plan_coherence(plan: &MembershipWritePlan) -> Result<()> {
    let event = &plan.event;
    if plan.value.campaign != event.campaign_ref {
        return Err(Error::InvalidClaimBody(
            "membership plan campaign does not match the event",
        ));
    }
    let derivation = plan
        .value
        .derivation
        .as_ref()
        .ok_or(Error::InvalidClaimBody(
            "derived membership requires a derivation",
        ))?;
    if derivation.source_query != event.query_ref
        || derivation.evidence_hash != event.evidence_hash
        || derivation.epoch != event.epoch
    {
        return Err(Error::InvalidClaimBody(
            "membership derivation does not match the event",
        ));
    }
    let exited = plan.value.state == CampaignMemberState::Exited;
    if (event.transition == MembershipTransition::Exited) != exited {
        return Err(Error::InvalidClaimBody(
            "membership transition does not match the member state",
        ));
    }
    Ok(())
}

/// Digest over everything a replay must reproduce EXACTLY to count as the same
/// plan. Two plans that differ anywhere here are different plans at the same
/// epoch, which is a conflict rather than a retry.
fn plan_content_digest(plan: &MembershipWritePlan) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.saved_query.plan.v1");
    hash_bytes(&mut hasher, &encode_event(&plan.event)?);
    hash_bytes(&mut hasher, &encode_member_value_bytes(&plan.value)?);
    Ok(hasher.finalize().into())
}

/// Builds the CA-01 member value for a derived membership.
///
/// The derivation is composed HERE, from the event, so the two cannot drift:
/// a caller that hand-built both halves could put a different epoch in each.
#[must_use]
pub fn derived_member_value(
    event: &MembershipEvent,
    state: CampaignMemberState,
    channels: Vec<crate::campaign::claims::CampaignMemberChannel>,
) -> CampaignMemberValue {
    CampaignMemberValue {
        campaign: event.campaign_ref,
        state,
        channels,
        derivation: Some(CampaignMemberDerivation {
            source_query: event.query_ref,
            evidence_hash: event.evidence_hash,
            epoch: event.epoch,
        }),
    }
}

/// Reads the entered/exited history for one `(query, entity)` pair across
/// every campaign the query feeds, grouped by campaign and oldest epoch first
/// within each; a reader takes a campaign's own rows by `campaign_ref`.
/// History is preserved: a re-entry appends, it never rewrites.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn membership_events(
    vault: &Vault,
    query_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Vec<MembershipEvent>> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = event_pair_prefix(&query_ref, &entity_ref);
    Ok(MEMBERSHIP_EVENTS
        .scan_from(&vault.store, &rtxn, &prefix)?
        .into_iter()
        .map(|(_, event)| event)
        .collect())
}

/// The epoch floor this `(query, entity)` pair may not write at or below in
/// `campaign_ref`.
///
/// `vault_meta` does not replicate, so the local watermark row alone is a
/// node-local opinion: a peer promoted to home after a failover would read
/// `None` and restart at epoch 1 while the replicated `campaign.member` claims
/// already carry later epochs. The CA-01 derivation carries the epoch on a
/// claim that DOES replicate, so the claim chain is the convergent floor and
/// the local row is only the fast path that can also prove content equality.
fn current_watermark(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    campaign_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Option<(u64, Option<[u8; EVIDENCE_HASH_LEN]>)>> {
    let local = read_watermark(vault, txn, query_ref, entity_ref, campaign_ref)?;
    let replicated = replicated_epoch_floor(vault, txn, query_ref, campaign_ref, entity_ref)?;
    Ok(match (local, replicated) {
        (None, None) => None,
        (Some((epoch, content)), None) => Some((epoch, Some(content))),
        (None, Some(floor)) => Some((floor, None)),
        (Some((epoch, content)), Some(floor)) => {
            if floor > epoch {
                Some((floor, None))
            } else {
                Some((epoch, Some(content)))
            }
        }
    })
}

/// Highest epoch any replicated `campaign.member` claim on `entity_ref` carries
/// for `query_ref` in `campaign_ref`, in its derivation or its recorded exit.
/// Every lifecycle counts: a superseded head still proves its epoch was spent.
fn replicated_epoch_floor(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    campaign_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Option<u64>> {
    let mut floor = None;
    for claim_id in vault.claims_for_subject_in_txn(txn, &entity_ref)? {
        let Some((body, value)) = member_claim_in_txn(vault, txn, &claim_id)? else {
            continue;
        };
        if value.campaign != campaign_ref {
            continue;
        }
        let recorded_exit = decode_member_recorded_exit(body.evidence.as_ref())?;
        for derivation in value.derivation.iter().chain(recorded_exit.iter()) {
            if derivation.source_query == query_ref {
                floor = floor.max(Some(derivation.epoch));
            }
        }
    }
    Ok(floor)
}
