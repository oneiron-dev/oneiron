use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::campaign::claims::{
    CampaignMemberDerivation, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    decode_campaign_member_value, encode_campaign_member_value,
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
    decode_event, encode_event, encode_member_value_bytes, encode_watermark, keys, read_watermark,
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
    /// Monotonic per-(query, entity) epoch.
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
}

/// The next epoch a transition on this `(query, entity)` pair may claim.
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
    entity_ref: EntityId,
) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let current = current_watermark(vault, &rtxn, query_ref, entity_ref)?;
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
    let claim_body = ClaimBody::new(
        PREDICATE_CAMPAIGN_MEMBER,
        ClaimSubject::Entity(event.entity_ref),
        encode_campaign_member_value(&plan.value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let encoded_event = encode_event(event)?;
    vault.with_write_txn(|wtxn| {
        let watermark = current_watermark(vault, wtxn, event.query_ref, event.entity_ref)?;
        if let Some(outcome) = watermark_verdict(watermark, event.epoch, &content) {
            return Ok(outcome);
        }
        // The prior heads are read BEFORE the replacement lands, so the
        // replacement is never its own competition.
        let superseded = live_member_heads_in_txn(
            vault,
            wtxn,
            event.query_ref,
            event.campaign_ref,
            event.entity_ref,
        )?;
        vault.store.vault_meta.put(
            wtxn,
            &keys::watermark(&event.query_ref, &event.entity_ref),
            &encode_watermark(event.epoch, &content),
        )?;
        vault.store.vault_meta.put(
            wtxn,
            &keys::event(&event.query_ref, &event.entity_ref, event.epoch),
            &encoded_event,
        )?;
        let claim_id = EntityId::now();
        vault.put_claim_in_txn(
            wtxn,
            &claim_id,
            &claim_body,
            TimeRange {
                start: event.valid_at,
                end: event.valid_at,
            },
            now,
        )?;
        // A transition REPLACES the cohort head; it does not add a second one.
        // Without this, Entered(1) -> Exited(2) -> Entered(3) would leave three
        // live `campaign.member` claims on the person carrying mutually
        // incompatible states, and `claims_for_subject` would expose all three
        // as current truth. Same-txn supersession is the CA-01 `crm.stage`
        // pattern: a rejection rolls the replacement back with it.
        for old_id in superseded {
            vault.supersede_claim_in_txn(wtxn, &claim_id, &old_id, now)?;
        }
        Ok(MembershipCommitOutcome::Applied)
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

/// Live `campaign.member` claim ids on `entity_ref` derived from this
/// `(query, campaign)` pair — the heads a new transition must close.
fn live_member_heads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    campaign_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Vec<EntityId>> {
    let mut heads = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(txn, &entity_ref)? {
        let Some((body, value)) = member_claim_in_txn(vault, txn, &claim_id)? else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active || value.campaign != campaign_ref {
            continue;
        }
        if value
            .derivation
            .is_some_and(|derivation| derivation.source_query == query_ref)
        {
            heads.push(claim_id);
        }
    }
    Ok(heads)
}

/// Decodes the `campaign.member` claim at `claim_id`, or `None` when the row is
/// absent, is not a CLAIM, or carries another predicate.
fn member_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
) -> Result<Option<(ClaimBody, CampaignMemberValue)>> {
    let Some(raw) = vault.store.entities.get(txn, claim_id.as_bytes())? else {
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

/// Reads the entered/exited history for one `(query, entity)` pair, oldest
/// epoch first. History is preserved: a re-entry appends, it never rewrites.
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
    let prefix = keys::event_prefix(&query_ref, &entity_ref);
    let mut events = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
        let (_, value) = row?;
        events.push(decode_event(&value)?);
    }
    Ok(events)
}

/// The epoch floor this `(query, entity)` pair may not write at or below.
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
    entity_ref: EntityId,
) -> Result<Option<(u64, Option<[u8; EVIDENCE_HASH_LEN]>)>> {
    let local = read_watermark(vault, txn, query_ref, entity_ref)?;
    let replicated = replicated_epoch_floor(vault, txn, query_ref, entity_ref)?;
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
/// for `query_ref`. Every lifecycle counts: a superseded head still proves its
/// epoch was spent.
fn replicated_epoch_floor(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Option<u64>> {
    let mut floor = None;
    for claim_id in vault.claims_for_subject_in_txn(txn, &entity_ref)? {
        let Some((_, value)) = member_claim_in_txn(vault, txn, &claim_id)? else {
            continue;
        };
        if let Some(derivation) = value.derivation
            && derivation.source_query == query_ref
        {
            floor = floor.max(Some(derivation.epoch));
        }
    }
    Ok(floor)
}
