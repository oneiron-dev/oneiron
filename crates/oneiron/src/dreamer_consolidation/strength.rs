//! Consolidation strength observations and an archive-only lifecycle (OF-216).
//! Evidence is counted at the gated promotion door, never from child agreement.
//! The score orders selection; it never changes confidence or judges a belief.

use super::evidence::VerifiedEvidenceSet;
use super::selection::{SelectionConfig, StrengthSignals, strength_score};
use super::watermark::decode_turn_body;
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ScopedReadActorKey};
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault, WriteActor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const OBSERVATIONS: SideTable<EntityId, StrengthObservations, Named> =
    SideTable::new(&side_table::DREAMER_CONSOLIDATION_STRENGTH);
const POLICY: SideTable<(), ConsolidationStrengthPolicy, Named> =
    SideTable::new(&side_table::DREAMER_CONSOLIDATION_STRENGTH_POLICY);
const ARCHIVES: SideTable<(EntityId, u64), ConsolidationStrengthSnapshot, Named> =
    SideTable::new(&side_table::DREAMER_CONSOLIDATION_STRENGTH_ARCHIVE);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationStrengthPolicy {
    /// Only a score strictly below this row can archive a quiet claim.
    pub archive_below: f64,
    /// Minimum time without newly observed independent evidence, in milliseconds.
    pub quiet_ms: u64,
}
impl Default for ConsolidationStrengthPolicy {
    fn default() -> Self {
        serde_json::from_str(include_str!("strength_defaults.json"))
            .expect("checked consolidation strength defaults")
    }
}
impl ConsolidationStrengthPolicy {
    fn validate(&self) -> Result<()> {
        if !self.archive_below.is_finite()
            || !(0.0..=1.0).contains(&self.archive_below)
            || self.quiet_ms == 0
        {
            return Err(Error::InvalidConfig(
                "invalid consolidation strength policy".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrengthSource {
    source: EntityId,
    hash: [u8; 32],
    revision: [u8; 32],
    learned_at_ms: u64,
    diversity: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrengthObservations {
    predicate: String,
    last_activity_ms: u64,
    sources: Vec<StrengthSource>,
}

/// The pre-archive revision and policy, co-committed with the local marker.
/// The revision's complete bytes and indexes remain in the entity store; no
/// second copy of claim text is put beyond the ordinary erase doors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationStrengthSnapshot {
    pub attempt: AttemptId,
    pub at_ms: u64,
    pub revision: [u8; 32],
    pub signals: StrengthSignals,
    pub score: f64,
    pub selection: SelectionConfig,
    pub policy: ConsolidationStrengthPolicy,
}

impl Vault {
    /// Operator configuration, separate from epistemic confidence and its policy.
    pub fn set_consolidation_strength_policy(
        &self,
        policy: &ConsolidationStrengthPolicy,
    ) -> Result<()> {
        policy.validate()?;
        self.with_write_txn_grouped(|txn| POLICY.put(&self.store, txn, &(), policy))
    }

    /// A holder of `engine.controls` sets the consolidation strength policy (untangle 6.6b; maintenance cadence),
    /// through the one check, with a receipt naming it. Returns the receipt.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` when `holder` holds no live `engine.controls`; the
    /// row's own validation; store failures.
    pub fn set_consolidation_strength_policy_as_holder(
        &self,
        holder: EntityId,
        policy: &ConsolidationStrengthPolicy,
    ) -> Result<EntityId> {
        policy.validate()?;
        self.apply_engine_control(
            crate::federation::EngineControlActor::Holder(holder),
            crate::federation::EngineControlClass::MaintenanceCadence,
            "DREAMER_CONSOLIDATION_STRENGTH_POLICY",
            &crate::federation::rendered_change(policy)?,
            |txn| POLICY.put(&self.store, txn, &(), policy),
        )
    }
    pub fn consolidation_strength_policy(&self) -> Result<ConsolidationStrengthPolicy> {
        let txn = self.store.env.read_txn()?;
        policy_in_txn(self, &txn)
    }
    pub fn consolidation_strength_snapshots(
        &self,
        claim: &EntityId,
    ) -> Result<Vec<ConsolidationStrengthSnapshot>> {
        let txn = self.store.env.read_txn()?;
        Ok(ARCHIVES
            .scan_from(&self.store, &txn, claim.as_bytes())?
            .into_iter()
            .map(|(_, snapshot)| snapshot)
            .collect())
    }
}
pub(crate) fn policy_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<ConsolidationStrengthPolicy> {
    let policy = POLICY.get(&vault.store, txn, &())?.unwrap_or_default();
    policy.validate()?;
    Ok(policy)
}

/// Called only after the promotion/attachment gate and its evidence fence.
/// Replays of the same (source, quote hash) do not refresh the quiet clock.
pub(crate) fn record_verified_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    claim: EntityId,
    evidence: &VerifiedEvidenceSet,
    now_ms: u64,
) -> Result<()> {
    let body = vault
        .get_claim_in_txn(txn, &claim)?
        .ok_or(Error::EntityNotFound)?;
    if body.source != Some(ClaimSource::Generated)
        || body.predicate == crate::claim::PREDICATE_CONFLICT_OPEN
        || crate::claim::session_claim_producer(&body)
            != Some(crate::dreamer_runner::authority::dreamer_actor_id()?)
    {
        return Ok(());
    }
    let mut observations = OBSERVATIONS
        .get(&vault.store, txn, &claim)?
        .unwrap_or_else(|| StrengthObservations {
            predicate: body.predicate.clone(),
            last_activity_ms: now_ms,
            sources: Vec::new(),
        });
    if observations.predicate != body.predicate {
        return Err(Error::InvalidClaimBody(
            "consolidation strength identity changed",
        ));
    }
    for (source, hash, is_claim) in evidence.signal_sources() {
        if observations
            .sources
            .iter()
            .any(|row| row.source == source && row.hash == hash)
        {
            continue;
        }
        let raw = vault
            .store
            .port_entity_raw(txn, &source)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("strength source metadata"))?;
        let diversity = if is_claim {
            Some(source.to_hex())
        } else {
            decode_turn_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                .speaker
                .map(|speaker| speaker.trim().to_lowercase())
        };
        observations.sources.push(StrengthSource {
            source,
            hash,
            revision: *blake3::hash(&raw).as_bytes(),
            learned_at_ms: header.learned_at.saturating_mul(1_000),
            diversity,
        });
        observations.last_activity_ms = observations.last_activity_ms.max(now_ms);
    }
    observations
        .sources
        .sort_by_key(|row| (row.source, row.hash));
    OBSERVATIONS.put(&vault.store, txn, &claim, &observations)
}

/// A deliberate restore starts a fresh quiet window instead of being archived
/// again on the next nightly pass. Unrelated cleanup restores have no row here.
pub(crate) fn restored_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    claim: &EntityId,
) -> Result<()> {
    if let Some(mut observations) = OBSERVATIONS.get(&vault.store, txn, claim)? {
        observations.last_activity_ms =
            crate::ports::recorded_at_in_txn(&vault.store, txn)?.saturating_mul(1_000);
        OBSERVATIONS.put(&vault.store, txn, claim, &observations)?;
    }
    Ok(())
}

/// One nightly recipe child. Snapshot, recheck and local archive share the
/// writer's revision. No confidence, lifecycle, claim bytes or graph edges change.
/// The archive takes back what the Dreamer landed, so it is judged in this
/// writer by the policy rows that let it land (X02): with the owner's Auto
/// ceiling or `Generated` permit for the Dreamer narrowed or removed, nothing
/// is archived and no receipt is written.
pub(crate) fn archive_quiet_claims(vault: &Vault, attempt: AttemptId, now_ms: u64) -> Result<u64> {
    let actor = vault.dreamer_actor_for_attempt(attempt)?;
    vault.with_write_txn_grouped(|txn| {
        let Some(verdict) = crate::gate::dreamer_landing_verdict_in_txn(&vault.store, txn, actor)?
        else {
            return Ok(0);
        };
        let policy = policy_in_txn(vault, txn)?;
        let selection = vault.consolidation_selection_in_txn(txn)?;
        let key = read_key(actor)?;
        let read = vault.scoped_read(key);
        let observations = OBSERVATIONS.scan(&vault.store, txn)?;
        let mut archived = 0;
        for (id, observations) in observations {
            let Some(raw) = read.entity_raw_live_in(txn, &id)? else {
                continue;
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("strength claim metadata"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                || raw.len() == ENTITY_METADATA_HEADER_LEN
            {
                continue;
            }
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if body.predicate != observations.predicate
                || archive_fence_in_txn(
                    vault,
                    txn,
                    actor.entity_ref(),
                    &id,
                    &body,
                    header.learned_at,
                    now_ms,
                    &policy,
                )?
                .is_some()
            {
                continue;
            }
            // Losing read authority or changing a cited revision is not weak
            // evidence: leave that claim alone for reconsolidation instead.
            let mut current = true;
            for source in &observations.sources {
                let raw = read.entity_raw_live_in(txn, &source.source)?;
                if raw
                    .as_ref()
                    .is_none_or(|raw| *blake3::hash(raw).as_bytes() != source.revision)
                {
                    current = false;
                    break;
                }
            }
            if !current || observations.sources.is_empty() {
                continue;
            }
            let diversity: BTreeSet<_> = observations
                .sources
                .iter()
                .filter_map(|source| source.diversity.as_ref())
                .collect();
            let latest = observations
                .sources
                .iter()
                .map(|source| source.learned_at_ms)
                .max()
                .unwrap_or_default();
            let signals = StrengthSignals::from_evidence(
                &body.predicate,
                observations.sources.len(),
                latest,
                diversity.len(),
                now_ms,
                &selection,
            );
            let score = strength_score(signals, &selection)?;
            if score >= policy.archive_below {
                continue;
            }
            let snapshot = ConsolidationStrengthSnapshot {
                attempt,
                at_ms: now_ms,
                revision: *blake3::hash(&raw).as_bytes(),
                signals,
                score,
                selection: selection.clone(),
                policy: policy.clone(),
            };
            archive_claim_in_txn(vault, txn, id, &snapshot, *attempt.as_bytes())?;
            let link = vault.attempt_action_link_in_txn(&*txn, attempt);
            let receipt = archive_receipt(actor, id, &snapshot, now_ms, link, &verdict);
            vault.store.append_gate_decision_in_txn(txn, &receipt)?;
            archived += 1;
        }
        Ok(archived)
    })
}
/// Why the archive fence keeps a claim (untangle 6.7a): the nightly
/// strength archive and a derivation batch's archive item meet the same
/// fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveFence {
    /// The claim is not the archiving actor's own `Generated` claim.
    NotOwnGenerated,
    /// It is not active.
    NotActive,
    /// It is neither Auto nor Approved.
    NotApproved,
    /// A critical confirmation on it is not settled.
    ConfirmOpen,
    /// A gate consent on it is pending.
    ConsentPending,
    /// It gained evidence, or was learned, within the policy's quiet window.
    NotQuiet,
}

impl ArchiveFence {
    /// The stable reason token a derivation receipt names.
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::NotOwnGenerated => "gate.deny.derive.archive_not_own_generated",
            Self::NotActive => "gate.deny.derive.archive_not_active",
            Self::NotApproved => "gate.deny.derive.archive_not_approved",
            Self::ConfirmOpen => "gate.deny.derive.archive_confirm_open",
            Self::ConsentPending => "gate.deny.derive.archive_consent_pending",
            Self::NotQuiet => "gate.deny.derive.archive_not_quiet",
        }
    }
}

/// The archive eligibility fence over the stored claim `id` (`body`,
/// learned at `learned_at` seconds) for `actor` at `now_ms` under `policy`:
/// `None` when it may be archived. Only the actor's own active `Generated`
/// claim at Auto or Approved, with any critical confirmation settled,
/// nothing pending, and quiet for the policy's window.
///
/// # Errors
///
/// Storage errors.
#[expect(
    clippy::too_many_arguments,
    reason = "the fence reads the claim's body, its learned time, the clock and the policy"
)]
pub(crate) fn archive_fence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    id: &EntityId,
    body: &crate::claim::ClaimBody,
    learned_at: u64,
    now_ms: u64,
    policy: &ConsolidationStrengthPolicy,
) -> Result<Option<ArchiveFence>> {
    if body.source != Some(ClaimSource::Generated)
        || crate::claim::session_claim_producer(body) != Some(actor)
    {
        return Ok(Some(ArchiveFence::NotOwnGenerated));
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Ok(Some(ArchiveFence::NotActive));
    }
    if !matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) {
        return Ok(Some(ArchiveFence::NotApproved));
    }
    if !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, id)? {
        return Ok(Some(ArchiveFence::ConfirmOpen));
    }
    if vault.store.pending_gate_consent_in_txn(txn, id)?.is_some() {
        return Ok(Some(ArchiveFence::ConsentPending));
    }
    let last_activity = OBSERVATIONS
        .get(&vault.store, txn, id)?
        .map_or(0, |observations| observations.last_activity_ms);
    let last_change = last_activity.max(learned_at.saturating_mul(1_000));
    if now_ms < last_change || now_ms - last_change < policy.quiet_ms {
        return Ok(Some(ArchiveFence::NotQuiet));
    }
    Ok(None)
}

/// Archives the claim `id` at `snapshot`: the snapshot row, the drop of its
/// person's `about` lines, and the cleanup-archive tombstone the owner's
/// cleanup restore lifts. `request_id` names the act (the attempt that
/// scored it).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn archive_claim_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    snapshot: &ConsolidationStrengthSnapshot,
    request_id: [u8; 16],
) -> Result<()> {
    ARCHIVES.put(&vault.store, txn, &(id, snapshot.at_ms), snapshot)?;
    let deleted_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let marker = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::ArchivedByCleanup,
        deleted_at,
        request_id,
    };
    // The archive drops a fact: its person's `about` lines hide until a wake
    // pass reads the facts left (FIX 3196).
    super::mark_person_about_dropped_in_txn(&vault.store, txn, &id)?;
    vault.put_archive_tombstone_in_txn(txn, &id, &marker)
}

/// The receipt one archive leaves (owner ruling 10-18: the Dreamer applies
/// and the owner reverts): the Dreamer's, naming the claim and the revision
/// its snapshot scored, so the owner finds it and restores the claim through
/// the cleanup restore door. `link` is the scoring attempt's (FIX 7500). The
/// verdict is the policy's (X02): what it was judged by (the Dreamer's
/// Steward grant once a host minted it, else its landing rows), and the
/// policy frontier it was judged under.
fn archive_receipt(
    actor: WriteActor,
    claim: EntityId,
    snapshot: &ConsolidationStrengthSnapshot,
    now_ms: u64,
    link: crate::store::GateLoopLink,
    verdict: &crate::gate::DreamerLandingVerdict,
) -> crate::store::GateDecisionRecord {
    crate::store::GateDecisionRecord {
        version: crate::store::GATE_DECISION_LEDGER_VERSION,
        decision_id: crate::store::GateDecisionId::now(),
        created_at: now_ms,
        outcome: "approved".to_owned(),
        reason_codes: vec![
            "gate.dreamer.strength.archived".to_owned(),
            "gate.dreamer.policy.lands_generated_auto".to_owned(),
        ],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: actor.actor_class().gate_actor_class().to_owned(),
        actor_ref: Some(actor.entity_ref().to_hex()),
        content_kind: "dreamer_strength_archive".to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: Some(*claim.as_bytes()),
        grant_ref: Some(verdict.grant_ref.clone()),
        diff_handle: snapshot.revision.to_vec(),
        read_frontier_hash: verdict.frontier,
        context: crate::store::GateDecisionContext::linked(link, None),
        redacted_at: None,
    }
}

fn read_key(actor: WriteActor) -> Result<ScopedReadActorKey> {
    ScopedReadActorKey::for_engine_actor(actor).ok_or(Error::InvalidClaimBody(
        "invalid consolidation strength reader",
    ))
}
