//! Consolidation strength observations and an archive-only lifecycle (OF-216).
//! Evidence is counted at the gated promotion door, never from child agreement.
//! The score orders selection; it never changes confidence or judges a belief.
//! The bounded observation read is [`crate::snapshot_read::strength_observations_page`].

use super::evidence::VerifiedEvidenceSet;
use super::selection::{SelectionConfig, StrengthSignals};
use super::watermark::decode_turn_body;
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

pub(crate) const OBSERVATIONS: SideTable<EntityId, StrengthObservations, Named> =
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
pub(crate) struct StrengthSource {
    pub(crate) source: EntityId,
    hash: [u8; 32],
    pub(crate) revision: [u8; 32],
    pub(crate) learned_at_ms: u64,
    pub(crate) diversity: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StrengthObservations {
    pub(crate) predicate: String,
    pub(crate) last_activity_ms: u64,
    pub(crate) sources: Vec<StrengthSource>,
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

    /// The owner, by its proof, or a holder of `engine.controls` sets the consolidation strength
    /// policy (untangle 6.6b; maintenance cadence), through the one check, with a receipt naming
    /// it. Untangle 6.6d gives it its verb. Returns the receipt.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` when `actor` is neither the owner, by a proof that still holds, nor a live
    /// holder of `engine.controls`; the row's own validation; store failures.
    pub fn set_consolidation_strength_policy_by(
        &self,
        actor: crate::federation::EngineControlActor<'_>,
        policy: &ConsolidationStrengthPolicy,
    ) -> Result<EntityId> {
        policy.validate()?;
        self.apply_engine_control(
            actor,
            crate::federation::EngineControlClass::MaintenanceCadence,
            "DREAMER_CONSOLIDATION_STRENGTH_POLICY",
            &crate::federation::rendered_change(policy)?,
            |txn| POLICY.put(&self.store, txn, &(), policy),
        )
    }

    /// [`Self::set_consolidation_strength_policy_by`] for a holder of `engine.controls` (untangle
    /// 6.6b).
    ///
    /// # Errors
    ///
    /// As [`Self::set_consolidation_strength_policy_by`].
    pub fn set_consolidation_strength_policy_as_holder(
        &self,
        holder: EntityId,
        policy: &ConsolidationStrengthPolicy,
    ) -> Result<EntityId> {
        self.set_consolidation_strength_policy_by(
            crate::federation::EngineControlActor::Holder(holder),
            policy,
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

/// The effective strength policy's domain-separated pin in this transaction.
pub(crate) fn strength_policy_pin_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<String> {
    let encoded = serde_json::to_vec(&policy_in_txn(vault, txn)?)
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:consolidation:strength-policy:v1\0");
    hash.update(&encoded);
    Ok(hash.finalize().to_hex().to_string())
}

/// Lands one archived DREAMER_CONSOLIDATION_STRENGTH_POLICY row live: a validated policy
/// installs through the archive seam, anything else is held back.
fn land_archived_strength_policy_row_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &crate::batch::export::OwnerArchiveRestorePermit,
    row: &crate::batch::export::ArchiveRetainedSideRow,
) -> crate::Result<crate::batch::export::archive_side_install::ArchivedSideRowOutcome> {
    use crate::batch::export::RetainedSideHeldBackReason;
    use crate::batch::export::archive_side_install::{
        ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
    };
    let (key, value) = match decode_archived_row(&POLICY, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    if value.validate().is_err() {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidValue,
        ));
    }
    install_archived_row(&POLICY, vault, txn, permit, &key, row)
}

/// Lands archived DREAMER_CONSOLIDATION_STRENGTH_POLICY rows live, one outcome per input row in
/// input order.
pub(crate) fn land_archived_dreamer_consolidation_rows_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &crate::batch::export::OwnerArchiveRestorePermit,
    rows: &[crate::batch::export::ArchiveRetainedSideRow],
) -> crate::Result<Vec<crate::batch::export::archive_side_install::ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        outcomes.push(land_archived_strength_policy_row_in_txn(
            vault, txn, permit, row,
        )?);
    }
    Ok(outcomes)
}

/// The claim id and its stored observations, or no pin when no row stands.
pub(crate) fn observation_pin_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: &EntityId,
) -> Result<Option<String>> {
    let Some(observations) = OBSERVATIONS.get(&vault.store, txn, claim)? else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&observations)
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:consolidation:strength-observation:v1\0");
    hash.update(claim.as_bytes());
    hash.update(&encoded);
    Ok(Some(hash.finalize().to_hex().to_string()))
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

/// Why the archive fence keeps a claim (untangle 6.7a): a derivation batch's
/// archive item meets it, and the strength observations page names it for
/// its caller (untangle 6.9c).
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
