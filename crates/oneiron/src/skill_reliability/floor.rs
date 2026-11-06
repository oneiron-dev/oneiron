//! The reliability floor dial and the quarantine proposal a floor crossing mints.

use std::collections::BTreeMap;

use rmpv::Value;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{ConsolidationReader, claim_consolidation_eligible_in_txn};
use crate::learning::project::StoredEstimateClaim;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Raw, RawValue, SideTable};
use crate::temporal::TimeRange;

use super::codec::invalid;
use super::equivalent::redirect_equivalent_subjects_in_txn;
use super::posterior::{KEY_ALPHA, KEY_BETA};
use super::read::{active_claims_in_txn, active_reliability_heads_in_txn, posterior_from_estimate};

/// The floor-crossing PROPOSAL predicate. A proposal to quarantine is a ROW,
/// never a lifecycle state (`skill.rs` lifecycle machine): the record stays
/// `active` until a human rules on this claim.
pub const PREDICATE_SKILL_QUARANTINE_PROPOSAL: &str = "skill.quarantine_proposal";

/// `vault_meta` key of the reliability floor dial. Kept as a public constant for crate
/// consumers (re-exported from [`crate::skill_reliability`]); `FLOOR` is this module's own
/// door onto the row and owns the read/write path below.
pub const SKILL_RELIABILITY_FLOOR_KEY: &[u8] = b"settings:skill:v1:reliability_floor";

/// The reliability floor dial. Key: ().
const FLOOR: SideTable<(), ReliabilityFloorRow, Raw> =
    SideTable::new(&side_table::SKILL_RELIABILITY_FLOOR);

/// `FLOOR`'s row: four big-endian bytes, finite and within `[0, 1]`. Any other shape is a
/// corrupted dial rather than a silently-defaulted one.
#[derive(Debug, Clone, Copy, PartialEq)]
struct ReliabilityFloorRow(f32);

impl RawValue for ReliabilityFloorRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok(self.0.to_be_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("skill reliability floor"))?;
        let floor = f32::from_be_bytes(bytes);
        if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
            return Err(Error::CorruptedIndex("skill reliability floor").into());
        }
        Ok(Self(floor))
    }
}

/// Default reliability floor: the posterior LOWER BOUND a skill must hold to
/// stay out of the quarantine-proposal path.
///
/// 0.25 is deliberately far below every seeded prior mean
/// ([`ProvenanceTrustClass`](crate::skill_reliability::ProvenanceTrustClass)), so crossing it takes real attributed losses
/// rather than an unlucky provenance class.
pub const DEFAULT_SKILL_RELIABILITY_FLOOR: f32 = 0.25;

/// Attributed outcomes a skill must carry before the floor can fire.
///
/// A lower bound computed on a pure prior measures IGNORANCE, not
/// unreliability — every prior in the table sits under the floor on its lower
/// bound, so without this guard the first projection pass would propose
/// quarantining every newborn skill. The floor answers "the evidence says this
/// is bad", which needs evidence.
pub const SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES: u32 = 5;

const KEY_LOWER_BOUND: &str = "lowerBound";

const KEY_FLOOR: &str = "floor";

// ---------------------------------------------------------------------------
// Floor crossing
// ---------------------------------------------------------------------------

/// Reads the reliability floor dial (default [`DEFAULT_SKILL_RELIABILITY_FLOOR`]).
pub fn skill_reliability_floor(vault: &Vault) -> Result<f32> {
    let rtxn = vault.store.env.read_txn()?;
    floor_in_txn(vault, &rtxn)
}

fn floor_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<f32> {
    Ok(FLOOR
        .get(&vault.store, rtxn, &())?
        .map_or(DEFAULT_SKILL_RELIABILITY_FLOOR, |row| row.0))
}

/// Sets the reliability floor dial.
pub fn set_skill_reliability_floor(vault: &Vault, floor: f32) -> Result<()> {
    if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
        return Err(invalid("reliability floor must be finite in [0, 1]"));
    }
    vault.with_write_txn_grouped(|wtxn| {
        FLOOR.put(&vault.store, wtxn, &(), &ReliabilityFloorRow(floor))?;
        Ok(())
    })
}

/// Mints a quarantine PROPOSAL when the skill's posterior lower bound has
/// fallen under the floor, and returns the proposal's claim id.
///
/// NEVER automatic (ARCH-0053 §5/§6): the lifecycle stays wherever it was and
/// the proposal lands as a row with `approval = proposed`. The record-shape
/// invariant in `skill.rs` enforces the other half — a `quarantined` record
/// stamped anything but `approved` is rejected at every door — so there is no
/// path from this function to a retired skill without a human ruling.
///
/// Returns the EXISTING proposal while one is open: a second crossing is the
/// same unanswered question, not a second question.
///
/// Checks each projected learning cell using its own effective run mass,
/// and returns one open proposal if any cell crosses the floor. Borrowed
/// priors alone never satisfy the minimum-evidence guard.
pub fn check_reliability_floor(
    vault: &Vault,
    skill: &EntityId,
    at: u64,
) -> Result<Option<EntityId>> {
    check_floor_for(vault, skill, None, at)
}

/// Checks every measured cell of an executor, never borrowed evidence.
pub fn check_reliability_floor_for_executor(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
    at: u64,
) -> Result<Option<EntityId>> {
    super::read::validate_executor(executor)?;
    check_floor_for(vault, skill, Some(executor), at)
}

fn check_floor_for(
    vault: &Vault,
    skill: &EntityId,
    executor: Option<&str>,
    at: u64,
) -> Result<Option<EntityId>> {
    vault.with_write_txn_grouped(|txn| check_floor_cells_in_txn(vault, txn, skill, executor, at))
}

/// Reconciles each measured cell independently, including proposals whose last
/// own run was withdrawn and therefore no longer has an estimate head.
pub(super) fn check_floor_cells_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
    at: u64,
) -> Result<Option<EntityId>> {
    let mut cells: BTreeMap<[u8; 32], (EntityId, StoredEstimateClaim)> = BTreeMap::new();
    for subject in redirect_equivalent_subjects_in_txn(vault, wtxn, skill)? {
        for (id, body, _) in active_reliability_heads_in_txn(vault, wtxn, &subject, executor)? {
            if !claim_consolidation_eligible_in_txn(
                &vault.store,
                wtxn,
                &id,
                ConsolidationReader::SkillReliabilityPosterior,
            )? {
                continue;
            }
            let stored = StoredEstimateClaim::from_value(&body.value)?;
            if stored.estimate.ver != crate::claim::learning_estimate::ESTIMATOR_VERSION {
                continue;
            }
            let digest = stored.cell.digest();
            if cells.get(&digest).is_none_or(|(held_id, held)| {
                stored.estimate.runs > held.estimate.runs
                    || (stored.estimate.runs == held.estimate.runs && id < *held_id)
            }) {
                cells.insert(digest, (id, stored));
            }
        }
    }
    let open: Vec<_> =
        active_claims_in_txn(vault, wtxn, skill, PREDICATE_SKILL_QUARANTINE_PROPOSAL)?
            .into_iter()
            .filter(|(_, body, _)| {
                executor.is_none_or(|executor| {
                    super::codec::map_str(&body.value, "executor") == Some(executor)
                })
            })
            .collect();
    let floor = floor_in_txn(vault, wtxn)?;
    let mut live_cells = Vec::with_capacity(cells.len());
    let mut first_proposal = None;
    for (head, stored) in cells.into_values() {
        let cell = rmpv::ext::to_value(&stored.cell)
            .map_err(|_| invalid("reliability floor cell encoding"))?;
        let matching: Vec<_> = open
            .iter()
            .filter(|(_, body, _)| super::codec::map_entry(&body.value, "cell") == Some(&cell))
            .collect();
        let posterior = posterior_from_estimate(&stored.estimate)?;
        let lower_bound = posterior.lower_bound();
        if stored.estimate.runs < f64::from(SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES)
            || lower_bound >= floor
        {
            for (old_id, _, old_start) in matching {
                vault.supersede_reserved_claim_in_txn(wtxn, &head, old_id, at.max(*old_start))?;
            }
        } else if let Some((existing, _, _)) = matching.first() {
            first_proposal.get_or_insert(*existing);
        } else {
            let proposal_id = vault.store.clock.entity_id()?;
            let mut fields = vec![
                (Value::from("cell"), cell.clone()),
                (Value::from(KEY_ALPHA), Value::F32(posterior.alpha)),
                (Value::from(KEY_BETA), Value::F32(posterior.beta)),
                (Value::from(KEY_LOWER_BOUND), Value::F32(lower_bound)),
                (Value::from(KEY_FLOOR), Value::F32(floor)),
            ];
            if let Some(executor) = &stored.cell.executor {
                fields.push((Value::from("executor"), Value::from(executor.as_str())));
            }
            let mut body = ClaimBody::new(
                PREDICATE_SKILL_QUARANTINE_PROPOSAL,
                ClaimSubject::Entity(*skill),
                Value::Map(fields),
                1.0,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
            )?;
            body.source = Some(ClaimSource::Observed);
            vault.put_reserved_claim_in_txn(
                wtxn,
                &proposal_id,
                &body,
                TimeRange { start: at, end: at },
                at,
            )?;
            first_proposal.get_or_insert(proposal_id);
        }
        live_cells.push(cell);
    }
    for (id, mut body, start) in open {
        if super::codec::map_entry(&body.value, "cell")
            .is_some_and(|cell| live_cells.contains(cell))
        {
            continue;
        }
        // The estimate was retracted when its own run mass reached zero.
        // Withdraw the recommendation without inventing a replacement head.
        let raw = vault
            .store
            .port_entity_record(wtxn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::CorruptedIndex("floor proposal"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let closed_at = at.max(start);
        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(closed_at);
        vault.put_reserved_claim_in_txn(
            wtxn,
            &id,
            &body,
            TimeRange {
                start,
                end: closed_at,
            },
            header.learned_at,
        )?;
    }
    Ok(first_proposal)
}

/// One downward floor crossing the contract recorded and no recovery has
/// superseded: an open quarantine proposal, with the numbers it was minted
/// on.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FloorCrossing {
    /// The open `skill.quarantine_proposal` claim.
    pub(crate) proposal: EntityId,
    /// The executor whose cell crossed; `None` for the skill-wide check.
    pub(crate) executor: Option<String>,
    pub(crate) lower_bound: f32,
    pub(crate) floor: f32,
    /// When the crossing was recorded.
    pub(crate) at: u64,
}

/// Every floor crossing still open on `skill`, at any executor, on the
/// caller's snapshot. A read only: the floor check above is what mints and
/// withdraws them.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn open_floor_crossings_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Vec<FloorCrossing>> {
    let mut crossings = Vec::new();
    for (proposal, body, at) in
        active_claims_in_txn(vault, txn, skill, PREDICATE_SKILL_QUARANTINE_PROPOSAL)?
    {
        if body.approval != ClaimApprovalStatus::Proposed
            || body.source != Some(ClaimSource::Observed)
        {
            continue;
        }
        let (Some(lower_bound), Some(floor)) = (
            super::codec::map_f32(&body.value, KEY_LOWER_BOUND),
            super::codec::map_f32(&body.value, KEY_FLOOR),
        ) else {
            continue;
        };
        crossings.push(FloorCrossing {
            proposal,
            executor: super::codec::map_str(&body.value, "executor").map(str::to_owned),
            lower_bound,
            floor,
            at,
        });
    }
    Ok(crossings)
}
