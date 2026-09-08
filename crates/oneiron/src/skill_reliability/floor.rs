//! The reliability floor dial and the quarantine proposal a floor crossing mints.

use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

use super::codec::invalid;
use super::ledger::tally_outcomes;
use super::posterior::{KEY_ALPHA, KEY_BETA, SkillReliabilityPosterior};
use super::projector::attributed_outcomes;
use super::provenance::skill_reliability_prior;
use super::read::{active_claims_in_txn, resolved_reliability_posterior_in_txn};

/// The floor-crossing PROPOSAL predicate. A proposal to quarantine is a ROW,
/// never a lifecycle state (`skill.rs` lifecycle machine): the record stays
/// `active` until a human rules on this claim.
pub const PREDICATE_SKILL_QUARANTINE_PROPOSAL: &str = "skill.quarantine_proposal";

/// `vault_meta` key of the reliability floor dial. Per-feature key const in the
/// owning module (the `INBOX_REVIEW_DIAL_KEY` house pattern) — `settings.rs` is
/// UI customization and owns nothing here.
pub const SKILL_RELIABILITY_FLOOR_KEY: &[u8] = b"settings:skill:v1:reliability_floor";

/// Default reliability floor: the posterior LOWER BOUND a skill must hold to
/// stay out of the quarantine-proposal path.
///
/// 0.25 is deliberately far below every seeded prior mean
/// ([`ProvenanceTrustClass`]), so crossing it takes real attributed losses
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
    let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, SKILL_RELIABILITY_FLOOR_KEY)?
    else {
        return Ok(DEFAULT_SKILL_RELIABILITY_FLOOR);
    };
    let bytes: [u8; 4] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("skill reliability floor"))?;
    let floor = f32::from_be_bytes(bytes);
    if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
        return Err(Error::CorruptedIndex("skill reliability floor"));
    }
    Ok(floor)
}

/// Sets the reliability floor dial.
pub fn set_skill_reliability_floor(vault: &Vault, floor: f32) -> Result<()> {
    if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
        return Err(invalid("reliability floor must be finite in [0, 1]"));
    }
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, SKILL_RELIABILITY_FLOOR_KEY, &floor.to_be_bytes())?;
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
/// Reads the CLAIM, exactly as selection does. The local outcome ledger is not
/// the whole posterior on a replica — a vault that synced a below-floor claim
/// holds no outcome rows behind it, so recomputing from the tally would exit at
/// `outcomes < MIN_OUTCOMES` and skip the quarantine proposal the evidence
/// already demands. The ledger answers only for a skill nobody has projected.
pub fn check_reliability_floor(
    vault: &Vault,
    skill: &EntityId,
    at: u64,
) -> Result<Option<EntityId>> {
    let prior = skill_reliability_prior(vault, skill)?;
    vault.with_write_txn(|wtxn| {
        let posterior = match resolved_reliability_posterior_in_txn(vault, wtxn, skill)? {
            Some(posterior) => posterior,
            None => tally_outcomes(vault, wtxn, skill)?.posterior(prior),
        };
        floor_check_in_txn(
            vault,
            wtxn,
            skill,
            posterior,
            attributed_outcomes(prior, posterior),
            at,
        )
    })
}

pub(super) fn floor_check_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    posterior: SkillReliabilityPosterior,
    outcomes: u32,
    at: u64,
) -> Result<Option<EntityId>> {
    if outcomes < SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES {
        return Ok(None);
    }
    let floor = floor_in_txn(vault, wtxn)?;
    let lower_bound = posterior.lower_bound();
    if lower_bound >= floor {
        return Ok(None);
    }
    if let Some((existing, _, _)) =
        active_claims_in_txn(vault, wtxn, skill, PREDICATE_SKILL_QUARANTINE_PROPOSAL)?
            .into_iter()
            .next()
    {
        return Ok(Some(existing));
    }
    let proposal_id = EntityId::now();
    let mut body = ClaimBody::new(
        PREDICATE_SKILL_QUARANTINE_PROPOSAL,
        ClaimSubject::Entity(*skill),
        Value::Map(vec![
            (Value::from(KEY_ALPHA), Value::F32(posterior.alpha)),
            (Value::from(KEY_BETA), Value::F32(posterior.beta)),
            (Value::from(KEY_LOWER_BOUND), Value::F32(lower_bound)),
            (Value::from(KEY_FLOOR), Value::F32(floor)),
        ]),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    vault.put_reserved_claim_in_txn(
        wtxn,
        &proposal_id,
        &body,
        TimeRange { start: at, end: at },
        at,
    )?;
    Ok(Some(proposal_id))
}
