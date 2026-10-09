//! Amendment verdicts on an attempt's outcome row (ARCH-0056 §5): one record per attempt, and
//! the later verdict holds.
//!
//! An attempt's outcome row holds the attempt lane's verdict: a contributing win, or a routed
//! defect. When the decider later approves that attempt's proposal WITH an edit, and the
//! amendment judge charges part of the edit to the skill, the amendment is a later verdict on the
//! same attempt. It replaces the attempt's record rather than joining it: an approved-and-amended
//! attempt counted as a win AND as a defect would tell the posterior two things about one
//! outcome.
//!
//! So the amendment's verdict is kept beside the row it replaces, keyed by that row's own full
//! key, and every fold reads the two as one record: an amended attempt counts as a loss weighted
//! by the amendment's `skill_defect` share, and as nothing else. The attempt lane's row is left
//! as it was, so an amendment judged again without a defect share hands the attempt back its own
//! verdict.
//!
//! These rows are a projection of the amendment judgment ledger, not a second source of truth:
//! [`reconcile_amended_outcomes`] recomputes the whole set on every pass and reprojects each arm
//! it moved.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, RawValue, SideKey, SideTable};

use super::codec::{
    KEY_AT, KEY_SCHEMA_VERSION, decode_value, encode_value, invalid, map_f32, map_str, map_u64,
};
use super::ledger::{
    OutcomeRef, outcome_arm_prefix, outcome_skill_prefixes, receipt_executor,
    receipt_manifest_names_skill,
};
use super::posterior::SKILL_RELIABILITY_SCHEMA_VERSION;
use super::projector::project_in_txn;
use super::provenance::skill_reliability_prior;

/// The amendment verdict that replaces one attempt's outcome row. Key: the outcome row's full
/// stored key, table prefix included — the displacement mark's key shape.
const AMENDED: SideTable<OutcomeRef, AmendedRow, Raw> =
    SideTable::new(&side_table::SKILL_RELIABILITY_AMENDED);

const KEY_AMENDMENT: &str = "amendment";

const KEY_SHARE: &str = "share";

/// One amendment's verdict on one attempt, as the amendment lane hands it over.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AmendedOutcome {
    /// The skill the amendment's evidence named.
    pub(crate) skill: EntityId,
    /// The terminal pack receipt of the attempt whose proposal was amended.
    pub(crate) attempt_receipt: String,
    /// The amendment receipt.
    pub(crate) amendment_receipt: String,
    /// The amendment's `skill_defect` share charging `skill`, `0` when it charges none.
    pub(crate) defect_share: f32,
    /// When the amendment was observed.
    pub(crate) at: u64,
}

/// [`AMENDED`]'s row: the amendment receipt, its defect share, and its event time.
#[derive(Debug, Clone, PartialEq)]
struct AmendedRow {
    amendment: String,
    share: f32,
    at: u64,
}

impl RawValue for AmendedRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        let row = Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(SKILL_RELIABILITY_SCHEMA_VERSION),
            ),
            (
                Value::from(KEY_AMENDMENT),
                Value::from(self.amendment.as_str()),
            ),
            (Value::from(KEY_SHARE), Value::F32(self.share)),
            (Value::from(KEY_AT), Value::from(self.at)),
        ]);
        Ok(encode_value(&row)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        let value = decode_value(bytes)?;
        if map_u64(&value, KEY_SCHEMA_VERSION) != Some(SKILL_RELIABILITY_SCHEMA_VERSION) {
            return Err(invalid("unsupported skill reliability amendment schema").into());
        }
        let amendment = map_str(&value, KEY_AMENDMENT)
            .ok_or(invalid("skill reliability amendment is missing its receipt"))?;
        let share = map_f32(&value, KEY_SHARE)
            .filter(|share| valid_share(*share))
            .ok_or(invalid("skill reliability amendment share is not in (0, 1]"))?;
        let at = map_u64(&value, KEY_AT)
            .ok_or(invalid("skill reliability amendment is missing its time"))?;
        Ok(Self {
            amendment: amendment.to_owned(),
            share,
            at,
        })
    }
}

/// A share that charges: finite and in `(0, 1]`. NaN fails both comparisons.
fn valid_share(share: f32) -> bool {
    share > 0.0 && share <= 1.0
}

/// Whether an amendment verdict replaces `outcome`.
pub(super) fn is_amended(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    outcome: &OutcomeRef,
) -> Result<bool> {
    AMENDED.contains(&vault.store, rtxn, outcome)
}

/// The amended attempts of one arm: attempt receipt → defect share.
pub(super) fn amended_shares_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<BTreeMap<String, f32>> {
    Ok(AMENDED
        .scan_from(&vault.store, rtxn, &outcome_arm_prefix(skill, executor))?
        .into_iter()
        .map(|(outcome, row)| (outcome.receipt().to_owned(), row.share))
        .collect())
}

/// The amended attempts of `skill` across every arm.
pub(super) fn amended_receipts_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<BTreeSet<String>> {
    let mut receipts = BTreeSet::new();
    for prefix in outcome_skill_prefixes(skill) {
        for (outcome, _) in AMENDED.scan_from(&vault.store, rtxn, &prefix)? {
            receipts.insert(outcome.receipt().to_owned());
        }
    }
    Ok(receipts)
}

/// One arm of one skill: the unit a reprojection runs over.
type Arm = (EntityId, Option<String>);

/// Lands the later verdict of every amended attempt, and reprojects each arm whose record moved,
/// returning those skills in first-seen order.
///
/// `verdicts` is every joined amendment the amendment lane holds, charging or not. Per skill and
/// attempt the LATER verdict holds, by event time and then receipt id, so an earlier amendment of
/// the same attempt is replaced, not added to. A later verdict that charges the skill nothing
/// leaves the attempt its own record.
///
/// Every verdict is grounded again here: the skill must exist and must not be a callable (a
/// callable's loss belongs to the executors that invoked it, which the attempt's stamp may not
/// name), and the attempt receipt must be a stamped pack receipt whose manifest loaded the skill.
/// The arm is the one that receipt's executor stamp names. An ungrounded verdict is skipped,
/// which withdraws whatever it held before.
///
/// The pass is idempotent: an arm whose rows already say exactly this is neither written nor
/// reprojected.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn reconcile_amended_outcomes(
    vault: &Vault,
    verdicts: &[AmendedOutcome],
) -> Result<Vec<EntityId>> {
    let desired = grounded_rows(vault, &later_verdicts(verdicts))?;
    let mut projected = Vec::new();
    for (skill, executor) in moved_arms(vault, &desired)? {
        settle_arm(vault, &desired, &skill, executor.as_deref())?;
        if !projected.contains(&skill) {
            projected.push(skill);
        }
    }
    Ok(projected)
}

/// The row one grounded verdict lands, keyed by the outcome row it replaces.
type Desired = BTreeMap<Vec<u8>, (Arm, OutcomeRef, AmendedRow)>;

/// The later verdict per skill and attempt, by event time and then receipt id.
fn later_verdicts(verdicts: &[AmendedOutcome]) -> Vec<&AmendedOutcome> {
    let mut latest: BTreeMap<(EntityId, &str), &AmendedOutcome> = BTreeMap::new();
    for verdict in verdicts {
        let held = latest
            .entry((verdict.skill, verdict.attempt_receipt.as_str()))
            .or_insert(verdict);
        if (verdict.at, &verdict.amendment_receipt) > (held.at, &held.amendment_receipt) {
            *held = verdict;
        }
    }
    latest.into_values().collect()
}

/// The rows the charging verdicts land, each grounded and placed on the arm its attempt's
/// executor stamp names.
fn grounded_rows(vault: &Vault, verdicts: &[&AmendedOutcome]) -> Result<Desired> {
    let mut desired = Desired::new();
    for verdict in verdicts {
        if !valid_share(verdict.defect_share) {
            continue;
        }
        let Some(record) = vault.get_skill_record(&verdict.skill)? else {
            continue;
        };
        if record.role == crate::skill::SkillRole::Callable {
            continue;
        }
        let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, &verdict.attempt_receipt)?
        else {
            continue;
        };
        if !receipt_manifest_names_skill(&receipt, &record) {
            continue;
        }
        let executor = receipt_executor(&receipt);
        let outcome = OutcomeRef::new(&verdict.skill, executor, &verdict.attempt_receipt);
        let row = AmendedRow {
            amendment: verdict.amendment_receipt.clone(),
            share: verdict.defect_share,
            at: verdict.at,
        };
        let arm = (verdict.skill, executor.map(str::to_owned));
        desired.insert(key_of(&outcome), (arm, outcome, row));
    }
    Ok(desired)
}

/// The arms whose stored rows differ from `desired`, in first-seen order.
fn moved_arms(vault: &Vault, desired: &Desired) -> Result<Vec<Arm>> {
    let mut arms: Vec<Arm> = Vec::new();
    let mut held = BTreeMap::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (outcome, row) in AMENDED.scan(&vault.store, &rtxn)? {
            let key = key_of(&outcome);
            if desired.get(&key).map(|(_, _, wanted)| wanted) != Some(&row) {
                let (skill, executor) = outcome.arm();
                arms.push((skill, executor.map(str::to_owned)));
            }
            held.insert(key, row);
        }
    }
    for (key, (arm, _, row)) in desired {
        if held.get(key) != Some(row) {
            arms.push(arm.clone());
        }
    }
    let mut seen = BTreeSet::new();
    arms.retain(|arm| seen.insert(arm.clone()));
    Ok(arms)
}

/// Brings one arm's rows to `desired` and reprojects the arm, in ONE write transaction, so the
/// rows and the claim never disagree. The rows are diffed again under the writer: the rows this
/// moves are the ones the ledger holds now, not the ones an earlier read saw.
fn settle_arm(
    vault: &Vault,
    desired: &Desired,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<()> {
    let prior = skill_reliability_prior(vault, skill)?;
    let prefix = outcome_arm_prefix(skill, executor);
    vault.with_write_txn(|wtxn| {
        let mut at = 0;
        let mut moved = false;
        let mut kept = BTreeSet::new();
        for (outcome, row) in AMENDED.scan_from(&vault.store, wtxn, &prefix)? {
            let key = key_of(&outcome);
            if desired.get(&key).map(|(_, _, wanted)| wanted) == Some(&row) {
                kept.insert(key);
                continue;
            }
            AMENDED.delete(&vault.store, wtxn, &outcome)?;
            at = at.max(row.at);
            moved = true;
        }
        let arm = desired
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix));
        for (key, (_, outcome, row)) in arm {
            if kept.contains(key) {
                continue;
            }
            AMENDED.put(&vault.store, wtxn, outcome, row)?;
            at = at.max(row.at);
            moved = true;
        }
        if moved {
            project_in_txn(vault, wtxn, skill, executor, prior, at)?;
        }
        Ok(())
    })
}

/// The full stored key of an outcome row: the identity one attempt's record has in every table
/// keyed by [`OutcomeRef`].
fn key_of(outcome: &OutcomeRef) -> Vec<u8> {
    let mut key = Vec::new();
    outcome.encode_into(&mut key);
    key
}
