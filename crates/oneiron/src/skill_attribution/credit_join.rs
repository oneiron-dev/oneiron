//! The one reconciler of an anchored outcome's late credit (FIX 3241, FIX
//! 10108, OF-540). A sealed credit receipt never changes. What the run's
//! later evidence makes of it is appended beside it: a contribution check
//! that lands after the outcome was credited, contributed or not, on a
//! loaded skill or on one used edge, and a use of the run that lands late (a
//! promotion or summary witness kept with `live = false`). Each recomputes
//! the outcome's effective credit from the sealed receipt by the original
//! projection's own rules: its frozen attribution with every matched check
//! of the exact outcome and every late landing joined
//! ([`effective_fields_in_txn`]), the `credit_decay` the projection froze
//! beside it (FIX 10107, [`seal_decay_in_txn`]), its direct subjects and the
//! shares their used chains pass ([`credit_shares_in_txn`]).
//!
//! A changed credit appends one immutable [`CreditAdjustmentReceipt`] and
//! replaces the outcome's learning mass under the sealed receipt's own
//! evidence key, so a late direct win and the lineage shares it opens count
//! once; a subject whose mass falls to none has its evidence withdrawn. A
//! replayed check or landing changes nothing and appends nothing.
//!
//! Reconciliation is capture-only: one outcome's adjustment and its evidence
//! commit in one savepoint of the caller's transaction, and an error drops
//! that savepoint alone with a WARN, so the check, landing or projection
//! carrying it stands.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::contribution::{followed_in_txn, with_recorded_checks_in_txn};
use super::contribution_targets::CheckedEdge;
use super::late_credit::{CREDIT_RECEIPT, LateCreditReceipt, LateCreditShare, shares_in_txn};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::EntityId;
use crate::learning::{LearningCell, LearningEvidence, LearningPredicate, Observation};
use crate::receipt::{PackAttributionFields, PackLearningContext};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::team::receipt::capture_parents_in_txn;
use crate::{Result, Vault};

/// Each sealed credit receipt's frozen decay and adjustments. Key: string
/// (the credit receipt id NUL [`DECAY`], or NUL a zero-padded index); an
/// erase moves an adjustment naming the erased entity to `erased` NUL a
/// fresh ULID.
const ADJUSTMENT: SideTable<String, CreditJoinRow, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_CREDIT_ADJUSTMENT);

/// The key suffix of a sealed receipt's frozen decay.
const DECAY: &str = "decay";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum CreditJoinRow {
    /// The `credit_decay` the original projection resolved for the outcome
    /// over the run's project and task type, which every reconciliation of
    /// it uses (FIX 10107).
    Decay(f64),
    Adjustment(CreditAdjustmentReceipt),
}

/// One immutable change to an anchored outcome's effective late credit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreditAdjustmentReceipt {
    pub receipt_id: String,
    /// The sealed credit receipt it adjusts, whose evidence key it reuses.
    pub base: String,
    /// The adjustment it follows; `None` when it follows the sealed receipt.
    pub previous: Option<String>,
    /// Every matched check the effective credit joins beyond the sealed
    /// receipt's, by receipt.
    pub checks: Vec<String>,
    /// Every late landed use it joins beyond the sealed receipt's; each end
    /// `None` once that entity is erased.
    pub landed: Vec<CheckedEdge>,
    /// Each subject credited directly, the sealed receipt's first; `None`
    /// for one since erased.
    pub direct_subjects: Vec<Option<EntityId>>,
    /// The effective shares, each with its used chain.
    pub shares: Vec<LateCreditShare>,
    /// When it was appended.
    pub at: u64,
}

/// The adjustments appended to the sealed credit receipt `receipt_id`,
/// oldest first. The receipt itself reads as it was sealed
/// ([`super::late_credit_receipt`]).
///
/// # Errors
///
/// Storage errors.
pub fn credit_adjustments(vault: &Vault, receipt_id: &str) -> Result<Vec<CreditAdjustmentReceipt>> {
    let txn = vault.store.env.read_txn()?;
    Ok(chain_in_txn(&vault.store, &txn, receipt_id)?
        .into_iter()
        .map(|(_, adjustment)| adjustment)
        .collect())
}

fn chain_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    base: &str,
) -> Result<Vec<(String, CreditAdjustmentReceipt)>> {
    Ok(ADJUSTMENT
        .scan_from(store, txn, format!("{base}\0").as_bytes())?
        .into_iter()
        .filter_map(|(key, row)| match row {
            CreditJoinRow::Adjustment(adjustment) => Some((key, adjustment)),
            CreditJoinRow::Decay(_) => None,
        })
        .collect())
}

/// Freezes `decay`, the `credit_decay` the original projection of the
/// sealed receipt `base` resolved, beside it in the projection's `wtxn`.
/// Capture-only: a freeze that fails is dropped in its savepoint with a WARN,
/// the projection stands, and a later reconciliation reads the decay then
/// ([`frozen_decay_in_txn`]).
pub(super) fn seal_decay_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>, base: &str, decay: f64) {
    let key = format!("{base}\0{DECAY}");
    if let Err(error) = super::derivation_witness::in_savepoint(store, wtxn, |txn| {
        ADJUSTMENT.put(store, txn, &key, &CreditJoinRow::Decay(decay))
    }) {
        tracing::warn!(
            kind = ?error.kind(),
            %error,
            "an outcome's credit_decay was not frozen; a reconciliation reads it then"
        );
    }
}

/// The direct subjects `credit` stands with now: its latest adjustment's,
/// else the sealed receipt's own.
///
/// # Errors
///
/// Storage errors.
pub(super) fn latest_direct_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    credit: &LateCreditReceipt,
) -> Result<Vec<Option<EntityId>>> {
    Ok(chain_in_txn(store, txn, &credit.receipt_id)?
        .pop()
        .map_or_else(
            || credit.direct_subjects.clone(),
            |(_, last)| last.direct_subjects,
        ))
}

/// The decay `credit` was projected under: the frozen one, or, for a
/// receipt that froze none, the scoped read now.
fn frozen_decay_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    credit: &LateCreditReceipt,
    sealed: &PackAttributionFields,
) -> Result<f64> {
    match ADJUSTMENT.get(
        &vault.store,
        txn,
        &format!("{}\0{DECAY}", credit.receipt_id),
    )? {
        Some(CreditJoinRow::Decay(decay)) => Ok(decay),
        _ => super::late_credit::credit_decay_in_txn(vault, txn, sealed),
    }
}

/// `fields`, the run `attempt_receipt`'s sealed attribution, with the run's
/// late landed uses appended and then every matched check of the exact
/// outcome joined: the attribution its credit reads, at projection and at
/// every reconciliation. The late landings read best effort: a read that
/// fails joins none, with a WARN.
///
/// # Errors
///
/// Storage errors.
pub(super) fn joined_fields_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_receipt: &str,
    outcome_receipt: &str,
    axis: &str,
    goal_revision: Option<&str>,
    mut fields: PackAttributionFields,
) -> Result<PackAttributionFields> {
    match landed_in_txn(vault, txn, attempt_receipt) {
        Ok(landed) => {
            super::derivation_witness::extend_used(&mut fields, landed);
        }
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                %error,
                "a run's late landed uses were not read; its credit goes on without them"
            );
        }
    }
    with_recorded_checks_in_txn(
        &vault.store,
        txn,
        attempt_receipt,
        outcome_receipt,
        axis,
        goal_revision,
        fields,
    )
}

/// [`joined_fields_in_txn`] for `credit`, from its `sealed` attribution.
///
/// # Errors
///
/// Storage errors.
pub(super) fn effective_fields_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    credit: &LateCreditReceipt,
    sealed: PackAttributionFields,
) -> Result<PackAttributionFields> {
    joined_fields_in_txn(
        vault,
        txn,
        &credit.attempt_receipt,
        &credit.outcome_receipt,
        &credit.axis,
        credit.goal_revision.as_deref(),
        sealed,
    )
}

/// The skills `fields` holds a contributing check for.
fn contributing(fields: &PackAttributionFields) -> Vec<EntityId> {
    fields
        .contributions
        .iter()
        .filter(|c| c.check.contributed)
        .map(|c| c.skill)
        .collect()
}

/// The skills among `direct` that `fields` holds a contributing check for:
/// the origins a successful outcome's lineage shares start from.
fn origins(fields: &PackAttributionFields, direct: &[Option<EntityId>]) -> Vec<EntityId> {
    let contributing = contributing(fields);
    direct
        .iter()
        .flatten()
        .copied()
        .filter(|subject| contributing.contains(subject))
        .collect()
}

/// The shares a successful outcome's `direct` subjects pass up `fields`'
/// used chains at `decay`; none while no one won directly.
///
/// # Errors
///
/// Storage errors.
pub(super) fn credit_shares_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fields: &PackAttributionFields,
    direct: &[Option<EntityId>],
    decay: f64,
) -> Result<Vec<LateCreditShare>> {
    if direct.is_empty() {
        return Ok(Vec::new());
    }
    shares_in_txn(vault, txn, fields, &origins(fields, direct), decay)
}

/// The reliability cell `subject`'s credit for an outcome on `axis` lands
/// in, in the run's frozen project (FIX 6038), never the credited subject's.
pub(super) fn credit_cell(
    fields: &PackAttributionFields,
    axis: &str,
    subject: EntityId,
) -> LearningCell {
    LearningCell::new(LearningPredicate::Reliability, subject)
        .executor(fields.executor.clone())
        .type_ref(fields.type_ref.clone())
        .axis(axis.to_owned())
        .project(fields.project)
}

/// Records `evidence` in a credit cell. A cell with no own head and no
/// stored prior first keeps the prior its read borrows through the stamp's
/// placed ancestry (FIX 9889), as a team outcome's first result does: the
/// evidence then adds runs against that weight instead of a shipped head.
/// The capture is best effort: a read it needs that fails keeps nothing and
/// is logged, and the evidence is recorded as it always was.
pub(super) fn record_credit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fields: &PackAttributionFields,
    cell: &LearningCell,
    evidence: &LearningEvidence,
    now: u64,
) -> Result<()> {
    // A savepoint, so a capture that fails part-way leaves none of its rows.
    if let Err(error) = super::derivation_witness::in_savepoint(&vault.store, txn, |txn| {
        capture_first_prior_in_txn(vault, txn, fields, cell, evidence)
    }) {
        tracing::warn!(
            kind = ?error.kind(),
            %error,
            "a credit cell's borrowed prior was not kept; its evidence records over the shipped prior"
        );
    }
    crate::learning::record_evidence_in_txn(vault, txn, cell, evidence, now)?;
    Ok(())
}

/// [`record_credit_in_txn`]'s capture: nothing for a cell that already has
/// an own head or a stored prior, so its ancestry is never read then.
fn capture_first_prior_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fields: &PackAttributionFields,
    cell: &LearningCell,
    evidence: &LearningEvidence,
) -> Result<()> {
    if crate::learning::prior::PRIOR.contains(&vault.store, txn, &cell.digest())?
        || crate::learning::read::own_estimate_in_txn(vault, txn, cell)?.is_some()
    {
        return Ok(());
    }
    let parents = capture_parents_in_txn(vault, txn, fields.project, &fields.type_ref)?;
    let form = evidence.observation.form();
    crate::learning::prior::capture_borrowed_prior_in_txn(vault, txn, cell, &parents, form)
}

/// One subject's observation of `credit`'s outcome at `weight`, under the
/// sealed receipt's own evidence key, so a later reconciliation replaces it.
pub(super) fn credit_evidence(
    credit: &LateCreditReceipt,
    fields: &PackAttributionFields,
    success: bool,
    weight: f64,
) -> LearningEvidence {
    let mut learning = LearningEvidence::anchored(
        &credit.receipt_id,
        credit.at,
        credit.anchor,
        Observation::Success(success),
    );
    learning.weight = weight;
    // An unknown judge stays unknown, and no run is on it (FIX 1877).
    learning.judge = fields.judge.clone();
    learning.on_judge_model = fields.judge.as_deref() == Some(fields.executor.as_str());
    learning.pack_attribution = Some(PackLearningContext {
        attempt_receipt: credit.attempt_receipt.clone(),
        outcome_receipt: credit.outcome_receipt.clone(),
        attribution: fields.clone(),
    });
    learning.goal_revision = credit.goal_revision.clone();
    learning
}

/// Each live subject's learning mass in a successful credit: a direct win
/// counts whole, and a share only for a subject that did not win directly.
fn masses(direct: &[Option<EntityId>], shares: &[LateCreditShare]) -> BTreeMap<EntityId, f64> {
    let mut out: BTreeMap<EntityId, f64> = direct.iter().flatten().map(|s| (*s, 1.0)).collect();
    for share in shares {
        if let Some(subject) = share.subject {
            out.entry(subject).or_insert(share.weight);
        }
    }
    out
}

/// The observation `subject`'s evidence for `credit` currently stands at:
/// the win and mass of the latest adjustment beside the sealed credit, or
/// the sealed projection's own when no adjustment landed. `None` when the
/// credit currently credits `subject` nothing. A failed credit is never
/// adjusted, so its direct subjects stand whole at the failure. The
/// anchored-amendment join (FIX 10148) restores to exactly this, never to
/// the sealed projection alone.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn standing_credit_observation_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    credit: &LateCreditReceipt,
    subject: &EntityId,
) -> Result<Option<(bool, f64)>> {
    if !credit.succeeded {
        return Ok(credit
            .direct_subjects
            .contains(&Some(*subject))
            .then_some((false, 1.0)));
    }
    let chain = chain_in_txn(&vault.store, txn, &credit.receipt_id)?;
    let (direct, shares) = match chain.last() {
        Some((_, last)) => (&last.direct_subjects, &last.shares),
        None => (&credit.direct_subjects, &credit.shares),
    };
    Ok(masses(direct, shares)
        .get(subject)
        .map(|mass| (true, *mass)))
}

/// The observation a credit write for `subject` lands under `credit`'s
/// stable key: the credited `success` at `weight`, unless a judged
/// amendment currently charges the attempt, whose loss at its defect share
/// is the attempt's one effective run whichever door writes the row
/// (FIX 10148). The reliability projection states the same effective form,
/// so the two doors converge instead of overwriting each other.
///
/// # Errors
///
/// Storage errors.
pub(super) fn effective_observation_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    credit: &LateCreditReceipt,
    fields: &PackAttributionFields,
    subject: &EntityId,
    success: bool,
    weight: f64,
) -> Result<(bool, f64)> {
    match crate::skill_reliability::amended_share_in_txn(
        vault,
        txn,
        subject,
        Some(fields.executor.as_str()),
        &credit.attempt_receipt,
    )? {
        Some(share) => Ok((false, f64::from(share))),
        None => Ok((success, weight)),
    }
}

/// Reconciles every successful credited outcome of the run `attempt_receipt`
/// in `txn` (see the module docs), each in a savepoint of its own; capture
/// only.
pub(super) fn reconcile_credited_outcomes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt_receipt: &str,
    now: u64,
) {
    let (credits, followed) = match credits_in_txn(vault, txn, attempt_receipt) {
        Ok(read) => read,
        Err(error) => {
            warn_unreconciled(&error);
            return;
        }
    };
    for credit in credits {
        capture_in_txn(&vault.store, txn, |txn| {
            reconcile_in_txn(vault, txn, &credit, &followed, now)
        });
    }
}

/// The run `attempt_receipt`'s successful credited outcomes and the skills
/// it followed to success, read only through `txn`.
fn credits_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_receipt: &str,
) -> Result<(Vec<LateCreditReceipt>, BTreeSet<EntityId>)> {
    let credits = CREDIT_RECEIPT
        .scan_from(&vault.store, txn, &[])?
        .into_iter()
        .map(|(_, credit)| credit)
        .filter(|credit| credit.attempt_receipt == attempt_receipt && credit.succeeded)
        .collect();
    Ok((credits, followed_in_txn(vault, txn, attempt_receipt)?))
}

fn reconcile_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    credit: &LateCreditReceipt,
    followed: &BTreeSet<EntityId>,
    now: u64,
) -> Result<()> {
    let Some(sealed) = credit.attribution.clone() else {
        return Ok(());
    };
    let fields = effective_fields_in_txn(vault, txn, credit, sealed.clone())?;
    // A skill followed to success wins directly with a contributing check
    // the sealed receipt did not hold (the projection already read the
    // ones it did), and the team pattern with its own once someone else won.
    let mut direct = credit.direct_subjects.clone();
    let checked = contributing(&fields);
    for skill in checked.iter().filter(|skill| {
        **skill != fields.pattern && !sealed.contributions.iter().any(|c| c.skill == **skill)
    }) {
        if followed.contains(skill) && !direct.contains(&Some(*skill)) {
            direct.push(Some(*skill));
        }
    }
    if checked.contains(&fields.pattern)
        && !direct.is_empty()
        && !direct.contains(&Some(fields.pattern))
    {
        direct.push(Some(fields.pattern));
    }
    let decay = frozen_decay_in_txn(vault, txn, credit, &sealed)?;
    let shares = credit_shares_in_txn(vault, txn, &fields, &direct, decay)?;
    let chain = chain_in_txn(&vault.store, txn, &credit.receipt_id)?;
    let (previous, last_direct, last_shares) = match chain.last() {
        Some((_, last)) => (
            Some(last.receipt_id.clone()),
            &last.direct_subjects,
            &last.shares,
        ),
        None => (None, &credit.direct_subjects, &credit.shares),
    };
    // A replayed check or landing, or one that moves no credit, appends
    // nothing.
    if *last_direct == direct && *last_shares == shares {
        return Ok(());
    }
    let before = masses(last_direct, last_shares);
    let after = masses(&direct, &shares);
    for (subject, weight) in &after {
        if before.get(subject) != Some(weight) {
            let cell = credit_cell(&fields, &credit.axis, *subject);
            let (success, weight) =
                effective_observation_in_txn(vault, txn, credit, &fields, subject, true, *weight)?;
            let evidence = credit_evidence(credit, &fields, success, weight);
            record_credit_in_txn(vault, txn, &fields, &cell, &evidence, now)?;
        }
    }
    for subject in before
        .keys()
        .filter(|subject| !after.contains_key(*subject))
    {
        let cell = credit_cell(&fields, &credit.axis, *subject);
        // A subject the standing credit no longer carries loses its row,
        // unless a standing amendment charges it: then the flipped loss is
        // the row (FIX 10148).
        match crate::skill_reliability::amended_share_in_txn(
            vault,
            txn,
            subject,
            Some(fields.executor.as_str()),
            &credit.attempt_receipt,
        )? {
            Some(share) => {
                let evidence = credit_evidence(credit, &fields, false, f64::from(share));
                record_credit_in_txn(vault, txn, &fields, &cell, &evidence, now)?;
            }
            None => {
                crate::learning::evidence::withdraw_evidence_in_txn(
                    vault,
                    txn,
                    &cell,
                    &credit.receipt_id,
                    now,
                )?;
            }
        }
    }
    let index = chain
        .last()
        .and_then(|(key, _)| key.rsplit_once('\0'))
        .and_then(|(_, index)| index.parse::<u64>().ok())
        .map_or(0, |index| index + 1);
    let sealed_checks = check_receipts(&sealed);
    let sealed_edges: BTreeSet<_> = sealed
        .used_edges
        .iter()
        .map(|edge| (edge.derived, edge.source))
        .collect();
    let adjustment = CreditAdjustmentReceipt {
        receipt_id: format!("{}:adjustment:{index}", credit.receipt_id),
        base: credit.receipt_id.clone(),
        previous,
        checks: check_receipts(&fields)
            .difference(&sealed_checks)
            .cloned()
            .collect(),
        landed: fields
            .used_edges
            .iter()
            .filter(|edge| !sealed_edges.contains(&(edge.derived, edge.source)))
            .map(|edge| CheckedEdge {
                derived: Some(edge.derived),
                source: Some(edge.source),
            })
            .collect(),
        direct_subjects: direct,
        shares,
        at: now,
    };
    let key = format!("{}\0{index:010}", credit.receipt_id);
    ADJUSTMENT.put(
        &vault.store,
        txn,
        &key,
        &CreditJoinRow::Adjustment(adjustment),
    )
}

/// Every check receipt `fields` joins, on a skill or on a used edge.
fn check_receipts(fields: &PackAttributionFields) -> BTreeSet<String> {
    fields
        .contributions
        .iter()
        .map(|c| c.check.receipt.clone())
        .chain(
            fields
                .used_edges
                .iter()
                .filter_map(|edge| edge.check.as_ref().map(|check| check.receipt.clone())),
        )
        .collect()
}

/// The roots `credit`'s lineage shares start from as it now stands: the
/// run's output and each skill that won it directly with a contributing
/// check. An edge whose derived end is one of them is adjacent to the
/// outcome.
///
/// # Errors
///
/// Storage errors.
pub(super) fn credit_roots_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    credit: &LateCreditReceipt,
) -> Result<BTreeSet<EntityId>> {
    let Some(sealed) = credit.attribution.clone() else {
        return Ok(BTreeSet::new());
    };
    let fields = effective_fields_in_txn(vault, txn, credit, sealed)?;
    let direct = latest_direct_in_txn(&vault.store, txn, credit)?;
    Ok(origins(&fields, &direct)
        .into_iter()
        .chain(fields.output)
        .collect())
}

/// The uses that landed late for the try of the run `attempt_receipt` that
/// closed it, every lease generation of its attempt's try, oldest first;
/// none for a receipt that names no attempt.
fn landed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_receipt: &str,
) -> Result<Vec<(EntityId, EntityId)>> {
    let Some(attempt) = receipt_attempt(attempt_receipt) else {
        return Ok(Vec::new());
    };
    let Some(record) = AttemptQueue::from_store(&vault.store).get_in_txn(txn, attempt)? else {
        return Ok(Vec::new());
    };
    super::derivation_witness::landed_all_pairs_in_txn(
        &vault.store,
        txn,
        attempt,
        record.attempt_count,
    )
}

/// The attempt a terminal pack receipt names, when it is one.
fn receipt_attempt(receipt: &str) -> Option<AttemptId> {
    let (_, hex) = receipt.rsplit_once(':')?;
    let attempt = AttemptId::from_bytes(EntityId::from_hex(hex).ok()?.as_bytes()).ok()?;
    (crate::receipt::attempt_pack_receipt_id(&attempt) == receipt).then_some(attempt)
}

/// Runs `reconcile` in a savepoint of `wtxn` that commits only when all of
/// it lands: an error aborts the savepoint alone with one WARN, and the
/// write carrying it goes on.
pub(super) fn capture_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    reconcile: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
) {
    if let Err(error) = super::derivation_witness::in_savepoint(store, wtxn, reconcile) {
        warn_unreconciled(&error);
    }
}

fn warn_unreconciled(error: &crate::Error) {
    tracing::warn!(
        kind = ?error.kind(),
        %error,
        "a credited outcome was not reconciled; its credit stands as it was"
    );
}

/// Keeps every row naming erased `entity` in erased form (FIX 8988).
///
/// - An adjustment clears a direct subject, share subject or landed end it
///   names, and a chain it is on or whose origin it is, and moves from its
///   key to `erased` NUL a fresh ULID that no id it held derives. It keeps
///   its checks (opaque ids), weights and time.
/// - A row whose sealed receipt's run or outcome reference spells the
///   entity's id has a key and links derived from them: an adjustment there
///   also drops its base, its previous link and its own id for opaque erased
///   ones and moves as above, and the frozen decay there goes.
///
/// A row that no longer decodes is deleted and counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_credit_adjustments_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let spelled = entity.to_hex().to_ascii_lowercase();
    let mut bases: BTreeMap<String, bool> = BTreeMap::new();
    for (key, row) in super::skill_erase::erase_scan_in_txn(vault, wtxn, ADJUSTMENT)? {
        let base = match &row {
            CreditJoinRow::Decay(_) => key.rsplit_once('\0').map(|(base, _)| base.to_owned()),
            CreditJoinRow::Adjustment(adjustment) => Some(adjustment.base.clone()),
        };
        let base_named = match base {
            Some(base) => match bases.get(&base) {
                Some(named) => *named,
                None => {
                    let named = base_names_in_txn(&vault.store, wtxn, &base, &spelled)?;
                    bases.insert(base, named);
                    named
                }
            },
            None => false,
        };
        let mut adjustment = match row {
            CreditJoinRow::Decay(_) => {
                if base_named {
                    ADJUSTMENT.delete(&vault.store, wtxn, &key)?;
                }
                continue;
            }
            CreditJoinRow::Adjustment(adjustment) => adjustment,
        };
        let mut named = base_named;
        for subject in &mut adjustment.direct_subjects {
            if *subject == Some(*entity) {
                *subject = None;
                named = true;
            }
        }
        for edge in &mut adjustment.landed {
            for end in [&mut edge.derived, &mut edge.source] {
                if *end == Some(*entity) {
                    *end = None;
                    named = true;
                }
            }
        }
        named |= super::late_credit::redact_shares(&mut adjustment.shares, *entity);
        if !named {
            continue;
        }
        let fresh = crate::entity_id::bytes_to_hex_lower(&vault.store.clock.ulid()?);
        if base_named {
            adjustment.receipt_id = format!("erased:{fresh}");
            adjustment.base = "erased".to_owned();
            adjustment.previous = None;
        }
        ADJUSTMENT.delete(&vault.store, wtxn, &key)?;
        let moved = format!("erased\0{fresh}");
        ADJUSTMENT.put(
            &vault.store,
            wtxn,
            &moved,
            &CreditJoinRow::Adjustment(adjustment),
        )?;
    }
    Ok(())
}

/// Whether the sealed receipt `base`'s run or outcome reference spells
/// `spelled`, an id's lowercase hex, without regard to case.
fn base_names_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    base: &str,
    spelled: &str,
) -> Result<bool> {
    let credit = CREDIT_RECEIPT.get(store, txn, &base.to_owned())?;
    Ok(credit.is_some_and(|credit| {
        [&credit.attempt_receipt, &credit.outcome_receipt]
            .iter()
            .any(|text| text.to_ascii_lowercase().contains(spelled))
    }))
}
