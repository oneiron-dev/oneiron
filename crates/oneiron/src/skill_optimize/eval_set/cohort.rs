//! Date-cut sealed cohorts and the exposure ledger (ARCH-0053: "The ledger
//! counts what each sealed cohort has served: candidates, queries and
//! promotions." "Sealed cohorts are cut by date from newer receipts.").
//!
//! A cohort holds whole sealed families: a family whose cases all fall inside
//! the cut window, and which no earlier cohort holds. Its membership is bound
//! by a digest at the cut. The one door that releases it records the serving
//! first, in the same transaction, so a crash after release still counts.
//! Cohort and exposure rows restore LIVE: a historical restore cannot make a
//! spent cohort fresh again.
//!
//! Every cut is audited: it commits with its near-copy audit in one
//! transaction, and only a served cohort retires, with the decision that
//! retired it kept on its row.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::cut_audit::{EvalCutAuditDraft, put_audit_in_txn};
use super::{
    CASE_PREFIX, EvalCase, EvalSeat, FamilyPurpose, decode, family_in_txn, invalid, rows_in_txn,
};
use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

pub(in crate::skill_optimize) const COHORT_PREFIX: &[u8] = b"skill_optimize:eval_cohort:v1:";
pub(in crate::skill_optimize) const EXPOSURE_PREFIX: &[u8] = b"skill_optimize:eval_exposure:v1:";
const MEMBERSHIP_DOMAIN: &[u8] = b"skill_optimize:eval_cohort_membership:v1\0";
const MAX_REF_BYTES: usize = 256;
/// Longest reason a cohort retirement keeps.
pub(super) const MAX_REASON_BYTES: usize = 512;

/// One date-cut cohort of sealed families for a seat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCohort {
    pub id: EntityId,
    pub seat: EvalSeat,
    /// Inclusive start and exclusive end of the cut, in receipt time.
    pub from: u64,
    pub until: u64,
    pub families: BTreeSet<EntityId>,
    pub cases: Vec<EntityId>,
    pub membership_digest: String,
    /// The rubric revision the cohort is scored under; a new rubric is a new
    /// set, and the sufficiency card reads unknown across it.
    pub rubric_revision: String,
    /// The seat's one fixed reference cohort for periodic comparison. It is
    /// never retired.
    pub reference: bool,
    pub cut_at: u64,
    pub retired_at: Option<u64>,
    /// Why the cohort retired, and on what exposure; `None` while it serves
    /// and on rows retired before decisions were kept.
    #[serde(default)]
    pub retirement: Option<CohortRetirement>,
}

/// The eval-authoring skill's decision to retire one cohort: its bounded
/// reason, the skill revision and attempt that made it, and the exposure it
/// read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CohortRetirement {
    pub reason: String,
    pub skill: EntityId,
    pub revision: String,
    pub attempt: EntityId,
    pub exposure: EvalExposureCounts,
}

/// What a serving of a sealed cohort was for. There is no search, authoring
/// or rubric-fit kind: those never read sealed rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvalExposureKind {
    /// One candidate scored against the cohort.
    Candidate,
    /// One query served from it.
    Query,
    /// One promotion decided on it.
    Promotion,
}

/// One counted serving of a cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalExposure {
    pub id: EntityId,
    pub cohort: EntityId,
    pub kind: EvalExposureKind,
    /// The run, campaign or proposal the serving was for.
    pub consumer: String,
    /// The candidate or model pin that was measured, when one was.
    pub candidate_pin: Option<String>,
    pub at: u64,
}

/// The release of a cohort's membership, after its serving was counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvalRelease {
    pub exposure: EvalExposure,
    pub cases: Vec<EvalCase>,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct EvalExposureCounts {
    pub candidates: u64,
    pub queries: u64,
    pub promotions: u64,
}

impl EvalExposureCounts {
    /// Whether the cohort has served anything.
    #[must_use]
    pub const fn served(&self) -> bool {
        self.candidates > 0 || self.queries > 0 || self.promotions > 0
    }
}

fn cohort_key(id: &EntityId) -> Vec<u8> {
    [COHORT_PREFIX, id.as_bytes()].concat()
}

fn encode<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| invalid("eval cohort row encoding failed"))
}

pub(super) fn membership_digest(cases: &[EntityId]) -> String {
    let mut hash = Sha256::new();
    hash.update(MEMBERSHIP_DOMAIN);
    hash.update(u64::try_from(cases.len()).unwrap_or(u64::MAX).to_be_bytes());
    for case in cases {
        hash.update(case.as_bytes());
    }
    bytes_to_hex_lower(&hash.finalize())
}

pub(super) fn cohorts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seat: &EvalSeat,
) -> Result<Vec<EvalCohort>> {
    Ok(rows_in_txn::<EvalCohort>(vault, txn, COHORT_PREFIX)?
        .into_iter()
        .filter(|cohort| &cohort.seat == seat)
        .collect())
}

/// Families of retired cohorts: development now, and never training.
pub(super) fn retired_families_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seat: &EvalSeat,
) -> Result<BTreeSet<EntityId>> {
    Ok(cohorts_in_txn(vault, txn, seat)?
        .into_iter()
        .filter(|cohort| cohort.retired_at.is_some())
        .flat_map(|cohort| cohort.families)
        .collect())
}

pub(in crate::skill_optimize) fn cohort_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<EvalCohort> {
    let raw = vault
        .store
        .vault_meta
        .get(txn, &cohort_key(id))?
        .ok_or(Error::EntityNotFound)?;
    decode(&raw)
}

/// What a cohort has served, by kind, on the caller's snapshot.
pub(super) fn exposure_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cohort: &EntityId,
) -> Result<EvalExposureCounts> {
    let mut counts = EvalExposureCounts::default();
    let prefix = [EXPOSURE_PREFIX, cohort.as_bytes()].concat();
    for exposure in rows_in_txn::<EvalExposure>(vault, txn, &prefix)? {
        let slot = match exposure.kind {
            EvalExposureKind::Candidate => &mut counts.candidates,
            EvalExposureKind::Query => &mut counts.queries,
            EvalExposureKind::Promotion => &mut counts.promotions,
        };
        *slot = slot.saturating_add(1);
    }
    Ok(counts)
}

/// The whole sealed families a cut of `from..until` takes for `seat`, with
/// their cases in id order: each sealed family whose every case's source
/// date falls in the window, and that no earlier cohort holds.
pub(super) fn cut_members_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seat: &EvalSeat,
    from: u64,
    until: u64,
) -> Result<(BTreeSet<EntityId>, Vec<EvalCase>)> {
    let held: BTreeSet<EntityId> = cohorts_in_txn(vault, txn, seat)?
        .iter()
        .flat_map(|cohort| cohort.families.iter().copied())
        .collect();
    let mut by_family: std::collections::BTreeMap<EntityId, Vec<EvalCase>> =
        std::collections::BTreeMap::new();
    for case in rows_in_txn::<EvalCase>(vault, txn, CASE_PREFIX)? {
        if &case.seat == seat && !held.contains(&case.family) {
            by_family.entry(case.family).or_default().push(case);
        }
    }
    let mut families = BTreeSet::new();
    let mut cases = Vec::new();
    for (family, rows) in by_family {
        let sealed = family_in_txn(vault, txn, &family)?
            .ok_or(Error::CorruptedIndex("eval case without its family"))?
            .purpose
            == FamilyPurpose::SealedConfirmation;
        if sealed
            && rows
                .iter()
                .all(|case| (from..until).contains(&case.source_at))
        {
            families.insert(family);
            cases.extend(rows);
        }
    }
    cases.sort_unstable_by_key(|case| case.id);
    Ok((families, cases))
}

/// The cut of `window` itself, in the caller's write transaction.
fn cut_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    seat: &EvalSeat,
    (from, until): (u64, u64),
    rubric_revision: &str,
    reference: bool,
    at: u64,
) -> Result<EvalCohort> {
    if reference
        && cohorts_in_txn(vault, txn, seat)?
            .iter()
            .any(|cohort| cohort.reference)
    {
        return Err(invalid("a seat keeps one fixed reference cohort"));
    }
    let (families, cases) = cut_members_in_txn(vault, txn, seat, from, until)?;
    if families.is_empty() {
        return Err(invalid("no whole sealed family falls in this window"));
    }
    let cases: Vec<EntityId> = cases.into_iter().map(|case| case.id).collect();
    let cohort = EvalCohort {
        id: vault.store.clock.entity_id()?,
        seat: seat.clone(),
        from,
        until,
        families,
        membership_digest: membership_digest(&cases),
        cases,
        rubric_revision: rubric_revision.to_owned(),
        reference,
        cut_at: at,
        retired_at: None,
        retirement: None,
    };
    vault
        .store
        .vault_meta
        .put(txn, &cohort_key(&cohort.id), &encode(&cohort)?)?;
    Ok(cohort)
}

impl Vault {
    /// Cut a cohort for `seat` from sealed families whose every case's source
    /// date falls in `from..until`, and that no earlier cohort holds. The cut
    /// reads history only: `until` may not be later than `at`. At most one
    /// reference cohort stands per seat. The cut and its near-copy `audit`
    /// commit in one transaction, and the audit must be of exactly the
    /// members the cut takes.
    /// # Errors
    /// An empty or future window, a second reference cohort, no family to
    /// cut, an unbounded rubric revision, an audit of another seat, window or
    /// membership, or storage errors.
    #[expect(clippy::too_many_arguments)]
    pub fn cut_eval_cohort(
        &self,
        seat: &EvalSeat,
        from: u64,
        until: u64,
        rubric_revision: &str,
        reference: bool,
        audit: &EvalCutAuditDraft,
        at: u64,
    ) -> Result<EvalCohort> {
        if from >= until || until > at {
            return Err(invalid(
                "an eval cohort is cut from a past, nonempty window",
            ));
        }
        if rubric_revision.trim().is_empty() || rubric_revision.len() > MAX_REF_BYTES {
            return Err(invalid("an eval cohort names a bounded rubric revision"));
        }
        if !audit.covers(seat, from, until) {
            return Err(invalid("a cut's audit is of another seat or window"));
        }
        self.with_write_txn_grouped(|txn| {
            let cohort = cut_in_txn(
                self,
                txn,
                seat,
                (from, until),
                rubric_revision,
                reference,
                at,
            )?;
            if cohort.membership_digest != audit.membership_digest() {
                return Err(invalid("a cut's audit is of other members than the cut"));
            }
            put_audit_in_txn(self, txn, &audit.row(&cohort))?;
            Ok(cohort)
        })
    }

    /// Serve a sealed cohort: count the serving, then release its cases, in
    /// one transaction. A retired cohort serves nothing. A membership that no
    /// longer matches its digest is corruption, never a smaller set.
    /// # Errors
    /// A missing or retired cohort, an unbounded consumer or pin, a case gone
    /// from the ledger, or storage errors.
    pub fn open_eval_cohort(
        &self,
        cohort: &EntityId,
        kind: EvalExposureKind,
        consumer: &str,
        candidate_pin: Option<&str>,
        at: u64,
    ) -> Result<EvalRelease> {
        self.with_write_txn_grouped(|txn| {
            self.open_eval_cohort_in_txn(txn, cohort, kind, consumer, candidate_pin, at)
        })
    }

    /// [`Self::open_eval_cohort`] under the caller's writer: the serving
    /// counts only when the caller's act commits with it.
    /// # Errors
    /// As [`Self::open_eval_cohort`].
    pub(crate) fn open_eval_cohort_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        cohort: &EntityId,
        kind: EvalExposureKind,
        consumer: &str,
        candidate_pin: Option<&str>,
        at: u64,
    ) -> Result<EvalRelease> {
        if consumer.trim().is_empty()
            || consumer.len() > MAX_REF_BYTES
            || candidate_pin.is_some_and(|pin| pin.trim().is_empty() || pin.len() > MAX_REF_BYTES)
        {
            return Err(invalid("an eval exposure names a bounded consumer and pin"));
        }
        let row = cohort_in_txn(self, txn, cohort)?;
        if row.retired_at.is_some() {
            return Err(invalid("a retired eval cohort serves nothing"));
        }
        if membership_digest(&row.cases) != row.membership_digest {
            return Err(Error::CorruptedIndex("eval cohort membership"));
        }
        let exposure = EvalExposure {
            id: self.store.clock.entity_id()?,
            cohort: *cohort,
            kind,
            consumer: consumer.to_owned(),
            candidate_pin: candidate_pin.map(str::to_owned),
            at,
        };
        self.store.vault_meta.put(
            txn,
            &[EXPOSURE_PREFIX, cohort.as_bytes(), exposure.id.as_bytes()].concat(),
            &encode(&exposure)?,
        )?;
        let mut cases = Vec::with_capacity(row.cases.len());
        for case in &row.cases {
            cases.push(
                super::case_in_txn(self, txn, case)?
                    .ok_or(Error::CorruptedIndex("eval cohort case"))?,
            );
        }
        Ok(EvalRelease { exposure, cases })
    }

    /// What a cohort has served, by kind.
    /// # Errors
    /// Unreadable rows, or storage errors.
    pub fn eval_cohort_exposure(&self, cohort: &EntityId) -> Result<EvalExposureCounts> {
        let txn = self.store.env.read_txn()?;
        exposure_in_txn(self, &txn, cohort)
    }

    /// A seat's cohorts, in cut order.
    /// # Errors
    /// Unreadable rows, or storage errors.
    pub fn eval_cohorts(&self, seat: &EvalSeat) -> Result<Vec<EvalCohort>> {
        let txn = self.store.env.read_txn()?;
        let mut cohorts = cohorts_in_txn(self, &txn, seat)?;
        cohorts.sort_by_key(|cohort| (cohort.cut_at, cohort.id));
        Ok(cohorts)
    }

    /// Retire an exposed cohort: its families read as development from now
    /// on, and still never feed training. The reference cohort stays fixed,
    /// and a cohort that has served nothing is not retired. Which exposure
    /// retires a cohort is the eval-authoring skill's policy; this door
    /// records the act with its `decision`. Retiring twice keeps the first
    /// date and decision.
    /// # Errors
    /// A missing cohort, the reference cohort, a cohort with no recorded
    /// exposure, an empty or unbounded reason or revision, or storage errors.
    pub fn retire_eval_cohort(
        &self,
        cohort: &EntityId,
        decision: CohortRetirement,
        at: u64,
    ) -> Result<EvalCohort> {
        if decision.reason.trim().is_empty()
            || decision.reason.len() > MAX_REASON_BYTES
            || decision.revision.trim().is_empty()
            || decision.revision.len() > MAX_REF_BYTES
        {
            return Err(invalid(
                "a cohort retirement names a bounded reason and revision",
            ));
        }
        self.with_write_txn_grouped(|txn| {
            let mut row = cohort_in_txn(self, txn, cohort)?;
            if row.reference {
                return Err(invalid("the reference eval cohort is never retired"));
            }
            if row.retired_at.is_some() {
                return Ok(row);
            }
            if !exposure_in_txn(self, txn, cohort)?.served() {
                return Err(invalid("an eval cohort that served nothing is not retired"));
            }
            row.retired_at = Some(at);
            row.retirement = Some(decision);
            self.store
                .vault_meta
                .put(txn, &cohort_key(cohort), &encode(&row)?)?;
            Ok(row)
        })
    }
}
