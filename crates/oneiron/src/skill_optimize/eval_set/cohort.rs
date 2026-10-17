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
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// One date-cut cohort of sealed families for a seat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

/// What a serving of a sealed cohort was for. There is no search, authoring
/// or rubric-fit kind: those never read sealed rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalRelease {
    pub exposure: EvalExposure,
    pub cases: Vec<EvalCase>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvalExposureCounts {
    pub candidates: u64,
    pub queries: u64,
    pub promotions: u64,
}

fn cohort_key(id: &EntityId) -> Vec<u8> {
    [COHORT_PREFIX, id.as_bytes()].concat()
}

fn encode<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| invalid("eval cohort row encoding failed"))
}

fn membership_digest(cases: &[EntityId]) -> String {
    let mut hash = Sha256::new();
    hash.update(MEMBERSHIP_DOMAIN);
    hash.update(u64::try_from(cases.len()).unwrap_or(u64::MAX).to_be_bytes());
    for case in cases {
        hash.update(case.as_bytes());
    }
    bytes_to_hex_lower(&hash.finalize())
}

fn cohorts_in_txn(
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

fn cohort_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<EvalCohort> {
    let raw = vault
        .store
        .vault_meta
        .get(txn, &cohort_key(id))?
        .ok_or(Error::EntityNotFound)?;
    decode(&raw)
}

impl Vault {
    /// Cut a cohort for `seat` from sealed families whose every case's source
    /// date falls in `from..until`, and that no earlier cohort holds. The cut
    /// reads history only: `until` may not be later than `at`. At most one
    /// reference cohort stands per seat.
    /// # Errors
    /// An empty or future window, a second reference cohort, no family to
    /// cut, an unbounded rubric revision, or storage errors.
    pub fn cut_eval_cohort(
        &self,
        seat: &EvalSeat,
        from: u64,
        until: u64,
        rubric_revision: &str,
        reference: bool,
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
        self.with_write_txn_grouped(|txn| {
            let existing = cohorts_in_txn(self, txn, seat)?;
            if reference && existing.iter().any(|cohort| cohort.reference) {
                return Err(invalid("a seat keeps one fixed reference cohort"));
            }
            let held: BTreeSet<EntityId> = existing
                .iter()
                .flat_map(|cohort| cohort.families.iter().copied())
                .collect();
            let mut by_family: std::collections::BTreeMap<EntityId, Vec<EvalCase>> =
                std::collections::BTreeMap::new();
            for case in rows_in_txn::<EvalCase>(self, txn, CASE_PREFIX)? {
                if &case.seat == seat && !held.contains(&case.family) {
                    by_family.entry(case.family).or_default().push(case);
                }
            }
            let mut families = BTreeSet::new();
            let mut cases = Vec::new();
            for (family, rows) in by_family {
                let sealed = family_in_txn(self, txn, &family)?
                    .ok_or(Error::CorruptedIndex("eval case without its family"))?
                    .purpose
                    == FamilyPurpose::SealedConfirmation;
                if sealed
                    && rows
                        .iter()
                        .all(|case| (from..until).contains(&case.source_at))
                {
                    families.insert(family);
                    cases.extend(rows.into_iter().map(|case| case.id));
                }
            }
            if families.is_empty() {
                return Err(invalid("no whole sealed family falls in this window"));
            }
            cases.sort_unstable();
            let cohort = EvalCohort {
                id: self.store.clock.entity_id()?,
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
            };
            self.store
                .vault_meta
                .put(txn, &cohort_key(&cohort.id), &encode(&cohort)?)?;
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
        if consumer.trim().is_empty()
            || consumer.len() > MAX_REF_BYTES
            || candidate_pin.is_some_and(|pin| pin.trim().is_empty() || pin.len() > MAX_REF_BYTES)
        {
            return Err(invalid("an eval exposure names a bounded consumer and pin"));
        }
        self.with_write_txn_grouped(|txn| {
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
        })
    }

    /// What a cohort has served, by kind.
    /// # Errors
    /// Unreadable rows, or storage errors.
    pub fn eval_cohort_exposure(&self, cohort: &EntityId) -> Result<EvalExposureCounts> {
        let txn = self.store.env.read_txn()?;
        let mut counts = EvalExposureCounts::default();
        let prefix = [EXPOSURE_PREFIX, cohort.as_bytes()].concat();
        for exposure in rows_in_txn::<EvalExposure>(self, &txn, &prefix)? {
            let slot = match exposure.kind {
                EvalExposureKind::Candidate => &mut counts.candidates,
                EvalExposureKind::Query => &mut counts.queries,
                EvalExposureKind::Promotion => &mut counts.promotions,
            };
            *slot = slot.saturating_add(1);
        }
        Ok(counts)
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
    /// on, and still never feed training. The reference cohort stays fixed.
    /// Which exposure retires a cohort is the eval-authoring skill's policy;
    /// this door only records the act. Retiring twice keeps the first date.
    /// # Errors
    /// A missing cohort, the reference cohort, or storage errors.
    pub fn retire_eval_cohort(&self, cohort: &EntityId, at: u64) -> Result<EvalCohort> {
        self.with_write_txn_grouped(|txn| {
            let mut row = cohort_in_txn(self, txn, cohort)?;
            if row.reference {
                return Err(invalid("the reference eval cohort is never retired"));
            }
            if row.retired_at.is_none() {
                row.retired_at = Some(at);
                self.store
                    .vault_meta
                    .put(txn, &cohort_key(cohort), &encode(&row)?)?;
            }
            Ok(row)
        })
    }
}
