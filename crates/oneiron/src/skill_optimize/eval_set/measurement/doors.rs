//! The measurement doors: ask, read, claim, record a case and fail. Each
//! keeps the row under its request's digest; nothing here pays for a leg.

use std::collections::BTreeSet;

use super::{
    EvalCaseMeasurement, EvalMeasurement, EvalMeasurementRequest, MeasurementMethodPin,
    MeasurementState, MeasurementUnavailable,
};
use crate::Vault;
use crate::dreamer_runner::maintenance::coach::enqueue_coach_eval_measurement_in_txn;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::eval_set::cohort::cohort_in_txn;
use crate::skill_optimize::eval_set::{EvalCohort, EvalExposureKind, EvalSeat};

/// One measurement, keyed by its request digest.
const MEASUREMENTS: SideTable<[u8; 32], EvalMeasurement, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_EVAL_MEASUREMENT);
/// The request digest's domain.
const DIGEST_DOMAIN: &[u8] = b"skill_optimize:eval_measurement:v1\0";
/// Longest pin, scorer, axis or slice a request names.
const MAX_REF_BYTES: usize = 256;
/// The legs a claim counts an exposure for, in order: the incumbent, the
/// candidate and the incumbent retest, each a Candidate serving (CALL: three
/// exposures, not two).
const EXPOSURE_LEGS: [&str; 3] = ["incumbent", "candidate", "retest"];
/// The canary metric a seat declares beside its measured axis. None is
/// declared in this build (CALL), so every measured card reads unknown with
/// `NoCanary` until a ruling names one.
const SEAT_CANARIES: &[(EvalSeat, &str)] = &[];

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}

/// The canary metric `seat` declares, if any.
#[must_use]
pub fn eval_seat_canary(seat: &EvalSeat) -> Option<&'static str> {
    SEAT_CANARIES
        .iter()
        .find(|(declared, _)| declared == seat)
        .map(|(_, metric)| *metric)
}

/// The digest that keys a request's row: its domain and its named encoding.
pub(super) fn request_digest(request: &EvalMeasurementRequest) -> Result<[u8; 32]> {
    let bytes = rmp_serde::to_vec_named(request)
        .map_err(|_| invalid("an eval measurement request does not encode"))?;
    let mut hash = blake3::Hasher::new();
    hash.update(DIGEST_DOMAIN);
    hash.update(&bytes);
    Ok(*hash.finalize().as_bytes())
}

/// A digest as its row and its Coach job name it.
pub(in crate::skill_optimize::eval_set) fn digest_hex(digest: &[u8; 32]) -> String {
    blake3::Hash::from(*digest).to_hex().as_str().to_owned()
}

/// One measurement on the caller's snapshot.
pub(in crate::skill_optimize::eval_set) fn measurement_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<EvalMeasurement>> {
    MEASUREMENTS.get(&vault.store, txn, digest)
}

pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
    row: &EvalMeasurement,
) -> Result<()> {
    MEASUREMENTS.put(&vault.store, txn, digest, row)
}

/// Whether the cohort moved from what the request froze.
pub(super) fn cohort_moved(cohort: &EvalCohort, request: &EvalMeasurementRequest) -> bool {
    cohort.retired_at.is_some()
        || cohort.membership_digest != request.membership_digest
        || cohort.rubric_revision != request.rubric_revision
}

fn bounded(text: &str) -> bool {
    !text.trim().is_empty() && text.len() <= MAX_REF_BYTES
}

fn validate(request: &EvalMeasurementRequest) -> Result<()> {
    let arms = [&request.incumbent, &request.candidate];
    if !bounded(&request.decision)
        || !bounded(&request.scorer)
        || !bounded(&request.axis.axis)
        || !bounded(&request.axis.units)
        || arms
            .iter()
            .any(|arm| !bounded(&arm.model) || !bounded(&arm.revision) || !bounded(&arm.label()))
        || request
            .floor_slices
            .required
            .iter()
            .any(|slice| !bounded(slice))
    {
        return Err(invalid(
            "an eval measurement names bounded pins, scorer, axis and slices",
        ));
    }
    if request.incumbent == request.candidate {
        return Err(invalid("an eval measurement compares two different arms"));
    }
    if request.method != MeasurementMethodPin::current() {
        return Err(invalid("an eval measurement runs this build's method"));
    }
    Ok(())
}

/// The row a fresh request starts.
fn pending(digest: &[u8; 32], request: &EvalMeasurementRequest, now: u64) -> EvalMeasurement {
    EvalMeasurement {
        digest: digest_hex(digest),
        request: request.clone(),
        state: MeasurementState::Pending,
        requested_at: now,
        claimed_at: None,
        settled_at: None,
        members: Vec::new(),
        exposures: Vec::new(),
        cases: Vec::new(),
        families: Vec::new(),
        mean_delta: None,
        gap: None,
        card: None,
    }
}

impl Vault {
    /// [`Self::request_eval_measurement`] under the caller's writer.
    /// # Errors
    /// As [`Self::request_eval_measurement`].
    pub(crate) fn request_eval_measurement_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: &EvalMeasurementRequest,
        now: u64,
    ) -> Result<[u8; 32]> {
        validate(request)?;
        let digest = request_digest(request)?;
        if let Some(row) = MEASUREMENTS.get(&self.store, &*txn, &digest)? {
            // An open measurement's job is queued again; the queue's dedupe
            // keeps one.
            if matches!(
                row.state,
                MeasurementState::Pending | MeasurementState::Claimed
            ) {
                enqueue_coach_eval_measurement_in_txn(self, txn, &digest, now)?;
            }
            return Ok(digest);
        }
        let cohort = cohort_in_txn(self, &*txn, &request.cohort)?;
        if cohort.seat != request.seat || cohort_moved(&cohort, request) {
            return Err(invalid(
                "an eval measurement names its seat's live cohort as it stands",
            ));
        }
        MEASUREMENTS.put(&self.store, txn, &digest, &pending(&digest, request, now))?;
        enqueue_coach_eval_measurement_in_txn(self, txn, &digest, now)?;
        Ok(digest)
    }

    /// Ask for one paired measurement and queue the Coach's measuring job.
    /// The same request again returns its digest and keeps its row; an open
    /// one's job is queued again. Nothing is counted or paid here.
    /// # Errors
    /// Unbounded or identical arms, another method, a cohort that is not the
    /// seat's as the request froze it, or storage errors.
    pub fn request_eval_measurement(
        &self,
        request: &EvalMeasurementRequest,
        now: u64,
    ) -> Result<[u8; 32]> {
        self.with_write_txn_grouped(|txn| self.request_eval_measurement_in_txn(txn, request, now))
    }

    /// One measurement, by its request digest.
    /// # Errors
    /// Storage errors.
    pub fn eval_measurement(&self, digest: &[u8; 32]) -> Result<Option<EvalMeasurement>> {
        let txn = self.store.env.read_txn()?;
        measurement_in_txn(self, &txn, digest)
    }

    /// Claim a Pending measurement before any paid work: count three
    /// Candidate servings of its cohort (incumbent, candidate, retest) and
    /// freeze its members, in one transaction. A claimed or settled row
    /// returns as it stands, so a resumed job reads its stored exposures. A
    /// cohort that moved since the request settles the row Partial.
    /// # Errors
    /// A missing measurement or cohort, or storage errors.
    pub fn claim_eval_measurement(&self, digest: &[u8; 32], now: u64) -> Result<EvalMeasurement> {
        self.with_write_txn_grouped(|txn| {
            let mut row = MEASUREMENTS
                .get(&self.store, &*txn, digest)?
                .ok_or(Error::EntityNotFound)?;
            if row.state != MeasurementState::Pending {
                return Ok(row);
            }
            let cohort = cohort_in_txn(self, &*txn, &row.request.cohort)?;
            if cohort_moved(&cohort, &row.request) {
                row.state = MeasurementState::Partial {
                    reasons: vec![MeasurementUnavailable::CohortMoved],
                };
                row.settled_at = Some(now);
            } else {
                let pins = [
                    row.request.incumbent.label(),
                    row.request.candidate.label(),
                    row.request.incumbent.label(),
                ];
                for (leg, pin) in EXPOSURE_LEGS.iter().zip(&pins) {
                    let release = self.open_eval_cohort_in_txn(
                        txn,
                        &cohort.id,
                        EvalExposureKind::Candidate,
                        &format!("eval_measurement:{}:{leg}", row.digest),
                        Some(pin.as_str()),
                        now,
                    )?;
                    row.exposures.push(release.exposure.id);
                }
                row.members = cohort.cases;
                row.state = MeasurementState::Claimed;
                row.claimed_at = Some(now);
            }
            MEASUREMENTS.put(&self.store, txn, digest, &row)?;
            Ok(row)
        })
    }

    /// Record one case's legs on a claimed measurement. A case is first
    /// marked started (`recorded_at: None`), before any leg is sent, then
    /// recorded settled; a settled case is kept as it is.
    /// # Errors
    /// A measurement that is not claimed, a case outside its members, or
    /// storage errors.
    pub fn record_eval_case_measurement(
        &self,
        digest: &[u8; 32],
        case: EvalCaseMeasurement,
    ) -> Result<EvalMeasurement> {
        self.with_write_txn_grouped(|txn| {
            let mut row = MEASUREMENTS
                .get(&self.store, &*txn, digest)?
                .ok_or(Error::EntityNotFound)?;
            if row.state != MeasurementState::Claimed || !row.members.contains(&case.case) {
                return Err(invalid(
                    "a case is recorded on a claimed measurement of its cohort",
                ));
            }
            match row.cases.iter().position(|kept| kept.case == case.case) {
                Some(index) if row.cases[index].recorded_at.is_some() => return Ok(row),
                Some(index) => row.cases[index] = case,
                None => row.cases.push(case),
            }
            MEASUREMENTS.put(&self.store, txn, digest, &row)?;
            Ok(row)
        })
    }

    /// Settle an open measurement Partial with `reasons`: no card, and no
    /// approving interval. A settled row is kept as it is.
    /// # Errors
    /// A missing measurement, or storage errors.
    pub fn fail_eval_measurement(
        &self,
        digest: &[u8; 32],
        reasons: &[MeasurementUnavailable],
        now: u64,
    ) -> Result<EvalMeasurement> {
        self.with_write_txn_grouped(|txn| {
            let mut row = MEASUREMENTS
                .get(&self.store, &*txn, digest)?
                .ok_or(Error::EntityNotFound)?;
            if matches!(
                row.state,
                MeasurementState::Pending | MeasurementState::Claimed
            ) {
                let mut reasons: BTreeSet<MeasurementUnavailable> =
                    reasons.iter().copied().collect();
                if reasons.is_empty() {
                    reasons.insert(MeasurementUnavailable::IncompleteCase);
                }
                row.state = MeasurementState::Partial {
                    reasons: reasons.into_iter().collect(),
                };
                row.settled_at = Some(now);
                MEASUREMENTS.put(&self.store, txn, digest, &row)?;
            }
            Ok(row)
        })
    }

    /// The members of a claimed measurement that have no settled case yet,
    /// in cohort order, and those of them a past run marked started: a
    /// started case's legs may have been sent.
    /// # Errors
    /// A missing measurement, or storage errors.
    pub fn eval_measurement_open_cases(&self, digest: &[u8; 32]) -> Result<Vec<(EntityId, bool)>> {
        let row = self
            .eval_measurement(digest)?
            .ok_or(Error::EntityNotFound)?;
        Ok(row
            .members
            .iter()
            .filter_map(
                |member| match row.cases.iter().find(|case| case.case == *member) {
                    Some(case) if case.recorded_at.is_some() => None,
                    Some(_) => Some((*member, true)),
                    None => Some((*member, false)),
                },
            )
            .collect())
    }
}

/// The re-measure's digest domain (FIX 12175).
const REMEASURE_DOMAIN: &[u8] = b"skill_optimize:eval_measurement:remeasure:v1\0";

/// Where the request `digest` keys is measured again while its Partial
/// `row` stands: one digest per Partial row, so each settled row opens a
/// new one.
fn remeasure_digest(digest: &[u8; 32], row: &EvalMeasurement) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(REMEASURE_DOMAIN);
    hash.update(digest);
    hash.update(&row.requested_at.to_be_bytes());
    hash.update(&row.settled_at.unwrap_or_default().to_be_bytes());
    *hash.finalize().as_bytes()
}

impl Vault {
    /// Measures a Partial row's request again, for a reader that reads
    /// Partial as not yet measured: the helper gate (FIX 12175). The
    /// request is measured beside the row, under its own digest, and the
    /// Partial row stays readable as it is until that measurement settles.
    /// The next call then puts the settled row in the Partial's place,
    /// under `digest`; one that settled Partial again is measured again.
    /// An open re-measure's job is queued again; the queue's dedupe keeps
    /// one. A Pending, Claimed or Final row, or a Partial whose cohort
    /// moved since its request, is returned as it stands.
    /// # Errors
    /// A missing measurement or cohort, or storage errors.
    pub fn remeasure_partial_eval_measurement(
        &self,
        digest: &[u8; 32],
        now: u64,
    ) -> Result<EvalMeasurement> {
        self.with_write_txn_grouped(|txn| {
            let mut row = MEASUREMENTS
                .get(&self.store, &*txn, digest)?
                .ok_or(Error::EntityNotFound)?;
            if !matches!(row.state, MeasurementState::Partial { .. }) {
                return Ok(row);
            }
            let mut again = remeasure_digest(digest, &row);
            if let Some(mut remeasured) = MEASUREMENTS.get(&self.store, &*txn, &again)? {
                if matches!(
                    remeasured.state,
                    MeasurementState::Pending | MeasurementState::Claimed
                ) {
                    enqueue_coach_eval_measurement_in_txn(self, txn, &again, now)?;
                    return Ok(row);
                }
                MEASUREMENTS.delete(&self.store, txn, &again)?;
                remeasured.digest = digest_hex(digest);
                MEASUREMENTS.put(&self.store, txn, digest, &remeasured)?;
                if !matches!(remeasured.state, MeasurementState::Partial { .. }) {
                    return Ok(remeasured);
                }
                again = remeasure_digest(digest, &remeasured);
                row = remeasured;
            }
            let cohort = cohort_in_txn(self, &*txn, &row.request.cohort)?;
            if cohort.seat != row.request.seat || cohort_moved(&cohort, &row.request) {
                return Ok(row);
            }
            MEASUREMENTS.put(
                &self.store,
                txn,
                &again,
                &pending(&again, &row.request, now),
            )?;
            enqueue_coach_eval_measurement_in_txn(self, txn, &again, now)?;
            Ok(row)
        })
    }
}
