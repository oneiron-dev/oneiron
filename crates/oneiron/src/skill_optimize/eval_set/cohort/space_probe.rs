//! The space probes' cohort metadata (FIX 6744; ARCH-0053 `#eval-exposure`), kept in the
//! ledger's own family, case, cohort and exposure rows under the reserved `space_probe.<kind>`
//! seats. It is a metadata-only import, not an audited sealed cut: it writes no audit,
//! releases no case, reads no retirement and names no runnable task. A space move's check
//! reads none of it.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use super::super::{
    CASE_PREFIX, DerivationKind, EvalCase, EvalCaseDraft, EvalSeat, FamilyPurpose,
    assign_family_in_txn, record_case_in_txn, root_family_in_txn, rows_in_txn,
};
use super::{
    EXPOSURE_PREFIX, EvalCohort, EvalExposure, EvalExposureKind, cohort_key, cohorts_in_txn,
    encode, membership_digest,
};
use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;

/// The reserved seat namespace (FIX 6744 CALLS): one `space_probe.<kind>` seat per probe kind.
const SPACE_PROBE_SEAT_PREFIX: &str = "space_probe.";

/// One probe as a call names it: its stable id, the document its query was written from, and
/// the date window that document falls in.
type Member = ([u8; 16], EntityId, Range<u64>);

/// What one call writes under: its seat, the rubric revision its cohorts are cut under, and
/// when.
struct Under {
    seat: EvalSeat,
    rubric_revision: String,
    at: u64,
}

/// One member as the ledger holds it: its case's root, its family and its window.
struct Kept {
    root: String,
    family: EntityId,
    window: Range<u64>,
}

impl Vault {
    /// Keeps the space probes' cohort metadata under the reserved `space_probe.<kind>` seat
    /// (FIX 6744). Each member is one probe of `kind` whose date window has ended by `at`.
    ///
    /// With no `exposures`, the call keeps the members' rows and cuts their cohorts. A member's
    /// source document is a root of its family, and the probe is that family's one case for
    /// its id, found again on every later call. `reference`, while the seat keeps none, is
    /// decided first: the members in that window freeze as its one reference cohort, exact
    /// bounds and membership digest, never redrawn or enlarged. The families no cohort holds
    /// then take one new frozen cohort per window, so no family is shared.
    ///
    /// With `exposures`, it only appends them for `consumer` to the cohorts that already hold
    /// the members' families: a query once per member, a candidate or a promotion once per
    /// cohort and consumer. Nothing is released, and retirement is not read.
    ///
    /// # Errors
    ///
    /// An invalid seat name, lineage the ledger refuses, or storage errors; the caller logs
    /// them and goes on.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn record_space_probe_cohort_metadata(
        &self,
        kind: &str,
        rubric_revision: &str,
        members: &[([u8; 16], EntityId, Range<u64>)],
        reference: Option<Range<u64>>,
        exposures: &[EvalExposureKind],
        consumer: &str,
        candidate_pin: Option<&str>,
        at: u64,
    ) -> Result<()> {
        let under = Under {
            seat: EvalSeat::Named(format!("{SPACE_PROBE_SEAT_PREFIX}{kind}")),
            rubric_revision: rubric_revision.to_owned(),
            at,
        };
        self.with_write_txn_grouped(|txn| {
            if !exposures.is_empty() {
                return append_exposures_in_txn(
                    self,
                    txn,
                    &under,
                    members,
                    exposures,
                    consumer,
                    candidate_pin,
                );
            }
            let kept = keep_cases_in_txn(self, txn, &under, members)?;
            if let Some(window) = reference {
                freeze_reference_in_txn(self, txn, &under, &kept, &window)?;
            }
            cut_new_families_in_txn(self, txn, &under, &kept)
        })
    }
}

/// A probe's case root: its stable id.
fn probe_root(probe: &[u8; 16]) -> String {
    format!("space_probe:{}", bytes_to_hex_lower(probe))
}

/// Each member's case root, family and window. A member seen for the first time gets its
/// family, with its source document as a root, and its one case.
fn keep_cases_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    under: &Under,
    members: &[Member],
) -> Result<Vec<Kept>> {
    let mut kept = Vec::with_capacity(members.len());
    for (probe, source, window) in members {
        let root = probe_root(probe);
        let family = match root_family_in_txn(vault, txn, &under.seat, &root)? {
            Some(family) => family,
            None => {
                let roots = BTreeSet::from([format!("entity:{}", source.to_hex()), root.clone()]);
                let family = assign_family_in_txn(
                    vault,
                    txn,
                    &under.seat,
                    &roots,
                    FamilyPurpose::SealedConfirmation,
                    under.at,
                )?;
                let draft = EvalCaseDraft {
                    seat: under.seat.clone(),
                    kind: DerivationKind::Synthetic,
                    receipts: vec![root.clone()],
                    parents: Vec::new(),
                    stratum: None,
                    draw_probability: None,
                    source_at: window.start,
                };
                // The probe row is the case's content; it names no frozen rows (FIX 5761).
                record_case_in_txn(vault, txn, &draft, None, under.at)?;
                family.id
            }
        };
        kept.push(Kept {
            root,
            family,
            window: window.clone(),
        });
    }
    Ok(kept)
}

/// Freezes the members in `window` as the seat's one reference cohort, unless it keeps one
/// already: a reference is never redrawn or enlarged. A family another cohort holds stays out
/// of it.
fn freeze_reference_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    under: &Under,
    kept: &[Kept],
    window: &Range<u64>,
) -> Result<()> {
    let cohorts = cohorts_in_txn(vault, txn, &under.seat)?;
    if cohorts.iter().any(|cohort| cohort.reference) {
        return Ok(());
    }
    let held = held_families(&cohorts);
    let roots: BTreeSet<&str> = kept
        .iter()
        .filter(|member| &member.window == window && !held.contains(&member.family))
        .map(|member| member.root.as_str())
        .collect();
    if roots.is_empty() {
        return Ok(());
    }
    let cases = seat_cases_in_txn(vault, txn, &under.seat)?
        .into_iter()
        .filter(|case| matches!(case.receipts.as_slice(), [root] if roots.contains(root.as_str())))
        .collect();
    put_cohort_in_txn(vault, txn, under, window, cases, true)
}

/// Gives the members' families that no cohort holds one new frozen cohort per window, each
/// holding every case of those families.
fn cut_new_families_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    under: &Under,
    kept: &[Kept],
) -> Result<()> {
    let held = held_families(&cohorts_in_txn(vault, txn, &under.seat)?);
    let mut fresh: BTreeMap<EntityId, (u64, u64)> = BTreeMap::new();
    for member in kept.iter().filter(|member| !held.contains(&member.family)) {
        fresh
            .entry(member.family)
            .or_insert((member.window.start, member.window.end));
    }
    if fresh.is_empty() {
        return Ok(());
    }
    let mut windows: BTreeMap<(u64, u64), Vec<EvalCase>> = BTreeMap::new();
    for case in seat_cases_in_txn(vault, txn, &under.seat)? {
        if let Some(window) = fresh.get(&case.family) {
            windows.entry(*window).or_default().push(case);
        }
    }
    for ((from, until), cases) in windows {
        put_cohort_in_txn(vault, txn, under, &(from..until), cases, false)?;
    }
    Ok(())
}

/// Appends `exposures` for `consumer` to each cohort that holds a member's family: a query
/// once per member, a candidate or a promotion once per cohort and consumer. A member with no
/// family yet adds nothing; a retired cohort counts as any other.
fn append_exposures_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    under: &Under,
    members: &[Member],
    exposures: &[EvalExposureKind],
    consumer: &str,
    candidate_pin: Option<&str>,
) -> Result<()> {
    let cohorts = cohorts_in_txn(vault, txn, &under.seat)?;
    for (probe, _, _) in members {
        let Some(family) = root_family_in_txn(vault, txn, &under.seat, &probe_root(probe))? else {
            continue;
        };
        for cohort in cohorts
            .iter()
            .filter(|cohort| cohort.families.contains(&family))
        {
            for kind in exposures {
                let once = !matches!(kind, EvalExposureKind::Query);
                if once && counted_in_txn(vault, txn, &cohort.id, *kind, consumer)? {
                    continue;
                }
                let exposure = EvalExposure {
                    id: vault.store.clock.entity_id()?,
                    cohort: cohort.id,
                    kind: *kind,
                    consumer: consumer.to_owned(),
                    candidate_pin: candidate_pin.map(str::to_owned),
                    at: under.at,
                };
                vault.store.vault_meta.put(
                    txn,
                    &[
                        EXPOSURE_PREFIX,
                        cohort.id.as_bytes(),
                        exposure.id.as_bytes(),
                    ]
                    .concat(),
                    &encode(&exposure)?,
                )?;
            }
        }
    }
    Ok(())
}

/// Whether `cohort` already counted a `kind` serving for `consumer`.
fn counted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cohort: &EntityId,
    kind: EvalExposureKind,
    consumer: &str,
) -> Result<bool> {
    let prefix = [EXPOSURE_PREFIX, cohort.as_bytes()].concat();
    Ok(rows_in_txn::<EvalExposure>(vault, txn, &prefix)?
        .iter()
        .any(|exposure| exposure.kind == kind && exposure.consumer == consumer))
}

/// The families any of `cohorts` holds.
fn held_families(cohorts: &[EvalCohort]) -> BTreeSet<EntityId> {
    cohorts
        .iter()
        .flat_map(|cohort| cohort.families.iter().copied())
        .collect()
}

/// Every case of `seat`.
fn seat_cases_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seat: &EvalSeat,
) -> Result<Vec<EvalCase>> {
    Ok(rows_in_txn::<EvalCase>(vault, txn, CASE_PREFIX)?
        .into_iter()
        .filter(|case| &case.seat == seat)
        .collect())
}

/// Writes one frozen cohort of `cases` and their families for `window`; nothing for no cases.
fn put_cohort_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    under: &Under,
    window: &Range<u64>,
    mut cases: Vec<EvalCase>,
    reference: bool,
) -> Result<()> {
    if cases.is_empty() {
        return Ok(());
    }
    cases.sort_unstable_by_key(|case| case.id);
    let families = cases.iter().map(|case| case.family).collect();
    let cases: Vec<EntityId> = cases.into_iter().map(|case| case.id).collect();
    let cohort = EvalCohort {
        id: vault.store.clock.entity_id()?,
        seat: under.seat.clone(),
        from: window.start,
        until: window.end,
        families,
        membership_digest: membership_digest(&cases),
        cases,
        rubric_revision: under.rubric_revision.clone(),
        reference,
        cut_at: under.at,
        retired_at: None,
        retirement: None,
    };
    vault
        .store
        .vault_meta
        .put(txn, &cohort_key(&cohort.id), &encode(&cohort)?)?;
    Ok(())
}
