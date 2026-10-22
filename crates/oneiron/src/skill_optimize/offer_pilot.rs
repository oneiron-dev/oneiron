//! Per-seat candidate pins and externally measured pilot evidence for OF-577.
//! Preparation releases receipt-backed cases through the existing counted
//! cohort door. It launches no compute and authorizes no training or egress.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    ComputeDestination, EvalExposure, EvalExposureKind, EvalRelease, EvalSeat, OfferCandidate,
    OfferModelPin, SufficiencyCard, SufficiencyInput, sufficiency_card,
};
use crate::ModelLocality;
use crate::consent::AuthenticatedOwner;
use crate::limit_ask::EngineLimit;
use crate::llm::manifest::read_manifest;
use crate::llm::registry::ModelRegistryRow;
use crate::side_table::{self, Named, SideTable};
use crate::training_pack::{ComputeChoice, TrainingRun};
use crate::{EntityId, Error, ModelId, Result, Vault};

const CANDIDATES: SideTable<EntityId, OfferCandidateRecord, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_OFFER_CANDIDATE);
const PILOTS: SideTable<EntityId, OfferPilot, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_OFFER_PILOT);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferCandidateSetup {
    pub seat: EvalSeat,
    pub incumbent: OfferModelPin,
    pub candidate: OfferCandidate,
    pub destination: ComputeDestination,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferCandidateRecord {
    pub id: EntityId,
    pub setup: OfferCandidateSetup,
    pub at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferCandidateQuery {
    #[serde(default)]
    pub seat: Option<EvalSeat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilotPrepare {
    pub candidate: EntityId,
    pub cohort: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilotRef {
    pub pilot: EntityId,
}

/// Measurements supplied by the owner's evaluator, not by the offer skill.
/// Unknowns stay null. `one_off_cost` includes pilot, migration and re-embed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilotMeasurement {
    pub sufficiency: SufficiencyInput,
    pub receipt_refs: Vec<String>,
    pub currency: String,
    pub one_off_cost: Option<f64>,
    pub incumbent_score: Option<f64>,
    pub candidate_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilotComplete {
    pub pilot: EntityId,
    pub measurement: OfferPilotMeasurement,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilot {
    pub id: EntityId,
    pub candidate: EntityId,
    pub exposure: EvalExposure,
    pub membership_digest: String,
    pub rubric_revision: String,
    pub families: u32,
    pub floor_slices: BTreeMap<String, u32>,
    pub prepared_at: u64,
    pub measurement: Option<OfferPilotMeasurement>,
    pub card: Option<SufficiencyCard>,
    pub completed_at: Option<u64>,
    /// The rows the released cohort's cases and labels were read from,
    /// frozen in the exposure's own transaction (FIX 5761); `None` when any
    /// of them is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_source_rows: Option<Vec<EntityId>>,
    /// The rows the measurement was read from: the release's, with the
    /// evaluator's own trace of its receipts, scores, costs and sufficiency
    /// (FIX 5761). `None` until measured, and when either is unknown; an
    /// evaluator's receipt keys are never read as rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_source_rows: Option<Vec<EntityId>>,
}

/// The rows a prepared pilot's answer was read from: its released cases and
/// their labels, and the pilot's frozen set (FIX 5761); `None` when any is
/// unknown.
#[must_use]
pub fn listed_prepared(prepared: &OfferPilotPrepared) -> Option<Vec<EntityId>> {
    super::union_source_rows([
        prepared.release.source_rows(),
        prepared.pilot.release_source_rows.clone(),
    ])
}

/// The rows a pilot's answer was read from (FIX 5761): its measurement's
/// once measured, its release's before; `None` when unknown.
#[must_use]
pub fn listed_pilot(pilot: &OfferPilot) -> Option<Vec<EntityId>> {
    if pilot.measurement.is_some() {
        pilot.measurement_source_rows.clone()
    } else {
        pilot.release_source_rows.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPilotPrepared {
    pub pilot: OfferPilot,
    pub release: EvalRelease,
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}

fn registered_pin(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: &OfferModelPin,
) -> Result<crate::llm::registry::ModelRegistryRow> {
    let model =
        ModelId::new(pin.model.clone()).map_err(|_| invalid("the model pin does not parse"))?;
    let row = vault
        .model_registry_row_in_txn(txn, &model)?
        .ok_or(Error::EntityNotFound)?;
    if row.is_stale()
        || model_offer_pin(&row)
            .as_ref()
            .is_none_or(|(registered, _)| registered != pin)
    {
        return Err(invalid(
            "the offer pin must match the registered serving revision",
        ));
    }
    Ok(row)
}

fn validate(vault: &Vault, txn: &heed::RoTxn<'_>, setup: &OfferCandidateSetup) -> Result<()> {
    let role = super::seat_model_role(&setup.seat)
        .ok_or(invalid("the seat names no served model role"))?;
    let manifest = read_manifest(&vault.store, txn)?.ok_or(Error::EntityNotFound)?;
    if manifest
        .roles
        .get(&role)
        .is_none_or(|binding| binding.model.as_str() != setup.incumbent.model)
    {
        return Err(invalid("the seat no longer holds this incumbent"));
    }
    let incumbent = registered_pin(vault, txn, &setup.incumbent)?;
    let (pin, licence) = match &setup.candidate {
        OfferCandidate::Stock {
            model,
            licence,
            source,
        } => {
            if *model == setup.incumbent {
                return Err(invalid("a stock candidate differs from the incumbent"));
            }
            let row = registered_pin(vault, txn, model)?;
            if row
                .backends()?
                .first()
                .is_none_or(|backend| &backend.pin.backend != source)
                || !incumbent
                    .catalog
                    .capabilities
                    .iter()
                    .all(|capability| row.catalog.supports(capability))
            {
                return Err(invalid(
                    "the stock source or capabilities differ from the served candidate",
                ));
            }
            let destination = match row.catalog.locality {
                ModelLocality::OnDevice => ComputeDestination::OnDevice,
                ModelLocality::OwnServer => ComputeDestination::SelfHosted {
                    host: source.clone(),
                },
                ModelLocality::ThirdParty => ComputeDestination::Hosted {
                    provider: source.clone(),
                    rows_leaving: 0,
                },
            };
            if destination != setup.destination {
                return Err(invalid(
                    "the stock destination differs from its registered backend",
                ));
            }
            (model, licence)
        }
        OfferCandidate::TrainRecipe {
            base,
            licence,
            recipe_ref,
        } => {
            let id = recipe_ref
                .strip_prefix("training_run:")
                .and_then(|id| EntityId::from_hex(id).ok())
                .ok_or(invalid("the recipe names an existing training run"))?;
            let run = crate::training_pack::training_run_in(vault, txn, &id)?
                .ok_or(Error::EntityNotFound)?;
            if run.plan.seat != setup.seat
                || training_base_pin(&run).as_ref() != Some(base)
                || training_destination(&run).as_ref() != Some(&setup.destination)
            {
                return Err(invalid(
                    "the recipe does not match this seat, base pin and destination",
                ));
            }
            (base, licence)
        }
    };
    let row = vault
        .model_registry_row_in_txn(
            txn,
            &ModelId::new(pin.model.clone())
                .map_err(|_| invalid("the model pin does not parse"))?,
        )?
        .ok_or(Error::EntityNotFound)?;
    if model_offer_licence(&row).as_deref() != Some(licence.as_str()) {
        return Err(invalid("the candidate licence must match its catalog pin"));
    }
    match &setup.destination {
        ComputeDestination::OnDevice => {}
        ComputeDestination::SelfHosted { host } if !host.trim().is_empty() && host.len() <= 256 => {
        }
        ComputeDestination::Hosted { provider, .. }
            if !provider.trim().is_empty() && provider.len() <= 256 => {}
        _ => {
            return Err(invalid(
                "the compute destination must name a bounded host or provider",
            ));
        }
    }
    Ok(())
}

pub fn prepare_candidate(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    setup: OfferCandidateSetup,
) -> Result<OfferCandidateRecord> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        validate(vault, txn, &setup)?;
        for (_, row) in CANDIDATES.scan(&vault.store, txn)? {
            if row.setup == setup {
                return Ok(row);
            }
        }
        let row = OfferCandidateRecord {
            id: vault.store.clock.entity_id()?,
            setup,
            at: now,
        };
        CANDIDATES.put(&vault.store, txn, &row.id, &row)?;
        Ok(row)
    })
}

pub fn candidates(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    query: OfferCandidateQuery,
) -> Result<Vec<OfferCandidateRecord>> {
    owner.revalidate_person(vault)?;
    candidate_rows(vault, query.seat.as_ref())
}

pub fn candidate_rows(vault: &Vault, seat: Option<&EvalSeat>) -> Result<Vec<OfferCandidateRecord>> {
    let txn = vault.store.env.read_txn()?;
    Ok(CANDIDATES
        .scan(&vault.store, &txn)?
        .into_iter()
        .map(|(_, row)| row)
        .filter(|row| seat.is_none_or(|seat| *seat == row.setup.seat))
        .collect())
}

pub fn prepare_pilot(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferPilotPrepare,
) -> Result<OfferPilotPrepared> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let candidate = CANDIDATES
            .get(&vault.store, txn, &input.candidate)?
            .ok_or(Error::EntityNotFound)?;
        validate(vault, txn, &candidate.setup)?;
        let id = vault.store.clock.entity_id()?;
        let release = vault.open_eval_cohort_in_txn(
            txn,
            &input.cohort,
            EvalExposureKind::Candidate,
            &format!("offer_pilot:{}", id.to_hex()),
            Some(&candidate.id.to_hex()),
            now,
        )?;
        if release.cases.is_empty()
            || release
                .cases
                .iter()
                .any(|case| case.seat != candidate.setup.seat)
        {
            return Err(invalid(
                "the pilot needs a nonempty cohort for its own seat",
            ));
        }
        let cohort = super::eval_set::cohort_for_offer_in_txn(vault, txn, &input.cohort)?;
        let mut slices: BTreeMap<String, BTreeSet<EntityId>> = BTreeMap::new();
        for case in &release.cases {
            slices.entry("all".into()).or_default().insert(case.family);
            if let Some(slice) = &case.stratum {
                slices.entry(slice.clone()).or_default().insert(case.family);
            }
        }
        let pilot = OfferPilot {
            id,
            candidate: candidate.id,
            exposure: release.exposure.clone(),
            membership_digest: cohort.membership_digest,
            rubric_revision: cohort.rubric_revision,
            families: u32::try_from(cohort.families.len())
                .map_err(|_| invalid("too many pilot families"))?,
            floor_slices: slices
                .into_iter()
                .map(|(key, families)| (key, families.len() as u32))
                .collect(),
            prepared_at: now,
            measurement: None,
            card: None,
            completed_at: None,
            // A source an erase reached since the release was read does not
            // come back (FIX 6933).
            release_source_rows: super::live_source_rows_in(vault, txn, release.source_rows())?,
            measurement_source_rows: None,
        };
        PILOTS.put(&vault.store, txn, &id, &pilot)?;
        Ok(OfferPilotPrepared { pilot, release })
    })
}

pub fn complete_pilot(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferPilotComplete,
) -> Result<OfferPilot> {
    // The owner's evaluator names its receipts by key only (FIX 5761).
    complete_pilot_traced(vault, owner, input, None)
}

/// [`complete_pilot`] for an evaluator whose host holds the complete trace
/// of the rows its measurement was read from (FIX 5761). The pilot keeps it
/// beside its release's; `None` is unknown.
/// # Errors
/// As [`complete_pilot`].
pub fn complete_pilot_traced(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferPilotComplete,
    trace: Option<Vec<EntityId>>,
) -> Result<OfferPilot> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let mut pilot = PILOTS.get(&vault.store, txn, &input.pilot)?.ok_or(Error::EntityNotFound)?;
        if let Some(measured) = &pilot.measurement {
            return if *measured == input.measurement { Ok(pilot) } else { Err(invalid("pilot measurements are immutable")) };
        }
        let candidate = CANDIDATES.get(&vault.store, txn, &pilot.candidate)?.ok_or(Error::EntityNotFound)?;
        validate(vault, txn, &candidate.setup)?;
        let measurement = input.measurement;
        // Every receipt the evaluator names is kept whole (Rule 5): their
        // count and length are measured, never cut.
        let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, measurement.receipt_refs.len() as u64);
        let longest = measurement.receipt_refs.iter().map(String::len).max().unwrap_or(0);
        let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
        if measurement.sufficiency.families != pilot.families
            || measurement.sufficiency.floor_slices != pilot.floor_slices
            || measurement.receipt_refs.is_empty()
            || measurement.receipt_refs.iter().any(|reference| reference.trim().is_empty())
            || measurement.currency.trim().is_empty() || measurement.currency.len() > 16
            || [measurement.one_off_cost, measurement.incumbent_score, measurement.candidate_score]
                .into_iter().flatten().any(|value| !value.is_finite() || value < 0.0)
        { return Err(invalid("the pilot measurements must bind their counted own-seat families and bounded receipts")); }
        let cohort = super::eval_set::cohort_for_offer_in_txn(vault, txn, &pilot.exposure.cohort)?;
        let mut sufficiency = measurement.sufficiency.clone();
        sufficiency.set_changed |= cohort.membership_digest != pilot.membership_digest || cohort.retired_at.is_some();
        sufficiency.rubric_changed |= cohort.rubric_revision != pilot.rubric_revision;
        pilot.card = Some(sufficiency_card(sufficiency)?);
        pilot.measurement = Some(measurement);
        pilot.completed_at = Some(now);
        // A source an erase reached since the release, or one the trace names, does not come
        // back (FIX 6933).
        let measured = super::union_source_rows([pilot.release_source_rows.clone(), trace]);
        pilot.measurement_source_rows = super::live_source_rows_in(vault, txn, measured)?;
        PILOTS.put(&vault.store, txn, &pilot.id, &pilot)?;
        Ok(pilot)
    })
}

pub fn pilot(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferPilotRef,
) -> Result<Option<OfferPilot>> {
    owner.revalidate_person(vault)?;
    let txn = vault.store.env.read_txn()?;
    PILOTS.get(&vault.store, &txn, &input.pilot)
}

/// The latest completed pilot for this exact setup, while its cohort and
/// serving pins still hold. Stale evidence is never copied into a new offer.
pub fn latest_pilot(vault: &Vault, candidate: &OfferCandidateRecord) -> Result<Option<OfferPilot>> {
    let txn = vault.store.env.read_txn()?;
    match validate(vault, &txn, &candidate.setup) {
        Ok(()) => {}
        Err(Error::InvalidConfig(_) | Error::EntityNotFound) => return Ok(None),
        Err(error) => return Err(error),
    }
    let pilots = PILOTS.scan(&vault.store, &txn)?;
    let Some((_, pilot)) = pilots
        .into_iter()
        .filter(|(_, pilot)| pilot.candidate == candidate.id && pilot.completed_at.is_some())
        .max_by_key(|(_, pilot)| (pilot.completed_at, pilot.id))
    else {
        return Ok(None);
    };
    let cohort = super::eval_set::cohort_for_offer_in_txn(vault, &txn, &pilot.exposure.cohort)?;
    if cohort.retired_at.is_some()
        || cohort.membership_digest != pilot.membership_digest
        || cohort.rubric_revision != pilot.rubric_revision
    {
        return Ok(None);
    }
    Ok(Some(pilot))
}

/// A registry row's pin and the backend that serves it: its first registered
/// backend at that backend's serving revision. A row with no backend has no
/// revision to pin, so no offer names it.
pub fn model_offer_pin(row: &ModelRegistryRow) -> Option<(OfferModelPin, String)> {
    let backend = row.backends().ok()?.into_iter().next()?;
    let model = row.catalog.model.as_str();
    // The backend is also the stock offer's source, which the offer door
    // still bounds at 256 B.
    (named(model) && named(&backend.pin.serving_revision) && bounded(&backend.pin.backend, 256))
        .then(|| {
            (
                OfferModelPin {
                    model: model.to_owned(),
                    revision: backend.pin.serving_revision.clone(),
                    content_hash: None,
                },
                backend.pin.backend.clone(),
            )
        })
}

/// A recipe's base: the starting checkpoint at its source revision and the
/// content hash of its first file.
pub fn training_base_pin(run: &TrainingRun) -> Option<OfferModelPin> {
    let checkpoint = &run.plan.starting_checkpoint;
    let file = checkpoint.files.first()?;
    let model = checkpoint.model.as_str();
    (named(model) && named(&file.source.revision)).then(|| OfferModelPin {
        model: model.to_owned(),
        revision: file.source.revision.clone(),
        content_hash: Some(
            file.content
                .blake3
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ),
    })
}

/// Where a recipe ran before, and the rows that left with it.
pub fn training_destination(run: &TrainingRun) -> Option<ComputeDestination> {
    let compute = &run.compute;
    Some(match compute.choice {
        ComputeChoice::OwnerMachines if compute.locality == ModelLocality::OnDevice => {
            ComputeDestination::OnDevice
        }
        ComputeChoice::OwnerMachines => ComputeDestination::SelfHosted {
            host: named(&compute.origin).then(|| compute.origin.clone())?,
        },
        ComputeChoice::External => ComputeDestination::Hosted {
            provider: named(&compute.connector).then(|| compute.connector.clone())?,
            rows_leaving: u64::try_from(run.corpus.rows.len()).ok()?,
        },
    })
}

/// The licence a registry row names, if it names one.
pub fn model_offer_licence(row: &ModelRegistryRow) -> Option<String> {
    ["licence", "license"]
        .iter()
        .find_map(|key| row.catalog.metadata.get(*key)?.as_str())
        .map(str::trim)
        .filter(|licence| named(licence))
        .map(str::to_owned)
}

fn bounded(value: &str, max: usize) -> bool {
    named(value) && value.len() <= max
}

/// Not blank. Pins, hosts, providers and licences are kept whole (Rule 5).
fn named(value: &str) -> bool {
    !value.trim().is_empty()
}

/// Revalidate any pilot evidence a draft uses in the offer's committing
/// transaction, after the host's model has had time to answer.
pub(crate) fn validate_snapshot_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    offer: &super::TrainingOffer,
) -> Result<()> {
    for (_, pilot) in PILOTS.scan(&vault.store, txn)? {
        let primary = offer.evidence.exposures.contains(&pilot.exposure.id);
        let reference = format!("offer_pilot:{}", pilot.id.to_hex());
        let comparison = offer.baseline.evidence_refs.contains(&reference)
            || offer
                .alternatives
                .iter()
                .any(|option| option.evidence_refs.contains(&reference));
        if !primary && !comparison {
            continue;
        }
        let candidate = CANDIDATES
            .get(&vault.store, txn, &pilot.candidate)?
            .ok_or(Error::EntityNotFound)?;
        validate(vault, txn, &candidate.setup)?;
        let cohort = super::eval_set::cohort_for_offer_in_txn(vault, txn, &pilot.exposure.cohort)?;
        if candidate.setup.seat != offer.seat
            || candidate.setup.incumbent != offer.incumbent
            || cohort.retired_at.is_some()
            || cohort.membership_digest != pilot.membership_digest
            || cohort.rubric_revision != pilot.rubric_revision
            || pilot.completed_at.is_none()
            || (primary
                && (candidate.setup.candidate != offer.candidate
                    || candidate.setup.destination != offer.destination
                    || pilot.card != offer.evidence.card))
        {
            return Err(invalid(
                "the pilot evidence changed before the offer committed",
            ));
        }
    }
    Ok(())
}

/// Drops an erased row `id` from every pilot's release and measurement source
/// rows (FIX 6933), each set on its own, rewriting only the pilots that named
/// it: exposure, digest, card, measurement, receipt keys, costs and times
/// stay. Registered on the pilot table's declaration; a source may be any
/// row, so this reads every pilot for each erased id.
///
/// # Errors
///
/// Storage errors, or a stored pilot that does not decode.
pub(crate) fn erase_pilot_source_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut named = Vec::new();
    for (key, mut pilot) in PILOTS.scan(&vault.store, wtxn)? {
        let released = super::forget_source_row(&mut pilot.release_source_rows, id);
        let measured = super::forget_source_row(&mut pilot.measurement_source_rows, id);
        if released || measured {
            named.push((key, pilot));
        }
    }
    for (key, pilot) in named {
        PILOTS.put(&vault.store, wtxn, &key, &pilot)?;
    }
    Ok(())
}
