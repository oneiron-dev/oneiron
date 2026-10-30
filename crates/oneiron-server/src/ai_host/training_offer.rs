//! The Coach's training offers (ARCH-0026 #dreamer, ARCH-0053 #training-offers,
//! OF-420): each night it reads each served seat's last month of metered
//! calls and may raise one offer, to switch the seat to a stock model or to
//! train a custom one. Fixed code prices every option on the seat's own
//! workload from the catalog's list prices and gathers what was measured; the
//! Coach's model, running the offer skill it loads on its attempt, only says
//! whether a case is worth raising, and which priced option it is. Each offer
//! names the skill revision that drafted it, and the skill's record on the
//! Coach's model goes into the next brief. Nothing applies by itself: the
//! owner answers the offer.
//!
//! The check reads the same meter on the offer's check date. A promise is
//! checked only after a yes, on the approved model's calls over a whole
//! metered window after it; until then the check waits, and the next night
//! queues it again. A window with no such call to read, with calls the check
//! cannot price or sum, or with the seat's calls on other models counted out,
//! closes as unverifiable, neither a pass nor a fail (FIX 6265, 6317, 6406,
//! 6475, 6477).
//! The check is fixed code: no model call.
use oneiron::attempt_queue::{AttemptId, ReadSetProducer};
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::dreamer_runner::maintenance::coach::coach_offer_check_target;
use oneiron::learning::learning_estimate_with_sources;
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::manifest::{MODEL_ROLES, ModelRole};
use oneiron::llm::registry::ModelRegistryRow;
use oneiron::skill_optimize::offer_pilot::{
    model_offer_licence as licence, model_offer_pin as pin, training_base_pin as base_pin,
    training_destination as destination,
};
use oneiron::skill_optimize::{
    ComputeDestination, EvalSeat, OfferCandidate, OfferCheckInput, OfferCost, OfferEvidence,
    OfferIntent, OfferModelPin, OfferOption, SeatWorkload, TrainingOffer, TrainingOfferDraft,
    model_role_seat, offer_skill_cell, offer_training_handoff, seat_model_role, training_offer,
    training_offer_checks, training_offer_skill_id, training_offers, union_source_rows,
};
use oneiron::training_pack::{TrainingRun, TrainingState};
use oneiron::{EntityId, Error, LlmMessageRole, ModelLocality, Vault};
use serde::Deserialize;

use super::code_fix::{HostModels, message};
use crate::config::models::role_key;
use crate::server::SyncServer;
use crate::usage::SeatUsage;

mod check;
mod choices;
mod cost;
mod draft;
mod pilot;
mod sources;
mod unverifiable;
pub(super) use check::check;
use choices::{recipe_choices, stock_choices};
use cost::{candidate_monthly, monthly, payback};
use sources::Sources;
use unverifiable::{Alone, Unverifiable};

const DAY_SECS: u64 = 24 * 60 * 60;
/// The workload an offer is priced from, and the window its check reads.
/// Canon names no window: the offer skill's own record reads 30 days.
const WINDOW_SECS: u64 = 30 * DAY_SECS;
/// A month's bill, from a window's.
const MONTH_SECS: u64 = 30 * DAY_SECS;
/// When an offer's promise is checked, after it is made.
const CHECK_AFTER_SECS: u64 = 30 * DAY_SECS;
/// The currency an offer quotes its money in. Only a catalog row quoted in it
/// projects a month's bill; a row quoted in another currency, or in none its
/// provider named, projects none and stays an option (FIX 9534). A row whose
/// rates are all zero is free in any currency and projects zero.
const CATALOG_CURRENCY: &str = "USD";
/// How far a checked month may run over the promised one and still hold.
const COST_TOLERANCE: f64 = 0.10;
/// The call purpose the offer's model calls are metered under.
const OFFER_CALL_PURPOSE: &str = "coach_training_offer";
/// What one job's calls may spend.
const BUDGET_UNITS: u64 = 1 << 20;
/// What the offer says of its prices, beside the Coach's risk.
const PRICING_NOTE: &str = "Both sides are priced at list price on this seat's measured \
    token counts, cached prompt tokens at each model's quoted cache rates, or at its input price \
    where it quotes none; the candidate's counts are the incumbent's scaled by how many tokens \
    each model's tokenizer counts in one fixed passage. Only list prices quoted in USD are \
    priced: a model whose price names another currency, or none, shows no figure. A free model, \
    every rate zero, shows 0 in any currency.";
/// The note instead when the candidate's price is an estimate: a tokenizer
/// of the two was never measured.
const ESTIMATE_NOTE: &str = "The candidate's price is an estimate: it is priced at list \
    price on the incumbent's own token counts, cached prompt tokens at its quoted cache rates, or \
    at its input price where it quotes none, since the two models' tokenizers were not both \
    measured; the candidate's tokenizer may count the same work differently.";
/// The offer skill's file the Coach runs; the seat goes as data.
const SKILL_FILE: &str = "SKILL.md";
/// The pass's key in its attempt's read set (FIX 7073).
const OFFER_DRAFT: ReadSetProducer = ReadSetProducer::COACH_OFFER_DRAFT;

/// Raises at most one offer for each served seat, the busiest first.
pub(super) fn draft(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    // With no meter there is no workload to price an offer on.
    let Some(meter) = server.vault_usage() else {
        return Ok(());
    };
    let runtime = server.ai.model_runtime();
    let (owner, vault_id) = (meter.owner(), meter.vault_id());
    let from = now.saturating_sub(WINDOW_SECS);
    let mut seats = Vec::new();
    for role in MODEL_ROLES {
        let Some(seat) = runtime.seat(role) else {
            continue;
        };
        let Ok(route) = runtime.route_role(vault, role, seat) else {
            continue;
        };
        let usage = server
            .usage_ledger
            .seat_usage(owner, vault_id, &role_key(role), None, from, now)
            .map_err(|_| Error::InvalidConfig("the seat's usage could not be read".into()))?;
        // A seat with no metered call has no receipts to ground an offer.
        if usage.calls == 0 || usage.refs.is_empty() {
            continue;
        }
        seats.push((role, route.model.as_str().to_owned(), route.locality, usage));
    }
    if seats.is_empty() {
        return Ok(());
    }
    seats.sort_by(|a, b| b.3.calls.cmp(&a.3.calls).then(a.0.cmp(&b.0)));
    // Every served seat is asked about (Rule 5): how many is measured.
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, seats.len() as u64);
    // A model the catalog refresh left uncounted is counted before it is
    // priced (OF-577).
    if let Some(ratios) = runtime.token_ratios() {
        ratios.measure_missing_blocking(vault)?;
    }
    let registry = vault.model_registry_rows()?;
    let runs = vault.training_runs()?;
    let models = HostModels::open(
        server,
        format!(
            "coach-training-offer:{}",
            EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?.to_hex()
        ),
        OFFER_CALL_PURPOSE,
        BUDGET_UNITS,
    )?;
    let Some(executor) = runtime
        .seat(models.coach())
        .map(|seat| seat.model.as_str().to_owned())
    else {
        return Ok(());
    };
    // The offer skill's body is the Coach's instruction. The load stamps its
    // revision and the Coach's model on the attempt, and each offer names
    // them.
    let attempt = &admitted.status.attempt;
    // The pass and the pack load door that reads the offer skill are the
    // producers its attempt's read set waits on: declared before the load
    // reads anything, the set reads complete only once both reported, and
    // stays unknown if either never does (FIX 7073, 7017).
    let mut read_set_lost = false;
    if let Err(error) = vault
        .declare_attempt_read_producers(attempt.id, &[OFFER_DRAFT, ReadSetProducer::SKILL_PACK])
    {
        read_set_lost = true;
        tracing::warn!(
            attempt = ?attempt.id,
            %error,
            "the offer draft could not declare its read set; its pack receipt keeps it unknown"
        );
    }
    let loaded = match vault.load_attempt_skill_pack(
        attempt.id,
        &training_offer_skill_id()?,
        attempt.lease_owner.as_deref().unwrap_or_default(),
        attempt.attempt_count,
        &executor,
        now,
    ) {
        Ok(loaded) => loaded,
        // A retired, unapproved or deleted offer skill drafts nothing.
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let Some(instruction) = loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == SKILL_FILE))
        .and_then(|file| std::str::from_utf8(&file.content).ok())
        .map(str::to_owned)
    else {
        return Ok(());
    };
    let offer_skill = (loaded.entity, loaded.record.version.clone());
    // The offer skill's own record on this model: how its checked offers
    // held, read from the head claim it names (FIX 5760).
    let cell = offer_skill_cell(vault, loaded.entity, &executor)?;
    let (record, record_rows) = match learning_estimate_with_sources(vault, &cell)? {
        Some((estimate, rows)) => (
            serde_json::json!({ "estimate": estimate.value, "runs": estimate.runs }),
            rows,
        ),
        None => (serde_json::Value::Null, Vec::new()),
    };
    for (role, model, locality, usage) in seats {
        let Some(brief) = Brief::gather(
            vault,
            &registry,
            &runs,
            role,
            &model,
            locality,
            usage,
            (&record, record_rows.as_slice()),
            now,
        )?
        else {
            continue;
        };
        // The call reads the brief and the offer skill's body (FIX 5760).
        // The attempt it runs on records that set before the model sees it,
        // and its pack receipt keeps the union of its calls' (FIX 6934).
        let read = union_source_rows([brief.sources.rows(), Some(vec![offer_skill.0])]);
        record_read(vault, attempt.id, read.clone(), &mut read_set_lost);
        let Some(text) = models.generate_sourced(
            models.coach(),
            vec![
                message(LlmMessageRole::System, instruction.clone()),
                message(LlmMessageRole::User, brief.data().to_string()),
            ],
            read,
        )?
        else {
            // No seat took the call: the next night asks again.
            return Ok(());
        };
        let Some(mut draft) =
            parse_answer(&text).and_then(|answer| brief.draft(answer, offer_skill.clone(), now))
        else {
            continue;
        };
        // An exact Final paired measurement of this pair supplies its own
        // card (FIX 574); without one the grounded evidence stands.
        super::eval_measurement::attach_measured_card(vault, &mut draft, now)?;
        // The offer also reads the pilots its options were grounded on, each
        // its own option's exact pilot from the brief (FIX 7021, 9469): its
        // set, `None` when any such pilot's measurement set is unknown.
        let grounded = draft.source_rows.clone();
        record_read(vault, attempt.id, grounded, &mut read_set_lost);
        match vault.run_coach_training_offer(admitted, draft, now) {
            Ok(offer) => {
                tracing::debug!(offer = %offer.id.to_hex(), "the Coach raised a training offer")
            }
            // A draft the offer door refuses is no offer; the other seats go on.
            Err(Error::InvalidConfig(_)) => {
                tracing::debug!("the Coach's training offer draft was refused");
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Records rows the pass read under the offer draft's key (FIX 6934, 7073).
/// Capture only (FIX 7021): a storage error recording them never ends the
/// pass. The attempt's set goes unknown, as an unsourced inlet's, and later
/// reads of the pass record nothing more.
fn record_read(vault: &Vault, attempt: AttemptId, rows: Option<Vec<EntityId>>, lost: &mut bool) {
    if *lost {
        return;
    }
    if let Err(error) = vault.record_attempt_sources(attempt, OFFER_DRAFT, rows) {
        *lost = true;
        tracing::warn!(
            attempt = ?attempt,
            %error,
            "the offer draft could not record its read set; its pack receipt keeps it unknown"
        );
        let _ = vault.record_attempt_sources(attempt, OFFER_DRAFT, None);
    }
}

/// One option fixed code priced for a seat.
struct Choice {
    id: String,
    label: String,
    candidate: OfferCandidate,
    pin: OfferModelPin,
    monthly: Option<f64>,
    /// `monthly` is on the incumbent's own counts: a tokenizer of the two
    /// was not measured.
    estimate: bool,
    destination: ComputeDestination,
    evidence_refs: Vec<String>,
    data: serde_json::Value,
    /// The latest pilot of exactly this option for the seat's incumbent: its
    /// whole candidate and its destination (FIX 9469). `None` when none
    /// matched.
    pilot: Option<oneiron::skill_optimize::offer_pilot::OfferPilot>,
}

/// Everything one seat's offer is drafted from.
struct Brief {
    seat: EvalSeat,
    incumbent: OfferModelPin,
    incumbent_data: serde_json::Value,
    baseline_monthly: Option<f64>,
    workload: SeatWorkload,
    usage: SeatUsage,
    choices: Vec<Choice>,
    evidence: OfferEvidence,
    cohort_data: serde_json::Value,
    previous: Option<EntityId>,
    prior: Vec<serde_json::Value>,
    /// The offer skill's own record: how its checked offers held.
    record: serde_json::Value,
    /// The rows everything above was read from (FIX 5482).
    sources: Sources,
}

impl Brief {
    /// The seat's brief, or `None` when it cannot ground an offer: no pinned
    /// incumbent, or no option to raise.
    #[allow(clippy::too_many_arguments)]
    fn gather(
        vault: &Vault,
        registry: &[ModelRegistryRow],
        runs: &[TrainingRun],
        role: ModelRole,
        model: &str,
        locality: ModelLocality,
        usage: SeatUsage,
        (record, record_rows): (&serde_json::Value, &[EntityId]),
        now: u64,
    ) -> oneiron::Result<Option<Self>> {
        let seat = model_role_seat(role);
        let Some(current) = registry
            .iter()
            .find(|row| row.catalog.model.as_str() == model)
        else {
            return Ok(None);
        };
        let Some((incumbent, _)) = pin(current) else {
            return Ok(None);
        };
        let from = now.saturating_sub(WINDOW_SECS);
        let workload = SeatWorkload {
            from,
            until: now,
            calls: Some(usage.calls),
            input_tokens: Some(usage.input_tokens),
            output_tokens: Some(usage.output_tokens),
            // A record that does not decode leaves its tokens unread.
            complete: usage.undecodable == 0
                && usage.metered_since.is_some_and(|since| since <= from),
            receipt_refs: usage.refs.clone(),
        };
        // The seat's metered calls, as each one's settlement froze its rows,
        // and every catalog row the pricing and the option filters read,
        // chosen or not (FIX 5760).
        let mut sources = Sources::new();
        sources.set(usage.source_rows.as_deref());
        for row in registry {
            sources.set(row.source_rows.as_deref());
        }
        let baseline_monthly = monthly(current, &workload, &usage);
        let stock = stock_choices(registry, current, &workload, &usage);
        let (recipes, seat_runs) = recipe_choices(runs, registry, role, &seat, &mut sources);
        let mut choices: Vec<Choice> = stock.into_iter().chain(recipes).collect();
        if choices.is_empty() {
            return Ok(None);
        }
        let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, choices.len() as u64);
        pilot::brief(vault, &seat, &incumbent, &mut choices, &mut sources)?;
        for (index, choice) in choices.iter_mut().enumerate() {
            choice.id = format!("option-{}", index + 1);
        }
        let cohort = vault
            .eval_cohorts(&seat)?
            .into_iter()
            .rev()
            .find(|cohort| cohort.retired_at.is_none());
        // The cohort's cases and labels, as the ledger keeps their rows
        // (FIX 5760); a lineage read that fails stops the draft instead of
        // erasing its rows to unknown (FIX 11913).
        if let Some(cohort) = &cohort {
            let read = vault.eval_cohort_source_rows(&cohort.id)?;
            sources.set(read.as_deref());
        }
        // Names and the rubric revision ride whole (Rule 5).
        let longest = registry
            .iter()
            .map(|row| row.catalog.display_name.len())
            .chain(cohort.iter().map(|cohort| cohort.rubric_revision.len()))
            .max()
            .unwrap_or(0);
        let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
        let cohort_data = cohort.as_ref().map_or(serde_json::Value::Null, |cohort| {
            serde_json::json!({
                "rubric_revision": cohort.rubric_revision,
                "families": cohort.families.len(),
                "cases": cohort.cases.len(),
                "reference": cohort.reference,
            })
        });
        let evidence = OfferEvidence {
            cohort: cohort.as_ref().map(|cohort| cohort.id),
            exposures: seat_runs
                .iter()
                .filter_map(|run| run.eval_exposure.as_ref().map(|exposure| exposure.id))
                .collect(),
            rubric_revision: cohort
                .as_ref()
                .map(|cohort| cohort.rubric_revision.clone())
                .filter(|revision| !revision.trim().is_empty()),
            // No measured card for the seat: unknown, never not-worse.
            card: None,
            losses: Vec::new(),
            risk: None,
        };
        let earlier = training_offers(vault, Some(&seat))?;
        let previous = earlier.last().map(|(offer, _)| offer.id);
        let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, earlier.len() as u64);
        let mut prior = Vec::new();
        for (offer, answer) in earlier.iter().rev() {
            let checks = training_offer_checks(vault, &offer.id)?;
            sources.set(offer.source_rows.as_deref());
            for check in &checks {
                sources.set(check.source_rows.as_deref());
            }
            prior.push(serde_json::json!({
                "offered_at": offer.offered_at,
                "candidate": offered_model(offer),
                "monthly_before": offer.cost.monthly_before,
                "monthly_after": offer.cost.monthly_after,
                "answer": answer.as_ref().map(|answer| answer.answer),
                "checks": checks.iter().map(|check| serde_json::json!({
                    "held": check.held,
                    "observed_monthly_cost": check.observed_monthly_cost,
                    // Why a check could not judge, e.g. unverifiable_unpriced_cache (FIX 6318).
                    "note": check.note,
                })).collect::<Vec<_>>(),
            }));
        }
        // The skill's record, from the head claim it was read from (FIX 5760).
        sources.set(Some(record_rows));
        let incumbent_data = serde_json::json!({
            "model": incumbent.model,
            "revision": incumbent.revision,
            "locality": locality,
            "monthly_at_list_price": baseline_monthly,
            "public_benchmarks": current.scores,
        });
        Ok(Some(Self {
            seat,
            incumbent,
            incumbent_data,
            baseline_monthly,
            workload,
            usage,
            choices,
            evidence,
            cohort_data,
            previous,
            prior,
            record: record.clone(),
            sources,
        }))
    }

    /// What the Coach reads.
    fn data(&self) -> serde_json::Value {
        serde_json::json!({
            "seat": self.seat,
            "incumbent": self.incumbent_data,
            "workload": {
                "days": WINDOW_SECS / DAY_SECS,
                "calls": self.usage.calls,
                "input_tokens": self.usage.input_tokens,
                "cache_read_tokens": self.usage.cache_read_tokens,
                "cache_write_tokens": self.usage.cache_write_tokens,
                "output_tokens": self.usage.output_tokens,
                "metered_throughout": self.workload.complete,
                "metered_cost": self.usage.complete.then(|| serde_json::json!({
                    "amount": self.usage.cost_amount as f64 / 1e9,
                    "currency": self.usage.currency,
                })),
            },
            "currency": CATALOG_CURRENCY,
            "options": self.choices.iter().map(|choice| {
                let mut data = choice.data.clone();
                data["id"] = serde_json::Value::from(choice.id.clone());
                data
            }).collect::<Vec<_>>(),
            "eval_cohort": self.cohort_data,
            "earlier_offers": self.prior,
            "your_offer_record": self.record,
        })
    }
}

/// The Coach's answer as it writes it.
#[derive(Deserialize)]
struct AnswerWire {
    offer: Option<String>,
    #[serde(default)]
    losses: Vec<String>,
    #[serde(default)]
    risk: Option<String>,
    #[serde(default)]
    what_changed: Option<String>,
}

/// The one JSON object in the answer; `None` when there is none.
fn parse_answer(text: &str) -> Option<AnswerWire> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    serde_json::from_str(text.get(start..=end)?).ok()
}

/// The model an offer proposes.
fn offered_model(offer: &TrainingOffer) -> &str {
    match &offer.candidate {
        OfferCandidate::Stock { model, .. } => &model.model,
        OfferCandidate::TrainRecipe { base, .. } => &base.model,
    }
}
