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
//! queues it again. The seat's calls on other models are counted out. A
//! window with no such call to read, or with calls the check cannot price or
//! sum, closes as unverifiable, neither a pass nor a fail (FIX 6265, 6317,
//! 6406).
//! The check is fixed code: no model call.
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::dreamer_runner::maintenance::coach::coach_offer_check_target;
use oneiron::learning::learning_estimate;
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
    training_offer_checks, training_offer_skill_id, training_offers,
};
use oneiron::training_pack::{TrainingRun, TrainingState};
use oneiron::{EntityId, Error, LlmMessageRole, ModelLocality, Vault};
use serde::Deserialize;

use super::code_fix::{HostModels, clip, message};
use crate::config::models::role_key;
use crate::server::SyncServer;
use crate::usage::SeatUsage;

mod cost;
mod pilot;
mod sources;
mod unverifiable;
use cost::{candidate_monthly, monthly, payback};
use sources::Sources;
use unverifiable::{Alone, Unverifiable, counted_out};

const DAY_SECS: u64 = 24 * 60 * 60;
/// The workload an offer is priced from, and the window its check reads.
/// Canon names no window: the offer skill's own record reads 30 days.
const WINDOW_SECS: u64 = 30 * DAY_SECS;
/// A month's bill, from a window's.
const MONTH_SECS: u64 = 30 * DAY_SECS;
/// When an offer's promise is checked, after it is made.
const CHECK_AFTER_SECS: u64 = 30 * DAY_SECS;
/// Seats one job asks about, the busiest first.
const SEAT_BATCH: usize = 8;
/// Options one brief carries: stock models, and recipes that ran before. The
/// offer keeps the rest as its alternatives.
const MAX_STOCK: usize = 12;
const MAX_RECIPES: usize = 4;
/// Earlier offers for the seat the brief carries, the newest.
const PRIOR_OFFERS: usize = 8;
/// The catalog's per-million list prices carry no currency; they are read as
/// this one.
const CATALOG_CURRENCY: &str = "USD";
/// How far a checked month may run over the promised one and still hold.
const COST_TOLERANCE: f64 = 0.10;
/// The call purpose the offer's model calls are metered under.
const OFFER_CALL_PURPOSE: &str = "coach_training_offer";
/// What one job's calls may spend.
const BUDGET_UNITS: u64 = 1 << 20;
/// How much of a model's display name or a cohort's rubric revision the
/// Coach's brief shows; the offer keeps the revision whole.
const REF_BYTES: usize = 256;
/// What the offer says of its prices, beside the Coach's risk.
const PRICING_NOTE: &str = "Both sides are priced at list price on this seat's measured \
    token counts, cached prompt tokens at each model's quoted cache rates, or at its input price \
    where it quotes none; the candidate's counts are the incumbent's scaled by how many tokens \
    each model's tokenizer counts in one fixed passage.";
/// The note instead when the candidate's price is an estimate: a tokenizer
/// of the two was never measured.
const ESTIMATE_NOTE: &str = "The candidate's price is an estimate: it is priced at list \
    price on the incumbent's own token counts, cached prompt tokens at its quoted cache rates, or \
    at its input price where it quotes none, since the two models' tokenizers were not both \
    measured; the candidate's tokenizer may count the same work differently.";
/// The offer skill's file the Coach runs; the seat goes as data.
const SKILL_FILE: &str = "SKILL.md";

/// Raises at most one offer for each of the busiest served seats.
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
    seats.truncate(SEAT_BATCH);
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
    // The offer skill's own record on this model: how its checked offers held.
    let record = learning_estimate(vault, &offer_skill_cell(vault, loaded.entity, &executor)?)?
        .map_or(
            serde_json::Value::Null,
            |estimate| serde_json::json!({ "estimate": estimate.value, "runs": estimate.runs }),
        );
    for (role, model, locality, usage) in seats {
        let Some(brief) = Brief::gather(
            vault, &registry, &runs, role, &model, locality, usage, &record, now,
        )?
        else {
            continue;
        };
        let Some(text) = models.generate(
            models.coach(),
            vec![
                message(LlmMessageRole::System, instruction.clone()),
                message(LlmMessageRole::User, brief.data().to_string()),
            ],
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
        pilot::ground(vault, &mut draft)?;
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
        record: &serde_json::Value,
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
        // The seat's metered calls are named by receipt key and the catalog's
        // models by name, not by row (FIX 5482).
        let mut sources = Sources::new();
        sources.unknown();
        let baseline_monthly = monthly(current, &workload, &usage);
        let mut stock: Vec<Choice> = registry
            .iter()
            .filter(|row| row.catalog.model != current.catalog.model)
            .filter(|row| {
                current
                    .catalog
                    .capabilities
                    .iter()
                    .all(|capability| row.catalog.supports(capability))
            })
            .filter_map(|row| {
                let (pin, backend) = pin(row)?;
                let licence = licence(row)?;
                let (monthly, estimate) = candidate_monthly(current, row, &workload, &usage);
                let label = format!("switch to {}", row.catalog.model.as_str());
                Some(Choice {
                    id: String::new(),
                    label: if estimate {
                        format!("{label} (estimated price)")
                    } else {
                        label
                    },
                    candidate: OfferCandidate::Stock {
                        model: pin.clone(),
                        licence: licence.clone(),
                        source: backend.clone(),
                    },
                    pin,
                    monthly,
                    estimate,
                    destination: match row.catalog.locality {
                        ModelLocality::OnDevice => ComputeDestination::OnDevice,
                        ModelLocality::OwnServer => ComputeDestination::SelfHosted {
                            host: backend.clone(),
                        },
                        ModelLocality::ThirdParty => ComputeDestination::Hosted {
                            provider: backend.clone(),
                            rows_leaving: 0,
                        },
                    },
                    evidence_refs: Vec::new(),
                    data: serde_json::json!({
                        "kind": "switch",
                        "model": row.catalog.model.as_str(),
                        "display_name": clip(&row.catalog.display_name, REF_BYTES),
                        "locality": row.catalog.locality,
                        "backend": backend,
                        "licence": licence,
                        "context_window_tokens": row.catalog.context_window_tokens,
                        "monthly_at_list_price": monthly,
                        "estimate": estimate,
                        "public_benchmarks": row.scores,
                    }),
                })
            })
            .collect();
        // The cheapest first, unknown prices last; the cheapest local option
        // stays beside any paid one.
        stock.sort_by(|a, b| match (a.monthly, b.monthly) {
            (Some(a), Some(b)) => a.total_cmp(&b),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        if let Some(local) = stock
            .iter()
            .position(|choice| choice.destination == ComputeDestination::OnDevice)
            && local >= MAX_STOCK
        {
            let choice = stock.remove(local);
            stock.insert(MAX_STOCK - 1, choice);
        }
        stock.truncate(MAX_STOCK);
        let mut recipes: Vec<Choice> = Vec::new();
        let mut seat_runs: Vec<&TrainingRun> = runs
            .iter()
            .filter(|run| run.plan.role == role && run.plan.seat == seat)
            .collect();
        seat_runs.sort_by_key(|run| std::cmp::Reverse((run.created_at, run.id)));
        // A training run keeps no set of the rows its plan and scores came from.
        if !seat_runs.is_empty() {
            sources.unknown();
        }
        for run in &seat_runs {
            if recipes.len() == MAX_RECIPES {
                break;
            }
            let Some(base) = base_pin(run) else {
                continue;
            };
            if recipes.iter().any(|choice| choice.pin == base) {
                continue;
            }
            let Some(licence) = registry
                .iter()
                .find(|row| row.catalog.model == run.plan.starting_checkpoint.model)
                .and_then(licence)
            else {
                continue;
            };
            let Some(destination) = destination(run) else {
                continue;
            };
            let recipe_ref = format!("training_run:{}", run.id.to_hex());
            recipes.push(Choice {
                id: String::new(),
                label: format!("train from {}", base.model),
                candidate: OfferCandidate::TrainRecipe {
                    base: base.clone(),
                    recipe_ref: recipe_ref.clone(),
                    licence: licence.clone(),
                },
                pin: base.clone(),
                // A custom model's serving price is not known before it runs.
                monthly: None,
                estimate: false,
                destination: destination.clone(),
                evidence_refs: vec![recipe_ref.clone()],
                data: serde_json::json!({
                    "kind": "train",
                    "base": base.model,
                    "recipe": recipe_ref,
                    "licence": licence,
                    "state": run.state,
                    "destination": destination,
                    "held_out": run.evaluation.as_ref().map(|evaluation| serde_json::json!({
                        "cases": evaluation.cases,
                        "metrics": evaluation.metrics,
                        "passed": evaluation.passed,
                    })),
                    "monthly_at_list_price": null,
                }),
            });
        }
        let mut choices: Vec<Choice> = stock.into_iter().chain(recipes).collect();
        if choices.is_empty() {
            return Ok(None);
        }
        pilot::brief(vault, &seat, &incumbent, &mut choices, &mut sources)?;
        for (index, choice) in choices.iter_mut().enumerate() {
            choice.id = format!("option-{}", index + 1);
        }
        let cohort = vault
            .eval_cohorts(&seat)?
            .into_iter()
            .rev()
            .find(|cohort| cohort.retired_at.is_none());
        // A cohort's cases name their receipts by key.
        if cohort.is_some() {
            sources.unknown();
        }
        let cohort_data = cohort.as_ref().map_or(serde_json::Value::Null, |cohort| {
            serde_json::json!({
                "rubric_revision": clip(&cohort.rubric_revision, REF_BYTES),
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
        let mut prior = Vec::new();
        for (offer, answer) in earlier.iter().rev().take(PRIOR_OFFERS) {
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
                })).collect::<Vec<_>>(),
            }));
        }
        // The skill's record names the checks it learned from by key.
        if !record.is_null() {
            sources.unknown();
        }
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

    /// The offer the Coach's answer names, or `None` for no offer: it named
    /// none, named no option given, or repeats an offer without saying what
    /// changed.
    fn draft(
        mut self,
        answer: AnswerWire,
        offer_skill: (EntityId, String),
        now: u64,
    ) -> Option<TrainingOfferDraft> {
        let chosen = answer.offer?;
        let index = self.choices.iter().position(|choice| choice.id == chosen)?;
        let what_changed = answer
            .what_changed
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned);
        if self.previous.is_some() && what_changed.is_none() {
            return None;
        }
        let choice = self.choices.remove(index);
        let note = if choice.estimate {
            ESTIMATE_NOTE
        } else {
            PRICING_NOTE
        };
        let cost = |monthly: Option<f64>, one_off: Option<f64>| OfferCost {
            currency: CATALOG_CURRENCY.to_owned(),
            monthly_before: self.baseline_monthly,
            monthly_after: monthly,
            one_off,
            payback_months: payback(self.baseline_monthly, monthly, one_off),
        };
        let baseline = OfferOption {
            label: format!("keep {}", self.incumbent.model),
            model: self.incumbent.clone(),
            // Keeping the seat costs nothing once.
            cost: cost(self.baseline_monthly, Some(0.0)),
            score: None,
            evidence_refs: Vec::new(),
        };
        let alternatives = self
            .choices
            .iter()
            .map(|other| OfferOption {
                label: other.label.clone(),
                model: other.pin.clone(),
                cost: cost(other.monthly, None),
                score: None,
                evidence_refs: other.evidence_refs.clone(),
            })
            .collect();
        // The risk line carries the price note after the Coach's words.
        let risk = answer
            .risk
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map_or_else(|| note.to_owned(), |risk| format!("{risk} {note}"));
        let mut evidence = self.evidence;
        evidence.losses = answer
            .losses
            .iter()
            .map(|loss| loss.trim())
            .filter(|loss| !loss.is_empty())
            .map(str::to_owned)
            .collect();
        evidence.risk = Some(risk);
        // The offer skill whose body the Coach ran on this brief.
        let mut sources = self.sources;
        sources.row(offer_skill.0);
        Some(TrainingOfferDraft {
            seat: self.seat,
            offer_skill: Some(offer_skill),
            incumbent: self.incumbent,
            candidate: choice.candidate,
            baseline,
            alternatives,
            workload: self.workload,
            cost: cost(choice.monthly, None),
            evidence,
            destination: choice.destination,
            previous: self.previous,
            what_changed: self.previous.and(what_changed),
            check_at: now.saturating_add(CHECK_AFTER_SECS),
            source_rows: sources.rows(),
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

/// Checks one approved offer's promise against the seat's metered calls.
pub(super) fn check(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let id = coach_offer_check_target(admitted)?;
    let Some(offer) = training_offer(vault, &id)? else {
        return Ok(());
    };
    if !training_offer_checks(vault, &id)?.is_empty() {
        return Ok(());
    }
    // A promise is checked only after a yes.
    let Some(answer) = training_offers(vault, Some(&offer.seat))?
        .into_iter()
        .find(|(row, _)| row.id == id)
        .and_then(|(_, answer)| answer)
    else {
        return Ok(());
    };
    let (Some(intent), Some(role)) = (answer.intent.as_ref(), seat_model_role(&offer.seat)) else {
        return Ok(());
    };
    // A whole window after the yes; until then the check waits.
    let from = now.saturating_sub(WINDOW_SECS);
    if from < answer.at {
        return Ok(());
    }
    // The model the yes asked for: the stock model, or the custom one bound
    // from the exact run the yes handed off.
    let approved = match intent {
        OfferIntent::Switch { to, .. } => to.model.clone(),
        OfferIntent::Train { .. } => {
            let run = match offer_training_handoff(vault, &id)? {
                Some(handoff) => vault.training_run(&handoff.run)?,
                None => None,
            };
            let Some(run) = run.filter(|run| run.state == TrainingState::Bound) else {
                return Unverifiable::unread(Alone::NotBound, vault, admitted, &offer, now);
            };
            run.plan.output_binding.model.as_str().to_owned()
        }
    };
    let Some(meter) = server.vault_usage() else {
        return Unverifiable::unread(Alone::NoMeter, vault, admitted, &offer, now);
    };
    let (owner, vault_id) = (meter.owner(), meter.vault_id());
    let usage = server
        .usage_ledger
        .seat_usage(owner, vault_id, &role_key(role), Some(&approved), from, now)
        .map_err(|_| Error::InvalidConfig("the seat's usage could not be read".into()))?;
    // Metered throughout, or a later night reads it. The seat's calls on
    // another model are counted out; with none of the approved model's left,
    // or some the check cannot price or sum, it closes unverifiable.
    if usage.metered_since.is_some_and(|since| since > from) {
        return Ok(());
    }
    if let Some(outcome) = Unverifiable::of(&usage) {
        return outcome.record(vault, admitted, &offer, &approved, usage.refs, now);
    }
    let comparable = usage.currency.as_deref() == Some(offer.cost.currency.as_str());
    let observed = comparable
        .then(|| usage.cost_amount as f64 / 1e9 * MONTH_SECS as f64 / (now - from) as f64);
    let cost_held = observed
        .zip(offer.cost.monthly_after)
        .map(|(observed, promised)| observed <= promised * (1.0 + COST_TOLERANCE));
    // An offer that carried a measured card also promised the score, which
    // no meter reads: a kept cost then leaves the promise unknown.
    let held = match cost_held {
        Some(false) => Some(false),
        Some(true) if offer.evidence.card.is_none() => Some(true),
        _ => None,
    };
    let note = format!(
        "{} calls on {approved} over the {} days to the check, all priced{}; promised {} {} a \
         month, within {}%.{}",
        usage.calls,
        WINDOW_SECS / DAY_SECS,
        if comparable {
            String::new()
        } else {
            format!(
                " in {}, not the offer's {}",
                usage.currency.as_deref().unwrap_or("no currency"),
                offer.cost.currency
            )
        },
        offer
            .cost
            .monthly_after
            .map_or_else(|| "an unknown".to_owned(), |after| format!("{after:.2}")),
        offer.cost.currency,
        COST_TOLERANCE * 100.0,
        counted_out(usage.counted_out),
    );
    // The check reads the offer, with its own set, and the seat's metered
    // calls, named by receipt key only (FIX 5482).
    let mut sources = Sources::new();
    sources.set(offer.source_rows.as_deref());
    sources.unknown();
    let check = vault.run_coach_offer_check(
        admitted,
        OfferCheckInput {
            receipt_refs: usage.refs,
            observed_monthly_cost: observed,
            observed_score: None,
            held,
            note: Some(note),
            source_rows: sources.rows(),
        },
        now,
    )?;
    tracing::debug!(offer = %id.to_hex(), held = ?check.held, "the Coach checked an offer's promise");
    Ok(())
}
