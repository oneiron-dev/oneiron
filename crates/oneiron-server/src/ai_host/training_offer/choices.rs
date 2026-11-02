//! The two option lists a seat's brief is gathered from: each stock model
//! the seat may switch to, priced on its workload and sorted, and each
//! recipe a seat run trained from. `Brief::gather` calls them in order.
use super::{
    Choice, ComputeDestination, EvalSeat, ModelLocality, ModelRegistryRow, ModelRole,
    OfferCandidate, SeatUsage, SeatWorkload, Sources, TrainingRun, base_pin, candidate_monthly,
    destination, licence, pin,
};

/// Every stock model the seat could switch to, priced on its workload,
/// the cheapest first and unknown prices last.
pub(super) fn stock_choices(
    registry: &[ModelRegistryRow],
    current: &ModelRegistryRow,
    workload: &SeatWorkload,
    usage: &SeatUsage,
) -> Vec<Choice> {
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
            let (monthly, estimate) = candidate_monthly(current, row, workload, usage);
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
                pilot: None,
                data: serde_json::json!({
                    "kind": "switch",
                    "model": row.catalog.model.as_str(),
                    "display_name": row.catalog.display_name,
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
    // The cheapest first, unknown prices last. Every option rides whole
    // (Rule 5).
    stock.sort_by(|a, b| match (a.monthly, b.monthly) {
        (Some(a), Some(b)) => a.total_cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    stock
}

/// Each recipe a seat run of this role trained from, newest run first, and
/// the seat's runs it read.
pub(super) fn recipe_choices<'a>(
    runs: &'a [TrainingRun],
    registry: &[ModelRegistryRow],
    role: ModelRole,
    seat: &EvalSeat,
    sources: &mut Sources,
) -> (Vec<Choice>, Vec<&'a TrainingRun>) {
    let mut recipes: Vec<Choice> = Vec::new();
    // A question head trains no seat's role, so no offer recipe names it.
    let mut seat_runs: Vec<&TrainingRun> = runs
        .iter()
        .filter(|run| {
            run.plan
                .target
                .role_binding()
                .is_some_and(|(run_role, _)| run_role == role)
                && run.plan.seat == *seat
        })
        .collect();
    seat_runs.sort_by_key(|run| std::cmp::Reverse((run.created_at, run.id)));
    for run in &seat_runs {
        // Each seat run is read for its recipe, kept or not (FIX 5760).
        sources.set(run.source_rows.as_deref());
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
            pilot: None,
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
    (recipes, seat_runs)
}
