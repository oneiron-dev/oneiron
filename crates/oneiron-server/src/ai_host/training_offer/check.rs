//! The check of one approved offer's promise against the seat's metered
//! calls: fixed code, no model call.
use super::{
    Alone, COST_TOLERANCE, DAY_SECS, DreamerAdmittedAttempt, Error, MONTH_SECS, OfferCheckInput,
    OfferIntent, Sources, SyncServer, TrainingState, Unverifiable, WINDOW_SECS,
    coach_offer_check_target, offer_training_handoff, role_key, seat_model_role, training_offer,
    training_offer_checks, training_offers,
};

/// Checks one approved offer's promise against the seat's metered calls.
pub(in crate::ai_host) fn check(
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
    let Some(intent) = answer.intent.as_ref() else {
        return Ok(());
    };
    // A whole window after the yes; until then the check waits.
    let from = now.saturating_sub(WINDOW_SECS);
    if from < answer.at {
        return Ok(());
    }
    // The check reads the offer, with its own set, the run a Train yes
    // handed off and the seat's metered calls, each as it froze its rows
    // (FIX 5760).
    let mut sources = Sources::new();
    sources.set(offer.source_rows.as_deref());
    let Some(role) = seat_model_role(&offer.seat) else {
        return Unverifiable::unread(Alone::NoModelRole, vault, admitted, &offer, sources, now);
    };
    // The model the yes asked for: the stock model, or the custom one bound
    // from the exact run the yes handed off.
    let approved = match intent {
        OfferIntent::Switch { to, .. } => to.model.clone(),
        OfferIntent::Train { .. } => {
            let run = match offer_training_handoff(vault, &id)? {
                Some(handoff) => vault.training_run(&handoff.run)?,
                None => None,
            };
            if let Some(run) = &run {
                sources.set(run.source_rows.as_deref());
            }
            // Only a role run binds the seat's model; a question head never
            // counts as the seat's savings.
            let Some((_, binding)) = run
                .as_ref()
                .filter(|run| run.state == TrainingState::Bound)
                .and_then(|run| run.plan.target.role_binding())
            else {
                return Unverifiable::unread(
                    Alone::NotBound,
                    vault,
                    admitted,
                    &offer,
                    sources,
                    now,
                );
            };
            binding.model.as_str().to_owned()
        }
    };
    let Some(meter) = server.vault_usage() else {
        return Unverifiable::unread(Alone::NoMeter, vault, admitted, &offer, sources, now);
    };
    let (owner, vault_id) = (meter.owner(), meter.vault_id());
    let usage = server
        .usage_ledger
        .seat_usage(owner, vault_id, &role_key(role), Some(&approved), from, now)
        .map_err(|_| Error::InvalidConfig("the seat's usage could not be read".into()))?;
    // Metered throughout, or a later night reads it. With the seat's calls on
    // another model counted out, none of the approved model's left, or some
    // the check cannot price or sum, it closes unverifiable.
    if usage.metered_since.is_some_and(|since| since > from) {
        return Ok(());
    }
    sources.set(usage.source_rows.as_deref());
    if let Some(outcome) = Unverifiable::of(&usage) {
        return outcome.record(vault, admitted, &offer, &approved, usage.refs, sources, now);
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
         month, within {}%.",
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
    );
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
