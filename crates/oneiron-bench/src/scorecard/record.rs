//! `scorecard proposals` and `scorecard stamp`: list proposals, record the owner's stamp.
//!
//! A withdrawn proposal stays listed with both scorecards and the reason; the
//! owner's stamp may still promote it, and the stamp records that it overrode
//! the sealed check. Nothing here refuses the owner's stamp because of the
//! sealed verdict. The stamp prints the owner's pin calls; it never makes them.

use std::path::Path;

use oneiron::store::{RetrievalBlendSignal, RetrievalPolicyPin, RetrievalPolicyPins};
use oneiron::task_verb::sdk::RetrievalPolicyPinRequest;
use oneiron_ruler::proposal::{ProposalError, ProposalListing, ProposalStore};

use super::params::pinned_weights;
use super::{ScorecardFailure, flag_unix_seconds, parse_flags, required_flag};

/// The flags `scorecard proposals` takes.
const LIST_FLAGS: &[&str] = &["proposals"];

/// The flags `scorecard stamp` takes.
const STAMP_FLAGS: &[&str] = &["proposals", "proposal", "at", "note"];

/// The pin verb the stamp prints for each signal.
const PIN_VERB: &str = "vault.retrieval.policy.pin";

/// The five blend signals in pin order.
const SIGNALS: [RetrievalBlendSignal; 5] = [
    RetrievalBlendSignal::Recency,
    RetrievalBlendSignal::Salience,
    RetrievalBlendSignal::Confidence,
    RetrievalBlendSignal::Gravity,
    RetrievalBlendSignal::Relevance,
];

/// List every proposal, withdrawn included.
pub(crate) fn list(args: &[String]) -> Result<serde_json::Value, ScorecardFailure> {
    let flags = parse_flags(args, LIST_FLAGS)?;
    let dir = required_flag(&flags, "proposals")?;
    let store = ProposalStore::open(Path::new(dir)).map_err(map_store_error)?;
    let proposals = store.list().map_err(map_store_error)?;
    Ok(serde_json::json!({ "proposals": proposals }))
}

/// Record the owner's stamp, and print the pin calls it stands for.
pub(crate) fn stamp(args: &[String]) -> Result<serde_json::Value, ScorecardFailure> {
    let flags = parse_flags(args, STAMP_FLAGS)?;
    let dir = required_flag(&flags, "proposals")?;
    let proposal = required_flag(&flags, "proposal")?;
    let stamped_at = flag_unix_seconds(&flags, "at")?;
    let note = flags.get("note").map_or("", String::as_str);
    let store = ProposalStore::open(Path::new(dir)).map_err(map_store_error)?;
    let listing = store.get(proposal).map_err(map_store_error)?;
    let (pin_calls, pin_note) = build_pin_calls(&listing)?;
    let stamp = store
        .put_stamp(proposal, stamped_at, note)
        .map_err(map_store_error)?;
    Ok(serde_json::json!({
        "stamp": stamp,
        "pin_calls": pin_calls,
        "pin_note": pin_note,
    }))
}

/// The owner's pin calls for a listing's candidate params, with their note.
///
/// Pinned weights are pinned as the normalized shares the run evaluated
/// (`with_blend_weights` normalizes them). The calls first clear every pin,
/// so no earlier pin adds to the mass, and each call is checked here against
/// the pin rules the verb applies: no prefix of the calls is refused.
fn build_pin_calls(
    listing: &ProposalListing,
) -> Result<(Vec<serde_json::Value>, String), ScorecardFailure> {
    let weights = listing.held_out.candidate_params.get("blend_weights");
    let mut calls = Vec::with_capacity(2 * SIGNALS.len());
    for signal in SIGNALS {
        calls.push(pin_call(signal, None)?);
    }
    match weights {
        Some(serde_json::Value::String(named)) if named == "learned_table" => Ok((
            calls,
            "the candidate is the learned table: clear every pin".to_owned(),
        )),
        Some(blend @ serde_json::Value::Object(_)) => {
            let shares = pinned_weights(blend)
                .and_then(|raw| raw.normalized().map_err(|error| error.to_string()))
                .map_err(|reason| {
                    ScorecardFailure::Run(format!("candidate blend_weights: {reason}"))
                })?;
            let mut pins = RetrievalPolicyPins::default();
            for signal in SIGNALS {
                let value = shares.weight(signal);
                pins.pins.push(RetrievalPolicyPin { signal, value });
                pins.validate().map_err(|error| {
                    ScorecardFailure::Run(format!(
                        "the pin of {signal:?} would be refused: {error}"
                    ))
                })?;
                calls.push(pin_call(signal, Some(value))?);
            }
            Ok((
                calls,
                "clear every pin, then pin the candidate's normalized blend weights, in this order"
                    .to_owned(),
            ))
        }
        _ => Err(ScorecardFailure::Run(
            "candidate blend_weights is neither pinned weights nor learned_table".to_owned(),
        )),
    }
}

/// One pin call: the verb and its input, written by the verb's own request type.
fn pin_call(
    signal: RetrievalBlendSignal,
    value: Option<f32>,
) -> Result<serde_json::Value, ScorecardFailure> {
    let input = serde_json::to_value(RetrievalPolicyPinRequest { signal, value })
        .map_err(|error| ScorecardFailure::Run(format!("pin call encode failed: {error}")))?;
    Ok(serde_json::json!({ "verb": PIN_VERB, "input": input }))
}

/// Map a store failure: bad proposals are bad input, IO and JSON are run failures.
fn map_store_error(error: ProposalError) -> ScorecardFailure {
    let message = error.to_string();
    if matches!(
        error,
        ProposalError::Io { .. } | ProposalError::Json(_) | ProposalError::Canonical(_)
    ) {
        ScorecardFailure::Run(message)
    } else {
        ScorecardFailure::Input(message)
    }
}
