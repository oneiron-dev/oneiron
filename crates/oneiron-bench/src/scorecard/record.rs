//! `scorecard proposals` and `scorecard stamp`: list proposals, record the owner's stamp.
//!
//! A withdrawn proposal stays listed with both scorecards and the reason; the
//! owner's stamp may still promote it, and the stamp records that it overrode
//! the sealed check. Nothing here refuses the owner's stamp because of the
//! sealed verdict. The stamp prints the owner's pin calls; it never makes them.

use std::path::Path;

use oneiron_ruler::proposal::{ProposalError, ProposalListing, ProposalStore};

use super::{ScorecardFailure, flag_unix_seconds, parse_flags, required_flag};

/// The flags `scorecard proposals` takes.
const LIST_FLAGS: &[&str] = &["proposals"];

/// The flags `scorecard stamp` takes.
const STAMP_FLAGS: &[&str] = &["proposals", "proposal", "at", "note"];

/// The pin verb the stamp prints for each signal.
const PIN_VERB: &str = "vault.retrieval.policy.pin";

/// The five blend signals in pin order.
const SIGNALS: [&str; 5] = ["recency", "salience", "confidence", "gravity", "relevance"];

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
fn build_pin_calls(
    listing: &ProposalListing,
) -> Result<(Vec<serde_json::Value>, String), ScorecardFailure> {
    let weights = listing.held_out.candidate_params.get("blend_weights");
    match weights {
        Some(serde_json::Value::String(named)) if named == "learned_table" => {
            let mut calls = Vec::with_capacity(SIGNALS.len());
            for signal in SIGNALS {
                calls.push(serde_json::json!({
                    "verb": PIN_VERB,
                    "input": {"signal": signal, "value": null},
                }));
            }
            Ok((
                calls,
                "the candidate is the learned table: clear every pin".to_owned(),
            ))
        }
        Some(serde_json::Value::Object(pinned)) => {
            let mut calls = Vec::with_capacity(SIGNALS.len());
            for signal in SIGNALS {
                let Some(value) = pinned.get(signal) else {
                    return Err(ScorecardFailure::Run(format!(
                        "candidate blend_weights has no {signal}"
                    )));
                };
                if !value.is_number() {
                    return Err(ScorecardFailure::Run(format!(
                        "candidate blend weight {signal} is not a number"
                    )));
                }
                calls.push(serde_json::json!({
                    "verb": PIN_VERB,
                    "input": {"signal": signal, "value": value},
                }));
            }
            Ok((calls, "pin the candidate's blend weights".to_owned()))
        }
        _ => Err(ScorecardFailure::Run(
            "candidate blend_weights is neither pinned weights nor learned_table".to_owned(),
        )),
    }
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
