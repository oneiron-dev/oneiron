//! A program step's outbound leg checked against its connector's descriptor
//! at write time (FIX 2774).
//!
//! The descriptor is the connector's outbound capability manifest. When one
//! is registered for the step's channel, the verb must be one of its verbs,
//! stored in the manifest's spelling, and whether the channel honours the
//! ledger's idempotency key is read from the verb's replay safety, the rule
//! the dispatch pipeline applies, never from the caller. A channel no
//! manifest describes keeps the step as written: the send-time frozen-call
//! validation stays its judge.
//!
//! A manifest's `params` describe each field in prose, not as a schema, so
//! the payload is not checked against them here.

use super::program::CampaignProgramOutbound;
use super::storage::invalid;
use crate::error::Result;
use crate::outbound::{OutboundReplaySafety, outbound_capability_manifest, outbound_verb_contract};

/// `outbound` as the descriptor of `channel`'s connector admits it: its verb
/// in the manifest's spelling and its idempotency derived from that verb.
/// Unchanged when no manifest describes `channel`.
///
/// # Errors
///
/// [`crate::error::Error::InvalidConfig`] when the connector's manifest does
/// not carry the verb.
pub(super) fn descriptor_checked(
    channel: &str,
    outbound: &CampaignProgramOutbound,
) -> Result<CampaignProgramOutbound> {
    if outbound_capability_manifest(channel).is_none() {
        return Ok(outbound.clone());
    }
    let contract = outbound_verb_contract(channel, &outbound.verb)
        .map_err(|_| invalid("a step's outbound verb is not one its channel's connector carries"))?;
    Ok(CampaignProgramOutbound {
        verb: contract.kind.clone(),
        idempotency_supported: !matches!(
            contract.replay_safety(),
            OutboundReplaySafety::Reconcile
        ),
        ..outbound.clone()
    })
}
