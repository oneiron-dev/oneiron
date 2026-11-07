//! The rows an MCP call's result was derived from, as its producers listed
//! them (DEC-0005; SCAN C018, FIX 5988): a list, and whether one of its paths
//! listed none. Unknown is sticky, so no later producer's rows make the set
//! known again. On this device it changes nothing. Off it, an act whose rows
//! are unknown has still run and answers only that it ran
//! (`ActAnswer::DetailsOnDevice`). A read whose rows are unknown releases by
//! the rows its other producers listed, as before, unless
//! [`NARROW_UNKNOWN_MCP_READS`] holds: the producers that list none are the
//! ones to fix (the FIX 5817 ruling: unknown is not "not found").
use std::ops::{Deref, DerefMut};

use oneiron::EntityId;
use oneiron::runtime_hooks::VerbHookStop;
use oneiron::task_verb::sdk::{ActAnswer, AgentVerb};
use serde_json::Value;

use super::{McpCallContext, McpGatewayError};
use crate::server::SyncServer;

/// While this holds, an act whose rows are unknown has run and answers an
/// off-device caller only that it ran (Engine 10-20 09:04). False answers it
/// as before.
pub(crate) const NARROW_UNKNOWN_MCP_ACT_ANSWERS: bool = true;

/// While this holds, a read whose rows are unknown is withheld off this
/// device as `ProducersUnknown`, fresh, retained or continued. False (as
/// before): it releases by the rows its other producers listed.
pub(crate) const NARROW_UNKNOWN_MCP_READS: bool = false;

/// The rows one MCP call served, as its producers listed them. It reads and
/// extends as the list it holds; [`Self::listed`] takes a listing that may be
/// unknown.
#[derive(Debug, Default)]
pub(crate) struct McpServed {
    rows: Vec<EntityId>,
    unknown: bool,
}

impl McpServed {
    /// A producer's listing: its rows, or `None` when its path lists none.
    pub(crate) fn listed(&mut self, rows: Option<Vec<EntityId>>) {
        match rows {
            Some(rows) => self.rows.extend(rows),
            None => self.unknown = true,
        }
    }

    /// Whether one producer's rows were unknown.
    fn unknown(&self) -> bool {
        self.unknown
    }

    /// The rows a release judges by: the listed ones, or `None` for unknown
    /// rows while [`NARROW_UNKNOWN_MCP_READS`] holds.
    pub(crate) fn rows(&self) -> Option<&[EntityId]> {
        (!(self.unknown && NARROW_UNKNOWN_MCP_READS)).then_some(self.rows.as_slice())
    }

    /// [`Self::rows`], owned.
    pub(crate) fn into_rows(self) -> Option<Vec<EntityId>> {
        (!(self.unknown && NARROW_UNKNOWN_MCP_READS)).then_some(self.rows)
    }
}

impl Deref for McpServed {
    type Target = Vec<EntityId>;

    fn deref(&self) -> &Vec<EntityId> {
        &self.rows
    }
}

impl DerefMut for McpServed {
    fn deref_mut(&mut self) -> &mut Vec<EntityId> {
        &mut self.rows
    }
}

/// `output` of verb `tool` beside the rows it `served`, for `actor`: an act
/// whose rows are unknown has run, and an off-device caller hears only that,
/// beside no row, while [`NARROW_UNKNOWN_MCP_ACT_ANSWERS`] holds (FIX 5988).
/// Every other answer, and every answer on this device, is returned as it
/// was, beside the rows its release judges by ([`McpServed::into_rows`]).
pub(super) fn unknown_act_answer(
    tool: &str,
    actor: &McpCallContext,
    output: Value,
    served: McpServed,
) -> Result<(Value, Option<Vec<EntityId>>), McpGatewayError> {
    let act = AgentVerb::from_name(tool).is_some_and(AgentVerb::writes);
    if !NARROW_UNKNOWN_MCP_ACT_ANSWERS
        || !served.unknown()
        || !act
        || !actor.destination().is_off_device()
    {
        return Ok((output, served.into_rows()));
    }
    let ran = serde_json::to_value(ActAnswer::<Value>::details_on_device()).map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "typed agent result cannot be encoded",
        )
    })?;
    Ok((ran, Some(Vec::new())))
}

/// The rows the answer of verb `tool` a drain ran is saved beside, for the
/// caller's retry of the same invocation to be released by (FIX 21054):
/// the rows its release judges by ([`McpServed::into_rows`]). An act whose
/// rows are unknown saves none while [`NARROW_UNKNOWN_MCP_ACT_ANSWERS`]
/// holds. Off this device its retry is then withheld, never released by
/// the rows its other producers listed.
#[cfg(feature = "code-sandbox-wasmtime")]
pub(super) fn saved_answer_rows(tool: &str, served: McpServed) -> Option<Vec<EntityId>> {
    let act = AgentVerb::from_name(tool).is_some_and(AgentVerb::writes);
    if NARROW_UNKNOWN_MCP_ACT_ANSWERS && act && served.unknown() {
        return None;
    }
    served.into_rows()
}

/// The rows a generated row's hook `stop` is released by. A retry that gets
/// the answer an ask's settlement already ran restores into `served` the
/// rows that saved answer was derived from (FIX 1435, FIX 21054). An answer
/// saved with none is released by no listed row, so off this device it is
/// withheld as a result whose rows are unknown is, never released as an
/// empty set. Any other stop is released by the rows `served` lists.
pub(super) fn stop_release_rows<'s>(
    server: &SyncServer,
    actor: &McpCallContext,
    stop: &VerbHookStop,
    served: &'s mut McpServed,
) -> Option<&'s [EntityId]> {
    if !matches!(stop, VerbHookStop::Completed { .. }) {
        return served.rows();
    }
    let saved = actor.invocation.and_then(|invocation| {
        server
            .vault
            .verb_hook_saved_producers(invocation)
            .inspect_err(|error| tracing::warn!(%error, "a drained call's rows did not read"))
            .ok()
            .flatten()
    })?;
    served.extend(saved);
    served.rows()
}

/// Whether a retry's `Completed` stop carries an answer derived from a row
/// of `rows` that `actor`'s credential no longer reads, or that was erased
/// since (FIX 21614). The drain read those rows, not this retry, so the
/// answer is released only as a claimed invocation's waiter is
/// ([`crate::api::facade::rows_still_admitted`]); a lapsed one answers only
/// that the call ran. Any other stop, or rows that are unknown, is not
/// judged here.
pub(super) fn drained_rows_lapsed(
    server: &SyncServer,
    actor: &McpCallContext,
    stop: &VerbHookStop,
    rows: Option<&[EntityId]>,
) -> bool {
    matches!(stop, VerbHookStop::Completed { .. })
        && rows.zip(actor.auth.as_ref()).is_some_and(|(rows, auth)| {
            !crate::api::facade::rows_still_admitted(&server.vault, auth, rows)
        })
}

/// The acts that answer the word that they ran when the off-device
/// release holds their known rows, never a withheld error after their commit
/// (FIX 8171, FIX 8526): the pilot prepare whose producers started listing
/// rows, and every act whose facade door already narrows a held answer that
/// way (FIX 3414). Each lists known rows, so none answered as
/// [`unknown_act_answer`].
const KNOWN_ROW_ACTS: &[&str] = &[
    "vault.coach.training_offers.pilots.prepare",
    "vault.records.erase_confirm",
    "connector.call",
    "vault.fanout.resume",
    "vault.fanout.resume_as",
    "vault.fanout.ack",
    "vault.shared.execute",
    "vault.artifacts.review_slides",
    "vault.artifacts.ask",
];

/// [`unknown_act_answer`], then, for one of [`KNOWN_ROW_ACTS`] whose rows
/// are known (FIX 8171, F1): an act that ran, off this device, whose answer
/// its rows' release would hold answers only that it ran, as it did while
/// its rows were unknown, never a withheld error after its commit. Any
/// other answer is returned as [`unknown_act_answer`] returns it.
pub(super) fn held_act_answer(
    server: &std::sync::Arc<crate::server::SyncServer>,
    tool: &str,
    actor: &McpCallContext,
    output: Value,
    served: McpServed,
) -> Result<(Value, Option<Vec<EntityId>>), McpGatewayError> {
    let (output, rows) = unknown_act_answer(tool, actor, output, served)?;
    let held = match rows.as_deref() {
        Some(known) if KNOWN_ROW_ACTS.contains(&tool) && actor.destination().is_off_device() => {
            super::device_release::mcp_release_result(
                server,
                actor,
                known,
                false,
                output.clone(),
                false,
            )
            .is_err()
        }
        _ => false,
    };
    if !held {
        return Ok((output, rows));
    }
    let ran = serde_json::to_value(ActAnswer::<Value>::details_on_device()).map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "typed agent result cannot be encoded",
        )
    })?;
    Ok((ran, Some(Vec::new())))
}
