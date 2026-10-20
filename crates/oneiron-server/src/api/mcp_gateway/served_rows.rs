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
use oneiron::task_verb::sdk::{ActAnswer, AgentVerb};
use serde_json::Value;

use super::{McpCallContext, McpGatewayError};

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
