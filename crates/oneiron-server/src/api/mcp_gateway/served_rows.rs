//! The rows an MCP call's result was derived from, as its producers listed
//! them (DEC-0005; SCAN C018, FIX 5988): a list, or unknown once one of its
//! paths listed none. Unknown is sticky, so no later producer's rows make the
//! set known again, and it never stands as an empty list. On this device it
//! changes nothing. Off it, an act whose rows are unknown has still run and
//! answers only that it ran (`ActAnswer::DetailsOnDevice`), and a read whose
//! rows are unknown is withheld as `ProducersUnknown`, fresh or retained.
use std::ops::{Deref, DerefMut};

use oneiron::EntityId;
use oneiron::task_verb::sdk::{ActAnswer, AgentVerb};
use serde_json::Value;

use super::{McpCallContext, McpGatewayError};

/// While this holds, a producer's unknown row set stays unknown through its
/// call's release, its retained page and every continuation of it, and the
/// off-device answer narrows as above. False flattens it into the rows the
/// call's other producers listed, as before.
pub(crate) const NARROW_UNKNOWN_MCP_ANSWERS: bool = true;

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
            None => self.unknown |= NARROW_UNKNOWN_MCP_ANSWERS,
        }
    }

    /// The rows, `None` once one producer's were unknown.
    pub(crate) fn rows(&self) -> Option<&[EntityId]> {
        (!self.unknown).then_some(self.rows.as_slice())
    }

    /// [`Self::rows`], owned.
    pub(crate) fn into_rows(self) -> Option<Vec<EntityId>> {
        (!self.unknown).then_some(self.rows)
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

/// `output` of verb `tool` beside `rows`, for `actor`: an act whose rows are
/// unknown has run, and an off-device caller hears only that, beside no row
/// (FIX 5988). Every other answer, and every answer on this device, is
/// returned as it was; a read keeps its unknown rows for its release.
pub(super) fn unknown_act_answer(
    tool: &str,
    actor: &McpCallContext,
    output: Value,
    rows: Option<Vec<EntityId>>,
) -> Result<(Value, Option<Vec<EntityId>>), McpGatewayError> {
    let act = AgentVerb::from_name(tool).is_some_and(AgentVerb::writes);
    if rows.is_some() || !act || !actor.destination().is_off_device() {
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
