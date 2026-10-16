//! The reader's optional-memory profile (ZERO-RETRIEVAL = A, ARCH-0004
//! #reader-budget): the named agent definition picks the optional recall for
//! the task family, and the pack request is narrowed to it, never widened.

use super::super::core_engine_error;
use super::controls::{ContextPackBudgetControls, ContextPackReaderControls};
use super::response::field_profile_for_view;
use crate::error::ApiError;
use crate::projection::View;
use crate::server::SyncServer;

/// The optional recall the named reader's profile picks for this task, or
/// `None` when the request names no reader or its definition has no
/// optional-memory profile. A definition the caller cannot read is one that
/// does not exist.
pub(crate) fn reader_optional_memory(
    server: &SyncServer,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    reader: Option<&ContextPackReaderControls>,
) -> Result<Option<oneiron::agent_def::OptionalMemory>, ApiError> {
    let Some(reader) = reader else {
        return Ok(None);
    };
    let unknown = || {
        ApiError::bad_request(
            "reader.definition names no readable agent definition",
            Some("reader.definition"),
        )
    };
    let id = oneiron::EntityId::from_hex(&reader.definition).map_err(|_| unknown())?;
    if !scoped_read
        .is_entity_readable(&id)
        .map_err(|error| core_engine_error("reader definition read failed", error))?
    {
        return Err(unknown());
    }
    let definition = match server.vault.get_agent_definition(&id) {
        Ok(Some(definition)) => definition,
        Ok(None) => return Err(unknown()),
        Err(error) if error.kind() == oneiron::ErrorKind::InvalidAgentDefBody => {
            return Err(unknown());
        }
        Err(error) => return Err(core_engine_error("reader definition read failed", error)),
    };
    Ok(definition
        .memory_profile
        .and_then(|profile| profile.optional_memory)
        .map(|profile| profile.for_family(reader.task_family.as_deref())))
}

/// Narrows the request's `budget` and its resolved `view` to the reader's
/// choice. Returns true when the pack takes no optional recall at all.
pub(crate) fn narrow_to_reader(
    budget: &mut Option<ContextPackBudgetControls>,
    view: &mut View,
    choice: oneiron::agent_def::OptionalMemory,
) -> bool {
    let caller_tokens = budget
        .as_ref()
        .and_then(|budget| budget.token_budget)
        .unwrap_or(0);
    let Some((tokens, profile)) = choice.narrow(caller_tokens, field_profile_for_view(*view))
    else {
        return true;
    };
    budget
        .get_or_insert_with(ContextPackBudgetControls::default)
        .token_budget = Some(tokens);
    *view = match profile {
        oneiron::FieldProfile::Minimal => View::Summary,
        oneiron::FieldProfile::Full => View::Full,
        _ => View::Standard,
    };
    false
}
