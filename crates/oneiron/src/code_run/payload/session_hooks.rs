//! The replay codec of a `vault.search` outcome and what each verb hook
//! bound to it did in a room (WILL L11-01 S01-2c, FIX 5160; CALLS-9
//! `session_hook_meta_shape`).
//!
//! The run's record keeps the search's own query and hits, never a hook's
//! changed view of them, as for every hooked call. Beside them it keeps each
//! hook's disposition, so a replayed step answers the guest with it as the
//! step did. A search no hook ran on keeps no `hooks` key, and reads back
//! with none.

use rmpv::Value;

use crate::Result;
use crate::code_run::types::{SelfDispatchOutcome, SelfMemorySearchResult, SessionHookDisposition};

use super::super::support::{
    decode_array, entity_id_value, invalid_code_run_replay, map_get, request_map, str_value,
};
use super::decode_scored_entity;

/// The outcome key the hooks' dispositions ride under, as their JSON.
const HOOKS: &str = "hooks";

/// `result` as the run's record keeps it.
pub(super) fn memory_search_value(result: &SelfMemorySearchResult) -> Result<Value> {
    let mut entries = vec![
        ("kind", Value::from("memory_search")),
        ("query", Value::from(result.query.as_str())),
        (
            "results",
            Value::Array(
                result
                    .results
                    .iter()
                    .map(|hit| {
                        request_map(vec![
                            ("id", entity_id_value(hit.id)),
                            ("score", Value::F32(hit.score)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    keep_hooks(&mut entries, &result.hooks)?;
    Ok(request_map(entries))
}

/// `hooks` kept beside an outcome's own `entries` under [`HOOKS`], as their
/// JSON; none when no hook ran (FIX 5425: a room's forwarded reads and
/// writes keep theirs as its search does).
pub(super) fn keep_hooks(
    entries: &mut Vec<(&'static str, Value)>,
    hooks: &[SessionHookDisposition],
) -> Result<()> {
    if !hooks.is_empty() {
        let hooks = serde_json::to_string(hooks)
            .map_err(|_| invalid_code_run_replay("verb hook dispositions do not encode"))?;
        entries.push((HOOKS, Value::from(hooks)));
    }
    Ok(())
}

/// The hooks an outcome's map `entries` kept under [`HOOKS`]; none when it
/// kept none.
pub(super) fn decode_hooks(entries: &[(Value, Value)]) -> Result<Vec<SessionHookDisposition>> {
    match map_get(entries, HOOKS) {
        Ok(hooks) => serde_json::from_str(str_value(hooks)?)
            .map_err(|_| invalid_code_run_replay("invalid verb hook dispositions")),
        Err(_) => Ok(Vec::new()),
    }
}

/// A `memory_search` outcome the run's record kept, from its map `entries`.
pub(super) fn decode_memory_search(entries: &[(Value, Value)]) -> Result<SelfDispatchOutcome> {
    let results = decode_array(map_get(entries, "results")?, decode_scored_entity)?;
    let hooks = decode_hooks(entries)?;
    Ok(SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
        query: str_value(map_get(entries, "query")?)?.to_owned(),
        results,
        hooks,
    }))
}
