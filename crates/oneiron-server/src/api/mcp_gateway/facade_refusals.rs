//! A typed engine facade error on the gateway's JSON-RPC vocabulary: its code and its stable kind.
//! `mcp_facade_error` is its call surface.
//! The engine's `MemoryError` (`oneiron::memory`) is the record forwarded here.

use super::McpGatewayError;
use super::tasks_response::{MCP_HOST_ACTION_REFUSED, MCP_OWNER_BINDING_REQUIRED, mcp_hook_stop};

/// Maps a typed engine facade error onto the gateway's JSON-RPC vocabulary,
/// its reason codes kept whatever its kind (FIX 7398).
pub(crate) fn mcp_facade_error(mut error: oneiron::MemoryError) -> McpGatewayError {
    let reason_codes = std::mem::take(&mut error.reason_codes);
    McpGatewayError {
        reason_codes,
        ..mcp_facade_refusal(error)
    }
}

fn mcp_facade_refusal(error: oneiron::MemoryError) -> McpGatewayError {
    if let Some(stop) = error.hook {
        return mcp_hook_stop(*stop);
    }
    if let Some(correction) = error.wrong_root {
        let mut refusal = McpGatewayError::new(-32601, "wrong_root", error.message);
        refusal.wrong_root = Some(correction);
        return refusal;
    }
    let code = match error.code.as_str() {
        oneiron::MEMORY_CODE_NOT_FOUND => -32004,
        // OF-123: an effect whose person is not settled yet is a typed
        // refusal like these, never an argument error; its kind below names it.
        oneiron::MEMORY_CODE_FORBIDDEN
        | oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED
        | oneiron::memory::MEMORY_CODE_BUDGET_SPENT
        | oneiron::memory::MEMORY_CODE_IDENTITY_UNSETTLED
        | oneiron::memory::MEMORY_CODE_HOST_ACTION_REFUSED
        | oneiron::memory::MEMORY_CODE_ROOM_MANAGEMENT
        | oneiron::workspace_roster::MEMORY_CODE_AGENT_THREAD_WALK_IN_FORBIDDEN
        | oneiron_contracts::memory::MEMORY_CODE_SANDBOX_PROPOSAL_DISK_FLOOR
        | oneiron_contracts::memory::MEMORY_CODE_MODEL_PIN_UNAVAILABLE
        | oneiron::MEMORY_CODE_INVALID_STATE => -32020,
        // A row's world setting, a frozen vault and a render that met its
        // deadline or a machine floor are typed refusals too, never an
        // argument error (FIX 7562, 5325, 8242).
        code if refusal_kind(code).is_some() => -32020,
        oneiron::MEMORY_CODE_INTERNAL | oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE => -32603,
        _ => -32602,
    };
    // A paid call's own refusals keep their names: a client tells a spent
    // line from a model that did not answer without reading the sentence.
    let kind = match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BUDGET_SPENT => Some("budget_spent"),
        oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE => Some("model_unavailable"),
        // OF-123: an effect whose person is not settled yet keeps its name
        // too, so an agent reads it as `error.data.error_code`, not prose.
        oneiron::memory::MEMORY_CODE_IDENTITY_UNSETTLED => Some("identity_unsettled"),
        // FIX 2222: one stable kind for the typed host refusal, whichever
        // door reported it.
        oneiron::memory::MEMORY_CODE_HOST_ACTION_REFUSED => Some(MCP_HOST_ACTION_REFUSED),
        // FIX 11434: the owner binding refusal keeps one stable kind too.
        oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED => Some(MCP_OWNER_BINDING_REQUIRED),
        // WILL-PLAN L13 row 03: the room's audience gave no consent to this
        // management; an agent reads the name, not the sentence.
        oneiron::memory::MEMORY_CODE_ROOM_MANAGEMENT => {
            Some("off_record_room_management_consent_unavailable")
        }
        // FIX 7650: a foreign guest's proposal spool met the host's disk
        // floor; the agent reads the name, not the sentence.
        oneiron_contracts::memory::MEMORY_CODE_SANDBOX_PROPOSAL_DISK_FLOOR => {
            Some("sandbox_proposal_disk_floor")
        }
        // FIX 10011: an owner model pin no offered seat serves.
        oneiron_contracts::memory::MEMORY_CODE_MODEL_PIN_UNAVAILABLE => {
            Some("model_pin_unavailable")
        }
        // FIX 6547: an agent thread's walk-in its room's audience does not
        // admit, named as the facade's 409 names it.
        oneiron::workspace_roster::MEMORY_CODE_AGENT_THREAD_WALK_IN_FORBIDDEN => {
            Some("agent_thread_walk_in_forbidden")
        }
        code => refusal_kind(code),
    };
    if let Some(kind) = kind {
        // A model that did not answer says when to call again (FIX 3194),
        // and so does a render that can be asked again (FIX 8242).
        return McpGatewayError {
            retry_after: error.retry_after,
            ..McpGatewayError::new(code, kind, error.message)
        };
    }
    // A facade refusal carrying a successor keeps the same stable kind and
    // typed data the engine-error path emits (ONE-1936) — one vocabulary for
    // one condition, whichever door reported it.
    match error.successor_short_id {
        Some(successor_short_id) => {
            McpGatewayError::new(code, "write_verb_target_stale", error.message)
                .with_successor_short_id(successor_short_id)
        }
        None => McpGatewayError::new(code, "facade_error", error.message),
    }
}

/// The stable kind of a typed refusal whose code the gateway names in its
/// own spelling, each a -32020 refusal: the owner's world read setting
/// (FIX 7562), a hosted vault paused for its reap (FIX 5325), and a deck
/// render past its deadline or at a machine floor (FIX 8242). `None` for
/// any other code.
fn refusal_kind(code: &str) -> Option<&'static str> {
    Some(match code {
        oneiron_contracts::memory::MEMORY_CODE_WORLD_RECIPIENT_LIMIT => "world_recipient_limit",
        oneiron_contracts::memory::MEMORY_CODE_WORLD_PLACEMENT_UNVERIFIABLE => {
            "world_placement_unverifiable"
        }
        crate::managed::WRITES_FROZEN_TAG => "writes_frozen",
        crate::slide_render::RENDER_DEADLINE => "render_deadline",
        crate::slide_render::RENDER_MEMORY_FLOOR => "render_memory_floor",
        crate::slide_render::RENDER_DISK_FLOOR => "render_disk_floor",
        _ => return None,
    })
}
