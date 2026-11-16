//! Moved from `crates/oneiron/src/runtime_hooks/outcome.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::runtime_hooks::block::HookBlockLifetime;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

pub const MAX_TEXT: usize = 256;

pub const MAX_BODY: usize = 16 * 1024;

pub const MAX_TOKEN_CAP: u32 = 4_096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposedClaim {
    pub subject: String,
    pub predicate: String,
    pub value: serde_json::Value,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedEdge {
    pub from: String,
    pub to: String,
    pub edge: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedNote {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub about: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnqueuedTask {
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub assignee: Option<String>,
    /// When the TASK falls due, Unix seconds: it lands as the TASK's own
    /// due time and ticks on `schedule.tick` (FIX 4749).
    #[serde(default)]
    pub due_at: Option<u64>,
    /// The TASK is a watch TASK (FIX 22121): it needs `due_at`, queues no
    /// work, and its tick settles it. A watcher repeats by enqueuing its
    /// next watch TASK from the hook on its tick.
    #[serde(default)]
    pub watch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnqueuedDreamer {
    pub reason: String,
    #[serde(default)]
    pub about: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRequest {
    pub refs: Vec<String>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub lifetime: Option<HookBlockLifetime>,
    #[serde(default)]
    pub token_cap: Option<u32>,
}

pub fn validate_block(block: &BlockRequest) -> std::result::Result<(), String> {
    if block.refs.is_empty() {
        return Err("a block names one or more rows".to_owned());
    }
    entities(&block.refs)?;
    for id in [&block.session, &block.branch].into_iter().flatten() {
        text(id, MAX_TEXT)?;
    }
    match &block.lifetime {
        // Any positive count is kept as asked (FIX 10074); zero delivers nothing.
        Some(HookBlockLifetime::Deliveries(0)) => {
            return Err("block deliveries are zero".to_owned());
        }
        Some(HookBlockLifetime::UntilPredicate(glob)) => text(glob, MAX_TEXT)?,
        _ => {}
    }
    if block
        .token_cap
        .is_some_and(|cap| cap == 0 || cap > MAX_TOKEN_CAP)
    {
        return Err("block token cap is out of bounds".to_owned());
    }
    Ok(())
}

pub fn text(value: &str, max: usize) -> std::result::Result<(), String> {
    if value.trim().is_empty() || value.len() > max {
        return Err("a text field is empty or too long".to_owned());
    }
    Ok(())
}

pub fn entity(value: &str) -> std::result::Result<EntityId, String> {
    EntityId::from_hex(value).map_err(|_| "an entity ref is not 32 hex".to_owned())
}

/// Checks every ref the outcome names, however many (FIX 10074).
pub fn entities(values: &[String]) -> std::result::Result<(), String> {
    for value in values {
        entity(value)?;
    }
    Ok(())
}
