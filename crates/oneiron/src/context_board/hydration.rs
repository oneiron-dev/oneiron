//! The assembled context one hydration call returns: session prefix material (counts, last activity, notifications, unprocessed work, token meter) beside the MEMORIES cursor and section (ARCH-0067 §2, v5 assembled context). Step two: split into the cached-prefix blocks and the dynamic tail.

use std::collections::BTreeMap;

use super::memories::{MemoriesCursor, MemoriesSection};

/// Read-only session prefix: entity counts by type and the latest activity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionContext {
    pub api_version: String,
    pub counts: BTreeMap<String, u64>,
    pub last_activity: Option<u64>,
}

/// Pending notification surfaced during context-board hydration.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NotificationItem {
    pub id: String,
    pub learned_at: u64,
    pub body: serde_json::Value,
}

/// Existing work item that still needs caller-side processing.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UnprocessedItem {
    pub id: String,
    pub entity_type: u8,
    pub learned_at: u64,
    pub body: serde_json::Value,
}

/// Token meter snapshot included in every assembled context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HydrationBudget {
    pub tokens_used: u64,
    pub tokens_limit: u64,
    pub tokens_remaining: u64,
}

impl HydrationBudget {
    #[must_use]
    pub fn from_meter(tokens_used: u64, tokens_limit: u64) -> Self {
        Self {
            tokens_used,
            tokens_limit,
            tokens_remaining: tokens_limit.saturating_sub(tokens_used),
        }
    }
}

/// The assembled context one hydration call returns.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AssembledContext {
    pub session: SessionContext,
    pub notifications: Vec<NotificationItem>,
    pub unprocessed: Vec<UnprocessedItem>,
    pub budget: HydrationBudget,
    /// Per-session MEMORIES retrieval cursor, advanced when this call ran
    /// retrieval and otherwise the current one for the caller.
    #[serde(default)]
    pub cursor: MemoriesCursor,
    /// This turn's MEMORIES section; absent when retrieval was skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memories: Option<MemoriesSection>,
}

impl AssembledContext {
    #[must_use]
    pub fn new(
        session: SessionContext,
        notifications: Vec<NotificationItem>,
        unprocessed: Vec<UnprocessedItem>,
        budget: HydrationBudget,
        cursor: MemoriesCursor,
        memories: Option<MemoriesSection>,
    ) -> Self {
        Self {
            session,
            notifications,
            unprocessed,
            budget,
            cursor,
            memories,
        }
    }
}
