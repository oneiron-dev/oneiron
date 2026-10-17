//! `vault.shares.create`: the caller shares one stored brief with one
//! recipient and chooses which born-with text travels with it (OF-491). The
//! door is [`crate::Vault::create_share_travelling`]. The issuer is the
//! handle's own actor, never request data, and the share lands only after
//! the Gate records an allowing external-effect decision pinned to exactly
//! this share id, recipient, scope and travel choice. A pending or denied
//! decision is durable and creates no grant; once the owner approves it, the
//! same request with the same `share_id` lands it.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::access_grant::AccessGrantStatus;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::share::Share;
use crate::share_travel::{TravelChoice, TravelKind};
use crate::{EntityId, WriteActor};

/// `vault.shares.create`'s input: the brief, its recipient, the most the view
/// may show, and what born-with text travels.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareCreateRequest {
    /// The share's id, as 32 hex: the one a pending decision named, to land
    /// it after approval. A fresh id when absent.
    #[serde(default)]
    pub share_id: Option<String>,
    /// Who may read the brief, as 32 hex; every view authenticates as them.
    pub recipient: String,
    /// The stored brief shared: its NOTE document reference.
    pub brief_ref: String,
    /// The most WORLDs the view may show, as 32 hex each.
    #[serde(default)]
    pub world_refs: Vec<String>,
    /// The most FACETs the view may show, as 32 hex each.
    #[serde(default)]
    pub facet_refs: Vec<String>,
    /// Whether an unscoped dimension may pass.
    #[serde(default)]
    pub include_unscoped: bool,
    /// Exclusive expiry, Unix seconds; none keeps the share until revoked.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// The born-with text that travels: `prompt`, `why`, `keep`,
    /// `intent_prompt`. None sends a brief's default, which is nothing.
    #[serde(default)]
    pub travel: Option<TravelChoice>,
    /// The saved mention `recipient` came from, when the agent named the
    /// person (OF-123): the share refuses while it is unsettled, so settle it
    /// with `self.identity.settle` first.
    #[serde(default)]
    pub mention: Option<crate::outbound::MentionProvenance>,
}

/// `vault.shares.create`'s answer: the admitted share and what travels with
/// it, fixed in the transaction that admitted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareCreated {
    pub share_id: String,
    pub recipient: String,
    pub brief_ref: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub travel: TravelChoice,
}

/// `vault.shares.create` on a handle: the handle's actor issues the share.
pub fn create_share_as_caller(
    memory: &Memory<'_>,
    input: ShareCreateRequest,
) -> MemoryResult<ShareCreated> {
    let id = |field: &str, value: &str| {
        EntityId::from_hex(value)
            .map_err(|_| MemoryError::bad_request(format!("{field} must be a 32-hex entity id")))
    };
    let refs = |field: &str, values: &[String]| {
        values
            .iter()
            .map(|value| id(field, value.as_str()))
            .collect::<MemoryResult<BTreeSet<_>>>()
    };
    let share_id = match input.share_id.as_deref() {
        Some(share_id) => id("share_id", share_id)?,
        None => EntityId::now(),
    };
    let share = Share {
        recipient_ref: id("recipient", input.recipient.as_str())?,
        brief_ref: input.brief_ref,
        world_refs: refs("world_refs", &input.world_refs)?,
        facet_refs: refs("facet_refs", &input.facet_refs)?,
        include_unscoped: input.include_unscoped,
        status: AccessGrantStatus::Active,
        created_at: memory.vault().store.clock.now_recorded_at(),
        revoked_at: None,
        expires_at: input.expires_at,
        mention: input.mention,
    };
    let travel = TravelChoice::or_default(input.travel.as_ref(), TravelKind::Brief);
    let issuer = WriteActor::new(memory.actor(), memory.actor_class());
    memory
        .vault()
        .create_share_travelling(&share_id, &issuer, &share, &travel)?;
    Ok(ShareCreated {
        share_id: share_id.to_hex(),
        recipient: share.recipient_ref.to_hex(),
        brief_ref: share.brief_ref,
        created_at: share.created_at,
        expires_at: share.expires_at,
        travel,
    })
}
