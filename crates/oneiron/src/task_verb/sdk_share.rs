//! `vault.shares.create`: the caller shares one stored brief with one
//! recipient and chooses which born-with text travels with it (OF-491). The
//! door is [`crate::Vault::create_share_travelling`]. The issuer is the
//! handle's own actor, never request data, and the share lands only after
//! the Gate records an allowing external-effect decision pinned to exactly
//! this share id, recipient, scope and travel choice. A pending or denied
//! decision is durable and creates no grant; once the owner approves it, the
//! same request with the same `share_id` lands it.
//!
//! `vault.shares.revoke` stops a share at once: the door is
//! [`crate::Vault::revoke_share`], the revoker is the handle's own actor, and
//! only the share's issuer or the vault's live owner may stop it.
//! `vault.shares.view` opens a shared brief for its recipient through
//! [`crate::Vault::render_shared_brief`]: the viewer is the handle's own
//! actor and reads under its own scoped read, so a share that does not
//! resolve for it and a missing one answer the same `None`.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::access_grant::AccessGrantStatus;
use crate::claim::ScopedReadResult;
use crate::error::RecordError;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::receipt::{ShareRevokeReceipt, SharedBriefView};
use crate::share::{Share, ShareViewerScope};
use crate::share_travel::{TravelChoice, TravelKind};
use crate::{EntityId, Error, WriteActor};

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

/// `vault.shares.revoke`'s input: the share to stop.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareRevokeRequest {
    /// The share's id, as 32 hex: the `share_id` `vault.shares.create`
    /// answered.
    pub share_ref: String,
}

/// A viewer's own narrowing of a shared brief. It only takes away: the view
/// shows what the share's maximum, this narrowing and the viewer's live
/// authority all admit. A dimension left empty here shows nothing of it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareViewNarrowing {
    /// The WORLDs to keep, as 32 hex each.
    #[serde(default)]
    pub world_refs: Vec<String>,
    /// The FACETs to keep, as 32 hex each.
    #[serde(default)]
    pub facet_refs: Vec<String>,
    /// Whether an unscoped dimension may still pass.
    #[serde(default)]
    pub include_unscoped: bool,
}

/// `vault.shares.view`'s input: the share to open, and an optional
/// narrowing. The viewer is never named here: it is the caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareViewRequest {
    /// The share's id, as 32 hex.
    pub share_ref: String,
    #[serde(default)]
    pub narrowing: Option<ShareViewNarrowing>,
}

/// The engine's refusal of a revoker who is neither the issuer nor the live
/// owner ([`crate::Vault::revoke_share`]).
const SHARE_REVOKE_REFUSAL: &str = "share revocation requires issuer or owner";

/// `vault.shares.revoke` on a handle: the handle's actor stops the share, at
/// the vault clock's now. A share already revoked answers unchanged.
pub fn revoke_share_as_caller(
    memory: &Memory<'_>,
    input: ShareRevokeRequest,
) -> MemoryResult<ShareRevokeReceipt> {
    let share_id = share_ref(&input.share_ref)?;
    let actor = WriteActor::new(memory.actor(), memory.actor_class());
    let revoked_at = memory.vault().store.clock.now_recorded_at();
    let share = memory
        .vault()
        .revoke_share(&share_id, &actor, revoked_at)
        .map_err(|error| match error {
            // A caller who may not stop the share and one who names none
            // hear the same refusal, so a revoke never proves a share exists.
            Error::Record(RecordError::InvalidAccessGrantBody(SHARE_REVOKE_REFUSAL))
            | Error::EntityNotFound => MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("vault.shares.revoke: {SHARE_REVOKE_REFUSAL}"),
                &[
                    "Revoke as the share's issuer, or as the vault's live owner, naming the share_id vault.shares.create answered.",
                ],
            ),
            error => MemoryError::from(error),
        })?;
    Ok(ShareRevokeReceipt {
        share_ref: share_id.to_hex(),
        status: share.status.as_str().to_owned(),
        revoked_at: share.revoked_at,
    })
}

/// `vault.shares.view` on a handle: the handle's actor opens the shared
/// brief under its own scoped read. `None` is a share that does not resolve
/// for this viewer, or none at all.
pub fn view_shared_brief_as_caller(
    memory: &Memory<'_>,
    input: ShareViewRequest,
) -> MemoryResult<ScopedReadResult<Option<SharedBriefView>>> {
    let share_id = share_ref(&input.share_ref)?;
    let narrowing = input
        .narrowing
        .as_ref()
        .map(|narrowing| -> MemoryResult<ShareViewerScope> {
            Ok(ShareViewerScope {
                world_refs: entity_refs("narrowing.world_refs", &narrowing.world_refs)?,
                facet_refs: entity_refs("narrowing.facet_refs", &narrowing.facet_refs)?,
                include_unscoped: narrowing.include_unscoped,
            })
        })
        .transpose()?;
    render_shared_brief(memory, &share_id, narrowing.as_ref())
}

/// The shared brief, rendered under the viewer's own read lane and frame.
#[cfg(feature = "sync")]
fn render_shared_brief(
    memory: &Memory<'_>,
    share_id: &EntityId,
    narrowing: Option<&ShareViewerScope>,
) -> MemoryResult<ScopedReadResult<Option<SharedBriefView>>> {
    let read = memory.read_lane(crate::claim::ClaimReadStatus::Surfaceable)?;
    let frame = viewer_frame(&read)?;
    let rendered = memory
        .vault()
        .render_shared_brief(*share_id, memory.actor(), narrowing, &frame, &read)?;
    Ok(rendered.map(|view| view.map(|view| SharedBriefView::project(share_id, view))))
}

/// A build without the sync feature renders no brief.
#[cfg(not(feature = "sync"))]
fn render_shared_brief(
    _memory: &Memory<'_>,
    _share_id: &EntityId,
    _narrowing: Option<&ShareViewerScope>,
) -> MemoryResult<ScopedReadResult<Option<SharedBriefView>>> {
    Err(MemoryError::new(
        crate::memory::MEMORY_CODE_INVALID_STATE,
        "vault.shares.view renders a brief, which a build without the sync feature cannot",
        &["Open the share on a server, or on a build with the sync feature."],
    ))
}

/// The frame of the viewer's own selected key: an agent's task, else a
/// person's view, as the default projection builds one. Nothing broadens it.
#[cfg(feature = "sync")]
fn viewer_frame(
    read: &crate::claim::ScopedRead<'_>,
) -> crate::Result<crate::lens::LensRenderFrame> {
    use crate::edge::EdgeActorClass;
    use crate::lens::{LensPrincipalBinding, LensRenderFrame, LensRenderId};

    let key = read.actor_key().clone();
    let principal_ref = key.actor_ref().to_owned();
    let principal = if key.actor_class() == Some(EdgeActorClass::Agent.gate_actor_class()) {
        LensPrincipalBinding::agent_task(principal_ref, key.clone(), vec![key])?
    } else {
        LensPrincipalBinding::human_view(principal_ref, key.clone(), vec![key])?
    };
    let render_id = LensRenderId::new(format!("shared-brief-{}", EntityId::now().to_hex()))?;
    Ok(LensRenderFrame::new(render_id, principal))
}

fn share_ref(value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value)
        .map_err(|_| MemoryError::bad_request("share_ref must be a 32-hex entity id"))
}

fn entity_refs(field: &str, values: &[String]) -> MemoryResult<BTreeSet<EntityId>> {
    values
        .iter()
        .map(|value| {
            EntityId::from_hex(value)
                .map_err(|_| MemoryError::bad_request(format!("{field} must be 32-hex entity ids")))
        })
        .collect()
}
