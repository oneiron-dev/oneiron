//! A carrier its window binds with a body reference (FIX 5489, FIX 3911):
//! the ladder reads it as the ASSET body the reference names, never as the
//! manifest bytes it holds.
//!
//! The body is here when the stored row holds it, inline or in its file,
//! under the carrier's header: an echo, skipped. It came when the window's
//! body transfer staged it for this carrier ([`IngestCtx::with_asset_body`]):
//! it lands through the replicated staged door, as any replicated ASSET
//! lands. Else the step is [`EntityStep::Pending`]: nothing is written, the
//! stored row stays as it is, and no birth, delivery or dependent row is
//! discharged until the body comes.

use super::{EntityStep, IngestCtx};
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DeletionMarker, TombstoneStoreRead as _};
use crate::store::StagedAssetBody;
use crate::sync::asset_body::ref_echo_equal;
use crate::sync::asset_body::references::{AssetBodyRef, bound_in};
use crate::sync::client::ImportTier;
use crate::temporal::TimeRange;

impl<'a> IngestCtx<'a> {
    /// Lands `staged`, the body a transfer received for the carrier of `id`
    /// its window binds, where the ladder would leave that carrier pending.
    pub(in crate::sync) fn with_asset_body(
        mut self,
        id: EntityId,
        staged: &'a StagedAssetBody,
    ) -> Self {
        self.asset_body = Some((id, staged));
        self
    }

    /// The staged body for `id`, when it is the one `body` names.
    fn staged_for(&self, id: &EntityId, body: &AssetBodyRef) -> Option<&'a StagedAssetBody> {
        self.asset_body
            .filter(|(staged_id, staged)| staged_id == id && staged.facts() == body.facts())
            .map(|(_, staged)| staged)
    }
}

/// The reference the window binds `blob`, the carrier of `id`, with: `None`
/// outside a window, while the file plane is off, and for an ordinary inline
/// body.
pub(super) fn bound(ctx: &IngestCtx<'_>, id: &EntityId, blob: &[u8]) -> Option<AssetBodyRef> {
    bound_in(ctx.carrier_doc()?, id, blob)
}

/// H125 for a body that moves by reference: the fence a release left on `id`
/// lifts only for the body a transfer staged and verified, never for the
/// digest a peer offered. The staged body is read whole only under a fence.
///
/// # Errors
///
/// Storage errors, and the staged body's read error.
pub(super) fn readmit_staged(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &AssetBodyRef,
) -> Result<()> {
    let Some(staged) = ctx.staged_for(id, body) else {
        return Ok(());
    };
    if !ctx
        .vault
        .store
        .port_deletion_marked(wtxn, DeletionMarker::RowFence, id)?
    {
        return Ok(());
    }
    crate::blob_artifact::readmit_held_asset_in_txn(&ctx.vault.store, wtxn, id, &staged.to_vec()?)
}

/// Whether `local`, the row stored at `id`, is the body `body` names under
/// `blob`'s header. `false` without a reference.
///
/// # Errors
///
/// [`ref_echo_equal`]'s errors.
pub(super) fn echo(
    ctx: &IngestCtx<'_>,
    wtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: Option<&AssetBodyRef>,
    local: &[u8],
    blob: &[u8],
) -> Result<bool> {
    match body {
        Some(body) => ref_echo_equal(&ctx.vault.store, wtxn, id, body, local, blob),
        None => Ok(false),
    }
}

/// The carrier's last rung: the staged body lands as `id`'s row under the
/// carrier's header, through the replicated door at the tier every window
/// put takes; with no staged body the carrier waits, pending.
///
/// # Errors
///
/// The replicated door's errors.
pub(super) fn land(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    header: &EntityMetadataHeader,
    body: &AssetBodyRef,
) -> Result<EntityStep> {
    let Some(staged) = ctx.staged_for(&id, body) else {
        return Ok(EntityStep::Pending);
    };
    let occurred = TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    // The window's savepoint stamps the carried birth once the row is live.
    ctx.vault.put_replicated_asset_body_in_txn(
        wtxn,
        &id,
        occurred,
        header.learned_at,
        staged,
        ImportTier::OwnDevice,
        None,
    )?;
    Ok(EntityStep::Materialized(id))
}
