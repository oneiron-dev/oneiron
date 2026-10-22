//! A window blob as it persists here (KS-5, FIX 7107): its pad rows as their
//! bare references, the form a `u:` row, a `d:` snapshot and an image keep,
//! when current custody here holds every pad they reference live, so a send
//! that goes as the carrier inflates them back from custody (`inflate`).
//! The projector keeps op ids, deps, versions, frontiers, every historical
//! insert and the shallow root; no root metadata is touched.
//!
//! KEEP TODAY (Engine 10-22): a blob the projector does not take, one held
//! where no custody is bound, or one naming a pad custody here does not hold
//! live persists as it is, warned value-free. Nothing is refused, held or
//! waited on for it.

use std::borrow::Cow;

use loro::LoroDoc;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::store::WorldPadCustody;
use crate::sync::types::WindowKey;
use crate::world_keys::{
    WindowPadProjection, image_pad_row_of, project_window_pad_refs, projected_pad_row_equal,
};

/// What a window blob persists as here.
pub(crate) enum PersistedWindowPads<'a> {
    /// Its pad rows as their bare references.
    ByReference(Vec<u8>),
    /// As it is: a window of no world, or a blob that holds no pad row.
    AsIs(&'a [u8]),
    /// As it is for a fault (KEEP TODAY), with its value-free reason.
    Kept(&'a [u8], &'static str),
}

/// `blob`, window `window`'s snapshot, shallow snapshot or update, as it
/// persists here: reference-only when it holds a pad row and current custody
/// here holds every pad it references live; any other blob as it is, a fault
/// told by its reason. `context` is a document holding an update's
/// dependencies (the projector copies it).
pub(crate) fn persisted_window_pads_form<'a>(
    vault: &Vault,
    window: &WindowKey,
    blob: &'a [u8],
    context: Option<&LoroDoc>,
) -> PersistedWindowPads<'a> {
    // A live pad rides its world's windows alone (`types::entity_world`).
    if window.world().is_none() {
        return PersistedWindowPads::AsIs(blob);
    }
    let namespace = vault.store.world_pad_namespace();
    let hint = namespace.unwrap_or_default();
    let (bytes, required) = match project_window_pad_refs(window, blob, context, &hint) {
        Ok(WindowPadProjection::NothingToProject) => return PersistedWindowPads::AsIs(blob),
        Ok(WindowPadProjection::Projected {
            bytes,
            required_refs,
        }) => (bytes, required_refs),
        Err(_) => return PersistedWindowPads::Kept(blob, "projection fault"),
    };
    if namespace.is_none() {
        return PersistedWindowPads::Kept(blob, "no current custody here");
    }
    for reference in &required {
        // Only a pad custody holds live is proven here; a lookup that
        // faults proves nothing.
        match vault
            .store
            .world_pad_custody_entry(&reference.key.envelope_key_id())
        {
            Ok(WorldPadCustody::Live(_)) => {}
            Ok(WorldPadCustody::Missing | WorldPadCustody::Closed | WorldPadCustody::Retired) => {
                return PersistedWindowPads::Kept(blob, "a pad it references is not live here");
            }
            Err(_) => return PersistedWindowPads::Kept(blob, "custody fault"),
        }
    }
    PersistedWindowPads::ByReference(bytes)
}

/// [`persisted_window_pads_form`] as the bytes a `u:` row or a `d:`
/// snapshot persists, a blob kept as it is for a fault warned value-free.
pub fn persisted_window_pads<'a>(
    vault: &Vault,
    window: &WindowKey,
    blob: &'a [u8],
    context: Option<&LoroDoc>,
) -> Cow<'a, [u8]> {
    match persisted_window_pads_form(vault, window, blob, context) {
        PersistedWindowPads::ByReference(bytes) => Cow::Owned(bytes),
        PersistedWindowPads::AsIs(blob) => Cow::Borrowed(blob),
        PersistedWindowPads::Kept(blob, why) => {
            tracing::warn!(%window, why, "window blob persists as today, not by reference");
            Cow::Borrowed(blob)
        }
    }
}

/// Whether `held`, the row a window document holds at `id`, already is
/// `row`: the same bytes, or the same pad row in another form, compared as
/// both persist (`projected_pad_row_equal`: a carrier and a bare reference of
/// one key are one row). It says nothing of custody.
pub(in crate::sync::window) fn window_row_holds(
    id: &EntityId,
    held: Option<&[u8]>,
    row: &[u8],
) -> bool {
    let Some(held) = held else {
        return false;
    };
    held == row
        || (image_pad_row_of(held).is_some()
            && projected_pad_row_equal(id, held, row, &[0; 16]).unwrap_or(false))
}
