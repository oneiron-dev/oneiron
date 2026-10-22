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

/// A blob that persists as today for a fault, told value-free.
fn keep<'a>(window: &WindowKey, blob: &'a [u8], why: &'static str) -> Cow<'a, [u8]> {
    tracing::warn!(%window, why, "window blob persists as today, not by reference");
    Cow::Borrowed(blob)
}

/// `blob`, window `window`'s snapshot, shallow snapshot or update, as it
/// persists here: reference-only when it holds a pad row and current custody
/// here holds every pad it references live; any other blob as it is.
/// `context` is a document holding an update's dependencies (the projector
/// copies it).
pub fn persisted_window_pads<'a>(
    vault: &Vault,
    window: &WindowKey,
    blob: &'a [u8],
    context: Option<&LoroDoc>,
) -> Cow<'a, [u8]> {
    // A live pad rides its world's windows alone (`types::entity_world`).
    if window.world().is_none() {
        return Cow::Borrowed(blob);
    }
    let namespace = vault.store.world_pad_namespace();
    let hint = namespace.unwrap_or_default();
    let (bytes, required) = match project_window_pad_refs(window, blob, context, &hint) {
        Ok(WindowPadProjection::NothingToProject) => return Cow::Borrowed(blob),
        Ok(WindowPadProjection::Projected {
            bytes,
            required_refs,
        }) => (bytes, required_refs),
        Err(error) => {
            tracing::warn!(%window, kind = ?error.kind(), "window blob not projected");
            return keep(window, blob, "projection fault");
        }
    };
    if namespace.is_none() {
        return keep(window, blob, "no current custody here");
    }
    for reference in &required {
        match vault
            .store
            .world_pad_custody_entry(&reference.key.envelope_key_id())
        {
            Ok(WorldPadCustody::Live(_)) => {}
            Ok(WorldPadCustody::Missing | WorldPadCustody::Closed | WorldPadCustody::Retired) => {
                return keep(
                    window,
                    blob,
                    "a pad it references is not live in custody here",
                );
            }
            Err(error) => {
                tracing::warn!(%window, kind = ?error.kind(), "window pad custody not read");
                return keep(window, blob, "custody fault");
            }
        }
    }
    Cow::Owned(bytes)
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
