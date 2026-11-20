//! Door to the text the generic publication paths index for a stored CLAIM
//! (FIX REACTION-GENERIC-INDEX-TEXT-REACTOR-ID). The idle publication pass and
//! a room restage publish a row whose live revision moved past its indexed one
//! with no text staged, a later revision of a reaction among them, through
//! `publication_text_fields`; a birth is indexed as it is written, as
//! `Vault::react` stages its glyph. This door runs that step over a stored
//! CLAIM's live revision, so a test reads what those paths would index for it.

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;
use crate::vault::entity_revision::{
    ReadMode, publication_text_fields, read_entity_revision_in_txn, revision_for_mode_in_txn,
};

/// The `(field, text)` pairs the idle publication pass indexes for CLAIM `id`
/// at its live revision, or `None` when the claim is not surfaceable and
/// publishes nothing.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when `id` has no live revision, or the read's own.
pub fn published_claim_text(vault: &Vault, id: EntityId) -> Result<Option<Vec<(String, String)>>> {
    let txn = vault.store.env.read_txn()?;
    let live = revision_for_mode_in_txn(&vault.store, &txn, &id, ReadMode::Live)?
        .ok_or(Error::EntityNotFound)?;
    let raw = read_entity_revision_in_txn(vault, &txn, &id, ReadMode::Live)?
        .ok_or(Error::EntityNotFound)?;
    let entity_type = *raw.first().ok_or(Error::EntityNotFound)?;
    publication_text_fields(
        &vault.store,
        &txn,
        &id,
        live,
        entity_type,
        &raw[ENTITY_METADATA_HEADER_LEN..],
    )
}
