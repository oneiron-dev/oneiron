//! The shape every core entity write shares: its id, its interval, its
//! announcement-normalized body and its text index. The REST create routes
//! and the `vault.conversations.*` and `vault.batch` rows stage through
//! these, so one rule set holds for both callers.

use serde_json::Value;

use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::{BatchBuilder, EntityId, Vault};

pub use oneiron_store::core_write::shape::*;

/// The engine side of [`AnnouncementAuthority`]: an actor's authority, read
/// from the vault.
pub(crate) trait ActorAnnouncementAuthority: Sized {
    /// An actor-bound write's authority: the owner's while `actor` is a live
    /// owner of `vault`, read now.
    /// # Errors
    /// Storage errors.
    fn of_actor(vault: &Vault, actor: &EntityId) -> crate::Result<Self>;
}

impl ActorAnnouncementAuthority for AnnouncementAuthority {
    fn of_actor(vault: &Vault, actor: &EntityId) -> crate::Result<Self> {
        Ok(if vault.is_live_owner_person(actor)? {
            Self::Owner
        } else {
            Self::Writer
        })
    }
}

/// Stages one entity put, and its text index, on `batch`.
/// # Errors
/// A body that does not encode, or a scope summary's body.
pub fn stage_core_put<'a, 't>(
    batch: BatchBuilder<'a>,
    id: &EntityId,
    entity_type: u8,
    times: CoreWriteTimes,
    body: &Value,
    announcement: AnnouncementAuthority,
    text: Option<impl IntoIterator<Item = (&'t str, &'t str)>>,
) -> Result<BatchBuilder<'a>, CoreWriteRefusal> {
    let body = core_body_for_write(entity_type, body, announcement);
    let data = encode_core_body(&body)?;
    // ARCH-0006a: only the Dreamer writes a scope summary's body. A caller
    // declares the scope; it never puts the body through a generic write.
    if entity_type == ENTITY_TYPE_SUMMARY
        && crate::scope_summary::decode_scope_summary_body(&data).is_ok()
    {
        return Err(CoreWriteRefusal::ScopeSummary);
    }
    let mut batch = batch.put(id, entity_type, times.occurred, times.learned_at, &data);
    let text_fields = core_text_pairs(text, &body);
    if !text_fields.is_empty() {
        let refs: Vec<(&str, &str)> = text_fields
            .iter()
            .map(|(field, value)| (field.as_str(), value.as_str()))
            .collect();
        batch = batch.text(id, &refs);
    }
    Ok(batch)
}
