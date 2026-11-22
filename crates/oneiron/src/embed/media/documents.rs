//! Stored documents: whether a space holds one already, whether a record type
//! is a text document, the text of a text ASSET, the egress gate a pass reads
//! through, and whether stored bytes or rows may leave this device.

use super::*;

impl Vault {
    /// Whether `input`'s bytes may go to `embedder` now, as the backfill sends a stored document
    /// (FIX 382): to a model on this device, always; to one on the owner's server, always with
    /// no gate and otherwise as a third party's (FIX 9830); to one at a third
    /// party only with the host's gate `egress`, which must allow it, and only while no
    /// device-local world keeps it (DEC-0005), read under the flag lock right before the bytes
    /// go. A move's check asks it for each media query it encodes (FIX 1637); `false` sends
    /// nothing, and that probe does not run.
    ///
    /// # Errors
    ///
    /// Storage errors reading the world flags or the row.
    pub fn media_document_may_leave(
        &self,
        embedder: &dyn MediaEmbedder,
        egress: Option<&dyn EgressPredicate>,
        input: &MediaEmbeddingInput<'_>,
    ) -> Result<bool> {
        // One on the owner's server reads through the host's gate when it
        // gives one, as its backfill does (FIX 9830), and leaves ungated with
        // none.
        let gate = match (embedder.locality(), egress) {
            (EmbedderLocality::OnDevice, _) | (EmbedderLocality::OwnerServer, None) => {
                return Ok(true);
            }
            (EmbedderLocality::ThirdParty, None) => return Ok(false),
            (EmbedderLocality::OwnerServer | EmbedderLocality::ThirdParty, Some(egress)) => egress,
        };
        if gate.decide_media(input) != EgressDecision::Allow {
            return Ok(false);
        }
        self.media_rows_may_leave(None, input.source_rows(), &embedder.endpoint())
    }

    /// Whether every row of `rows` may leave this device now, as `session`'s room reads them,
    /// or base with none: none is one a device-local world keeps (DEC-0005), or whose world
    /// cannot be read while one is flagged. Read under the flag lock right before the bytes
    /// go, and held across no send.
    pub(crate) fn media_rows_may_leave(
        &self,
        session: Option<&OffRecordSession<'_>>,
        rows: &[EntityId],
        destination: &crate::settings::ReadDestination,
    ) -> Result<bool> {
        #[cfg(feature = "sync")]
        let _acceptance = self.device_only_acceptance();
        let rtxn = self.store.env.read_txn()?;
        let flagged = crate::settings::device_local_worlds_for(self, &rtxn, destination)?;
        if flagged.is_empty() {
            return Ok(true);
        }
        let kept = match session {
            None => any_kept_in(&self.store, &rtxn, &flagged, rows)?,
            Some(session) => any_kept_in(&session.read_view()?, &rtxn, &flagged, rows)?,
        };
        Ok(!kept)
    }
}

/// Whether `space`, as `store` reads it, holds `document`'s vector already, a text document's
/// of its current text.
pub(in crate::embed) fn media_held_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    space: &EmbeddingSpace,
    document: &PendingMedia,
) -> Result<bool> {
    match document.text_hash {
        Some(hash) => Ok(media_text_hash_in_txn(store, txn, space, &document.id)? == Some(hash)),
        None => has_media_vector_in_txn(store, txn, space, &document.id),
    }
}

/// Whether record type `entity_type` is one a text-bound space holds as a document.
pub(in crate::embed) fn is_text_document_type(entity_type: u8) -> bool {
    TEXT_DOCUMENT_TYPES.contains(&entity_type)
}

/// The host's gate a pass with `embedder` reads through: a third-party embedder's must be
/// there, or the pass is refused as it was before the gate; one on the owner's server reads
/// through the gate the host gives, or ungated with none (FIX 9830); one on this device reads
/// ungated.
pub(in crate::embed) fn media_egress_for<'a>(
    embedder: &dyn MediaEmbedder,
    egress: Option<&'a dyn EgressPredicate>,
) -> Result<Option<&'a dyn EgressPredicate>> {
    match embedder.locality() {
        EmbedderLocality::OnDevice => Ok(None),
        EmbedderLocality::OwnerServer => Ok(egress),
        EmbedderLocality::ThirdParty => egress.map(Some).ok_or_else(|| {
            Error::InvalidConfig(
                "a third-party media embedder has no egress grant for stored media".into(),
            )
        }),
    }
}

/// The UTF-8 content of a text ASSET, shared by both embedding workers: the
/// bytes of the blob its body names (FIX 9949), `read` reading one stored
/// row's body by id in the caller's own snapshot.
pub(in crate::embed) fn asset_text(
    body: &[u8],
    read: impl FnOnce(&EntityId) -> Result<Option<Vec<u8>>>,
) -> Result<Option<String>> {
    let Some((mime, bytes)) = crate::memory::asset_media_in(body, read)? else {
        return Ok(None);
    };
    if !mime.starts_with("text/") {
        return Ok(None);
    }
    Ok(String::from_utf8(bytes)
        .ok()
        .filter(|text| text.chars().any(|c| !c.is_whitespace() && !c.is_control())))
}
