//! FIX 3677: a live row's body as the whole-vault snapshot reads it. A row
//! is read where the snapshot holds it, never copied for the serializer. A
//! file-plane ASSET's stored file that the archive attaches as it is goes
//! out as it streams, read under the snapshot and checked to its end; one a
//! probe of the snapshot needs whole is read whole, as every body was.

use std::borrow::Cow;
use std::io::{self, Read};

use heed::RoTxn;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_NOTE};
use crate::store::AssetFileManifest;

/// A live row's body as the serializer takes it.
pub(crate) enum ExportSnapshotEntityBody<'t> {
    /// Its bytes: the row's own, borrowed from the snapshot, or projected.
    Bytes(Cow<'t, [u8]>),
    /// A file-plane ASSET's stored file, which the archive attaches as it is.
    File(ExportSnapshotFile),
}

/// A file-plane ASSET's stored file, open under the snapshot that found its
/// manifest: `bytes` long with BLAKE3 `blake3`, each checked as `reader`
/// reads its end.
pub(crate) struct ExportSnapshotFile {
    pub(crate) bytes: u64,
    pub(crate) blake3: [u8; 32],
    pub(crate) reader: Box<dyn Read>,
}

/// One live row's body as the snapshot's probes read it.
pub(super) enum RowBody<'t> {
    /// The body's bytes past the row's header: borrowed from the snapshot,
    /// or a file-plane ASSET's read whole.
    Bytes(Cow<'t, [u8]>),
    /// A file-plane ASSET's manifest, whose stored file the archive attaches
    /// as it is: no adapter's body, so each probe passes it unread.
    File(AssetFileManifest),
}

impl RowBody<'_> {
    /// The bytes a probe reads; none for a stored file the archive attaches.
    pub(super) fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::File(_) => None,
        }
    }

    /// The body as the serializer takes it. The entity-document head owns
    /// committed text after migration or stream finalization; the row then
    /// holds only a pointer. It is projected under this snapshot transaction
    /// before the NOTE-specific document and the serializer's unconditional
    /// credential nulling; a row with no head is read as it is, borrowed. In
    /// base mode there are no EntityDoc heads to resolve. A stored file the
    /// archive attaches has no head, and goes open to stream.
    ///
    /// # Errors
    ///
    /// The projection's errors, and a stored file that does not open.
    pub(super) fn projected(
        &self,
        vault: &Vault,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
    ) -> Result<ExportSnapshotEntityBody<'_>> {
        let row: &[u8] = match self {
            Self::Bytes(row) => row,
            Self::File(manifest) => {
                return Ok(ExportSnapshotEntityBody::File(ExportSnapshotFile {
                    bytes: manifest.facts.len,
                    blake3: manifest.facts.blake3,
                    reader: Box::new(vault.admitted_asset_file_in_txn(rtxn, manifest)?),
                }));
            }
        };
        #[cfg(feature = "sync")]
        if crate::entity_doc::has_record_head(&vault.store, rtxn, id)? {
            let resolved = crate::entity_doc::resolve_record_body(&vault.store, rtxn, id, row)?;
            let body = note_body(vault, rtxn, id, entity_type, &resolved)?.into_owned();
            return Ok(ExportSnapshotEntityBody::Bytes(Cow::Owned(body)));
        }
        note_body(vault, rtxn, id, entity_type, row).map(ExportSnapshotEntityBody::Bytes)
    }
}

/// Historical/archive-only NOTE rows may intentionally carry a different
/// body. Only the NOTE codec's live rows use its editor.
fn note_body<'b>(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &'b [u8],
) -> Result<Cow<'b, [u8]>> {
    if entity_type == ENTITY_TYPE_NOTE
        && crate::note::decode_note_body_using(body, crate::note::NoteKind::wire).is_ok()
    {
        return crate::note::live_body_in_txn(&vault.store, rtxn, id, entity_type, body);
    }
    Ok(Cow::Borrowed(body))
}

/// Live row `id`'s body, `raw` as the snapshot holds it, header included.
/// An archive (`attaches_files`) carries a file-plane ASSET's stored file
/// as it streams when no probe needs it whole: no entity-document head
/// projects it, the archive attaches it as it is
/// ([`crate::serialize::attaches_as_file`], judged as it streams), and it
/// opens no JSON object or array, so no birth source is it. Any other
/// file-plane ASSET is read whole, as every body was.
///
/// # Errors
///
/// A manifest its descriptor disagrees with, a stored file that does not
/// read back as its manifest names it, and storage errors.
pub(super) fn row_body<'t>(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    raw: Cow<'t, [u8]>,
    attaches_files: bool,
) -> Result<RowBody<'t>> {
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if entity_type == ENTITY_TYPE_ASSET
        && let Some(manifest) = crate::store::asset_file_in_txn(&vault.store, rtxn, id, body)?
    {
        #[cfg(feature = "sync")]
        let headed = crate::entity_doc::has_record_head(&vault.store, rtxn, id)?;
        #[cfg(not(feature = "sync"))]
        let headed = false;
        if attaches_files && !headed && plain_file(vault, rtxn, &manifest)? {
            return Ok(RowBody::File(manifest));
        }
        let body = vault.asset_file_body(rtxn, &manifest)?;
        return Ok(RowBody::Bytes(Cow::Owned(body)));
    }
    Ok(RowBody::Bytes(match raw {
        Cow::Borrowed(raw) => Cow::Borrowed(&raw[ENTITY_METADATA_HEADER_LEN..]),
        Cow::Owned(mut raw) => Cow::Owned(raw.split_off(ENTITY_METADATA_HEADER_LEN)),
    }))
}

/// Whether a stored file is one the archive attaches as it is and no birth
/// source: the serializer's file test, judged as the file streams, and no
/// JSON object or array, which the birth-source codec's marker needs (its
/// first byte past JSON whitespace opens neither).
fn plain_file(vault: &Vault, rtxn: &RoTxn<'_>, manifest: &AssetFileManifest) -> Result<bool> {
    vault.with_admitted_asset_file_in_txn(rtxn, manifest, |body| {
        let mut body = JsonLead { body, lead: None };
        let attaches = crate::serialize::attaches_as_file_read(ENTITY_TYPE_ASSET, &mut body)?;
        Ok(attaches && !matches!(body.lead, Some(b'{' | b'[')))
    })
}

/// A reader that notes the first byte past JSON whitespace it passes on.
struct JsonLead<'r> {
    body: &'r mut dyn Read,
    lead: Option<u8>,
}

impl Read for JsonLead<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.body.read(out)?;
        if self.lead.is_none() {
            self.lead = out[..read]
                .iter()
                .copied()
                .find(|&byte| !matches!(byte, b' ' | b'\n' | b'\t' | b'\r'));
        }
        Ok(read)
    }
}

/// Whether an ASSET body leaves the entity rows: an archived receipt source
/// or a skill's source carrier, which another section is folded from, or a
/// birth source the archive does not carry. A stored file the archive
/// attaches is none of them.
///
/// # Errors
///
/// A malformed source carrier, and the birth source's read errors.
pub(super) fn asset_folded(vault: &Vault, rtxn: &RoTxn<'_>, body: &RowBody<'_>) -> Result<bool> {
    let Some(body) = body.bytes() else {
        return Ok(false);
    };
    Ok(crate::receipt::is_receipt_archive_source(body)
        || crate::skill_hub::decode_source_carrier(body)?.is_some()
        || !crate::agent_def::birth_source_exportable(&vault.store, rtxn, body)?)
}

/// Whether row `id`, which this snapshot holds and whose header has parsed,
/// is live: the verdict [`crate::vault::live_entity_row_in_txn`] gives it,
/// read without that door's copy of the body.
///
/// # Errors
///
/// The deletion state's read errors.
pub(super) fn row_live_in_txn(
    store: &crate::store::Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let state = crate::ports::TombstoneStoreRead::port_deletion_state(store, rtxn, id)?;
    Ok(!state.deleted && !state.stale)
}
