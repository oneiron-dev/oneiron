//! Body instances an archive import's File ASSETs and receipt sources may
//! spill into, minted before its one write transaction opens. File rows past
//! the inline bound and preserved receipt sources each reserve one. Receipt
//! canonical bytes depend on the mapped holder inside the writer, so their
//! count is an upper bound; skipped, duplicate and inline sources leave
//! unused instances as debris. No instance is minted inside the writer.
//! The values custody holds are read in the writer itself (FIX 5395).

use std::io::{Read, Seek};
use std::sync::Arc;

use super::archive_index::{FLAG_FILE, IndexedArchive, Section, Tag};
use super::{ArchiveRecordKind, ExportDerivationEnvelope, ExportReceiptSource};
use crate::Vault;
use crate::error::Result;
use crate::serialize::ExportBody;
use crate::store::BodyMint;

/// What the import's ASSET files and receipt sources stage through: the body
/// instances minted for them, and the values custody holds, each `None`
/// while the file plane is off.
pub(super) struct ArchiveAssets {
    pub(super) mint: Option<BodyMint>,
    pub(super) known: Option<Arc<crate::store::known_value_index::KnownValues>>,
}

/// The instances `archive`'s ASSETs may spill into, minted before its writer:
/// one for each File row past [`crate::store::ASSET_INLINE_BODY_BYTES`] and
/// an upper bound for preserved receipt sources. Unavailable sources have
/// only a fixed-width receipt id and a unit reason, so remain inline.
/// `None` while the file plane is off.
///
/// # Errors
///
/// The row index's and custody's errors.
pub(super) fn reserved_asset_mint<R: Read + Seek>(
    vault: &Vault,
    archive: &IndexedArchive<'_, R>,
) -> Result<Option<BodyMint>> {
    if !crate::store::ASSET_FILE_PLANE {
        return Ok(None);
    }
    let mut count = 0_usize;
    let mut after = None;
    while let Some((id, at)) = archive.next_entity(after.as_ref())? {
        if at.section == Section::Ledger
            && at.has(FLAG_FILE)
            && !archive.index.contains(Tag::Omitted, id.as_bytes())?
            && let ExportBody::File(file) = archive.entity_row(&at)?.body
            && file.bytes() > crate::store::ASSET_INLINE_BODY_BYTES
        {
            count = count.saturating_add(1);
        }
        after = Some(id);
    }
    // Canonical bytes depend on the mapped holder inside the writer. Reserve
    // an upper bound here; skipped, duplicate and inline sources leave debris.
    let mut envelopes = archive.spool.rows(ArchiveRecordKind::DerivationEnvelope);
    while let Some((_, envelope)) =
        envelopes.next_parsed::<ExportDerivationEnvelope>(&archive.spool)?
    {
        let holder = super::document_import::parse_id(&envelope.id)?;
        if !archive.index.contains(Tag::Omitted, holder.as_bytes())? {
            count = count.saturating_add(
                envelope
                    .receipts
                    .iter()
                    .filter(|source| matches!(source, ExportReceiptSource::Preserved { .. }))
                    .count(),
            );
        }
    }
    Ok(Some(vault.store.body_mint()?.reserve(count)?))
}
