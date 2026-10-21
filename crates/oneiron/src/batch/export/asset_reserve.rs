//! The body instances an archive import's File ASSETs may spill into (FIX
//! 3677, KS-2A): minted before the import's one write transaction opens, as
//! its run results' are, since no body instance is minted inside a writer.
//! Each File row past the inline bound gets one, and only while the file
//! plane is on: off, every ASSET body stays in its row and none is minted.
//! One a File row leaves unspilled (a row already here, or a body the
//! stager keeps inline) is debris. The values custody holds are read in
//! the writer itself (FIX 5395).

use std::io::{Read, Seek};
use std::sync::Arc;

use super::archive_index::{FLAG_FILE, IndexedArchive, Section, Tag};
use crate::Vault;
use crate::error::Result;
use crate::serialize::ExportBody;
use crate::store::BodyMint;

/// What the import's File ASSETs stage through inside its writer: the body
/// instances minted for them, and the values custody holds, each `None`
/// while the file plane is off.
pub(super) struct ArchiveAssets {
    pub(super) mint: Option<BodyMint>,
    pub(super) known: Option<Arc<crate::secret_custody::KnownValues>>,
}

/// The instances `archive`'s File ASSETs may spill into, minted now, before
/// the writer opens: one for each File row the import may write whose body
/// is past [`crate::store::ASSET_INLINE_BODY_BYTES`], counted from the row
/// index. `None` while the file plane is off.
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
    Ok(Some(vault.store.body_mint()?.reserve(count)?))
}
