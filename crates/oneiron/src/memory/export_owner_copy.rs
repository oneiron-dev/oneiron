//! The owner's own whole-vault copy through the memory doors (owner ruling
//! 1-EXPORT = B; fix list row 15416): made where only this engine reads it
//! and handed back once it is recorded ([`Vault::release_owner_copy`]).

use super::export::{ExportBy, ExportOptions, MemoryExportReceipt};
use super::export_audit::{ExportAuditScope, ExportCopy};
use super::{MemoryError, MemoryResult};
use crate::Vault;
use crate::batch::export::{ExportCut, OwnerCopyPass, ReleasedCopy};
use crate::entity_id::EntityId;
use crate::serialize::{EXPORT_TARGET_ARCHIVE, EXPORT_TARGET_OKF};
use crate::settings::ReadDestination;
use crate::share_travel::WorldRecipientNotice;
use crate::write_envelope::WriteActor;

/// The owner's own copy (owner ruling 1-EXPORT = B), made in a spool only
/// this engine reads and recorded once before it is handed back with its
/// receipt and the rows its snapshot read (fix list row 15416): one that
/// carries another member's personal mailbox, or uses an approval of the
/// owner's request for one, is recorded in the one write that tells each
/// mailbox's person; when that write does not commit, the copy is made once
/// more, `admit` admitting the owner again in its own snapshot, without
/// those mailboxes, each named in `mailbox_notices`. The receipt is the
/// vault's export audit row, the copy `reader`'s, and each private thread
/// the archive carries that he is not in is told of it (FIX 6427).
pub(super) fn render_owner_copy(
    vault: &Vault,
    opts: &ExportOptions,
    by: ExportBy<'_>,
    destination: impl Into<ReadDestination>,
    reader: WriteActor,
    admit: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
) -> MemoryResult<(MemoryExportReceipt, Vec<EntityId>, ReleasedCopy)> {
    let name = opts.format.as_deref().unwrap_or(EXPORT_TARGET_ARCHIVE);
    let cut = match name {
        EXPORT_TARGET_ARCHIVE => ExportCut::Archive,
        EXPORT_TARGET_OKF => ExportCut::Okf,
        _ => return Err(unknown_format(name)),
    };
    let exporter = reader.entity_ref();
    let mut copy = vault.release_owner_copy(
        &OwnerCopyPass {
            destination: destination.into(),
            cut,
            // OKF carries no custody value.
            include_secrets: cut == ExportCut::Archive && opts.include_secrets.unwrap_or(true),
            reader,
        },
        admit,
        |export, bytes, digest| ExportCopy {
            scope: ExportAuditScope::WholeVault,
            exporter,
            format: name.to_owned(),
            bytes: Some(bytes),
            digest: Some(digest.to_owned()),
            by: by.name.to_owned(),
            diary_reads: export.diary_reads().to_vec(),
            act: by.act,
            thread_roots: std::mem::take(&mut export.thread_roots),
            holder_requests: std::mem::take(&mut export.holder_requests),
            recipient: opts.secrets_recipient,
        },
    )?;
    let export = &mut copy.receipt;
    // The owner's notices ride his own answer alone, each naming its world
    // by name, never by id, and each member's mailbox it left out; the
    // co-Owners' audit row names none.
    let receipt = MemoryExportReceipt {
        format: export.manifest().format.clone(),
        bytes: copy.bytes,
        digest: copy.digest.clone(),
        holder_requests: std::mem::take(&mut export.holder_requests),
        notices: std::mem::take(&mut export.notices)
            .into_iter()
            .map(WorldRecipientNotice::in_result)
            .collect(),
        mailbox_notices: std::mem::take(&mut export.mailbox_notices),
        act: by.act,
    };
    let sources = std::mem::take(&mut export.sources);
    Ok((receipt, sources, copy))
}

/// The refusal of an export target this door does not write.
pub(super) fn unknown_format(name: &str) -> MemoryError {
    MemoryError::bad_request_with(
        format!("unknown export format {name:?}"),
        &["Use one of: archive, okf."],
    )
}
