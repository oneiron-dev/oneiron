//! Retained carriers with a door of their own (OF-067, Engine ruling D = a).
//! Their bytes stay as they are; each is read the way its own new write is,
//! and a hit gets the treatment a new write of it gets today, through the
//! carrier's own module, then a value-free proposal:
//!
//! - a run's result body: the S7 mark on each occurrence of it;
//! - a codebase snapshot: each file with a secret quarantined in the custody
//!   report beside its fork, as a new snapshot keeps it out;
//! - a repo snapshot: each file with a secret marked withheld, as a new
//!   capture stores it;
//! - an LFS object, which a new upload is refused for: marked, and withheld
//!   from every reader off this device;
//! - a code document's head, tested frontiers and ingress receipts, and a
//!   typed body's state and each fork's (a deck's fork log among its texts),
//!   which a new edit is refused for: each text's keys go to custody, marked
//!   under the text's hash as a file's are (owner ruling C2; Engine ruling
//!   G2 = b). A reader other than the owner reads each as its handle.
//!
//! A row the owning module cannot read is read as stored, and a hit in it
//! still files a proposal.

use heed::{RoTxn, RwTxn};

use super::{Done, LiftCause};
use crate::Vault;
use crate::batch::secret_scan::CarrierText;
use crate::code_document::{CodeDocumentRows, code_document_texts_in_txn};
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, Result};
use crate::origin::lfs::LfsOid;
use crate::side_table::{self as t, SideTableDecl};
use crate::typed_body::{TypedBodyRows, lift_typed_body_in_txn, typed_body_lift_hit_in_txn};

/// One carrier with a door here, by the row key after its prefix.
enum Row<'a> {
    Output(&'a str),
    Codebase(EntityId),
    Repo(&'a str),
    Lfs(LfsOid),
    Code(CodeDocumentRows, &'a [u8]),
    Typed(TypedBodyRows, &'a [u8]),
}

impl<'a> Row<'a> {
    /// `decl`'s row `key` (the whole key), when `decl` has a door here;
    /// `Some(None)` for a key its door cannot name.
    fn of(decl: &SideTableDecl, key: &'a [u8]) -> Option<Option<Self>> {
        let row = key.strip_prefix(decl.prefix)?;
        let is = |other: &SideTableDecl| std::ptr::eq(decl, other);
        Some(if is(&t::CODE_RUN_RAW_OUTPUT) {
            std::str::from_utf8(row).ok().map(Self::Output)
        } else if is(&t::CODEBASE_SNAPSHOT) {
            <[u8; 16]>::try_from(row)
                .ok()
                .and_then(|id| EntityId::from_bytes(id).ok())
                .map(Self::Codebase)
        } else if is(&t::REPO_MUTATION_SNAPSHOT) {
            std::str::from_utf8(row).ok().map(Self::Repo)
        } else if is(&t::ORIGIN_LFS_OBJECT) {
            <[u8; 32]>::try_from(row)
                .ok()
                .map(|oid| Self::Lfs(LfsOid::from_bytes(oid)))
        } else if is(&t::CODE_DOCUMENT_HEAD) {
            Some(Self::Code(CodeDocumentRows::Head, row))
        } else if is(&t::CODE_DOCUMENT_FRONTIER) {
            Some(Self::Code(CodeDocumentRows::Frontier, row))
        } else if is(&t::CODE_DOCUMENT_INGRESS) {
            Some(Self::Code(CodeDocumentRows::Ingress, row))
        } else if is(&t::TYPED_BODY_DOC) {
            Some(Self::Typed(TypedBodyRows::Doc, row))
        } else if is(&t::TYPED_BODY_FORK_DOC) {
            Some(Self::Typed(TypedBodyRows::ForkDoc, row))
        } else {
            return None;
        })
    }
}

/// The door's reason for a hit in carrier row `key` (the whole key) of
/// `decl`, by its own module's reading; `None` when `decl` has no door here.
/// A row that reading cannot take reads as `stored` does.
pub(super) fn hit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    decl: &SideTableDecl,
    key: &[u8],
    stored: &[u8],
) -> Result<Option<Option<&'static str>>> {
    let Some(row) = Row::of(decl, key) else {
        return Ok(None);
    };
    let read = match row {
        None => return Ok(Some(super::super::write_payload_hit(stored))),
        Some(Row::Output(handle)) => vault.code_run_output_lift_hit_in_txn(txn, handle),
        Some(Row::Codebase(id)) => vault.codebase_snapshot_lift_hit_in_txn(txn, &id),
        Some(Row::Repo(fork)) => vault.repo_snapshot_lift_hit_in_txn(txn, fork),
        Some(Row::Lfs(oid)) => vault.lfs_object_lift_hit_in_txn(txn, oid),
        Some(Row::Code(rows, row)) => code_document_texts_in_txn(&vault.store, txn, rows, row)
            .and_then(|texts| {
                crate::batch::secret_scan::carrier_texts_hit_in_txn(&vault.store, txn, &texts)
            }),
        Some(Row::Typed(rows, row)) => typed_body_lift_hit_in_txn(&vault.store, txn, rows, row),
    };
    match read {
        Ok(found) => Ok(Some(found)),
        Err(error) if stored_failure(error.kind()) => Err(error),
        Err(_) => Ok(Some(super::super::write_payload_hit(stored))),
    }
}

/// Reads carrier row `key` (the whole key) of `decl` again and marks a hit
/// it still holds through its own module; `None` when `decl` has no door
/// here.
pub(super) fn lift(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    decl: &SideTableDecl,
    key: &[u8],
) -> Result<Option<Done>> {
    let Some(row) = Row::of(decl, key) else {
        return Ok(None);
    };
    let marked = match row {
        // A key no door here names: the stored reading stands.
        None => return Ok(None),
        Some(Row::Output(handle)) => vault.lift_code_run_output_in_txn(txn, handle)?,
        Some(Row::Codebase(id)) => vault.lift_codebase_snapshot_in_txn(txn, &id)?,
        Some(Row::Repo(fork)) => vault.lift_repo_snapshot_in_txn(txn, fork)?,
        Some(Row::Lfs(oid)) => vault.lift_lfs_object_in_txn(txn, oid)?,
        Some(Row::Code(rows, row)) => {
            let texts = code_document_texts_in_txn(&vault.store, txn, rows, row)?;
            let marked = crate::batch::secret_scan::mark_carrier_texts_in_txn(
                vault, txn, decl, row, &texts,
            )?;
            return Ok(Some(text_done(marked)));
        }
        Some(Row::Typed(rows, row)) => {
            return Ok(Some(text_done(lift_typed_body_in_txn(
                vault, txn, rows, row,
            )?)));
        }
    };
    Ok(Some(match marked {
        Some(reason) => Done::Propose(LiftCause::File, reason),
        None => Done::Clean,
    }))
}

/// A lifted text's outcome: its keys marked, with the owner's proposal; a
/// hit no span places, proposed; nothing left to mark.
pub(super) const fn text_done(marked: CarrierText) -> Done {
    match marked {
        CarrierText::Minted(reason) => Done::Propose(LiftCause::File, reason),
        CarrierText::Unplaceable(reason) => Done::Propose(LiftCause::Unplaceable, reason),
        CarrierText::Clean | CarrierText::Marked => Done::Clean,
    }
}

/// A failure of the store, which the census does not read past.
const fn stored_failure(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::Storage | ErrorKind::Io | ErrorKind::MapFull | ErrorKind::ConcurrentWrite
    )
}
