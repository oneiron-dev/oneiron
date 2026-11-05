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

use crate::code_document_values::CodeDocumentRows;
use crate::origin::lfs::oid::LfsOid;
use oneiron_base::error::ErrorKind;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// A failure of the store, which the census does not read past.
pub const fn stored_failure(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::Storage | ErrorKind::Io | ErrorKind::MapFull | ErrorKind::ConcurrentWrite
    )
}
