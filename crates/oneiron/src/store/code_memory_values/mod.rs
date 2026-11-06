//! Core half of `store::code_memory_values`: its store-layer items live in `oneiron_store::code_memory_values` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::code_memory_values::*;

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{CodeError, Error, Result};
use crate::side_table::{self, Raw, RawValue, SideTable};
use crate::store::code_document_values::CodeSpanAnchor;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use oneiron_contracts::claim::ClaimSource;
pub use pull_result::CodeMemoryPullResult;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Named code-memory slot holding the live (possibly conflicting) values
/// recorded against one code symbol. Key: id16 "\x00" string. Never decomposed
/// back into its parts, so it stays the opaque `Vec<u8>` [`SideKey`] shape.
pub(crate) const SLOT: SideTable<Vec<u8>, CodeMemorySlot, Raw> =
    SideTable::new(&side_table::CODE_MEMORY_SLOT);

/// Durable L2 attachment row binding a code-symbol slot value to a
/// note/claim payload. Key: id16 "\x00" string "\x00" u8 id16 (opaque).
pub(crate) const ATTACHMENT: SideTable<Vec<u8>, (CodeMemoryLocator, EntityId), Raw> =
    SideTable::new(&side_table::CODE_MEMORY_ATTACHMENT);

/// Registered always-on code-memory contract. Key: id16 "\x00" string "\x00"
/// u8 id16 (opaque).
pub(crate) const ALWAYS_ON: SideTable<Vec<u8>, AlwaysOnCodeMemoryContract, Raw> =
    SideTable::new(&side_table::CODE_MEMORY_ALWAYS_ON);

/// Idempotent anchor-transfer receipt. Key: id16 + id16 + u64be + hash32
/// (opaque).
pub(crate) const TRANSFER: SideTable<Vec<u8>, AnchorTransferRecord, Raw> =
    SideTable::new(&side_table::CODE_MEMORY_TRANSFER);

/// OF-222 (FIX 3681) archive seam: the code-memory tables an archive carries beside each
/// CODE_SYMBOL (slots, attachments, always-on contracts, transfer receipts), lent with their
/// own key types and codec.
pub(crate) fn archive_code_memory_tables() -> [crate::batch::export::LentSideTable; 4] {
    [&SLOT, &ATTACHMENT, &ALWAYS_ON, &TRANSFER]
}
