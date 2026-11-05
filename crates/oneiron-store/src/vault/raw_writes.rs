//! The raw storage writes a bound caller makes (OF-063, FIX 3387).
//!
//! The raw native vault handles (the C ABI, JNI's `NativeVault`, the raw
//! napi vault) put entity blobs, edges and vectors by id and delete by id.
//! A handle its app host bound to a principal and, optionally, an off-record
//! session writes through here, as that caller: each write takes the
//! caller's [`Memory`] and runs the doors a `Memory` surface's writes run, so
//! the bound actor and session ride every admission and receipt those doors
//! write. An unbound handle keeps the bare [`crate::Vault`] doors, as before.
//!
//! - A put, a batch of puts, an edge and a vector commit as one batch whose
//!   writer snapshot first proves the actor, as every verified actor write
//!   does: its stored type admits its class, and a shared vault grants it
//!   content writes. It commits below owner grade, as an embedded handle's
//!   `vault.batch` does ([`Memory::core_batch_write`]), and its gate
//!   decisions are receipted as any batch's are. It is held to the caller's
//!   own read (OF-063, FIX 1223, 6068): a put over a stored row it does not
//!   read refuses as missing, and a CLAIM's typed record refs must resolve
//!   for it. A caller whose credential grants no read is held to the bounds
//!   of what that credential may write to: a put over a stored row outside
//!   them refuses as missing, and its CLAIMs commit as before.
//! - A delete is the `vault.delete` row: its target is admitted as a record
//!   ref, so an id naming no record is refused `INVENTED_REFERENCE` with a
//!   reference-refusal receipt, none inside an anonymous off-record session
//!   the actor is verified in; then the owner's
//!   [`Memory::safe_delete`] runs with its gate and redaction receipt. A row
//!   only an off-record room staged is deleted in that room (FIX 10763).
//!
//! A handle bound inside an off-record session writes into its room while
//! the room is off record, and reads the room over base (FIX 8119, 8603;
//! `session`); a raw CLAIM put carries its verified caller's envelope
//! through its gate and apply (FIX 8118).
//!
//! A raw body is opaque bytes here, except for prose admission (OF-063,
//! FIX 1228, 3734): a NOTE's markdown and a keyed value's nested value are
//! read for links once, through the caller, as their typed writers read
//! them, and their `unlinked` receipt is written only once the batch lands.
//! A put its room stages lands in no base batch and earns none.

use oneiron_base::edge::EdgeKind;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;
use oneiron_contracts::temporal::TimeRange;
use serde::{Deserialize, Serialize};

/// One entity blob a bound raw write puts ([`Memory::raw_put_entities`]).
#[derive(Debug, Clone, Copy)]
pub struct RawEntityPut<'a> {
    /// The entity's id.
    pub id: EntityId,
    /// Its entity type byte.
    pub entity_type: u8,
    /// When what it records happened.
    pub occurred: TimeRange,
    /// When the vault learned it.
    pub learned_at: u64,
    /// Its body bytes, borrowed for the call.
    pub data: &'a [u8],
}
