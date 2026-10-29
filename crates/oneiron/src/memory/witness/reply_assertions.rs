//! The canonical reply assertions a MESSAGE generation keeps (FIX 10258,
//! FIX 10259, FIX 10260): the typed records its reply asserts it cited or
//! created, by the registry type its row has and its id, as admitted in the
//! write that saved it.
//!
//! - A streamed generation keeps them on its own receipt
//!   ([`super::MessageStreamReceipt::reply_assertions`]): its stream's seed
//!   set and its terminal's, a Continue's included, never rewriting the
//!   MESSAGE's birth envelope.
//! - A MESSAGE born whole (a witnessed turn, an atomic commit) keeps them in
//!   one side row beside it ([`MessageReplyAssertions`]), written in its
//!   witness write after its admission. A streamed birth keeps none here:
//!   its receipt is its record.
//!
//! Every record in them was read through the writer's own lane in that
//! write (OF-063): readability, which is no proof that the writer made a
//! record it says it `created`. Only ids and types are kept, never a
//! caller's kind, short id or label. A MESSAGE's metadata is its caller's
//! own: a `reply_assertions` key there is never read as this record. The
//! rows go with their MESSAGE, TURN, conversation or writer.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::{ReplyAssertionRecord, ReplyAssertions};
use crate::memory::WitnessAssertions;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::{ResponseCarriage, ResponseOwners, ResponseScan, Store};

/// The reply assertions one MESSAGE was born with whole. Key: id16(message).
const BIRTHS: SideTable<EntityId, MessageReplyAssertions, Named> =
    SideTable::new(&side_table::MESSAGE_REPLY_ASSERTIONS);

/// The reply assertions a MESSAGE born whole (not streamed) keeps beside it
/// (FIX 10260): which MESSAGE, in which TURN and conversation, written by
/// whom, and the records its turn asserts, as admitted when it landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MessageReplyAssertions {
    pub message: EntityId,
    pub conversation: EntityId,
    pub turn: EntityId,
    /// The writer the MESSAGE was witnessed as, and its actor class.
    pub writer: EntityId,
    pub writer_class: u8,
    /// The records its turn asserts it cited or created, each readable by
    /// its writer when it landed: no proof of authorship.
    pub assertions: ReplyAssertions,
}

/// The canonical set `sets` assert, in order, cited and created each once:
/// each record by the registry type its row has in `txn` and its id. A
/// record whose id names no row is left out, never kept by the caller's
/// word; callers run after the write's readable-id check, so none should.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn admitted_reply_assertions_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    sets: &[&WitnessAssertions],
) -> Result<ReplyAssertions> {
    let mut admitted = ReplyAssertions::default();
    for set in sets {
        for record in &set.cited {
            if let Some(record) = stored_record(store, txn, &record.id)? {
                admitted.cite(record);
            }
        }
        for record in &set.created {
            if let Some(record) = stored_record(store, txn, &record.id)? {
                admitted.create(record);
            }
        }
    }
    Ok(admitted)
}

/// The record `id` names, by its stored type; `None` for an id that does not
/// parse or names no row.
fn stored_record(store: &Store, txn: &RoTxn<'_>, id: &str) -> Result<Option<ReplyAssertionRecord>> {
    let Ok(id) = EntityId::from_hex(id) else {
        return Ok(None);
    };
    Ok(crate::batch::stored_entity_type(store, txn, &id)?
        .map(|entity_type| ReplyAssertionRecord { entity_type, id }))
}

/// Keeps `row` for its MESSAGE, in the witness write that landed it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_birth_reply_assertions_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    row: &MessageReplyAssertions,
) -> Result<()> {
    BIRTHS.put(store, txn, &row.message, row)
}

/// Keeps `assertions`, the set a turn's witness write admitted, beside each
/// MESSAGE in `messages` that write landed new whole (FIX 10260), naming its
/// `conversation`, `turn` and `writer` (its id and actor class). A MESSAGE
/// whose stream receipt the write saved is a streamed birth: its receipt
/// keeps the set, and it gets no row here. An empty set keeps none.
///
/// # Errors
///
/// Storage errors.
pub(super) fn keep_birth_reply_assertions_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    conversation: EntityId,
    turn: EntityId,
    (writer, writer_class): (EntityId, u8),
    assertions: &ReplyAssertions,
    messages: &[EntityId],
) -> Result<()> {
    if assertions.is_empty() {
        return Ok(());
    }
    for message in messages {
        if crate::memory::message_stream_finality_in_txn(vault, txn, message)?.is_some() {
            continue;
        }
        let row = MessageReplyAssertions {
            message: *message,
            conversation,
            turn,
            writer,
            writer_class,
            assertions: assertions.clone(),
        };
        put_birth_reply_assertions_in_txn(&vault.store, txn, &row)?;
    }
    Ok(())
}

/// The reply assertions `message` was born with whole; `None` for a MESSAGE
/// that asserted none, was streamed, or was born before they were kept.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn birth_reply_assertions_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    message: &EntityId,
) -> Result<Option<MessageReplyAssertions>> {
    BIRTHS.get(store, txn, message)
}

/// Drops the birth row the MESSAGE `message` was born with whole, in `txn`.
/// The row's key is the MESSAGE, so it goes by key, even when its value does
/// not decode (FIX 10631). A restore's removal scrub calls this; the live
/// erase below calls it first.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_birth_reply_assertions_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    message: &EntityId,
) -> Result<()> {
    BIRTHS.delete(store, txn, message)?;
    Ok(())
}

/// Drops the rows an erase of `id` covers: its own MESSAGE's, and every row
/// whose TURN, conversation or writer is `id`, and takes the assertions off
/// its stream receipts. Registered in `deletion/derived_rows.rs`. A row that
/// does not decode names no TURN, conversation or writer and stays, never
/// refused (FIX 10631).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_reply_assertions_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    erase_birth_reply_assertions_in_txn(store, txn, id)?;
    let mut covered = Vec::new();
    for row in BIRTHS.iter_raw_from(store, txn, &[])? {
        let (key, value) = row?;
        let Ok(decoded) = BIRTHS.decode_value(&value) else {
            continue;
        };
        if owners_of(&decoded).contains(id)
            && let Some(message) = <EntityId as SideKey>::decode_key(&key)
        {
            covered.push(message);
        }
    }
    for message in covered {
        BIRTHS.delete(store, txn, &message)?;
    }
    super::stream::redact_receipt_assertions_in_txn(store, txn, id)
}

/// The owners a row's copies are kept for: its MESSAGE, TURN, conversation
/// and writer.
fn owners_of(row: &MessageReplyAssertions) -> [EntityId; 4] {
    [row.message, row.turn, row.conversation, row.writer]
}

/// What a checkpoint carries of a row once an owner's erase retired it:
/// nothing, the whole row goes. `None` for a row that does not decode.
pub(crate) fn reply_assertions_stub(value: &[u8]) -> Option<Vec<u8>> {
    BIRTHS.decode_value(value).ok().map(|_| Vec::new())
}

/// What a checkpoint carries of the birth row `value`: the whole row, and
/// nothing once retired, as a captured request is carried (its retirement
/// drops the row, in images and live alike). A row that does not decode is
/// carried whole as an opaque response (FIX 6227).
pub(crate) fn reply_assertions_scan(value: &[u8]) -> ResponseScan {
    if BIRTHS.decode_value(value).is_err() {
        return ResponseScan::opaque_row();
    }
    ResponseScan::Decoded(ResponseCarriage {
        keep: 0,
        stub: Vec::new(),
        retired: 0,
    })
}

/// Who owns the row `value`'s copies; none for a row that does not decode.
pub(crate) fn reply_assertions_owners(value: &[u8]) -> Vec<EntityId> {
    BIRTHS
        .decode_value(value)
        .map(|row| owners_of(&row).to_vec())
        .unwrap_or_default()
}

/// Who owns the opaque response in the row `key` holding `value`, as far as
/// its key proves (FIX 10631): its MESSAGE alone, never a guessed TURN,
/// conversation or writer; the decoded row's four owners when it decodes.
pub(crate) fn reply_assertions_opaque_owners(key: &[u8], value: &[u8]) -> ResponseOwners {
    if let Ok(row) = BIRTHS.decode_value(value) {
        return ResponseOwners::Partial(owners_of(&row).to_vec());
    }
    key.strip_prefix(side_table::MESSAGE_REPLY_ASSERTIONS.prefix)
        .and_then(<EntityId as SideKey>::decode_key)
        .map_or(ResponseOwners::Unknown, |message| {
            ResponseOwners::Partial(vec![message])
        })
}
