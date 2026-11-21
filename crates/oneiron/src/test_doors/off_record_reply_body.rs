//! Door for `tests/room_custody_reply_bodies.rs`
//! (ROOM-CUSTODY-REPLY-BODIES): a code run's reply body published in an
//! off-record room as a run bound there publishes one, admitted by the
//! side-row wall in the room's writer, then said as the run's result
//! MESSAGE in the room; the body read back in the room, and the body a
//! saved result MESSAGE names read back in base.

use crate::code_run::ExecutorStorage;
use crate::error::{Error, Result};
use crate::memory::MessageResultAttachment;
use crate::off_record::OffRecordSession;
use crate::store::result_body_rows::{RAW_OUTPUTS, StoredBody};
use crate::{EntityId, Vault};

/// What a run in a room said: the turn its result MESSAGE opened, and the
/// content handle of the reply body that MESSAGE names.
pub struct RoomResult {
    pub turn: EntityId,
    pub handle: String,
}

/// A saved result MESSAGE as base holds it: its id, its attachment's
/// handle, length, lines and preview, and the whole body that handle names
/// in base, checked against its digest.
pub struct SavedResult {
    pub message: EntityId,
    pub handle: String,
    pub bytes: u64,
    pub lines: u64,
    pub preview: String,
    pub body: Vec<u8>,
}

/// Publishes `body` as the complete reply of a run bound to `session` as
/// `participant`, admitted as a bound run's reply is, then says it as the
/// run's result MESSAGE in the room. `Ok(Err(..))` is the typed unavailable
/// content that stands in for a reply the wall does not keep, of which
/// nothing is stored.
///
/// # Errors
///
/// The run's binding, the admission's and the witness's errors.
pub fn say_room_result(
    session: &OffRecordSession<'_>,
    participant: EntityId,
    body: &[u8],
) -> Result<std::result::Result<RoomResult, serde_json::Value>> {
    let storage = ExecutorStorage::for_session(session, participant)?;
    let mut spool = storage.code_run_reply_spool()?;
    spool.write(body)?;
    let run = EntityId::now();
    let output = match storage.publish_code_run_reply("stdout".to_owned(), spool, run, &[], None)? {
        Ok(output) => output,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    let attachment = MessageResultAttachment::of(
        run,
        &output,
        output.preview.text.clone(),
        output.preview.truncated,
    )?;
    let receipt = storage.witness_executor_result_sourced(
        &format!("code-run:{}", run.to_hex()),
        run,
        &attachment,
        None,
        1000,
        0,
        crate::WriteActor::new(participant, crate::EdgeActorClass::Human),
        crate::memory::WitnessAssertions::default(),
    )?;
    let turn = receipt
        .receipt_ref
        .strip_prefix("witness:")
        .and_then(|turn| EntityId::from_hex(turn).ok())
        .ok_or(Error::InvariantViolation(
            "the witness receipt names no turn",
        ))?;
    Ok(Ok(RoomResult {
        turn,
        handle: output.handle,
    }))
}

/// The whole reply body `handle` names, as `session`'s room over `vault`
/// holds it: in its row, or in the file of the room's body directory its
/// row names.
///
/// # Errors
///
/// A participant no longer in the room, and storage and filesystem errors.
pub fn room_result_body(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    handle: &str,
) -> Result<Option<Vec<u8>>> {
    let digest = oneiron_verb_wire::memory::result_attachment::handle_digest(handle)
        .ok_or(Error::InvariantViolation("no code-run output handle"))?;
    let row = session.routed_side_read(|rtxn, read| {
        let row = RAW_OUTPUTS.get(&read, rtxn, &handle.to_owned())?;
        let key = crate::store::body_key_row_in_txn(&read, rtxn, &digest)?;
        Ok(row.map(|row| (row, key)))
    })?;
    match row {
        None => Ok(None),
        Some((StoredBody::Inline { bytes, .. }, _)) => Ok(Some(bytes)),
        Some((StoredBody::File { len, .. }, key)) => {
            let Some(dir) = vault.store.session_body_dir(session.session_ref(), false)? else {
                return Ok(None);
            };
            let Some(file) = dir.open_reader(&digest, len, key.as_ref())? else {
                return Ok(None);
            };
            let len = usize::try_from(len)
                .map_err(|_| Error::ArithmeticOverflow("room result body length"))?;
            file.read_range(0, len).map(Some)
        }
    }
}

/// The first base row of `ids` that is a MESSAGE carrying a result
/// attachment, with the body that attachment names in base.
///
/// # Errors
///
/// Storage errors, and a body that does not match its digest.
pub fn saved_result(vault: &Vault, ids: &[EntityId]) -> Result<Option<SavedResult>> {
    for id in ids {
        let Some(row) = vault.get(id)? else {
            continue;
        };
        let mut cursor = row.as_slice();
        let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut cursor) else {
            continue;
        };
        let Some(metadata) = fields
            .iter()
            .find(|(key, _)| key.as_str() == Some("metadata"))
            .map(|(_, value)| crate::serialize::msgpack_value_to_json(value))
        else {
            continue;
        };
        let Ok(Some(attachment)) = MessageResultAttachment::from_metadata(Some(&metadata)) else {
            continue;
        };
        let body = vault
            .get_code_run_raw_output(&attachment.output()?)?
            .ok_or(Error::CorruptedIndex("saved result body"))?;
        return Ok(Some(SavedResult {
            message: *id,
            handle: attachment.handle,
            bytes: attachment.bytes,
            lines: attachment.lines,
            preview: attachment.preview,
            body,
        }));
    }
    Ok(None)
}
