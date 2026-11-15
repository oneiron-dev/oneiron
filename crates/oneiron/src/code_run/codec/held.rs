//! The parts of a stored replay record a guarded append reads, decoded from
//! the row's bytes in place (FIX 16). An append compares the stored row's
//! generation and keeps its stored bridge calls (`over_held`); it never needs
//! the row's outputs, bindings, live-run binding or earlier checkpoints. The
//! walk passes over those as MessagePack and never decodes them, so an append
//! no longer decodes the whole record it replaces at every executor step.

use rmpv::Value;

use crate::Result;

use super::super::replay::{
    CODE_RUN_REPLAY_HASH_LEN, CODE_RUN_REPLAY_SCHEMA_VERSION, CodeRunBridgeCall,
    CodeRunReplayGeneration, CodeRunReplayHeld,
};
use super::super::support::{entity_value, invalid_code_run_replay, u64_value};
use super::{
    CODE_RUN_REPLAY_RECORD_KEYS, decode_bridge_call, decode_pending_step, decode_step_checkpoint,
    pending_step_digest,
};

const INDEX_SCHEMA_VERSION: usize = 0;
const INDEX_RUN_ID: usize = 1;
const INDEX_BRIDGE_CALLS: usize = 3;
const INDEX_STEP_CHECKPOINTS: usize = 4;
const INDEX_OUTPUTS: usize = 5;
const INDEX_CALLABLE_ROWS: usize = 9;
const INDEX_BIRTH_WORLD: usize = 10;
const INDEX_PENDING_STEP: usize = 11;

/// The generation of the stored record `bytes`, as
/// [`super::super::replay::CodeRunReplayRecord::generation`] reads it from
/// the decoded record: the three counts, the last checkpoint's state hash and
/// the pending step's digest. No bridge call or output is decoded.
pub(crate) fn decode_code_run_replay_generation(bytes: &[u8]) -> Result<CodeRunReplayGeneration> {
    Ok(walk(bytes, false)?.generation)
}

/// The generation, run, birth world and bridge calls of the stored record
/// `bytes`: what a guarded append compares and keeps.
pub(crate) fn decode_code_run_replay_held(bytes: &[u8]) -> Result<CodeRunReplayHeld> {
    walk(bytes, true)
}

fn walk(bytes: &[u8], with_calls: bool) -> Result<CodeRunReplayHeld> {
    let mut cursor = bytes;
    let entries = map_len(&mut cursor)?;
    let mut seen = [false; CODE_RUN_REPLAY_RECORD_KEYS.len()];
    let mut schema_version = None;
    let mut run_id = None;
    let mut birth_world = None;
    let mut bridge_calls = Vec::new();
    let mut bridge_call_count = 0_u64;
    let mut step_checkpoint_count = 0_u64;
    let mut output_count = 0_u64;
    let mut last_state_hash = [0; CODE_RUN_REPLAY_HASH_LEN];
    let mut pending_digest = [0; CODE_RUN_REPLAY_HASH_LEN];
    for _ in 0..entries {
        let index = key_index(&mut cursor)?;
        if std::mem::replace(&mut seen[index], true) {
            return Err(invalid_code_run_replay("duplicate map key"));
        }
        match index {
            INDEX_SCHEMA_VERSION => schema_version = Some(u64_value(&read(&mut cursor)?)?),
            INDEX_RUN_ID => run_id = Some(entity_value(&read(&mut cursor)?)?),
            INDEX_BRIDGE_CALLS => {
                let len = array_len(&mut cursor)?;
                bridge_call_count = count(len)?;
                if with_calls {
                    bridge_calls = (0..len)
                        .map(|_| decode_bridge_call(&read(&mut cursor)?))
                        .collect::<Result<Vec<CodeRunBridgeCall>>>()?;
                } else {
                    skip_values(&mut cursor, len)?;
                }
            }
            INDEX_STEP_CHECKPOINTS => {
                let len = array_len(&mut cursor)?;
                step_checkpoint_count = count(len)?;
                if let Some(earlier) = len.checked_sub(1) {
                    skip_values(&mut cursor, earlier)?;
                    last_state_hash = decode_step_checkpoint(&read(&mut cursor)?)?.state_hash;
                }
            }
            INDEX_OUTPUTS => {
                let len = array_len(&mut cursor)?;
                output_count = count(len)?;
                skip_values(&mut cursor, len)?;
            }
            INDEX_BIRTH_WORLD => {
                birth_world = match read(&mut cursor)? {
                    Value::Nil => None,
                    value => Some(entity_value(&value)?),
                };
            }
            INDEX_PENDING_STEP => {
                if let Some(pending) = decode_pending_step(Some(&read(&mut cursor)?))? {
                    pending_digest = pending_step_digest(&pending)?;
                }
            }
            _ => skip_values(&mut cursor, 1)?,
        }
    }
    if !cursor.is_empty() {
        return Err(invalid_code_run_replay(
            "trailing bytes after code-run replay record",
        ));
    }
    // The keys the whole decode requires; `callable_rows` and `pending_step`
    // may be absent from an older row.
    let missing = seen
        .iter()
        .enumerate()
        .any(|(index, seen)| !seen && index != INDEX_CALLABLE_ROWS && index != INDEX_PENDING_STEP);
    if missing {
        return Err(invalid_code_run_replay("missing replay record field"));
    }
    if schema_version != Some(CODE_RUN_REPLAY_SCHEMA_VERSION) {
        return Err(invalid_code_run_replay(
            "unsupported code-run replay schema_version",
        ));
    }
    let run_id = run_id.ok_or(invalid_code_run_replay("missing replay run_id"))?;
    Ok(CodeRunReplayHeld {
        run_id,
        birth_world,
        bridge_calls,
        generation: CodeRunReplayGeneration {
            bridge_call_count,
            step_checkpoint_count,
            output_count,
            last_state_hash,
            pending_digest,
        },
    })
}

fn not_message_pack() -> crate::Error {
    invalid_code_run_replay("record is not valid MessagePack")
}

/// One whole value at the cursor, decoded.
fn read(cursor: &mut &[u8]) -> Result<Value> {
    rmpv::decode::read_value(cursor).map_err(|_| not_message_pack())
}

fn take<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let whole: &'a [u8] = *cursor;
    let (head, rest) = whole.split_at_checked(len).ok_or_else(not_message_pack)?;
    *cursor = rest;
    Ok(head)
}

/// A big-endian length `width` bytes wide.
fn length(cursor: &mut &[u8], width: usize) -> Result<usize> {
    let value = take(cursor, width)?
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    usize::try_from(value).map_err(|_| not_message_pack())
}

/// The bytes after an extension's length: its data, which the length
/// counts, and its type byte.
fn extension_len(cursor: &mut &[u8], width: usize) -> Result<usize> {
    length(cursor, width)?
        .checked_add(1)
        .ok_or_else(not_message_pack)
}

fn count(len: usize) -> Result<u64> {
    u64::try_from(len).map_err(|_| not_message_pack())
}

fn map_len(cursor: &mut &[u8]) -> Result<usize> {
    match take(cursor, 1)?[0] {
        lead @ 0x80..=0x8f => Ok(usize::from(lead & 0x0f)),
        0xde => length(cursor, 2),
        0xdf => length(cursor, 4),
        _ => Err(invalid_code_run_replay("value must be a MessagePack map")),
    }
}

fn array_len(cursor: &mut &[u8]) -> Result<usize> {
    match take(cursor, 1)?[0] {
        lead @ 0x90..=0x9f => Ok(usize::from(lead & 0x0f)),
        0xdc => length(cursor, 2),
        0xdd => length(cursor, 4),
        _ => Err(invalid_code_run_replay("value must be an array")),
    }
}

/// The index in [`CODE_RUN_REPLAY_RECORD_KEYS`] of the string key at the cursor.
fn key_index(cursor: &mut &[u8]) -> Result<usize> {
    let len = match take(cursor, 1)?[0] {
        lead @ 0xa0..=0xbf => usize::from(lead & 0x1f),
        0xd9 => length(cursor, 1)?,
        0xda => length(cursor, 2)?,
        0xdb => length(cursor, 4)?,
        _ => return Err(invalid_code_run_replay("map key is not pinned")),
    };
    let key = take(cursor, len)?;
    CODE_RUN_REPLAY_RECORD_KEYS
        .iter()
        .position(|known| known.as_bytes() == key)
        .ok_or(invalid_code_run_replay("map key is not pinned"))
}

/// Passes over `values` whole MessagePack values without decoding them. An
/// array or a map adds its members to the values still to pass over.
fn skip_values(cursor: &mut &[u8], mut values: usize) -> Result<()> {
    while values > 0 {
        // Each value takes at least one byte: more values than bytes left
        // cannot all be whole.
        if values > cursor.len() {
            return Err(not_message_pack());
        }
        values -= 1;
        let skipped = match take(cursor, 1)?[0] {
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => 0,
            0xcc | 0xd0 => 1,
            0xcd | 0xd1 | 0xd4 => 2,
            0xd5 => 3,
            0xca | 0xce | 0xd2 => 4,
            0xd6 => 5,
            0xcb | 0xcf | 0xd3 => 8,
            0xd7 => 9,
            0xd8 => 17,
            lead @ 0xa0..=0xbf => usize::from(lead & 0x1f),
            0xc4 | 0xd9 => length(cursor, 1)?,
            0xc5 | 0xda => length(cursor, 2)?,
            0xc6 | 0xdb => length(cursor, 4)?,
            0xc7 => extension_len(cursor, 1)?,
            0xc8 => extension_len(cursor, 2)?,
            0xc9 => extension_len(cursor, 4)?,
            lead @ 0x90..=0x9f => {
                values += usize::from(lead & 0x0f);
                0
            }
            0xdc => {
                values += length(cursor, 2)?;
                0
            }
            0xdd => {
                values += length(cursor, 4)?;
                0
            }
            lead @ 0x80..=0x8f => {
                values += 2 * usize::from(lead & 0x0f);
                0
            }
            0xde => {
                values += 2 * length(cursor, 2)?;
                0
            }
            0xdf => {
                values += 2 * length(cursor, 4)?;
                0
            }
            // 0xc1, which no value starts with.
            _ => return Err(not_message_pack()),
        };
        take(cursor, skipped)?;
    }
    Ok(())
}
