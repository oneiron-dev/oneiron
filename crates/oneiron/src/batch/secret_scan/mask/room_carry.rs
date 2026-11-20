//! A save moves the room's secrets its rows name into the vault's custody
//! (ROOM-LOCAL-CUSTODY; the lead's ruling of 21 Nov, "fingerprint only on
//! save"). An off-record room keeps a fresh key in its own custody, in
//! memory, and a row there holds its room handle (`[secret r1]`); a message
//! said in the room may name that handle too. A save writes the room's rows
//! to base: in the save's own transaction, each room handle a row it writes
//! names takes the handle of a base custody record that holds the value,
//! one minted there through the vault's custody door unless base custody
//! holds the value already. Only that mint teaches the known-value index the
//! value's fingerprint. A room handle the room keeps no value under (its
//! close wiped it) stays as written: it names nothing, in base as in the
//! room. A row base holds already keeps its bytes, as the save's replay
//! compares them, so a retry never mints again.

use std::collections::BTreeMap;

use heed::RwTxn;
use rmpv::Value;
use zeroize::Zeroize;

use super::HANDLE_OPEN;
use super::wipe::{PlanOps, PlanTree};
use crate::Vault;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::session_overlay::{KeptRoomSecret, SessionOverlay, is_room_secret_handle};
use crate::store::known_value_index::KnownValues;

/// Where a custody record a save mints names its value as found.
const SAVED_PLACE: &str = "off_record.save";

/// `ops`, a save's writes out of the room whose overlay is `room`, with
/// each room handle a fresh row names moved into the vault's custody in
/// `wtxn` (see the module notes).
///
/// # Errors
///
/// Custody and storage errors, and a carried row that does not encode
/// again.
pub(crate) fn carry_room_secrets_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    room: &SessionOverlay,
    ops: Vec<BatchOp>,
) -> Result<Vec<BatchOp>> {
    let kept = room.kept_room_secrets()?;
    if kept.is_empty() {
        return Ok(ops);
    }
    let mut carry = RoomCarry {
        kept,
        moved: BTreeMap::new(),
    };
    let mut ops = PlanOps::from_owned(ops);
    for op in ops.iter_mut() {
        let BatchOp::Put { id, data, .. } = op else {
            continue;
        };
        if !names_room_handle(data) || vault.store.port_entity_present(wtxn, id)? {
            continue;
        }
        // A row that is no one MessagePack value keeps its bytes: a room
        // handle in it stays as written, naming nothing.
        let mut cursor = data.as_slice();
        let Ok(decoded) = rmpv::decode::read_value(&mut cursor) else {
            continue;
        };
        let mut tree = PlanTree(decoded);
        if !cursor.is_empty() || !carry.value(vault, wtxn, *id, &mut tree.0)? {
            continue;
        }
        let mut body = Vec::with_capacity(data.len());
        rmpv::encode::write_value(&mut body, &tree.0)
            .map_err(|_| Error::InvariantViolation("a carried saved row did not encode"))?;
        data.zeroize();
        *data = body;
    }
    Ok(ops.into_ops())
}

/// Whether `data` holds a room handle's opening, as written.
fn names_room_handle(data: &[u8]) -> bool {
    let open = room_handle_open();
    data.windows(open.len())
        .any(|window| window == open.as_bytes())
}

/// `[secret r`: how a room handle opens in a text.
fn room_handle_open() -> String {
    format!("{HANDLE_OPEN}{}", crate::session_overlay::ROOM_SECRET_SIGIL)
}

/// One save's moves: the secrets the room keeps, and each room handle moved
/// so far with its base handle, so a value takes one base record.
struct RoomCarry {
    kept: Vec<KeptRoomSecret>,
    moved: BTreeMap<String, String>,
}

impl RoomCarry {
    /// `value`, a row `record` writes, with each room handle in its texts
    /// moved: whether any was.
    fn value(
        &mut self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        record: EntityId,
        value: &mut Value,
    ) -> Result<bool> {
        match value {
            Value::String(text) => {
                let Some(carried) = (match text.as_str() {
                    Some(text) => self.text(vault, wtxn, record, text)?,
                    None => None,
                }) else {
                    return Ok(false);
                };
                *value = Value::from(carried);
                Ok(true)
            }
            Value::Binary(bytes) => {
                let Some(carried) = (match std::str::from_utf8(bytes) {
                    Ok(text) => self.text(vault, wtxn, record, text)?,
                    Err(_) => None,
                }) else {
                    return Ok(false);
                };
                *value = Value::Binary(carried.into_bytes());
                Ok(true)
            }
            Value::Array(items) => {
                let mut moved = false;
                for item in items {
                    moved |= self.value(vault, wtxn, record, item)?;
                }
                Ok(moved)
            }
            Value::Map(fields) => {
                let mut moved = false;
                for (key, member) in fields {
                    moved |= self.value(vault, wtxn, record, key)?;
                    moved |= self.value(vault, wtxn, record, member)?;
                }
                Ok(moved)
            }
            _ => Ok(false),
        }
    }

    /// `text` with each room handle the room keeps a value under moved to
    /// its base handle; `None` when it names none.
    fn text(
        &mut self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        record: EntityId,
        text: &str,
    ) -> Result<Option<String>> {
        if !text.contains(&room_handle_open()) {
            return Ok(None);
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        let mut moved = false;
        while let Some(at) = rest.find(HANDLE_OPEN) {
            out.push_str(&rest[..at]);
            out.push_str(HANDLE_OPEN);
            let after = &rest[at + HANDLE_OPEN.len()..];
            rest = match after.split_once(']') {
                Some((handle, tail)) if is_room_secret_handle(handle) => {
                    match self.base_handle(vault, wtxn, record, handle)? {
                        Some(base) => {
                            out.push_str(&base);
                            out.push(']');
                            moved = true;
                            tail
                        }
                        None => after,
                    }
                }
                _ => after,
            };
        }
        out.push_str(rest);
        Ok(moved.then_some(out))
    }

    /// The base handle the value the room keeps under `handle` (bare) takes:
    /// the one it took earlier in this save, else that of the record base
    /// custody holds it in, else a record minted for it now, in `wtxn`,
    /// named as found in `record`. `None` when the room keeps no value
    /// under `handle`.
    fn base_handle(
        &mut self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        record: EntityId,
        handle: &str,
    ) -> Result<Option<String>> {
        if let Some(base) = self.moved.get(handle) {
            return Ok(Some(base.clone()));
        }
        let Some(secret) = self.kept.iter().find(|secret| secret.handle == handle) else {
            return Ok(None);
        };
        let held = KnownValues::shared_in_writer(&vault.store, wtxn)?.and_then(|known| {
            known
                .spans(&secret.value)
                .into_iter()
                .find(|hit| hit.span == (0..secret.value.len()))
                .map(|hit| hit.handle.to_owned())
        });
        let base = match held {
            Some(base) => base,
            None => {
                let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
                super::seal_whole_part_in_txn(
                    vault,
                    wtxn,
                    record,
                    SAVED_PLACE,
                    &secret.value,
                    Some(secret.reason),
                    at,
                )?
            }
        };
        self.moved.insert(handle.to_owned(), base.clone());
        Ok(Some(base))
    }
}
