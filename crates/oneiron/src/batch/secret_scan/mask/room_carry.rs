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
//!
//! A selected save carries the NOTE, CLAIM and conversation shell it lands
//! too (ROOM-CUSTODY-SAVED-ARTIFACTS), through one [`RoomCarry`]: a NOTE's
//! texts ([`RoomCarry::text_in_txn`]), a CLAIM's values
//! ([`RoomCarry::value_in_txn`]), a shell's row ([`RoomCarry::ops_in_txn`]).
//! A saved result MESSAGE's body is carried whole, read as the door read it
//! ([`RoomCarry::body_in_txn`], ROOM-CUSTODY-REPLY-BODIES): the carried bytes
//! are a new body in base, which the MESSAGE names in place of the room's.

use std::collections::BTreeMap;
use std::ops::Range;

use heed::RwTxn;
use rmpv::Value;
use zeroize::Zeroize;

use super::HANDLE_OPEN;
use super::body::{opens_json, opens_whole_messagepack};
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
    match RoomCarry::of(room)? {
        Some(mut carry) => carry.ops_in_txn(vault, wtxn, ops),
        None => Ok(ops),
    }
}

/// `[secret r`: how a room handle opens in a text.
fn room_handle_open() -> String {
    format!("{HANDLE_OPEN}{}", crate::session_overlay::ROOM_SECRET_SIGIL)
}

/// One save's moves out of a room: the secrets the room keeps, and each
/// room handle moved so far with its base handle, so a value takes one base
/// record.
pub(crate) struct RoomCarry {
    kept: Vec<KeptRoomSecret>,
    moved: BTreeMap<String, String>,
}

/// A text a carry moved a room handle of: the text as carried, and each
/// span of the text as read that took a span of it, in order.
pub(crate) struct CarriedText {
    pub(crate) text: String,
    pub(crate) spans: Vec<(Range<usize>, Range<usize>)>,
}

impl RoomCarry {
    /// The carry of one save out of the room whose overlay is `room`;
    /// `None` when the room keeps no secret.
    ///
    /// # Errors
    ///
    /// A poisoned room custody lock.
    pub(crate) fn of(room: &SessionOverlay) -> Result<Option<Self>> {
        let kept = room.kept_room_secrets()?;
        Ok((!kept.is_empty()).then(|| Self {
            kept,
            moved: BTreeMap::new(),
        }))
    }

    /// `ops`, writes of this save, with each room handle a fresh row names
    /// moved (see the module notes).
    ///
    /// # Errors
    ///
    /// Custody and storage errors, and a carried row that does not encode
    /// again.
    pub(crate) fn ops_in_txn(
        &mut self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        ops: Vec<BatchOp>,
    ) -> Result<Vec<BatchOp>> {
        let mut ops = PlanOps::from_owned(ops);
        for op in ops.iter_mut() {
            let BatchOp::Put { id, data, .. } = op else {
                continue;
            };
            if !self.names_kept_handle(data) || vault.store.port_entity_present(wtxn, id)? {
                continue;
            }
            // A row that is no one MessagePack value keeps its bytes: a room
            // handle in it stays as written, naming nothing.
            let mut cursor = data.as_slice();
            let Ok(decoded) = rmpv::decode::read_value(&mut cursor) else {
                continue;
            };
            let mut tree = PlanTree(decoded);
            if !cursor.is_empty() || !self.value_in_txn(vault, wtxn, *id, &mut tree.0)? {
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

    /// `body`, the result body a saved MESSAGE of `record` names, with each
    /// room handle it holds moved (ROOM-CUSTODY-REPLY-BODIES), the body read
    /// as the door read it when the room admitted it (`Masker::mask_body`):
    /// JSON, a whole MessagePack value, or one text. A JSON field the door
    /// lifted whole holds a bare room handle, which only a JSON read finds
    /// (REVIEW-10057 round 2). `None` when it moves none; a body that is none
    /// of these keeps its bytes, and a room handle in it stays as written,
    /// naming nothing.
    ///
    /// # Errors
    ///
    /// Custody and storage errors, and a carried body that does not encode
    /// again.
    pub(crate) fn body_in_txn(
        &mut self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        record: EntityId,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if !self.names_kept_handle(body) {
            return Ok(None);
        }
        if opens_json(body)
            && let Ok(value) = serde_json::from_slice::<Value>(body)
        {
            let mut tree = PlanTree(value);
            if !self.value_in_txn(vault, wtxn, record, &mut tree.0)? {
                return Ok(None);
            }
            return serde_json::to_vec(&tree.0).map(Some).map_err(|_| {
                Error::InvariantViolation("a carried JSON result body did not encode")
            });
        }
        let mut cursor = body;
        if opens_whole_messagepack(body)
            && let Ok(decoded) = rmpv::decode::read_value(&mut cursor)
            && cursor.is_empty()
        {
            let mut tree = PlanTree(decoded);
            if !self.value_in_txn(vault, wtxn, record, &mut tree.0)? {
                return Ok(None);
            }
            let mut carried = Vec::with_capacity(body.len());
            rmpv::encode::write_value(&mut carried, &tree.0)
                .map_err(|_| Error::InvariantViolation("a carried result body did not encode"))?;
            return Ok(Some(carried));
        }
        match std::str::from_utf8(body) {
            Ok(text) => Ok(self
                .text_in_txn(vault, wtxn, record, text)?
                .map(|carried| carried.text.into_bytes())),
            Err(_) => Ok(None),
        }
    }

    /// Whether `data` holds, as written, the handle of a secret the room
    /// keeps: bare, or in a text.
    fn names_kept_handle(&self, data: &[u8]) -> bool {
        self.kept.iter().any(|secret| {
            data.windows(secret.handle.len())
                .any(|window| window == secret.handle.as_bytes())
        })
    }

    /// `value`, a value `record` writes, with each room handle in its texts
    /// moved: whether any was.
    ///
    /// # Errors
    ///
    /// Custody and storage errors.
    pub(crate) fn value_in_txn(
        &mut self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        record: EntityId,
        value: &mut Value,
    ) -> Result<bool> {
        match value {
            Value::String(text) => {
                let Some(carried) = (match text.as_str() {
                    Some(text) => self
                        .text_in_txn(vault, wtxn, record, text)?
                        .map(|carried| carried.text),
                    None => None,
                }) else {
                    return Ok(false);
                };
                *value = Value::from(carried);
                Ok(true)
            }
            Value::Binary(bytes) => {
                let Some(carried) = (match std::str::from_utf8(bytes) {
                    Ok(text) => self
                        .text_in_txn(vault, wtxn, record, text)?
                        .map(|carried| carried.text),
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
                    moved |= self.value_in_txn(vault, wtxn, record, item)?;
                }
                Ok(moved)
            }
            Value::Map(fields) => {
                let mut moved = false;
                for (key, member) in fields {
                    moved |= self.value_in_txn(vault, wtxn, record, key)?;
                    moved |= self.value_in_txn(vault, wtxn, record, member)?;
                }
                Ok(moved)
            }
            _ => Ok(false),
        }
    }

    /// `text`, a text `record` writes, with each room handle the room keeps
    /// a value under moved to its base handle, and where each moved; `None`
    /// when it moves none.
    ///
    /// # Errors
    ///
    /// Custody and storage errors.
    pub(crate) fn text_in_txn(
        &mut self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        record: EntityId,
        text: &str,
    ) -> Result<Option<CarriedText>> {
        // A whole text that is a bare room handle takes the bare base handle,
        // as a field a mask lifted whole holds one (REVIEW-10003).
        if is_room_secret_handle(text) {
            return Ok(self
                .base_handle(vault, wtxn, record, text)?
                .map(|base| CarriedText {
                    spans: vec![(0..text.len(), 0..base.len())],
                    text: base,
                }));
        }
        if !text.contains(&room_handle_open()) {
            return Ok(None);
        }
        let mut out = String::with_capacity(text.len());
        let mut spans = Vec::new();
        // `out` holds `text` up to `from`; the search goes on at `at`.
        let mut from = 0;
        let mut at = 0;
        while let Some(open) = text[at..].find(HANDLE_OPEN).map(|found| at + found) {
            let inner = open + HANDLE_OPEN.len();
            let Some(len) = text[inner..].find(']') else {
                break;
            };
            let handle = &text[inner..inner + len];
            at = inner;
            if !is_room_secret_handle(handle) {
                continue;
            }
            let Some(base) = self.base_handle(vault, wtxn, record, handle)? else {
                continue;
            };
            out.push_str(&text[from..open]);
            let carried = out.len();
            out.push_str(HANDLE_OPEN);
            out.push_str(&base);
            out.push(']');
            from = inner + len + 1;
            spans.push((open..from, carried..out.len()));
            at = from;
        }
        if spans.is_empty() {
            return Ok(None);
        }
        out.push_str(&text[from..]);
        Ok(Some(CarriedText { text: out, spans }))
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
