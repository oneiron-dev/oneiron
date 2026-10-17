//! The side-row wall (OF-067; ARCH-0069 #mask-on-write and
//! #handles-in-fields, owner ruling G04 = A). A row a module writes outside
//! the batch door is read by that door's rules before it is stored: a row of
//! a side table the catalog classes as authored, an attempt record's payload
//! and notes, an intake event. A secret the mask places goes to custody in the
//! writer's own transaction, and the row keeps its handle where the secret
//! was. A hit the mask cannot place refuses the write with the scan's error:
//! a recovery phrase, a key split over members, bytes no reading takes (an
//! opaque codec), a masked copy the row's own codec refuses, or a writer whose
//! target holds no custody door. With the owner's switch off the row is
//! written as given, as the batch door skips its scan.
//!
//! The custody records a mask mints go through their own door, into tables
//! the catalog does not class as authored, so nothing here reads them again.

use std::borrow::Cow;

use heed::RwTxn;
use rmpv::Value;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::super::{SecretScanMode, scan_payload, secret_scan_mode_in_txn};
use super::{HANDLE_OPEN, Masker, STAND_IN};
use crate::entity_id::{EntityId, derived_domains::SIDE_ROW_MASK};
use crate::error::{Error, Result};
use crate::side_table::{CodecName, SideTableDbs, SideTableDecl};

/// One part of a row the wall reads.
#[derive(Debug, Clone)]
pub(crate) enum SidePart {
    /// Bytes read as the batch door reads a body: JSON, a whole MessagePack
    /// value, or text.
    Body(Vec<u8>),
    /// Text, read by the door's text rules.
    Text(String),
    /// A structured value, read member by member, and a value under a
    /// credential name whole.
    Value(Value),
}

impl SidePart {
    /// The bytes the door scans.
    fn scanned(&self) -> Result<Cow<'_, [u8]>> {
        Ok(match self {
            Self::Body(bytes) => Cow::Borrowed(bytes.as_slice()),
            Self::Text(text) => Cow::Borrowed(text.as_bytes()),
            Self::Value(value) => Cow::Owned(encoded(value)?),
        })
    }

    /// Replaces each secret `masker` places with its handle.
    fn mask(&mut self, masker: &mut Masker) -> Result<()> {
        match self {
            Self::Body(bytes) => {
                if let Some(masked) = mask_body(masker, bytes)? {
                    *bytes = masked;
                }
            }
            Self::Text(text) => {
                if let Some(masked) = masker.mask_text(text)? {
                    *text = masked;
                }
            }
            Self::Value(value) => {
                mask_tree(masker, value)?;
            }
        }
        Ok(())
    }
}

/// A body read as the batch door reads one, and each body a member carries
/// as bytes (a stored model response, an encoded definition) read as a body
/// too, so a key inside it is placed rather than refused.
fn mask_body(masker: &mut Masker, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let json = serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok();
    let Some(mut tree) = whole_messagepack(bytes).filter(|_| !json) else {
        return masker.mask_body(bytes);
    };
    if !mask_tree(masker, &mut tree)? {
        return Ok(None);
    }
    encoded(&tree).map(Some)
}

/// The bodies `tree`'s byte members carry, then the door's rules over the
/// whole tree; whether anything was placed.
fn mask_tree(masker: &mut Masker, tree: &mut Value) -> Result<bool> {
    let nested = mask_nested(masker, tree)?;
    Ok(masker.mask_value(tree)? | nested)
}

/// Each member of `value` that carries bytes, binary or an array of byte
/// values (how JSON spells them), read as a body of its own, as the door's
/// scan reads it.
fn mask_nested(masker: &mut Masker, value: &mut Value) -> Result<bool> {
    match value {
        Value::Binary(bytes) => {
            let Some(masked) = mask_body(masker, bytes)? else {
                return Ok(false);
            };
            *bytes = masked;
            Ok(true)
        }
        Value::Array(items) => {
            if let Some(bytes) = byte_values(items) {
                let Some(masked) = mask_body(masker, &bytes)? else {
                    return Ok(false);
                };
                *items = masked.into_iter().map(Value::from).collect();
                return Ok(true);
            }
            let mut changed = false;
            for item in items {
                changed |= mask_nested(masker, item)?;
            }
            Ok(changed)
        }
        Value::Map(fields) => {
            let mut changed = false;
            for (_, member) in fields {
                changed |= mask_nested(masker, member)?;
            }
            Ok(changed)
        }
        _ => Ok(false),
    }
}

/// An array's items as bytes, when there are some and every one is a byte
/// value.
fn byte_values(items: &[Value]) -> Option<Vec<u8>> {
    if items.is_empty() {
        return None;
    }
    items
        .iter()
        .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect()
}

/// `bytes` as one whole MessagePack value.
fn whole_messagepack(bytes: &[u8]) -> Option<Value> {
    let mut cursor = std::io::Cursor::new(bytes);
    rmpv::decode::read_value(&mut cursor)
        .ok()
        .filter(|_| cursor.position() == bytes.len() as u64)
}

fn encoded(tree: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, tree)
        .map_err(|_| Error::InvariantViolation("a masked side row did not encode"))?;
    Ok(out)
}

/// Admits one row's `parts` in the writer's transaction: `false` when they
/// are written as given (the switch is off, or the door finds nothing),
/// `true` when each secret in them now reads as its handle. `accepts` is the
/// row's own reading of a masked copy (its codec or its type); a copy it
/// refuses is a hit the mask cannot place. `place` and `key` name the row on
/// each custody record's origin.
pub(crate) fn admit_side_parts(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    (place, key): (&str, &[u8]),
    parts: &mut [SidePart],
    accepts: impl Fn(&[SidePart]) -> bool,
) -> Result<bool> {
    if secret_scan_mode_in_txn(dbs, &*wtxn)? == SecretScanMode::Off {
        return Ok(false);
    }
    let mut refusal = None;
    for part in parts.iter() {
        if let Err(error) = scan_payload(&part.scanned()?) {
            refusal = Some(error);
            break;
        }
    }
    let Some(refusal) = refusal else {
        return Ok(false);
    };
    let mut planned = parts.to_vec();
    let mut plan = Masker {
        mints: true,
        at: Some((origin(place, key)?, place.to_owned())),
        ..Masker::default()
    };
    for part in &mut planned {
        part.mask(&mut plan)?;
    }
    if plan.found.is_empty() {
        return Err(refusal);
    }
    // A hit no span places is still in the copy, and refuses as before.
    for part in &planned {
        let _secrets_nulled = scan_payload(&part.scanned()?)?;
    }
    if !accepts(&planned) {
        return Err(refusal);
    }
    drop(planned);
    let Some(custody) = dbs.side_custody() else {
        return Err(refusal);
    };
    let at = custody.store.clock.now_recorded_at();
    let mut minted = Masker {
        handles: plan
            .mint(&custody, wtxn, at)?
            .into_iter()
            .map(|(value, (handle, _))| (value, handle))
            .collect(),
        minted: true,
        ..Masker::default()
    };
    for part in parts.iter_mut() {
        part.mask(&mut minted)?;
    }
    if !accepts(parts) {
        return Err(Error::InvariantViolation(
            "a side row's own reading refused the handles its plan placed",
        ));
    }
    Ok(true)
}

/// One row of an authored side table, admitted at its write: `None` to
/// write `row` as given, or the row as masked. The row is read as its codec
/// lays it out (past a version byte, as JSON or MessagePack, or as text), and
/// `decodes` is the table's codec over the masked copy.
pub(crate) fn admit_side_row(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    decl: &SideTableDecl,
    key: &[u8],
    row: &[u8],
    decodes: impl Fn(&[u8]) -> bool,
) -> Result<Option<Vec<u8>>> {
    let (version, body) = match decl.codec {
        CodecName::VersionedNamed => row.split_at(row.len().min(1)),
        CodecName::Named | CodecName::LegacyJson | CodecName::LegacyCompact | CodecName::Raw => {
            (&[][..], row)
        }
    };
    let laid_out = |body: &[u8]| [version, body].concat();
    let accepts = |parts: &[SidePart]| match parts {
        [SidePart::Body(body)] => decodes(&laid_out(body)),
        _ => false,
    };
    let mut parts = [SidePart::Body(body.to_vec())];
    let place = format!("side:{}", decl.name);
    if !admit_side_parts(dbs, wtxn, (place.as_str(), key), &mut parts, accepts)? {
        return Ok(None);
    }
    match &parts {
        [SidePart::Body(body)] => Ok(Some(laid_out(body))),
        _ => Err(Error::InvariantViolation(
            "a masked side row is no longer a body",
        )),
    }
}

/// Whether `held`, a value the wall may have masked, is what admitting `raw`
/// stored: a replay that compares a held row with the value offered again.
/// Each handle on either side reads as the plan's one stand-in, so a secret
/// the wall lifted matches the same secret offered again. Nothing is minted.
pub(crate) fn admitted_from(held: &Value, raw: &Value) -> Result<bool> {
    if held == raw {
        return Ok(true);
    }
    let mut planned = raw.clone();
    Masker {
        mints: true,
        at: Some((origin("replay", &[])?, "replay".to_owned())),
        ..Masker::default()
    }
    .mask_value(&mut planned)?;
    let mut held = held.clone();
    stand_in_handles(&mut held);
    stand_in_handles(&mut planned);
    Ok(held == planned)
}

/// `value` as a MessagePack tree that keeps its field names, as a named row
/// stores it, for the wall's field rule.
pub(crate) fn named_tree<T: Serialize>(value: &T) -> Result<Value> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|_| Error::InvariantViolation("a side row did not encode as a tree"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| Error::InvariantViolation("a side row did not encode as a tree"))
}

/// The value a [`named_tree`] spells; `None` when it no longer reads as one.
pub(crate) fn from_named_tree<T: DeserializeOwned>(tree: &Value) -> Option<T> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, tree).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}

/// Every handle in `value`, a whole `sc12` or `[secret sc12]` in text,
/// spelled as the plan's stand-in.
fn stand_in_handles(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some(spelled) = text.as_str().map(stand_in_text) {
                *text = spelled.into();
            }
        }
        Value::Binary(bytes) => {
            if let Ok(spelled) = std::str::from_utf8(bytes).map(stand_in_text) {
                *bytes = spelled.into_bytes();
            }
        }
        Value::Array(items) => items.iter_mut().for_each(stand_in_handles),
        Value::Map(fields) => {
            for (key, member) in fields {
                stand_in_handles(key);
                stand_in_handles(member);
            }
        }
        _ => {}
    }
}

fn stand_in_text(text: &str) -> String {
    if bare_handle(text) {
        return STAND_IN.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(HANDLE_OPEN) {
        out.push_str(&rest[..at]);
        out.push_str(HANDLE_OPEN);
        let after = &rest[at + HANDLE_OPEN.len()..];
        rest = match after.split_once(']') {
            Some((handle, tail)) if bare_handle(handle) => {
                out.push_str(STAND_IN);
                out.push(']');
                tail
            }
            _ => after,
        };
    }
    out.push_str(rest);
    out
}

/// `sc` and digits: a custody handle.
fn bare_handle(text: &str) -> bool {
    text.strip_prefix("sc").is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// The record a custody origin names for a row no entity holds: derived from
/// where the row is and its key.
fn origin(place: &str, key: &[u8]) -> Result<EntityId> {
    EntityId::derive(SIDE_ROW_MASK, &[place.as_bytes(), key])
}
