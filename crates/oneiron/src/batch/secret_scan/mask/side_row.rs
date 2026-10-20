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
//! [`admit_seeded_parts`] is the one core a record's own parts admit through
//! too (`admit`): a stream's text, a NOTE's body.
//!
//! A table's declaration may name the fields its rows keep structural
//! references in (FIX 6634, [`RefPath`]): the value there is read with no
//! known-value sweep, so a run id, a context domain or a type node equal to a
//! value custody holds still resolves; every shape the door's rules place is
//! placed there as anywhere else.

use std::borrow::Cow;
use std::sync::Arc;

use heed::RwTxn;
use rmpv::Value;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::super::{SecretScanMode, scan_payload, secret_scan_mode_in_txn};
use super::admit::Lifted;
pub(crate) use super::text::TextReplacements;
use super::{HANDLE_OPEN, Masker, STAND_IN, credential_member};
use crate::entity_id::{EntityId, derived_domains::SIDE_ROW_MASK};
use crate::error::{Error, Result};
use crate::secret_custody::KnownValues;
use crate::side_table::{CodecName, RefPath, RefStep, SideTableDbs, SideTableDecl};

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

    /// Replaces each secret `masker` places with its handle; whether it
    /// placed one. A value at a path in `refs` is read with no known-value
    /// sweep ([`mask_referenced`]); a text has no fields to name.
    fn mask(&mut self, masker: &mut Masker, refs: &[RefPath]) -> Result<bool> {
        Ok(match self {
            Self::Body(bytes) => mask_body(masker, bytes, refs)?.is_some_and(|masked| {
                *bytes = masked;
                true
            }),
            Self::Text(text) => masker.mask_text(text)?.is_some_and(|masked| {
                *text = masked;
                true
            }),
            Self::Value(value) => mask_referenced(masker, value, refs, true)?,
        })
    }
}

/// A body read as the batch door reads one, and each body a member carries
/// as bytes (a stored model response, an encoded definition) read as a body
/// too, so a key inside it is placed rather than refused. A value at a path
/// in `refs` is read with no known-value sweep.
fn mask_body(masker: &mut Masker, bytes: &[u8], refs: &[RefPath]) -> Result<Option<Vec<u8>>> {
    let json = serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok();
    // A JSON body with references, read member by member as
    // `Masker::mask_body` reads one, its references aside.
    if json
        && !refs.is_empty()
        && let Ok(mut tree) = serde_json::from_slice::<Value>(bytes)
    {
        if !mask_referenced(masker, &mut tree, refs, false)? {
            return Ok(None);
        }
        return serde_json::to_vec(&tree)
            .map(Some)
            .map_err(|_| Error::InvariantViolation("a masked JSON body did not encode"));
    }
    let Some(mut tree) = whole_messagepack(bytes).filter(|_| !json) else {
        return masker.mask_body(bytes);
    };
    if !mask_referenced(masker, &mut tree, refs, true)? {
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

/// `tree` read as [`mask_tree`] reads it, or, unless `nested`, by the door's
/// field rule alone, as `Masker::mask_body` reads a JSON body; but each value
/// a path in `refs` ends at is read with no known-value sweep (FIX 6634): a
/// structural reference that equals or holds a value custody holds stays as
/// written, while a shape the door's rules place in it is placed, or
/// refused, as anywhere else. With no path this is that reading exactly.
fn mask_referenced(
    masker: &mut Masker,
    tree: &mut Value,
    refs: &[RefPath],
    nested: bool,
) -> Result<bool> {
    if refs.iter().any(|path| path.is_empty()) {
        let known = masker.known.take();
        let placed = mask_plain(masker, tree, nested);
        masker.known = known;
        return placed;
    }
    if refs.is_empty() {
        return mask_plain(masker, tree, nested);
    }
    if let Value::Map(fields) = tree {
        let mut changed = false;
        for (key, member) in fields.iter_mut() {
            let under = beneath(refs, key);
            changed |= masker.mask_value(key)?;
            // A value under a credential name is read whole, path or none.
            if under.is_empty() || credential_member(key, member) {
                if nested {
                    changed |= mask_nested(masker, member)?;
                }
                changed |= masker.mask_member(key, member)?;
            } else {
                changed |= mask_referenced(masker, member, &under, nested)?;
            }
        }
        return Ok(changed);
    }
    // A path into the JSON a string member spells: that tree, read the same
    // way, and spelled again only where something was placed.
    let within: Vec<RefPath> = refs
        .iter()
        .copied()
        .filter_map(|path| match path {
            [RefStep::Json, rest @ ..] => Some(rest),
            _ => None,
        })
        .collect();
    let descriptor = match &*tree {
        Value::String(text) if !within.is_empty() => text
            .as_str()
            .and_then(|text| serde_json::from_str::<Value>(text).ok()),
        _ => None,
    };
    let Some(mut descriptor) = descriptor else {
        return mask_plain(masker, tree, nested);
    };
    if !mask_referenced(masker, &mut descriptor, &within, nested)? {
        return Ok(false);
    }
    let spelled = serde_json::to_string(&descriptor)
        .map_err(|_| Error::InvariantViolation("a masked descriptor did not encode"))?;
    *tree = Value::from(spelled);
    Ok(true)
}

/// A value no path names a reference in: [`mask_tree`]'s reading, or the
/// field rule alone unless `nested`.
fn mask_plain(masker: &mut Masker, value: &mut Value, nested: bool) -> Result<bool> {
    if nested {
        return mask_tree(masker, value);
    }
    masker.mask_value(value)
}

/// What is left of each path in `refs` that steps into the member under
/// `key`.
fn beneath(refs: &[RefPath], key: &Value) -> Vec<RefPath> {
    refs.iter()
        .copied()
        .filter_map(|path| match path {
            [RefStep::Field(name), rest @ ..] if key.as_str() == Some(*name) => Some(rest),
            _ => None,
        })
        .collect()
}

/// Each member of `value` that carries bytes, binary or an array of byte
/// values (how JSON spells them), read as a body of its own, as the door's
/// scan reads it.
fn mask_nested(masker: &mut Masker, value: &mut Value) -> Result<bool> {
    match value {
        Value::Binary(bytes) => {
            let Some(masked) = mask_body(masker, bytes, &[])? else {
                return Ok(false);
            };
            *bytes = masked;
            Ok(true)
        }
        Value::Array(items) => {
            if let Some(bytes) = byte_values(items) {
                let Some(masked) = mask_body(masker, &bytes, &[])? else {
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
    let reading = Reading::default();
    Ok(admit_read_parts(dbs, wtxn, (place, key), parts, accepts, reading)?.is_some())
}

/// [`admit_side_parts`], tracked (FIX 6144): the same pass, which also keeps
/// where each handle went in each text it masked, for a writer that indexes
/// into those texts and moves its bounds with them. `None` when the parts
/// are written as given.
pub(crate) fn admit_tracked_side_parts(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    (place, key): (&str, &[u8]),
    parts: &mut [SidePart],
    accepts: impl Fn(&[SidePart]) -> bool,
) -> Result<Option<TextReplacements>> {
    let reading = Reading {
        tracked: true,
        ..Reading::default()
    };
    admit_read_parts(dbs, wtxn, (place, key), parts, accepts, reading)
}

/// One row's `parts`, each naming the row at `place` and `key` on the custody
/// records minted from it, admitted as `reading` says.
fn admit_read_parts(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    (place, key): (&str, &[u8]),
    parts: &mut [SidePart],
    accepts: impl Fn(&[SidePart]) -> bool,
    reading: Reading,
) -> Result<Option<TextReplacements>> {
    let origins = vec![(origin(place, key)?, place); parts.len()];
    admitted(
        dbs,
        wtxn,
        &origins,
        parts,
        &mut Lifted::default(),
        accepts,
        reading,
    )
}

/// How one admission reads its parts.
#[derive(Clone, Copy, Default)]
struct Reading {
    /// The fields the row keeps structural references in (FIX 6634).
    refs: &'static [RefPath],
    /// Whether the pass keeps where each handle went in each text it masked
    /// (FIX 6144).
    tracked: bool,
}

/// The wall's one admission, for a side row and for a record's own parts
/// alike. With the owner's switch on, parts the door would refuse are
/// planned on a copy with a stand-in for each secret their spans place, and
/// the copy is read again: only a clean copy the row's own reading `accepts`
/// mints custody records, one per value. The parts then hold their handles.
/// A hit the plan leaves refuses the write with the door's reason, before
/// anything is minted.
///
/// `origins` names, for each part in turn, the record and the place each
/// custody record minted from it names. `seed` holds the handles this writer
/// minted before, by value: a value in it keeps its handle and mints
/// nothing, and each value minted here joins it. A writer that keeps it past
/// this transaction (a stream, between checkpoints) adopts the grown copy
/// only once the transaction commits. Each record is stamped with the
/// transaction's time.
pub(crate) fn admit_seeded_parts(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    origins: &[(EntityId, &str)],
    parts: &mut [SidePart],
    seed: &mut Lifted,
    accepts: impl Fn(&[SidePart]) -> bool,
) -> Result<bool> {
    Ok(admitted(dbs, wtxn, origins, parts, seed, accepts, Reading::default())?.is_some())
}

/// [`admit_seeded_parts`]' pass: `None` when the parts are written as given,
/// else, with `reading.tracked`, where each handle went in each text it
/// masked. Both the plan and the minted pass read `reading.refs`.
fn admitted(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    origins: &[(EntityId, &str)],
    parts: &mut [SidePart],
    seed: &mut Lifted,
    accepts: impl Fn(&[SidePart]) -> bool,
    reading: Reading,
) -> Result<Option<TextReplacements>> {
    if secret_scan_mode_in_txn(dbs, &*wtxn)? == SecretScanMode::Off {
        return Ok(None);
    }
    if origins.len() != parts.len() {
        return Err(Error::InvariantViolation(
            "a part the side-row wall reads names no origin",
        ));
    }
    let mut refusal = None;
    for part in parts.iter() {
        if let Err(error) = scan_payload(&part.scanned()?) {
            refusal = Some(error);
            break;
        }
    }
    // A value custody already holds keeps its own handle in a row whose
    // writer holds a custody door, shape or none (OF-560 C).
    let known = match dbs.side_custody() {
        Some(custody) => KnownValues::load_in_writer(custody.store, wtxn)?.map(Arc::new),
        None => None,
    };
    if refusal.is_none() && known.is_none() {
        return Ok(None);
    }
    let mut planned = parts.to_vec();
    let mut plan = Masker {
        handles: seed.0.clone(),
        mints: true,
        known: known.clone(),
        ..Masker::default()
    };
    let mut placed = false;
    for (part, (record, place)) in planned.iter_mut().zip(origins) {
        plan.at = Some((*record, (*place).to_owned()));
        placed |= part.mask(&mut plan, reading.refs)?;
    }
    // Nothing placed, not even a value the seed holds: the hit is the
    // door's.
    if !placed {
        return refusal.map_or(Ok(None), Err);
    }
    // A hit no span places is still in the copy, and refuses as before.
    for part in &planned {
        let _secrets_nulled = scan_payload(&part.scanned()?)?;
    }
    if !accepts(&planned) {
        return refusal.map_or(Ok(None), Err);
    }
    drop(planned);
    let Some(custody) = dbs.side_custody() else {
        return refusal.map_or(Ok(None), Err);
    };
    let at = crate::ports::recorded_at_in_txn(custody.store, wtxn)?;
    seed.0.extend(
        plan.mint(&custody, wtxn, at)?
            .into_iter()
            .map(|(value, (handle, _))| (value, handle)),
    );
    let mut minted = Masker {
        handles: seed.0.clone(),
        minted: true,
        known,
        traced: reading.tracked.then(TextReplacements::default),
        ..Masker::default()
    };
    for part in parts.iter_mut() {
        part.mask(&mut minted, reading.refs)?;
    }
    if !accepts(parts) {
        return Err(Error::InvariantViolation(
            "a side row's own reading refused the handles its plan placed",
        ));
    }
    Ok(Some(minted.traced.take().unwrap_or_default()))
}

/// One row of an authored side table, admitted at its write: `None` to
/// write `row` as given, or the row as masked. The row is read as its codec
/// lays it out (past a version byte, as JSON or MessagePack, or as text), and
/// `decodes` is the table's codec over the masked copy. Each value at one of
/// the table's declared references is read with no known-value sweep (FIX
/// 6634); a writer that admits a body its row keeps (a frozen step, FIX
/// 6637) passes that body as `row`, and `decodes` reads it.
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
    let reading = Reading {
        refs: decl.references,
        ..Reading::default()
    };
    if admit_read_parts(
        dbs,
        wtxn,
        (place.as_str(), key),
        &mut parts,
        accepts,
        reading,
    )?
    .is_none()
    {
        return Ok(None);
    }
    match &parts {
        [SidePart::Body(body)] => Ok(Some(laid_out(body))),
        _ => Err(Error::InvariantViolation(
            "a masked side row is no longer a body",
        )),
    }
}

/// A typed authored row a module writes outside a declared authored table,
/// admitted whole at its write: `value` takes the handles the wall placed, and
/// `true` says it placed one. The masked copy must read back as a `T`.
pub(crate) fn admit_typed<T: Serialize + DeserializeOwned>(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    at: (&str, &[u8]),
    value: &mut T,
) -> Result<bool> {
    let mut parts = [SidePart::Value(named_tree(&*value)?)];
    let reads_back = |parts: &[SidePart]| matches!(parts, [SidePart::Value(tree)] if from_named_tree::<T>(tree).is_some());
    if !admit_side_parts(dbs, wtxn, at, &mut parts, reads_back)? {
        return Ok(false);
    }
    *value = match &parts {
        [SidePart::Value(tree)] => from_named_tree(tree),
        _ => None,
    }
    .ok_or(Error::InvariantViolation(
        "a masked side row does not read back",
    ))?;
    Ok(true)
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
