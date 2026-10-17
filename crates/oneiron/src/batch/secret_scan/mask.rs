//! Mask on write (OF-560; ARCH-0069 #mask-on-write and #handles-in-fields,
//! owner ruling G04 = A): a secret the batch door finds in text or in a
//! structured field goes to custody, and the text or field keeps its handle.
//! A span of text becomes `[secret sc12]`; a value under a credential name
//! becomes `sc12`. The rest of the write is kept.
//!
//! A file (an ASSET, named by its bytes) keeps its bytes as they are (owner
//! ruling G04 binary = C2): each key in it goes to custody, and the file is
//! marked with each key's span and the Restricted band; serving doors read
//! that mark (`secret_custody::masked_files`). A key in a container's member
//! (a ZIP entry, a gzip payload, a PDF stream) is marked at its span in the
//! decoded member, and the plan's copy is rebuilt around it as a serving
//! door's is (OF-067 C, `container`).
//!
//! What the door finds but cannot place still refuses the whole write: a
//! recovery phrase, a key split over members, an entity the engine itself
//! authors or a peer replicated, and a replayed batch. A plan runs first on
//! a copy, with a stand-in handle for each secret and each file's keys
//! overwritten, and the door reads that copy again; only a clean copy mints
//! custody records.

pub(super) mod admit;
pub(super) mod side_row;

use std::collections::HashMap;
use std::ops::Range;

use heed::RwTxn;
use rmpv::Value;

use super::container::{
    self, MAX_FILE_KEYS, REASON_OVER_BUDGET, Stop, holds_spans, masked_copy, walk_members,
};
use super::shapes::{self, Door, HANDLE_OPEN};
use super::{REASON_PRIVATE_KEY, provider_token_spans, scan_batch_ops, secret_scan_error};
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::ShortIdStoreRead;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SECRET_CUSTODY};
use crate::secret_custody::{
    CustodyClass, CustodyWrite, KeyPlaces, KeySpan, MASKED_FILE_BAND, MaskedFile, MemberKeys,
    MemberStep, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
    SecretCustodyStatus, masked_file_in_txn, put_masked_file_in_txn, register_custody_in_txn,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const REASON_BLOCKLIST: &str = "gate.secret_scan.blocklist";
const REASON_SENSITIVE_ENV: &str = "gate.secret_scan.sensitive_env";
/// The handle a plan leaves: any `sc` handle reads the same to the door.
const STAND_IN: &str = "sc0";

/// Where a mask on write found the secret one custody record holds. Key:
/// the custody record's id.
const MASK_ORIGIN: SideTable<EntityId, MaskOrigin, Named> =
    SideTable::new(&side_table::SECRET_MASK_ORIGIN);

/// One masked secret's origin. It holds no value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct MaskOrigin {
    /// The record whose text or field held the value; for a row outside the
    /// entity tables, an id derived from its place and key (`side_row`).
    pub(crate) record: EntityId,
    /// The scan's reason code: the key's kind.
    pub(crate) reason: String,
    /// Where in the record: `body`, `claim`, `text:<field>` or `file`; for a
    /// row outside the entity tables, `side:<table>`, `attempt` or `intake`.
    pub(crate) place: String,
    pub(crate) masked_at: u64,
}

/// Where a mask on write lifted the secret custody record `id` holds, read
/// in `txn`; `None` for a record an owner registered. A handle's `describe`
/// names it (OF-560).
pub(crate) fn mask_origin_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<MaskOrigin>> {
    MASK_ORIGIN.get(store, txn, id)
}

/// The batch door with mask on write. `masks` is false for a replayed batch,
/// which keeps the plain door: a hit refuses it, save in a file marked
/// before. `at` stamps each custody record the batch mints.
#[expect(
    clippy::too_many_arguments,
    reason = "the batch's own apply parts, its origin and its time"
)]
pub(in crate::batch) fn mask_batch_ops(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: &mut [BatchOp],
    text_index_trusted: bool,
    masks: bool,
    at: u64,
) -> Result<MaskedFiles> {
    let refusal = match scan_batch_ops(store, &*wtxn, ops) {
        Ok(()) => return Ok(MaskedFiles::default()),
        Err(refusal) => refusal,
    };
    let mut planned = ops.to_vec();
    let mut plan = Masker {
        marked: marked_files(store, &*wtxn, ops)?,
        mints: masks,
        ..Masker::default()
    };
    plan.mask_ops(&mut planned)?;
    if plan.found.is_empty() && plan.file_ids.is_empty() {
        return Err(refusal);
    }
    // A hit no span places is still in the copy, and refuses as before.
    scan_batch_ops(store, &*wtxn, &planned)?;
    drop(planned);
    let files = std::mem::take(&mut plan.files);
    let masked = MaskedFiles(std::mem::take(&mut plan.file_ids));
    if !masks {
        return Ok(masked);
    }
    let write = CustodyWrite {
        store,
        config,
        analyzer,
        text_index_trusted,
    };
    let minted = plan.mint(&write, wtxn, at)?;
    for file in files {
        let mut mark = MaskedFile {
            band: MASKED_FILE_BAND,
            keys: Vec::new(),
            masked_at: at,
            members: Vec::new(),
        };
        for key in file.keys {
            let (_, custody) = minted.get(&key.value).ok_or(Error::InvariantViolation(
                "a file's key has no custody record",
            ))?;
            let span = KeySpan {
                start: offset(key.span.start)?,
                end: offset(key.span.end)?,
                custody: *custody,
                reason: key.reason.to_owned(),
            };
            if key.path.is_empty() {
                mark.keys.push(span);
            } else if let Some(member) = mark
                .members
                .iter_mut()
                .find(|member| member.path == key.path)
            {
                member.keys.push(span);
            } else {
                mark.members.push(MemberKeys {
                    path: key.path,
                    keys: vec![span],
                });
            }
        }
        put_masked_file_in_txn(store, wtxn, &file.hash, &mark)?;
    }
    Masker {
        handles: minted
            .into_iter()
            .map(|(value, (handle, _))| (value, handle))
            .collect(),
        minted: true,
        ..Masker::default()
    }
    .mask_ops(ops)?;
    Ok(masked)
}

/// The files a batch stored with keys in them. Once the batch has stamped
/// each record, [`MaskedFiles::restrict`] raises a stamped one's band.
#[derive(Default)]
#[must_use]
pub(in crate::batch) struct MaskedFiles(Vec<EntityId>);

impl MaskedFiles {
    pub(in crate::batch) fn restrict(self, store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
        for id in self.0 {
            crate::federation::record_scope::restrict_stamp_in_txn(
                store,
                wtxn,
                id,
                MASKED_FILE_BAND,
            )?;
        }
        Ok(())
    }
}

/// The key places already recorded for each file a batch puts, by its
/// bytes' hash: a file put again keeps its mark and mints nothing.
fn marked_files(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    ops: &[BatchOp],
) -> Result<HashMap<[u8; 32], KeyPlaces>> {
    let mut marked = HashMap::new();
    for op in ops {
        if let BatchOp::Put {
            entity_type, data, ..
        } = op
            && *entity_type == ENTITY_TYPE_ASSET
        {
            let hash = *blake3::hash(data).as_bytes();
            if let Some(file) = masked_file_in_txn(store, txn, &hash)? {
                marked.insert(hash, file.places());
            }
        }
    }
    Ok(marked)
}

fn offset(at: usize) -> Result<u64> {
    u64::try_from(at).map_err(|_| Error::ArithmeticOverflow("masked file key span"))
}

/// One file a plan marks, before custody holds its keys.
struct FoundFile {
    hash: [u8; 32],
    keys: Vec<FileKey>,
}

/// One key a plan found in a file: the member that holds it (none for the
/// file's own bytes), its span there, and the key's kind and value.
struct FileKey {
    path: Vec<MemberStep>,
    span: Range<usize>,
    reason: &'static str,
    value: Vec<u8>,
}

/// Each place `keys` sit at, with its spans, in the order they were found.
fn places_of(keys: &[FileKey]) -> Result<KeyPlaces> {
    let mut places: KeyPlaces = Vec::new();
    for key in keys {
        let span = (offset(key.span.start)?, offset(key.span.end)?);
        match places.iter_mut().find(|(path, _)| *path == key.path) {
            Some((_, spans)) => spans.push(span),
            None => places.push((key.path.clone(), vec![span])),
        }
    }
    Ok(places)
}

/// One secret a plan found, before custody holds it.
struct Found {
    value: Vec<u8>,
    reason: &'static str,
    record: EntityId,
    place: String,
}

/// A pass over a batch's ops. A plan hands each new value a stand-in and
/// keeps it once; a minted pass reads each value's custody handle. A plan
/// that `mints` nothing (a replayed batch) only reads files marked before.
#[derive(Default)]
struct Masker {
    handles: HashMap<Vec<u8>, String>,
    found: Vec<Found>,
    minted: bool,
    mints: bool,
    /// Each file's key places by its bytes' hash: marked before, or by this
    /// plan.
    marked: HashMap<[u8; 32], KeyPlaces>,
    /// The files this plan marks.
    files: Vec<FoundFile>,
    /// Every file put that carries a mark.
    file_ids: Vec<EntityId>,
    /// The record and place the pass reads now.
    at: Option<(EntityId, String)>,
}

impl Masker {
    fn mask_ops(&mut self, ops: &mut [BatchOp]) -> Result<()> {
        for op in ops {
            match op {
                // A file keeps its bytes, whoever wrote them; the plan's copy
                // reads with its keys overwritten.
                BatchOp::Put {
                    id,
                    entity_type,
                    data,
                    ..
                } if *entity_type == ENTITY_TYPE_ASSET => {
                    if self.minted {
                        continue;
                    }
                    self.at = Some((*id, "file".to_owned()));
                    if let Some(copy) = self.mark_file(*id, data)? {
                        *data = copy;
                    }
                }
                _ if !self.mints && !self.minted => {}
                // An engine-authored or replicated body keeps the plain door:
                // its writer, not this door, owns its bytes. A custody body
                // is the value's home.
                BatchOp::Put {
                    id,
                    entity_type,
                    data,
                    allow_maintenance: false,
                    hub_sync_imported: false,
                    ..
                } if !matches!(*entity_type, ENTITY_TYPE_SECRET_CUSTODY | ENTITY_TYPE_ASSET) => {
                    self.at = Some((*id, "body".to_owned()));
                    if let Some(masked) = self.mask_body(data)? {
                        *data = masked;
                    }
                }
                BatchOp::ClaimCandidate { id, candidate, .. } => {
                    self.at = Some((*id, "claim".to_owned()));
                    for value in candidate.values_mut() {
                        self.mask_value(value)?;
                    }
                }
                BatchOp::Text { id, fields } => {
                    for (name, value) in fields.iter_mut() {
                        self.at = Some((*id, format!("text:{name}")));
                        if let Some(masked) = self.mask_text(value)? {
                            *value = masked;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// A file's keys, found in its bytes and in each member of a container
    /// in it: the copy the door reads again, rebuilt with each key
    /// overwritten where it sits. `None` when it holds none.
    fn mark_file(&mut self, id: EntityId, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let hash = *blake3::hash(data).as_bytes();
        if let Some(places) = self.marked.get(&hash) {
            self.file_ids.push(id);
            return masked_copy(data, places).map(Some);
        }
        if !self.mints {
            return Ok(None);
        }
        let mut keys = Vec::new();
        if holds_spans(data) {
            self.place(&[], data, &mut keys)?;
        }
        let mut visit = |path: &[MemberStep], member: &[u8]| -> std::result::Result<(), Stop> {
            if holds_spans(member) {
                self.place(path, member, &mut keys)?;
            }
            Ok(())
        };
        walk_members(data, &mut visit).map_err(container::refusal)?;
        if keys.is_empty() {
            return Ok(None);
        }
        let places = places_of(&keys)?;
        // The copy a serving door would rebuild; the door reads it again
        // before custody is minted.
        let copy = masked_copy(data, &places)?;
        self.marked.insert(hash, places);
        self.file_ids.push(id);
        self.files.push(FoundFile { hash, keys });
        Ok(Some(copy))
    }

    /// The keys the door's text and field rules place in `leaf` (a file's
    /// own bytes, or one member's), each at `path`.
    fn place(&mut self, path: &[MemberStep], leaf: &[u8], keys: &mut Vec<FileKey>) -> Result<()> {
        let mut spans = file_spans(leaf);
        // A value a structured reading places (a credential field), wherever
        // its bytes sit in the leaf.
        let mut fields = Masker {
            mints: true,
            at: self.at.clone(),
            ..Masker::default()
        };
        fields.mask_body(leaf)?;
        for found in fields.found {
            spans.extend(occurrences(leaf, &found.value).map(|span| (span, found.reason)));
        }
        for (span, reason) in merged(spans) {
            let value = leaf
                .get(span.clone())
                .ok_or(Error::InvariantViolation(
                    "a file's key span left its bytes",
                ))?
                .to_vec();
            self.handle(&value, reason)?;
            keys.push(FileKey {
                path: path.to_vec(),
                span,
                reason,
                value,
            });
        }
        if keys.len() > MAX_FILE_KEYS {
            return Err(secret_scan_error(REASON_OVER_BUDGET));
        }
        Ok(())
    }

    /// A body read as the door reads it: JSON, a whole MessagePack value, or
    /// text. `None` when nothing in it was placed.
    fn mask_body(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Ok(mut value) = serde_json::from_slice::<Value>(data) {
            if !self.mask_value(&mut value)? {
                return Ok(None);
            }
            return serde_json::to_vec(&value)
                .map(Some)
                .map_err(|_| Error::InvariantViolation("a masked JSON body did not encode"));
        }
        let mut cursor = std::io::Cursor::new(data);
        if let Ok(mut value) = rmpv::decode::read_value(&mut cursor)
            && cursor.position() == data.len() as u64
        {
            if !self.mask_value(&mut value)? {
                return Ok(None);
            }
            let mut out = Vec::with_capacity(data.len());
            rmpv::encode::write_value(&mut out, &value).map_err(|_| {
                Error::InvariantViolation("a masked MessagePack body did not encode")
            })?;
            return Ok(Some(out));
        }
        match std::str::from_utf8(data) {
            Ok(text) => Ok(self.mask_text(text)?.map(String::into_bytes)),
            Err(_) => Ok(None),
        }
    }

    /// Every string, byte string and map key in `value`, and each value under
    /// a credential name whole, as the write door's field rule reads it.
    fn mask_value(&mut self, value: &mut Value) -> Result<bool> {
        match value {
            Value::String(text) => {
                let masked = match text.as_str() {
                    Some(text) => self.mask_text(text)?,
                    None => None,
                };
                Ok(masked.is_some_and(|masked| {
                    *text = masked.into();
                    true
                }))
            }
            Value::Binary(bytes) => {
                let masked = match std::str::from_utf8(bytes) {
                    Ok(text) => self.mask_text(text)?,
                    Err(_) => None,
                };
                Ok(masked.is_some_and(|masked| {
                    *bytes = masked.into_bytes();
                    true
                }))
            }
            Value::Array(items) => {
                let mut changed = false;
                for item in items {
                    changed |= self.mask_value(item)?;
                }
                Ok(changed)
            }
            Value::Map(fields) => {
                let mut changed = false;
                for (key, member) in fields.iter_mut() {
                    changed |= self.mask_value(key)?;
                    let whole = key.as_str().is_some_and(shapes::sensitive_key)
                        && !member.is_nil()
                        && !member
                            .as_str()
                            .is_some_and(|text| shapes::field_placeholder(text, Door::Write));
                    if !whole {
                        changed |= self.mask_value(member)?;
                        continue;
                    }
                    let secret = match &*member {
                        Value::String(text) => text.as_bytes().to_vec(),
                        Value::Binary(bytes) => bytes.clone(),
                        other => {
                            let mut bytes = Vec::new();
                            rmpv::encode::write_value(&mut bytes, other).map_err(|_| {
                                Error::InvariantViolation("a credential field did not encode")
                            })?;
                            bytes
                        }
                    };
                    *member = Value::from(self.handle(&secret, REASON_SENSITIVE_ENV)?);
                    changed = true;
                }
                Ok(changed)
            }
            _ => Ok(false),
        }
    }

    /// `text` with each secret span the door's text rules place replaced by
    /// its handle. `None` when it holds none.
    fn mask_text(&mut self, text: &str) -> Result<Option<String>> {
        let spans = secret_spans(text);
        if spans.is_empty() {
            return Ok(None);
        }
        let mut out = String::with_capacity(text.len());
        let mut from = 0;
        for (span, reason) in spans {
            out.push_str(&text[from..span.start]);
            let handle = self.handle(text[span.clone()].as_bytes(), reason)?;
            out.push_str(HANDLE_OPEN);
            out.push_str(&handle);
            out.push(']');
            from = span.end;
        }
        out.push_str(&text[from..]);
        Ok(Some(out))
    }

    /// The handle `value` takes: one per distinct value in a batch.
    fn handle(&mut self, value: &[u8], reason: &'static str) -> Result<String> {
        if let Some(handle) = self.handles.get(value) {
            return Ok(handle.clone());
        }
        if self.minted {
            return Err(Error::InvariantViolation(
                "mask on write met a secret its plan did not",
            ));
        }
        let (record, place) = self
            .at
            .clone()
            .ok_or(Error::InvariantViolation("mask on write read no record"))?;
        self.handles.insert(value.to_vec(), STAND_IN.to_owned());
        self.found.push(Found {
            value: value.to_vec(),
            reason,
            record,
            place,
        });
        Ok(STAND_IN.to_owned())
    }

    /// Registers each found value as its own active custody record, in the
    /// batch's transaction, with no binding: no effector reads it until the
    /// owner grants one. Its `sc` handle is the record's short id. Each value
    /// maps to its handle and its record.
    fn mint(
        self,
        write: &CustodyWrite<'_>,
        wtxn: &mut RwTxn<'_>,
        at: u64,
    ) -> Result<HashMap<Vec<u8>, (String, EntityId)>> {
        let floor = SecretCustodyFloor::resolve(write.store, &*wtxn)?;
        let mut handles = HashMap::with_capacity(self.found.len());
        for found in self.found {
            let id = write.store.clock.entity_id()?;
            let mut rec = SecretCustodyRecord {
                schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
                name: format!("masked/{}", id.to_hex()),
                class: CustodyClass::CustodyPortable,
                device_only: false,
                value_bytes: found.value,
                status: SecretCustodyStatus::Active,
                registered_at: at,
                rotated_at: None,
                rotation_generation: 0,
                bindings: Vec::new(),
                manifest_ref: String::new(),
                declared_paths: Vec::new(),
                policy_floor_snapshot: floor.clone(),
            };
            register_custody_in_txn(write, wtxn, &id, &mut rec)?;
            let handle = write
                .store
                .port_short_id_reference(&*wtxn, &id)?
                .map(|(short_id, _)| short_id)
                .ok_or(Error::InvariantViolation(
                    "a masked secret's record has no handle",
                ))?;
            MASK_ORIGIN.put(
                write.store,
                wtxn,
                &id,
                &MaskOrigin {
                    record: found.record,
                    reason: found.reason.to_owned(),
                    place: found.place,
                    masked_at: at,
                },
            )?;
            handles.insert(std::mem::take(&mut rec.value_bytes), (handle, id));
        }
        Ok(handles)
    }
}

/// The spans of `text` the write door's text rules place, merged where they
/// meet, in order: a private-key block, a blocklist entry, a provider key
/// token, and an assigned value under a credential name. A recovery phrase is
/// not placed.
fn secret_spans(text: &str) -> Vec<(Range<usize>, &'static str)> {
    let spans: Vec<(Range<usize>, &'static str)> = shapes::private_key_block_spans(text)
        .into_iter()
        .map(|span| (span, REASON_PRIVATE_KEY))
        .chain(
            shapes::blocklist_spans(text)
                .into_iter()
                .map(|span| (span, REASON_BLOCKLIST)),
        )
        .chain(provider_token_spans(text))
        .chain(
            shapes::assignment_spans(text)
                .into_iter()
                .map(|span| (span, REASON_SENSITIVE_ENV)),
        )
        .collect();
    merged(spans)
}

/// The spans the door's text rules place in each run of text in a file, at
/// their offsets in its bytes.
fn file_spans(data: &[u8]) -> Vec<(Range<usize>, &'static str)> {
    let mut spans = Vec::new();
    let mut at = 0;
    while let Some(rest) = data.get(at..).filter(|rest| !rest.is_empty()) {
        let (valid, skip) = match std::str::from_utf8(rest) {
            Ok(_) => (rest.len(), 0),
            Err(error) => (
                error.valid_up_to(),
                error
                    .error_len()
                    .unwrap_or(rest.len() - error.valid_up_to()),
            ),
        };
        if let Some(text) = rest
            .get(..valid)
            .and_then(|run| std::str::from_utf8(run).ok())
        {
            spans.extend(
                secret_spans(text)
                    .into_iter()
                    .map(|(span, reason)| (span.start + at..span.end + at, reason)),
            );
        }
        at += valid + skip;
    }
    spans
}

/// Every place `value`'s bytes sit in `data`.
fn occurrences<'a>(data: &'a [u8], value: &'a [u8]) -> impl Iterator<Item = Range<usize>> + 'a {
    data.windows(value.len().max(1))
        .enumerate()
        .filter(move |(_, window)| !value.is_empty() && *window == value)
        .map(move |(at, _)| at..at + value.len())
}

/// `spans` in order, merged where they meet; the first span's reason names
/// a merged one.
fn merged(mut spans: Vec<(Range<usize>, &'static str)>) -> Vec<(Range<usize>, &'static str)> {
    spans.retain(|(span, _)| !span.is_empty());
    spans.sort_by_key(|(span, _)| (span.start, std::cmp::Reverse(span.end)));
    let mut merged: Vec<(Range<usize>, &'static str)> = Vec::with_capacity(spans.len());
    for (span, reason) in spans {
        match merged.last_mut() {
            Some((last, _)) if span.start <= last.end => last.end = last.end.max(span.end),
            _ => merged.push((span, reason)),
        }
    }
    merged
}
