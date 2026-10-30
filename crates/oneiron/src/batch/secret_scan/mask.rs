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
mod batch_door;
mod body;
pub(super) mod carrier;
// An escaped key's span (FIX 1369).
mod escaped_span;
mod file_plane;
pub(super) mod known_marks;
mod known_note;
mod leaf_keys;
pub(super) mod retained_repo;
pub(super) mod side_row;
pub(super) mod spool;
pub(super) mod stream_known;
mod text;
mod text_spans;
mod wipe;

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

use heed::RwTxn;
use rmpv::Value;
use zeroize::{Zeroize, Zeroizing};

use super::container::{self, Stop, holds_spans, is_sealed, masked_copy, walk_members};
use super::scan_batch_ops;
use super::shapes::{self, Door, HANDLE_OPEN};
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::ShortIdStoreRead;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SECRET_CUSTODY};
use crate::secret_custody::{
    CustodyClass, CustodyWrite, FoundNote, KeptValues, KeyPlaces, KeySpan, KnownValues,
    MASKED_FILE_BAND, MaskedFile, MemberStep, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus, masked_file_in_txn, note_found_keys_in_txn,
    put_masked_file_in_txn, register_custody_in_txn,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::write_envelope::ClaimCandidate;
pub(in crate::batch) use batch_door::mask_batch_ops;
use text_spans::{file_spans, merged, occurrences, secret_spans};
use wipe::{PlanOps, PlanValues, replace_wiped};

const REASON_BLOCKLIST: &str = "gate.secret_scan.blocklist";
const REASON_SENSITIVE_ENV: &str = "gate.secret_scan.sensitive_env";
/// A file's key that custody already holds (OF-560 C): it keeps that record.
pub(super) const REASON_KNOWN_VALUE: &str = "gate.secret_scan.known_value";
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

/// Records each file `files` marks: each key's span, in the file's bytes or
/// in the member that holds it, with the custody record `minted` holds it in
/// or the record custody held it in before, and the file's band.
fn put_file_marks_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    files: Vec<FoundFile>,
    minted: &PlanValues<(String, EntityId)>,
    at: u64,
) -> Result<()> {
    for file in files {
        // A file marked before keeps its marks; the values found since are
        // marked beside them (FIX 2781).
        let mut mark = masked_file_in_txn(store, wtxn, &file.hash)?.unwrap_or(MaskedFile {
            band: MASKED_FILE_BAND,
            keys: Vec::new(),
            masked_at: at,
            members: Vec::new(),
        });
        for key in file.keys {
            let custody = match key.custody {
                Some(custody) => custody,
                None => {
                    minted
                        .get(&key.value)
                        .ok_or(Error::InvariantViolation(
                            "a file's key has no custody record",
                        ))?
                        .1
                }
            };
            let span = KeySpan {
                start: offset(key.span.start)?,
                end: offset(key.span.end)?,
                custody,
                reason: key.reason.to_owned(),
            };
            mark.unite(&key.path, span);
        }
        put_masked_file_in_txn(store, wtxn, &file.hash, &mark)?;
    }
    Ok(())
}

/// The record a batch op writes, as the mask's places name it.
fn op_record(op: &BatchOp) -> Option<EntityId> {
    match op {
        BatchOp::Put { id, .. } | BatchOp::ClaimCandidate { id, .. } | BatchOp::Text { id, .. } => {
            Some(*id)
        }
        _ => None,
    }
}

/// The door's scan of `ops` where the owner ruled a value no secret: each
/// such value in its record's body or text overwritten by the mask's filler,
/// on a copy wiped once the scan has read it (FIX 1101).
fn scan_screened(
    store: &Store,
    wtxn: &RwTxn<'_>,
    kept: &KeptValues,
    ops: &[BatchOp],
) -> Result<()> {
    if kept.is_empty() {
        return scan_batch_ops(store, wtxn, ops);
    }
    let mut copy = PlanOps::of(ops);
    for op in &mut *copy {
        match op {
            BatchOp::Put { id, data, .. } => {
                if let Some(filled) = kept.screened(id, data) {
                    replace_wiped(data, filled);
                }
            }
            BatchOp::Text { id, fields } => {
                for (_, value) in fields.iter_mut() {
                    match kept.screened(id, value.as_bytes()).map(String::from_utf8) {
                        Some(Ok(filled)) => replace_wiped(value, filled),
                        Some(Err(error)) => error.into_bytes().zeroize(),
                        None => {}
                    }
                }
            }
            _ => {}
        }
    }
    scan_batch_ops(store, wtxn, &copy)
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
    /// The ASSET put that carried it, for the found-key notice (FIX 2780).
    record: EntityId,
}

/// One key a plan found in a file: the member that holds it (none for the
/// file's own bytes), its span there, and the key's kind and value, wiped
/// when it drops. A key custody already holds names its record, and nothing
/// is minted for it.
struct FileKey {
    path: Vec<MemberStep>,
    span: Range<usize>,
    reason: &'static str,
    value: Zeroizing<Vec<u8>>,
    custody: Option<EntityId>,
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

/// One secret a plan found, before custody holds it; its value is wiped
/// when it drops.
struct Found {
    value: Zeroizing<Vec<u8>>,
    reason: &'static str,
    record: EntityId,
    place: String,
}

/// A pass over a batch's ops. A plan hands each new value a stand-in and
/// keeps it once; a minted pass reads each value's custody handle. A plan
/// that `mints` nothing (a replayed batch) only reads files marked before.
#[derive(Default)]
struct Masker {
    /// Each value's handle, by its bytes, wiped when the pass ends.
    handles: PlanValues<String>,
    found: Vec<Found>,
    minted: bool,
    mints: bool,
    /// The switch is off: place known values only, mint nothing (FIX 8644).
    known_only: bool,
    /// The door's scan read each text this pass reads now by the same text
    /// rules and found no shape: none is sought again (speed).
    shapes_read: bool,
    /// Each file's key places by its bytes' hash: marked before, or by this
    /// plan.
    marked: HashMap<[u8; 32], KeyPlaces>,
    /// The files this plan marks.
    files: Vec<FoundFile>,
    /// Every file put that carries a mark.
    file_ids: Vec<EntityId>,
    /// The record and place the pass reads now.
    at: Option<(EntityId, String)>,
    /// The values the owner ruled no secret, by record: left as written.
    kept: KeptValues,
    /// The values custody already holds (OF-560 C): each keeps its record's
    /// handle, and nothing is minted for it.
    known: Option<Arc<KnownValues>>,
    /// Whether this pass placed a known value's handle.
    placed_known: bool,
    /// Where a tracked pass put each handle, by the text it masked (FIX 6144).
    traced: Option<text::TextReplacements>,
    /// Each MACHINE claim candidate the minted pass rewrote, with its
    /// pre-mask body, in op order: the candidate apply renews its proof
    /// over what is stored (FIX 11356). A plan pass never fills it.
    masked_claims: Vec<(EntityId, ClaimCandidate)>,
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
                        replace_wiped(data, copy);
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
                        replace_wiped(data, masked);
                    }
                }
                BatchOp::ClaimCandidate {
                    id,
                    candidate,
                    envelope,
                    ..
                } => {
                    self.at = Some((*id, "claim".to_owned()));
                    // The minted pass only: a plan rewrites a copy. Only a
                    // MACHINE candidate can need its proof renewed.
                    let before = (self.minted && envelope.machine_signature().is_some())
                        .then(|| (**candidate).clone());
                    // The door read the claim's encoded body, not each value
                    // as a text: each value is read by the text rules.
                    let shapes_read = std::mem::take(&mut self.shapes_read);
                    for value in candidate.values_mut() {
                        self.mask_value(value)?;
                    }
                    self.shapes_read = shapes_read;
                    if let Some(before) = before
                        && **candidate != before
                    {
                        self.masked_claims.push((*id, before));
                    }
                }
                BatchOp::Text { id, fields } => {
                    for (name, value) in fields.iter_mut() {
                        self.at = Some((*id, format!("text:{name}")));
                        if let Some(masked) = self.mask_text(value)? {
                            replace_wiped(value, masked);
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
        if let Some(places) = self.marked.get(&hash).cloned() {
            self.file_ids.push(id);
            let places = self.remark_known(data, hash, id, places)?;
            return masked_copy(data, &places).map(Some);
        }
        // A sealed file is stored as it is and left unmarked.
        if !self.mints || is_sealed(data) {
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
        self.files.push(FoundFile {
            hash,
            keys,
            record: id,
        });
        Ok(Some(copy))
    }

    /// A file marked before, put again: each value custody came to know
    /// since that its mark does not cover is marked beside it (FIX 2781),
    /// outside the file's key budget, unless the owner ruled it no secret in
    /// the record. Returns the file's places, the new ones included.
    fn remark_known(
        &mut self,
        data: &[u8],
        hash: [u8; 32],
        record: EntityId,
        places: KeyPlaces,
    ) -> Result<KeyPlaces> {
        let Some(known) = self.known.clone().filter(|_| self.mints) else {
            return Ok(places);
        };
        let found =
            known_marks::unmarked_known(data, &known, |value| self.is_kept(value), &places)?;
        if found.is_empty() {
            return Ok(places);
        }
        self.placed_known = true;
        let keys: Vec<FileKey> = found
            .into_iter()
            .map(|found| FileKey {
                path: found.path,
                span: found.span,
                reason: REASON_KNOWN_VALUE,
                value: Zeroizing::new(Vec::new()),
                custody: Some(found.custody),
            })
            .collect();
        let mut united = places;
        for (path, spans) in places_of(&keys)? {
            match united.iter_mut().find(|(held, _)| *held == path) {
                Some((_, held)) => {
                    held.extend(spans);
                    held.sort_unstable();
                }
                None => united.push((path, spans)),
            }
        }
        self.marked.insert(hash, united.clone());
        self.files.push(FoundFile { hash, keys, record });
        Ok(united)
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
                    let mut old = std::mem::replace(text, masked.into()).into_bytes();
                    old.zeroize();
                    true
                }))
            }
            Value::Binary(bytes) => {
                let masked = match std::str::from_utf8(bytes) {
                    Ok(text) => self.mask_text(text)?,
                    Err(_) => None,
                };
                Ok(masked.is_some_and(|masked| {
                    replace_wiped(bytes, masked.into_bytes());
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
                    changed |= self.mask_member(key, member)?;
                }
                Ok(changed)
            }
            _ => Ok(false),
        }
    }

    /// One map member under its `key`, as the field rule reads it: a value
    /// under a credential name whole, any other member by member.
    fn mask_member(&mut self, key: &Value, member: &mut Value) -> Result<bool> {
        if !credential_member(key, member) {
            return self.mask_value(member);
        }
        let secret = Zeroizing::new(match &*member {
            Value::String(text) => text.as_bytes().to_vec(),
            Value::Binary(bytes) => bytes.clone(),
            other => {
                let mut bytes = Zeroizing::new(Vec::new());
                rmpv::encode::write_value(&mut *bytes, other)
                    .map_err(|_| Error::InvariantViolation("a credential field did not encode"))?;
                std::mem::take(&mut *bytes)
            }
        });
        if self.is_kept(&secret) {
            return Ok(false);
        }
        let known = self.known_whole(&secret);
        // The switch is off: a structured-field value no record holds whole
        // stays as written (FIX 8644).
        if self.known_only && known.is_none() {
            return Ok(false);
        }
        let handle = match known {
            Some(handle) => {
                self.placed_known = true;
                handle
            }
            None => self.handle(&secret, REASON_SENSITIVE_ENV)?,
        };
        wipe::wipe_value(member);
        *member = Value::from(handle);
        Ok(true)
    }

    /// Whether the owner ruled `value` no secret in the record the pass
    /// reads now.
    fn is_kept(&self, value: &[u8]) -> bool {
        self.at
            .as_ref()
            .is_some_and(|(record, _)| self.kept.holds(record, value))
    }

    /// The handle of the custody record that holds `value` whole, if one
    /// does.
    fn known_whole(&self, value: &[u8]) -> Option<String> {
        match self.known.as_ref()?.spans(value).as_slice() {
            [hit] if hit.span == (0..value.len()) => Some(hit.handle.to_owned()),
            _ => None,
        }
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
            value: Zeroizing::new(value.to_vec()),
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
    ) -> Result<PlanValues<(String, EntityId)>> {
        let floor = SecretCustodyFloor::resolve(write.store, &*wtxn)?;
        let mut handles = PlanValues::default();
        let mut notes = Vec::with_capacity(self.found.len());
        for mut found in self.found {
            let id = write.store.clock.entity_id()?;
            let mut rec = SecretCustodyRecord {
                schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
                name: crate::repo_mutation::masked_record_name(found.reason, &found.value, &id),
                class: CustodyClass::CustodyPortable,
                device_only: false,
                value_bytes: std::mem::take(&mut *found.value),
                status: SecretCustodyStatus::Active,
                registered_at: at,
                rotated_at: None,
                rotation_generation: 0,
                bindings: Vec::new(),
                manifest_ref: String::new(),
                declared_paths: Vec::new(),
                policy_floor_snapshot: floor.clone(),
            };
            let registered = register_custody_in_txn(write, wtxn, &id, &mut rec);
            // The value goes back to a wiping owner whatever the door did.
            let mut value = Zeroizing::new(std::mem::take(&mut rec.value_bytes));
            registered?;
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
                    place: found.place.clone(),
                    masked_at: at,
                },
            )?;
            notes.push(FoundNote {
                record: found.record,
                custody: id,
                handle: handle.clone(),
                reason: found.reason,
                place: found.place,
            });
            handles.insert(std::mem::take(&mut *value), (handle, id));
        }
        // The owner hears of what was lifted, once per record.
        note_found_keys_in_txn(write.store, wtxn, &notes, at)?;
        Ok(handles)
    }
}

/// Whether the field rule reads `member`, under `key`, whole: a value under a
/// credential name, neither nil nor a placeholder.
fn credential_member(key: &Value, member: &Value) -> bool {
    key.as_str().is_some_and(shapes::sensitive_key)
        && !member.is_nil()
        && !member
            .as_str()
            .is_some_and(|text| shapes::field_placeholder(text, Door::Write))
}
