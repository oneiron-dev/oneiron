//! Seal on write (ARCH-0038 #secret-scan-target, ARCH-0040 #content-check;
//! owner, 2026-10-07 and 2026-10-17): the scan never refuses a write. Once
//! the plan has placed each span and field its rules place, a batch op
//! whose copy still reads as a hit is sealed: the smallest value in it that
//! reads as that hit on its own goes to custody whole, and its handle takes
//! its place, as a credential field's value does (`sc12`). A text field, or
//! a body read as text, is sealed whole and keeps `[secret sc12]`. The rest
//! of the write is kept. A hit spread over a value's parts (a key one line
//! per item) seals the value that holds all of it, never a part whose
//! stand-in only breaks the hit's pattern.
//!
//! The plan chooses each seal on its copy, by op and place, with a stand-in
//! there, and reads the copy again. Once the plan's own values are minted
//! and the minted pass has written their handles, each sealed value is read
//! from the op as that pass left it (a span inside it already a handle),
//! goes to custody as one record (or keeps the handle of the record that
//! holds it whole), and its handle takes its place. A value the owner ruled
//! no secret in the record is no hit there, so a write that puts it back
//! lands as written. A body no decoder reads whole (bytes that are no text,
//! a frame, a tree nested past its decoder's depth) is sealed whole: no
//! reading can say it holds no secret.
//!
//! The side-row wall seals the same way (`side_row`): a part of a row or
//! record a writer stores outside the batch (a NOTE's text, a stream's
//! text, a side table's row) whose copy still reads as a hit has its
//! smallest value sealed, a text whole. Its record goes through the
//! writer's own custody door; with none, a value custody already holds
//! whole keeps that record's handle, and any other seal refuses the write.
//! The row's own reading must accept the sealed copy, or the write refuses
//! as before. A tracked pass (a replay capsule's request, whose exposure
//! spans move by the spans the pass replaced) seals nothing.
//!
//! A file keeps its bytes as written (`seal_file`): the smallest value in it
//! that reads as the hit alone is marked as one key, or the file is sealed
//! whole, and no masked reader is served it.
//!
//! Not sealed, so their hit still refuses the write: a phonetic code, a
//! replayed batch, a body or file its writer owns (engine-authored or
//! replicated), and a claim whose hit sits outside its free values.

use heed::RwTxn;
use rmpv::Value;
use zeroize::Zeroizing;

use super::super::{REASON_DETECTED, scan_write_payload, secret_scan_error, write_payload_hit};
use super::body::{BodyForm, body_tree, encode_body};
use super::changed_scan::scan_reads_same;
use super::side_row::SidePart;
use super::wipe::{PlanValues, replace_wiped, wipe_value};
use super::{Found, HANDLE_OPEN, Masker, STAND_IN, op_record, part_at, scan_screened};
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::file_secret_marks::HeldForm;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SECRET_CUSTODY};
use crate::secret_custody::KeptValues;
use crate::secret_record::CustodyWrite;
use crate::store::Store;
use crate::store::known_value_index::KnownValues;
use crate::write_envelope::ClaimCandidate;

mod seal_file;

/// The most values one op, or one part of a row, seals; a copy still read
/// as a hit past them refuses the write. Each seal clears a value that
/// reads as a hit alone.
const MAX_SEALS_PER_OP: usize = 64;

/// Where a seal sits in the one value of an op or a part that holds it.
#[derive(Debug)]
enum SealIn {
    /// A text, sealed whole: a text field, or a row's text part.
    Text,
    /// A body: the value at this path in the tree it decodes to
    /// (`part_at`), or the whole body when it reads as text or no decoder
    /// reads it (`None`).
    Body(Option<Vec<usize>>),
    /// A structured value (a claim candidate's free value, a row's value
    /// part): the value at this path in it.
    Value(Vec<usize>),
}

/// One value the plan sealed: the index of the op, or of the row's part,
/// that holds it; the member of that op that holds it (a text field's or
/// a free value's index, 0 for a put's body and for a part); its place
/// there; and the reason the door's rules read it with.
#[derive(Debug)]
pub(super) struct Seal {
    index: usize,
    member: usize,
    at: SealIn,
    reason: &'static str,
}

/// Reads each op of `planned`, the plan's copy of `read`, again and seals
/// each one whose copy still reads as a hit: the copy takes a stand-in for
/// each sealed value, and the seals return in op order. A file is marked
/// in `plan` instead (`seal_file`). `kept` is the plan's kept values, taken
/// out of it. `only_changed`: the door's first scan read `read` clean and
/// the owner kept no value there, so only an op the plan changed is read
/// again (FIX 12212). A plan that mints nothing (a replayed batch) keeps the
/// plain door. An op no seal clears refuses the write with the door's
/// reason, before anything is minted.
pub(super) fn plan_seals(
    store: &Store,
    txn: &RwTxn<'_>,
    kept: &KeptValues,
    plan: &mut Masker,
    planned: &mut [BatchOp],
    read: &[BatchOp],
    only_changed: bool,
) -> Result<Vec<Seal>> {
    let mut seals = Vec::new();
    for (index, (op, before)) in planned.iter_mut().zip(read).enumerate() {
        if only_changed && scan_reads_same(op, before) {
            continue;
        }
        let Err(refusal) = scan_screened(store, txn, kept, std::slice::from_ref(&*op)) else {
            continue;
        };
        if !plan.mints {
            return Err(refusal);
        }
        let clean =
            |op: &BatchOp| scan_screened(store, txn, kept, std::slice::from_ref(op)).is_ok();
        if let Some(written) = written_file(before) {
            plan.seal_file(kept, op, written, &clean)?;
            continue;
        }
        if !sealable(op) {
            return Err(refusal);
        }
        let taken = seal_until_clean(op, refusal, |op| seal_in(op, kept), clean)?;
        seals.extend(taken.into_iter().map(|(member, at, reason)| Seal {
            index,
            member,
            at,
            reason,
        }));
    }
    Ok(seals)
}

/// Reads each of `planned`, the plan's copy of the parts a writer stores
/// outside a batch (`side_row`), again, and seals each one whose copy still
/// reads as a hit, as [`plan_seals`] seals an op: the copy takes a stand-in
/// for each sealed value, and the seals return in part order. `origins`
/// names each part's record, whose owner-kept values are screened first.
/// `sealing` is false where no seal can land: a part that still reads as a
/// hit then refuses the write with the door's reason, as one no seal clears
/// does, before anything is minted.
pub(super) fn plan_part_seals(
    kept: &KeptValues,
    planned: &mut [SidePart],
    origins: &[(EntityId, &str)],
    sealing: bool,
) -> Result<Vec<Seal>> {
    let mut seals = Vec::new();
    for (index, (part, (record, _))) in planned.iter_mut().zip(origins).enumerate() {
        let Err(refusal) = part.scan(kept, record) else {
            continue;
        };
        if !sealing {
            return Err(refusal);
        }
        let read = |bytes: &[u8]| hit(kept, record, bytes);
        let clean = |part: &SidePart| part.scan(kept, record).is_ok();
        let taken = seal_until_clean(part, refusal, |part| seal_part(part, &read), clean)?;
        seals.extend(taken.into_iter().map(|(at, reason)| Seal {
            index,
            member: 0,
            at,
            reason,
        }));
    }
    Ok(seals)
}

/// The door's seals predicted over `copy`, a put's body the door's plan has
/// masked, for a planner that holds no writer (OF-560): `Ok(())` once the
/// seals the door would take read it clean, else `refusal`. Nothing is
/// minted, and no value the owner kept is read.
pub(super) fn predict_body_seals(copy: &mut Vec<u8>, refusal: Error) -> Result<()> {
    let seal = |copy: &mut Vec<u8>| seal_body_copy(copy, &write_payload_hit);
    seal_until_clean(copy, refusal, seal, |copy| scan_write_payload(copy).is_ok()).map(drop)
}

/// [`predict_body_seals`] for a text field's text, which the door seals
/// whole.
pub(super) fn predict_text_seals(copy: &mut Vec<u8>, refusal: Error) -> Result<()> {
    let seal = |copy: &mut Vec<u8>| -> Result<Option<&'static str>> {
        Ok(seal_bytes_copy(copy, &write_payload_hit))
    };
    seal_until_clean(copy, refusal, seal, |copy| scan_write_payload(copy).is_ok()).map(drop)
}

/// Seals `item`, a plan's copy, one value at a time with `seal_once` until
/// `clean` reads it clean, and returns each seal in order. With no value
/// left that reads as a hit alone, or with [`MAX_SEALS_PER_OP`] taken and
/// the copy still a hit, it is `refusal`.
fn seal_until_clean<T: ?Sized, S>(
    item: &mut T,
    refusal: Error,
    seal_once: impl Fn(&mut T) -> Result<Option<S>>,
    clean: impl Fn(&T) -> bool,
) -> Result<Vec<S>> {
    let mut seals = Vec::new();
    while seals.len() < MAX_SEALS_PER_OP {
        let Some(seal) = seal_once(&mut *item)? else {
            return Err(refusal);
        };
        seals.push(seal);
        if clean(&*item) {
            return Ok(seals);
        }
    }
    Err(refusal)
}

/// The bytes of `op` when it puts a file its writer wrote, which the plan
/// seals by its mark (`seal_file`); `None` for any other op, and for a file
/// the engine authored or a peer replicated.
fn written_file(op: &BatchOp) -> Option<&[u8]> {
    match op {
        BatchOp::Put {
            entity_type,
            data,
            allow_maintenance: false,
            hub_sync_imported: false,
            ..
        } if *entity_type == ENTITY_TYPE_ASSET => Some(data),
        _ => None,
    }
}

/// Whether an op's own values can take a seal: the ops the mask writes
/// handles into (`Masker::mask_ops`). A file keeps its bytes, and an
/// engine-authored or replicated body, or a custody body, is not this
/// door's to rewrite.
fn sealable(op: &BatchOp) -> bool {
    match op {
        BatchOp::Put {
            entity_type,
            allow_maintenance: false,
            hub_sync_imported: false,
            ..
        } => !matches!(*entity_type, ENTITY_TYPE_SECRET_CUSTODY | ENTITY_TYPE_ASSET),
        BatchOp::ClaimCandidate { .. } | BatchOp::Text { .. } => true,
        _ => false,
    }
}

/// Finds the smallest value in `op`, the plan's copy, that reads as a hit
/// on its own, puts the stand-in in its place, and returns the member that
/// holds it, its place there and its reason; `None` when no value of the op
/// reads as one alone.
fn seal_in(op: &mut BatchOp, kept: &KeptValues) -> Result<Option<(usize, SealIn, &'static str)>> {
    match op {
        BatchOp::Text { id, fields } => {
            let record = *id;
            let read = |bytes: &[u8]| hit(kept, &record, bytes);
            for (index, (_, text)) in fields.iter_mut().enumerate() {
                if let Some(reason) = seal_text_copy(text, &read) {
                    return Ok(Some((index, SealIn::Text, reason)));
                }
            }
            Ok(None)
        }
        BatchOp::Put { id, data, .. } => {
            let record = *id;
            let read = |bytes: &[u8]| hit(kept, &record, bytes);
            Ok(seal_body_copy(data, &read)?.map(|(path, reason)| (0, SealIn::Body(path), reason)))
        }
        BatchOp::ClaimCandidate { id, candidate, .. } => {
            let record = *id;
            let read = |bytes: &[u8]| hit(kept, &record, bytes);
            for (index, value) in candidate.values_mut().enumerate() {
                if let Some((path, reason)) = seal_tree_copy(value, BodyForm::MessagePack, &read)? {
                    return Ok(Some((index, SealIn::Value(path), reason)));
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// [`seal_in`] for one part of a row: a text is sealed whole, a body as a
/// put's body is, and a value at its smallest value that reads as the hit
/// alone.
fn seal_part(
    part: &mut SidePart,
    read: &dyn Fn(&[u8]) -> Option<&'static str>,
) -> Result<Option<(SealIn, &'static str)>> {
    Ok(match part {
        SidePart::Text(text) => seal_text_copy(text, read).map(|reason| (SealIn::Text, reason)),
        SidePart::Body(data) => {
            seal_body_copy(data, read)?.map(|(path, reason)| (SealIn::Body(path), reason))
        }
        SidePart::Value(value) => seal_tree_copy(value, BodyForm::MessagePack, read)?
            .map(|(path, reason)| (SealIn::Value(path), reason)),
    })
}

/// What a value sealed whole as text keeps on a plan's copy.
fn text_stand_in() -> String {
    format!("{HANDLE_OPEN}{STAND_IN}]")
}

/// Seals `text`, on a plan's copy, whole when it reads as a hit: the
/// stand-in takes its place, and the hit's reason returns.
fn seal_text_copy(
    text: &mut String,
    read: &dyn Fn(&[u8]) -> Option<&'static str>,
) -> Option<&'static str> {
    let reason = read(text.as_bytes())?;
    replace_wiped(text, text_stand_in());
    Some(reason)
}

/// [`seal_text_copy`] for bytes read as text, or read by no decoder.
fn seal_bytes_copy(
    data: &mut Vec<u8>,
    read: &dyn Fn(&[u8]) -> Option<&'static str>,
) -> Option<&'static str> {
    let reason = read(data.as_slice())?;
    replace_wiped(data, text_stand_in().into_bytes());
    Some(reason)
}

/// Puts the stand-in in place of the smallest value of `data`, a body on a
/// plan's copy, that reads as a hit alone, and returns where it sat and its
/// reason. A body read as text, or one no decoder reads, is sealed whole
/// and keeps `[secret sc0]`, or `None` when it reads clean. A tree none of
/// whose values reads as the hit alone reads as one only as the door
/// encodes it: it is sealed whole.
fn seal_body_copy(
    data: &mut Vec<u8>,
    read: &dyn Fn(&[u8]) -> Option<&'static str>,
) -> Result<Option<(Option<Vec<usize>>, &'static str)>> {
    let Some((mut tree, form)) = body_tree(data) else {
        return Ok(seal_bytes_copy(data, read).map(|reason| (None, reason)));
    };
    let (path, reason) = match smallest_hit(&tree.0, form, read)? {
        Some(found) => found,
        None => (Vec::new(), read(data.as_slice()).unwrap_or(REASON_DETECTED)),
    };
    stand_in_at(&mut tree.0, &path)?;
    replace_wiped(data, encode_body(&tree.0, form)?);
    Ok(Some((Some(path), reason)))
}

/// Puts the stand-in in place of the smallest value of `tree`, on a plan's
/// copy, that reads as a hit alone, and returns its path and reason; `None`
/// when the tree reads clean alone.
fn seal_tree_copy(
    tree: &mut Value,
    form: BodyForm,
    read: &dyn Fn(&[u8]) -> Option<&'static str>,
) -> Result<Option<(Vec<usize>, &'static str)>> {
    let Some((path, reason)) = smallest_hit(tree, form, read)? else {
        return Ok(None);
    };
    stand_in_at(tree, &path)?;
    Ok(Some((path, reason)))
}

/// The reason the door's rules read `bytes` of `record` with, each value
/// the owner ruled no secret or kept as text there screened out; `None`
/// when they read clean.
fn hit(kept: &KeptValues, record: &EntityId, bytes: &[u8]) -> Option<&'static str> {
    let screened = kept.screened(record, bytes).map(Zeroizing::new);
    write_payload_hit(screened.as_deref().map_or(bytes, Vec::as_slice))
}

/// The path of the smallest value in `tree` that reads as a hit on its own
/// (`part_at`'s steps), and that hit's reason: the tree itself when none
/// of its parts does alone; `None` when the tree reads clean alone. Each
/// level reads its parts once, so the walk reads the tree about once per
/// level it descends.
fn smallest_hit(
    tree: &Value,
    form: BodyForm,
    read: &dyn Fn(&[u8]) -> Option<&'static str>,
) -> Result<Option<(Vec<usize>, &'static str)>> {
    let Some(mut reason) = value_hit(tree, form, read)? else {
        return Ok(None);
    };
    let mut path = Vec::new();
    let mut at = tree;
    'descend: loop {
        for (step, part) in parts(at) {
            if let Some(found) = value_hit(part, form, read)? {
                path.push(step);
                at = part;
                reason = found;
                continue 'descend;
            }
        }
        return Ok(Some((path, reason)));
    }
}

/// The parts of `value` a path steps into: an array's items by index, a
/// map's key at `2i` and its member at `2i + 1`.
fn parts(value: &Value) -> Vec<(usize, &Value)> {
    match value {
        Value::Array(items) => items.iter().enumerate().collect(),
        Value::Map(fields) => fields
            .iter()
            .enumerate()
            .flat_map(|(at, (key, member))| [(2 * at, key), (2 * at + 1, member)])
            .collect(),
        _ => Vec::new(),
    }
}

/// `value` read alone by the door's rules, as its sealed bytes
/// (`value_bytes`).
fn value_hit(
    value: &Value,
    form: BodyForm,
    read: &dyn Fn(&[u8]) -> Option<&'static str>,
) -> Result<Option<&'static str>> {
    Ok(read(&value_bytes(value, form)?))
}

/// The bytes custody holds for a sealed value: a string's or byte string's
/// own bytes; any other value in the encoding of the body that holds it
/// (`form`), so a revealed value reads as the body wrote it. A JSON value
/// that cannot be written as JSON is held in MessagePack, as a credential
/// field's value is (`Masker::mask_member`).
fn value_bytes(value: &Value, form: BodyForm) -> Result<Zeroizing<Vec<u8>>> {
    match value {
        Value::String(text) => Ok(Zeroizing::new(text.as_bytes().to_vec())),
        Value::Binary(bytes) => Ok(Zeroizing::new(bytes.clone())),
        other => {
            if let BodyForm::Json = form
                && let Ok(json) = serde_json::to_vec(other)
            {
                return Ok(Zeroizing::new(json));
            }
            let mut bytes = Zeroizing::new(Vec::new());
            rmpv::encode::write_value(&mut *bytes, other)
                .map_err(|_| Error::InvariantViolation("a sealed value did not encode"))?;
            Ok(bytes)
        }
    }
}

/// The value at `path` in `tree` wiped and replaced by `handle`.
fn put_handle_at(tree: &mut Value, path: &[usize], handle: &str) -> Result<()> {
    let part = part_at(tree, path).ok_or(Error::InvariantViolation(
        "a seal's path names no value in its tree",
    ))?;
    wipe_value(part);
    *part = Value::from(handle);
    Ok(())
}

fn stand_in_at(tree: &mut Value, path: &[usize]) -> Result<()> {
    put_handle_at(tree, path, STAND_IN)
}

/// The pre-mask candidate of each MACHINE claim candidate in `ops`, by op
/// index, when a seal rewrites a claim: the candidate apply renews a proof
/// only over its verified pre-mask body (FIX 11356). Read before the minted
/// pass; `None` when no seal rewrites a claim.
pub(super) fn claims_before(
    ops: &[BatchOp],
    seals: &[Seal],
) -> Option<Vec<(usize, EntityId, ClaimCandidate)>> {
    if !seals
        .iter()
        .any(|seal| matches!(ops.get(seal.index), Some(BatchOp::ClaimCandidate { .. })))
    {
        return None;
    }
    Some(
        ops.iter()
            .enumerate()
            .filter_map(|(index, op)| match op {
                BatchOp::ClaimCandidate {
                    id,
                    candidate,
                    envelope,
                    ..
                } if envelope.machine_signature().is_some() => {
                    Some((index, *id, (**candidate).clone()))
                }
                _ => None,
            })
            .collect(),
    )
}

/// Each MACHINE claim candidate of `before` that the minted pass or a seal
/// rewrote in `ops`, with its pre-mask body, in op order: what the minted
/// pass alone reports when no seal rewrites a claim.
pub(super) fn claims_rewritten(
    ops: &[BatchOp],
    before: Vec<(usize, EntityId, ClaimCandidate)>,
) -> Vec<(EntityId, ClaimCandidate)> {
    before
        .into_iter()
        .filter(|(index, _, pre)| {
            matches!(ops.get(*index), Some(BatchOp::ClaimCandidate { candidate, .. })
                if **candidate != *pre)
        })
        .map(|(_, id, pre)| (id, pre))
        .collect()
}

fn unnamed() -> Error {
    Error::InvariantViolation("a seal no longer names its op's part")
}

/// Writes each seal the plan chose into `ops`, as the minted pass left
/// them: each sealed value goes to custody as one record, or keeps the
/// handle of the record that holds it whole (`known`, or a seal of this
/// batch), and its handle takes its place. Seals apply in the plan's order,
/// so a value that holds an earlier seal holds that seal's handle. Each
/// record is stamped `at`.
pub(super) fn mint_seals(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    ops: &mut [BatchOp],
    seals: Vec<Seal>,
    known: Option<&KnownValues>,
    at: u64,
) -> Result<()> {
    let mut sealed = PlanValues::<String>::default();
    for seal in seals {
        let op = ops.get_mut(seal.index).ok_or_else(unnamed)?;
        let record = op_record(op).ok_or_else(unnamed)?;
        let mut sealer = Sealer {
            door: Some((write, at)),
            known,
            sealed: &mut sealed,
            record,
            reason: seal.reason,
        };
        match (seal.at, op) {
            (SealIn::Text, BatchOp::Text { fields, .. }) => {
                let (name, text) = fields.get_mut(seal.member).ok_or_else(unnamed)?;
                sealer.seal_text(wtxn, &format!("text:{name}"), text)?;
            }
            (SealIn::Body(path), BatchOp::Put { data, .. }) => {
                sealer.seal_body(wtxn, "body", data, path)?;
            }
            (SealIn::Value(path), BatchOp::ClaimCandidate { candidate, .. }) => {
                let value = candidate
                    .values_mut()
                    .nth(seal.member)
                    .ok_or_else(unnamed)?;
                sealer.seal_value(wtxn, "claim", value, BodyForm::MessagePack, &path)?;
            }
            _ => return Err(unnamed()),
        }
    }
    Ok(())
}

/// Writes each seal [`plan_part_seals`] chose into `parts`, as the minted
/// pass left them, as [`mint_seals`] writes an op's, each under its part's
/// record and place in `origins`. Each sealed value goes to custody as one
/// record through `door`, stamped with its time; or it keeps the handle of
/// the record that holds it whole (`known`, or `sealed`: the values this
/// writer sealed before, which each new seal joins). With no door a value
/// custody does not hold whole refuses the write with its seal's reason.
pub(super) fn mint_part_seals(
    door: Option<(&CustodyWrite<'_>, u64)>,
    wtxn: &mut RwTxn<'_>,
    parts: &mut [SidePart],
    origins: &[(EntityId, &str)],
    seals: Vec<Seal>,
    known: Option<&KnownValues>,
    sealed: &mut PlanValues<String>,
) -> Result<()> {
    for seal in seals {
        let (part, (record, place)) = parts
            .get_mut(seal.index)
            .zip(origins.get(seal.index))
            .ok_or_else(unnamed)?;
        let mut sealer = Sealer {
            door,
            known,
            sealed: &mut *sealed,
            record: *record,
            reason: seal.reason,
        };
        match (seal.at, part) {
            (SealIn::Text, SidePart::Text(text)) => sealer.seal_text(wtxn, place, text)?,
            (SealIn::Body(path), SidePart::Body(data)) => {
                sealer.seal_body(wtxn, place, data, path)?;
            }
            (SealIn::Value(path), SidePart::Value(value)) => {
                sealer.seal_value(wtxn, place, value, BodyForm::MessagePack, &path)?;
            }
            _ => return Err(unnamed()),
        }
    }
    Ok(())
}

/// One seal's custody write: the door its record goes through, with the
/// time it is stamped (none for a writer whose target holds no custody
/// door), the values custody already holds, the values sealed so far with
/// their handles, and the record and reason its value is minted under.
struct Sealer<'a, 'w> {
    door: Option<(&'a CustodyWrite<'w>, u64)>,
    known: Option<&'a KnownValues>,
    sealed: &'a mut PlanValues<String>,
    record: EntityId,
    reason: &'static str,
}

impl Sealer<'_, '_> {
    /// The handle `value`, sealed whole from the record at `place`, takes.
    fn handle(&mut self, wtxn: &mut RwTxn<'_>, place: &str, value: &[u8]) -> Result<String> {
        if let Some(handle) = self.sealed.get(value) {
            return Ok(handle.clone());
        }
        let handle = match self.door {
            Some((write, at)) => seal_value_in_txn(
                write,
                wtxn,
                self.known,
                self.record,
                place,
                value,
                self.reason,
                // As a seal is held on its own stack: the bytes the seal
                // read, a text's or a value's encoding alike.
                HeldForm::Raw,
                at,
            )?,
            // With no door nothing is minted (FIX 6647): only a value
            // custody already holds whole takes a handle.
            None => held_whole(self.known, value).ok_or_else(|| secret_scan_error(self.reason))?,
        };
        self.sealed.insert(value.to_vec(), handle.clone());
        Ok(handle)
    }

    /// `text`, sealed whole from `place`: it keeps its handle as
    /// `[secret sc12]`.
    fn seal_text(&mut self, wtxn: &mut RwTxn<'_>, place: &str, text: &mut String) -> Result<()> {
        let handle = self.handle(wtxn, place, text.as_bytes())?;
        replace_wiped(text, format!("{HANDLE_OPEN}{handle}]"));
        Ok(())
    }

    /// The value at `path` in the body `data` decodes to sealed, or with no
    /// path the whole body, which keeps its handle as `[secret sc12]`.
    fn seal_body(
        &mut self,
        wtxn: &mut RwTxn<'_>,
        place: &str,
        data: &mut Vec<u8>,
        path: Option<Vec<usize>>,
    ) -> Result<()> {
        let Some(path) = path else {
            let handle = self.handle(wtxn, place, data.as_slice())?;
            replace_wiped(data, format!("{HANDLE_OPEN}{handle}]").into_bytes());
            return Ok(());
        };
        let (mut tree, form) = body_tree(data).ok_or(Error::InvariantViolation(
            "a sealed body no longer decodes as its plan read it",
        ))?;
        self.seal_value(wtxn, place, &mut tree.0, form, &path)?;
        replace_wiped(data, encode_body(&tree.0, form)?);
        Ok(())
    }

    /// The value at `path` in `tree`, held as its bytes in `form`
    /// (`value_bytes`), sealed: its handle takes its place whole.
    fn seal_value(
        &mut self,
        wtxn: &mut RwTxn<'_>,
        place: &str,
        tree: &mut Value,
        form: BodyForm,
        path: &[usize],
    ) -> Result<()> {
        let value = part_at(tree, path)
            .map(|part| value_bytes(&*part, form))
            .ok_or_else(unnamed)??;
        let handle = self.handle(wtxn, place, &value)?;
        put_handle_at(tree, path, &handle)
    }
}

/// The handle of the custody record `known` says holds `value` whole.
fn held_whole(known: Option<&KnownValues>, value: &[u8]) -> Option<String> {
    known.and_then(|known| match known.spans(value).as_slice() {
        [whole] if whole.span == (0..value.len()) => Some(whole.handle.to_owned()),
        _ => None,
    })
}

/// The handle `value`, sealed whole from `record` at `place`, takes: that of
/// the custody record `known` says holds it whole, else a new active
/// record's, minted in `wtxn` with its mask origin and the owner's
/// found-key notice, as the plan's own values are, holding `value` as
/// `held` says.
#[expect(
    clippy::too_many_arguments,
    reason = "one custody write: its door, its known values, the value, its origin, its held form and its time"
)]
pub(super) fn seal_value_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    known: Option<&KnownValues>,
    record: EntityId,
    place: &str,
    value: &[u8],
    reason: &'static str,
    held: HeldForm,
    at: u64,
) -> Result<String> {
    if let Some(handle) = held_whole(known, value) {
        return Ok(handle);
    }
    let mut plan = Masker::default();
    plan.found.push(Found {
        value: Zeroizing::new(value.to_vec()),
        reason,
        record,
        place: place.to_owned(),
        held,
    });
    let minted = plan.mint(write, wtxn, at)?;
    minted
        .get(value)
        .map(|(handle, _)| handle.clone())
        .ok_or(Error::InvariantViolation(
            "a sealed value's custody record has no handle",
        ))
}
