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
//! lands as written.
//!
//! Not sealed, so their hit still refuses the write: a file (its bytes stay
//! the owner's, marked), a phonetic code, a replayed batch, a body its
//! writer owns (engine-authored or replicated), and a claim whose hit sits
//! outside its free values.

use heed::RwTxn;
use rmpv::Value;
use zeroize::Zeroizing;

use super::super::{REASON_DETECTED, write_payload_hit};
use super::body::{BodyForm, body_tree, encode_body};
use super::changed_scan::scan_reads_same;
use super::wipe::{PlanValues, replace_wiped, wipe_value};
use super::{Found, HANDLE_OPEN, Masker, STAND_IN, op_record, part_at, scan_screened};
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SECRET_CUSTODY};
use crate::secret_custody::KeptValues;
use crate::secret_record::CustodyWrite;
use crate::store::Store;
use crate::store::known_value_index::KnownValues;
use crate::write_envelope::ClaimCandidate;

/// The most values one op seals; an op still read as a hit past them
/// refuses the write. Each seal clears a value that reads as a hit alone.
const MAX_SEALS_PER_OP: usize = 64;

/// Where one seal sits in its op.
#[derive(Debug)]
enum SealAt {
    /// A text field, by its index among the op's fields: sealed whole.
    Field(usize),
    /// A put's body: the value at this path in the tree it decodes to
    /// (`part_at`), or the whole body when it reads as text (`None`).
    Body(Option<Vec<usize>>),
    /// A claim candidate's free value, by its index among them
    /// (`ClaimCandidate::values_mut`), and the path in it.
    Claim(usize, Vec<usize>),
}

/// One value the plan sealed: its op's index, its place there, and the
/// reason the door's rules read it with.
#[derive(Debug)]
pub(super) struct Seal {
    op: usize,
    at: SealAt,
    reason: &'static str,
}

/// Reads each op of `planned`, the plan's copy of `read`, again and seals
/// each one whose copy still reads as a hit: the copy takes a stand-in for
/// each sealed value, and the seals return in op order. `only_changed`: the
/// door's first scan read `read` clean and the owner kept no value there, so
/// only an op the plan changed is read again (FIX 12212). `sealing` is false
/// for a replayed batch, which keeps the plain door. An op no seal clears
/// refuses the write with the door's reason, before anything is minted.
pub(super) fn plan_seals(
    store: &Store,
    txn: &RwTxn<'_>,
    kept: &KeptValues,
    planned: &mut [BatchOp],
    read: &[BatchOp],
    only_changed: bool,
    sealing: bool,
) -> Result<Vec<Seal>> {
    let mut seals = Vec::new();
    for (index, (op, before)) in planned.iter_mut().zip(read).enumerate() {
        if only_changed && scan_reads_same(op, before) {
            continue;
        }
        let Err(refusal) = scan_screened(store, txn, kept, std::slice::from_ref(&*op)) else {
            continue;
        };
        if !sealing || !sealable(op) {
            return Err(refusal);
        }
        let mut taken = 0;
        loop {
            let Some((at, reason)) = seal_in(op, kept)? else {
                return Err(refusal);
            };
            seals.push(Seal {
                op: index,
                at,
                reason,
            });
            taken += 1;
            if scan_screened(store, txn, kept, std::slice::from_ref(&*op)).is_ok() {
                break;
            }
            if taken == MAX_SEALS_PER_OP {
                return Err(refusal);
            }
        }
    }
    Ok(seals)
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
/// on its own, puts the stand-in in its place, and returns its place and
/// reason; `None` when no value of the op reads as one alone.
fn seal_in(op: &mut BatchOp, kept: &KeptValues) -> Result<Option<(SealAt, &'static str)>> {
    match op {
        BatchOp::Text { id, fields } => {
            let record = *id;
            for (index, (_, text)) in fields.iter_mut().enumerate() {
                if let Some(reason) = hit(kept, &record, text.as_bytes()) {
                    replace_wiped(text, format!("{HANDLE_OPEN}{STAND_IN}]"));
                    return Ok(Some((SealAt::Field(index), reason)));
                }
            }
            Ok(None)
        }
        BatchOp::Put { id, data, .. } => {
            let record = *id;
            let read = |bytes: &[u8]| hit(kept, &record, bytes);
            let Some((mut tree, form)) = body_tree(data) else {
                let Some(reason) = read(data.as_slice()) else {
                    return Ok(None);
                };
                replace_wiped(data, format!("{HANDLE_OPEN}{STAND_IN}]").into_bytes());
                return Ok(Some((SealAt::Body(None), reason)));
            };
            // The body reads as a hit only as the door encodes it: it is
            // sealed whole.
            let (path, reason) = match smallest_hit(&tree.0, form, &read)? {
                Some(found) => found,
                None => (Vec::new(), read(data.as_slice()).unwrap_or(REASON_DETECTED)),
            };
            stand_in_at(&mut tree.0, &path)?;
            replace_wiped(data, encode_body(&tree.0, form)?);
            Ok(Some((SealAt::Body(Some(path)), reason)))
        }
        BatchOp::ClaimCandidate { id, candidate, .. } => {
            let record = *id;
            let read = |bytes: &[u8]| hit(kept, &record, bytes);
            for (index, value) in candidate.values_mut().enumerate() {
                if let Some((path, reason)) = smallest_hit(value, BodyForm::MessagePack, &read)? {
                    stand_in_at(value, &path)?;
                    return Ok(Some((SealAt::Claim(index, path), reason)));
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
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
        .any(|seal| matches!(seal.at, SealAt::Claim(..)))
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
    let unnamed = || Error::InvariantViolation("a seal no longer names its op's part");
    for seal in seals {
        let op = ops.get_mut(seal.op).ok_or_else(unnamed)?;
        let record = op_record(op).ok_or_else(unnamed)?;
        let mut sealer = Sealer {
            write,
            known,
            sealed: &mut sealed,
            record,
            reason: seal.reason,
            at,
        };
        match (seal.at, op) {
            (SealAt::Field(index), BatchOp::Text { fields, .. }) => {
                let (name, text) = fields.get_mut(index).ok_or_else(unnamed)?;
                let handle = sealer.handle(wtxn, &format!("text:{name}"), text.as_bytes())?;
                replace_wiped(text, format!("{HANDLE_OPEN}{handle}]"));
            }
            (SealAt::Body(None), BatchOp::Put { data, .. }) => {
                let handle = sealer.handle(wtxn, "body", data.as_slice())?;
                replace_wiped(data, format!("{HANDLE_OPEN}{handle}]").into_bytes());
            }
            (SealAt::Body(Some(path)), BatchOp::Put { data, .. }) => {
                let (mut tree, form) = body_tree(data).ok_or(Error::InvariantViolation(
                    "a sealed body no longer decodes as its plan read it",
                ))?;
                let value = part_at(&mut tree.0, &path)
                    .map(|part| value_bytes(&*part, form))
                    .ok_or_else(unnamed)??;
                let handle = sealer.handle(wtxn, "body", &value)?;
                put_handle_at(&mut tree.0, &path, &handle)?;
                replace_wiped(data, encode_body(&tree.0, form)?);
            }
            (SealAt::Claim(index, path), BatchOp::ClaimCandidate { candidate, .. }) => {
                let value = candidate.values_mut().nth(index).ok_or_else(unnamed)?;
                let bytes = part_at(value, &path)
                    .map(|part| value_bytes(&*part, BodyForm::MessagePack))
                    .ok_or_else(unnamed)??;
                let handle = sealer.handle(wtxn, "claim", &bytes)?;
                put_handle_at(value, &path, &handle)?;
            }
            _ => return Err(unnamed()),
        }
    }
    Ok(())
}

/// One seal's custody write: the record and reason its value is minted
/// under.
struct Sealer<'a, 'w> {
    write: &'a CustodyWrite<'w>,
    known: Option<&'a KnownValues>,
    sealed: &'a mut PlanValues<String>,
    record: EntityId,
    reason: &'static str,
    at: u64,
}

impl Sealer<'_, '_> {
    /// The handle `value`, sealed whole from the record at `place`, takes.
    fn handle(&mut self, wtxn: &mut RwTxn<'_>, place: &str, value: &[u8]) -> Result<String> {
        if let Some(handle) = self.sealed.get(value) {
            return Ok(handle.clone());
        }
        let handle = seal_value_in_txn(
            self.write,
            wtxn,
            self.known,
            self.record,
            place,
            value,
            self.reason,
            self.at,
        )?;
        self.sealed.insert(value.to_vec(), handle.clone());
        Ok(handle)
    }
}

/// The handle `value`, sealed whole from `record` at `place`, takes: that of
/// the custody record `known` says holds it whole, else a new active
/// record's, minted in `wtxn` with its mask origin and the owner's
/// found-key notice, as the plan's own values are.
#[expect(
    clippy::too_many_arguments,
    reason = "one custody write: its door, its known values, the value, its origin and its time"
)]
pub(super) fn seal_value_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    known: Option<&KnownValues>,
    record: EntityId,
    place: &str,
    value: &[u8],
    reason: &'static str,
    at: u64,
) -> Result<String> {
    let held = known.and_then(|known| match known.spans(value).as_slice() {
        [whole] if whole.span == (0..value.len()) => Some(whole.handle.to_owned()),
        _ => None,
    });
    if let Some(handle) = held {
        return Ok(handle);
    }
    let mut plan = Masker::default();
    plan.found.push(Found {
        value: Zeroizing::new(value.to_vec()),
        reason,
        record,
        place: place.to_owned(),
    });
    let minted = plan.mint(write, wtxn, at)?;
    minted
        .get(value)
        .map(|(handle, _)| handle.clone())
        .ok_or(Error::InvariantViolation(
            "a sealed value's custody record has no handle",
        ))
}
