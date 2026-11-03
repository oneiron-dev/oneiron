//! The mark of each key a retained repository blob holds (FIX 7608, owner
//! ruling SECRETS-IN-REPOS = A). A blob a push lands keeps its bytes and its
//! Git object identity, as a file does (owner ruling G04 binary = C2): each
//! key the file mask's own rules place in it, in its bytes or in a
//! container's member, goes to custody, and the blob is marked under its
//! bytes' hash (`secret_custody::masked_files`). A key no span isolates is
//! opaque (C5): the blob is still kept and marked, never skipped or refused.
//!
//! The work is split around the writer. [`plan_retained_repo_blob`] runs
//! outside any transaction while the blob's original bytes are at hand: it
//! places keys with the file mask's detectors, field rules and the values
//! custody knows, reads members under the retained repository read (no
//! member, object, depth or byte bound, rule 5), and reads the rebuilt copy
//! again for what is left. [`mark_retained_repo_blob_in_txn`] runs in the
//! receive intent's writer: each key keeps the record an earlier mark, a
//! value this writer minted, or the known-value index already gives it; the
//! rest are minted by the file mask's own mint, and the blob is marked by
//! its own mark writer. What it returns holds no value.
//!
//! This is not a second detector or masker: the generic file and carrier
//! doors, their key bound and their container budget are unchanged.

use std::ops::Range;
use std::sync::Arc;

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use super::super::container::{
    Stop, holds_spans, masked_retained_repo_copy, walk_retained_repo_members,
};
use super::super::release_hit;
use super::body::reads_as_text;
use super::text_log::{TextLog, TextSpans};
use super::wipe::PlanValues;
use super::{
    FileKey, FoundFile, Masker, REASON_KNOWN_VALUE, file_spans, merged, occurrences, offset,
    places_of, put_file_marks_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::lfs::find_custody_credential;
use crate::ports::ShortIdStoreRead;
use crate::repo_mutation::{
    REPO_ENV_VALUE_REASON, dotenv_value_lifts, repo_env_entries, repo_env_file,
};
use crate::secret_custody::{
    CustodyWrite, KeySpan, KnownValues, MaskedFile, MemberStep, masked_file_in_txn,
};
use crate::store::Store;

pub(crate) mod read;

/// Where a retained repository blob's custody records say their keys were
/// found.
const PLACE: &str = "repo:receive-pack";

/// One retained blob's plan, made outside any transaction: its bytes' hash,
/// each key placed in it with its value, and the reason for what no span
/// isolates. Each value is wiped when it drops; it has no `Debug`.
pub(crate) struct RetainedRepoBlobPlan {
    raw_blake3: [u8; 32],
    keys: Vec<FileKey>,
    opaque: Option<&'static str>,
}

/// Plans the marks of `bytes`, one retained repository blob at `path` (the
/// door's label) the receive door's scan named under `proved`. A dotenv
/// blob's every value [`dotenv_value_lifts`] takes is a key too,
/// token-shaped or not (FIX 7608 slice 6, CALL DOTENV-IMPORT). `known` is
/// the index a pass read now; `origin` is the record a plan's stand-ins
/// read for (the push's operation). A blob no rule places a key in, whose container no reader
/// here reads, or whose rebuilt copy still reads as secret is opaque: the
/// keys placed stay, and the residue's reason is kept beside them.
///
/// # Errors
/// An engine failure while reading. A stop the blob's own bytes cause is
/// opaque residue, never an error.
pub(crate) fn plan_retained_repo_blob(
    path: &str,
    bytes: &[u8],
    known: Option<&KnownValues>,
    proved: &'static str,
    origin: EntityId,
) -> Result<RetainedRepoBlobPlan> {
    let mut keys = Vec::new();
    if holds_spans(bytes) {
        let env = dotenv_value_spans(path, bytes);
        place_leaf(&[], bytes, &env, known, origin, &mut keys)?;
    }
    let walked = {
        let mut visit = |path: &[MemberStep], member: &[u8]| -> std::result::Result<(), Stop> {
            if holds_spans(member) {
                place_leaf(path, member, &[], known, origin, &mut keys)?;
            }
            Ok(())
        };
        walk_retained_repo_members(bytes, &mut visit)
    };
    let mut opaque = match walked {
        Ok(()) => residue(bytes, &keys)?,
        Err(Stop::Refuse(reason)) => Some(reason),
        Err(Stop::Fail(error)) => return Err(error),
    };
    // The door proved a key the rules here placed nowhere: the blob is
    // marked whole under the door's own reason.
    if keys.is_empty() && opaque.is_none() {
        opaque = Some(proved);
    }
    Ok(RetainedRepoBlobPlan {
        raw_blake3: *blake3::hash(bytes).as_bytes(),
        keys,
        opaque,
    })
}

/// Each value span of the dotenv blob at `path` that receive lifts, under
/// the dotenv reason; none for any other blob.
fn dotenv_value_spans(path: &str, bytes: &[u8]) -> Vec<(Range<usize>, &'static str)> {
    if repo_env_file(path).is_none() {
        return Vec::new();
    }
    repo_env_entries(bytes)
        .into_iter()
        .filter(|entry| {
            bytes
                .get(entry.value.clone())
                .is_some_and(dotenv_value_lifts)
        })
        .map(|entry| (entry.value, REPO_ENV_VALUE_REASON))
        .collect()
}

/// The keys the file mask's text and field rules, the values custody
/// knows, and `extra` (a dotenv blob's values) place in `leaf` (a blob's
/// own bytes, or one member's), each at `path`, in byte order. No count
/// bounds them (rule 5).
fn place_leaf(
    path: &[MemberStep],
    leaf: &[u8],
    extra: &[(Range<usize>, &'static str)],
    known: Option<&KnownValues>,
    origin: EntityId,
    keys: &mut Vec<FileKey>,
) -> Result<()> {
    let known: Vec<Range<usize>> = match known {
        Some(known) => known.spans(leaf).into_iter().map(|hit| hit.span).collect(),
        None => Vec::new(),
    };
    let mut spans = file_spans(leaf);
    // A value a structured reading places (a credential field), wherever
    // its bytes sit in the leaf.
    let mut fields = Masker {
        mints: true,
        at: Some((origin, PLACE.to_owned())),
        ..Masker::default()
    };
    // A leaf no decoder takes is read as one text, whose spans are
    // the ones just found: they are not found again (speed, FIX 12211).
    if reads_as_text(leaf) {
        let leaf_spans = TextSpans {
            known: Vec::new(),
            shapes: spans.clone(),
        };
        fields.text_log = TextLog::seeded(leaf, leaf_spans);
    }
    fields.mask_body(leaf)?;
    spans.extend(extra.iter().cloned());
    for found in fields.found {
        spans.extend(occurrences(leaf, &found.value).map(|span| (span, found.reason)));
    }
    let mut placed = Vec::new();
    for (span, reason) in merged(spans) {
        if !known
            .iter()
            .any(|held| held.start < span.end && span.start < held.end)
        {
            placed.push(key_at(path, leaf, span, reason)?);
        }
    }
    for span in known {
        placed.push(key_at(path, leaf, span, REASON_KNOWN_VALUE)?);
    }
    placed.sort_by_key(|key| key.span.start);
    keys.extend(placed);
    Ok(())
}

fn key_at(
    path: &[MemberStep],
    leaf: &[u8],
    span: Range<usize>,
    reason: &'static str,
) -> Result<FileKey> {
    let value = Zeroizing::new(
        leaf.get(span.clone())
            .ok_or(Error::InvariantViolation(
                "a blob's key span left its bytes",
            ))?
            .to_vec(),
    );
    Ok(FileKey {
        path: path.to_vec(),
        span,
        reason,
        value,
        custody: None,
    })
}

/// What the copy of `bytes` with each of `keys` overwritten still reads
/// as, or why no copy could be rebuilt; `None` when nothing is left.
fn residue(bytes: &[u8], keys: &[FileKey]) -> Result<Option<&'static str>> {
    let places = places_of(keys)?;
    let copy = match masked_retained_repo_copy(bytes, &places) {
        Ok(copy) => Zeroizing::new(copy),
        Err(Stop::Refuse(reason)) => return Ok(Some(reason)),
        Err(Stop::Fail(error)) => return Err(error),
    };
    validate_retained_repo_copy(&copy)
}

/// The release rules and the custody automaton over `copy` and over every
/// member under it, read the retained repository way: the first reason
/// either names. Never the generic scan, whose container read is bounded.
fn validate_retained_repo_copy(copy: &[u8]) -> Result<Option<&'static str>> {
    if let Some(reason) = leaf_hit(copy)? {
        return Ok(Some(reason));
    }
    let mut visit = |_: &[MemberStep], member: &[u8]| -> std::result::Result<(), Stop> {
        match leaf_hit(member)? {
            Some(reason) => Err(Stop::Refuse(reason)),
            None => Ok(()),
        }
    };
    match walk_retained_repo_members(copy, &mut visit) {
        Ok(()) => Ok(None),
        Err(Stop::Refuse(reason)) => Ok(Some(reason)),
        Err(Stop::Fail(error)) => Err(error),
    }
}

/// The release rules over one run of bytes, then the custody automaton.
fn leaf_hit(bytes: &[u8]) -> Result<Option<&'static str>> {
    match release_hit(bytes) {
        Some(reason) => Ok(Some(reason)),
        None => find_custody_credential(bytes),
    }
}

/// What one push's writer holds while it marks the push's blobs: the
/// known-value index as the writer read it, and each value it minted so
/// far, wiped when it drops. A value met again, in one blob or another,
/// keeps the record it took the first time.
pub(crate) struct RetainedRepoCustody {
    known: Option<Arc<KnownValues>>,
    minted: PlanValues<(String, EntityId)>,
}

impl RetainedRepoCustody {
    /// The index as `wtxn` reads it, with nothing minted yet.
    pub(crate) fn load_in_writer(store: &Store, wtxn: &RwTxn<'_>) -> Result<Self> {
        Ok(Self {
            known: KnownValues::shared_in_writer(store, wtxn)?,
            minted: PlanValues::default(),
        })
    }

    /// The record holding `value` whole: one this writer minted, or one the
    /// index knows.
    fn holder(&self, value: &[u8]) -> Option<EntityId> {
        if let Some((_, id)) = self.minted.get(value) {
            return Some(*id);
        }
        match self.known.as_ref()?.spans(value).as_slice() {
            [hit] if hit.span == (0..value.len()) => Some(hit.custody),
            _ => None,
        }
    }
}

/// One key a blob's mark holds, as a claim names it: where (ordinal member
/// steps, never member names), its kind, and the custody record holding it
/// with that record's handle. No value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetainedRepoPlacedKey {
    pub(crate) member: Vec<MemberStep>,
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) reason: String,
    pub(crate) custody: EntityId,
    pub(crate) handle: String,
}

/// What one blob's mark holds: value-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetainedRepoBlobMarks {
    /// The BLAKE3 of the whole original blob: the mark's key.
    pub(crate) raw_blake3: [u8; 32],
    pub(crate) keys: Vec<RetainedRepoPlacedKey>,
    /// The reason for what no span isolates, when something is left.
    pub(crate) opaque: Option<&'static str>,
}

/// Marks `plan`'s blob in `wtxn`, the receive intent's writer, at `at`. A
/// key a mark of the same bytes already holds keeps that mark (FIX 2781); a
/// value this writer minted, or one custody knows, keeps its record; every
/// other value is minted as its own custody record with no binding, its
/// origin `origin`, and the owner hears of it as of any key found.
///
/// # Errors
/// A custody, mark or store failure: the writer aborts with it.
pub(crate) fn mark_retained_repo_blob_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    custody: &mut RetainedRepoCustody,
    plan: RetainedRepoBlobPlan,
    origin: EntityId,
    at: u64,
) -> Result<RetainedRepoBlobMarks> {
    let store = write.store;
    let RetainedRepoBlobPlan {
        raw_blake3,
        keys,
        opaque,
    } = plan;
    let held = masked_file_in_txn(store, wtxn, &raw_blake3)?;
    let mut placed = Vec::with_capacity(keys.len());
    let mut marked = Vec::with_capacity(keys.len());
    let mut fresh = Masker {
        at: Some((origin, PLACE.to_owned())),
        ..Masker::default()
    };
    for mut key in keys {
        if let Some(span) = held.as_ref().and_then(|file| held_span(file, &key)) {
            placed.push(RetainedRepoPlacedKey {
                member: key.path.clone(),
                start: span.start,
                end: span.end,
                reason: span.reason.clone(),
                custody: span.custody,
                handle: handle_of(store, wtxn, &span.custody)?,
            });
            continue;
        }
        match custody.holder(&key.value) {
            Some(id) => key.custody = Some(id),
            None => {
                fresh.handle(&key.value, key.reason)?;
            }
        }
        marked.push(key);
    }
    let minted = if fresh.found.is_empty() {
        PlanValues::default()
    } else {
        fresh.mint(write, wtxn, at)?
    };
    for key in &marked {
        let id = match key.custody {
            Some(id) => id,
            None => {
                minted
                    .get(&key.value)
                    .ok_or(Error::InvariantViolation(
                        "a blob's key has no custody record",
                    ))?
                    .1
            }
        };
        placed.push(RetainedRepoPlacedKey {
            member: key.path.clone(),
            start: offset(key.span.start)?,
            end: offset(key.span.end)?,
            reason: key.reason.to_owned(),
            custody: id,
            handle: handle_of(store, wtxn, &id)?,
        });
    }
    if !marked.is_empty() {
        let file = FoundFile {
            hash: raw_blake3,
            keys: marked,
            record: origin,
        };
        put_file_marks_in_txn(store, wtxn, vec![file], &minted, at)?;
    }
    custody.minted.adopt(minted);
    Ok(RetainedRepoBlobMarks {
        raw_blake3,
        keys: placed,
        opaque,
    })
}

/// The key a mark already holds over `key`'s place, if one does.
fn held_span<'f>(file: &'f MaskedFile, key: &FileKey) -> Option<&'f KeySpan> {
    let spans = if key.path.is_empty() {
        &file.keys
    } else {
        &file
            .members
            .iter()
            .find(|member| member.path == key.path)?
            .keys
    };
    let start = offset(key.span.start).ok()?;
    let end = offset(key.span.end).ok()?;
    spans
        .iter()
        .find(|held| held.start < end && start < held.end)
}

fn handle_of(store: &Store, txn: &RoTxn<'_>, custody: &EntityId) -> Result<String> {
    store
        .port_short_id_reference(txn, custody)?
        .map(|(handle, _)| handle)
        .ok_or(Error::InvariantViolation(
            "a marked key's custody record has no handle",
        ))
}

impl RetainedRepoBlobPlan {
    /// This plan as one spool record's bytes, appended to `out` (the
    /// caller's wiping buffer): each reason code by the index `intern`
    /// gives it.
    ///
    /// # Errors
    /// A length past the record's encoding, or `intern`'s own refusal.
    pub(crate) fn encode_into(
        &self,
        out: &mut Vec<u8>,
        intern: &mut dyn FnMut(&'static str) -> Result<u16>,
    ) -> Result<()> {
        out.extend_from_slice(&self.raw_blake3);
        match self.opaque {
            Some(reason) => {
                out.push(1);
                out.extend_from_slice(&intern(reason)?.to_be_bytes());
            }
            None => out.push(0),
        }
        put_count(out, self.keys.len())?;
        for key in &self.keys {
            out.extend_from_slice(&intern(key.reason)?.to_be_bytes());
            put_count(out, key.path.len())?;
            for step in &key.path {
                put_step(out, *step);
            }
            put_count(out, key.span.start)?;
            put_count(out, key.span.end)?;
            put_count(out, key.value.len())?;
            out.extend_from_slice(&key.value);
        }
        Ok(())
    }

    /// The plan [`Self::encode_into`] wrote as `bytes`, each reason code
    /// read back through `reason_at`.
    ///
    /// # Errors
    /// Bytes no record of that shape holds.
    pub(crate) fn decode(
        bytes: &[u8],
        reason_at: &dyn Fn(u16) -> Result<&'static str>,
    ) -> Result<Self> {
        let mut input = Spooled(bytes);
        let raw_blake3: [u8; 32] = input.array()?;
        let opaque = match input.byte()? {
            0 => None,
            1 => Some(reason_at(input.u16()?)?),
            _ => return Err(unspooled()),
        };
        let mut keys = Vec::new();
        for _ in 0..input.count()? {
            let reason = reason_at(input.u16()?)?;
            let mut path = Vec::new();
            for _ in 0..input.count()? {
                path.push(input.step()?);
            }
            let start = input.count()?;
            let end = input.count()?;
            let len = input.count()?;
            let value = Zeroizing::new(input.take(len)?.to_vec());
            keys.push(FileKey {
                path,
                span: start..end,
                reason,
                value,
                custody: None,
            });
        }
        if !input.0.is_empty() {
            return Err(unspooled());
        }
        Ok(Self {
            raw_blake3,
            keys,
            opaque,
        })
    }
}

fn put_count(out: &mut Vec<u8>, count: usize) -> Result<()> {
    let count =
        u64::try_from(count).map_err(|_| Error::ArithmeticOverflow("retained repo plan length"))?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn put_step(out: &mut Vec<u8>, step: MemberStep) {
    match step {
        MemberStep::Zip { entry } => {
            out.push(0);
            out.extend_from_slice(&entry.to_be_bytes());
        }
        MemberStep::Gzip => out.push(1),
        // FIX 2471: a tar entry and an xz payload.
        MemberStep::Tar { entry } => {
            out.push(4);
            out.extend_from_slice(&entry.to_be_bytes());
        }
        MemberStep::Xz => out.push(5),
        MemberStep::PdfStream { object, generation } => {
            out.push(2);
            out.extend_from_slice(&object.to_be_bytes());
            out.extend_from_slice(&generation.to_be_bytes());
        }
        MemberStep::PdfStrings { object, generation } => {
            out.push(3);
            out.extend_from_slice(&object.to_be_bytes());
            out.extend_from_slice(&generation.to_be_bytes());
        }
        // FIX 11550: a PDF object stream's decoded bytes.
        MemberStep::PdfObjectStream { object, generation } => {
            out.push(6);
            out.extend_from_slice(&object.to_be_bytes());
            out.extend_from_slice(&generation.to_be_bytes());
        }
    }
}

fn unspooled() -> Error {
    Error::CorruptedIndex("a retained repo plan's spool record")
}

/// A spooled plan's bytes, read from the front.
struct Spooled<'b>(&'b [u8]);

impl<'b> Spooled<'b> {
    fn take(&mut self, len: usize) -> Result<&'b [u8]> {
        if self.0.len() < len {
            return Err(unspooled());
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| unspooled())
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn count(&mut self) -> Result<usize> {
        usize::try_from(u64::from_be_bytes(self.array()?)).map_err(|_| unspooled())
    }

    fn step(&mut self) -> Result<MemberStep> {
        Ok(match self.byte()? {
            0 => MemberStep::Zip { entry: self.u32()? },
            1 => MemberStep::Gzip,
            // FIX 2471: a tar entry and an xz payload.
            4 => MemberStep::Tar { entry: self.u32()? },
            5 => MemberStep::Xz,
            2 => MemberStep::PdfStream {
                object: self.u32()?,
                generation: self.u16()?,
            },
            3 => MemberStep::PdfStrings {
                object: self.u32()?,
                generation: self.u16()?,
            },
            // FIX 11550: a PDF object stream's decoded bytes.
            6 => MemberStep::PdfObjectStream {
                object: self.u32()?,
                generation: self.u16()?,
            },
            _ => return Err(unspooled()),
        })
    }
}
