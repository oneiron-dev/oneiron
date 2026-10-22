//! The reader's half of a pushed key's mark (FIX 7608 slice 2a, CALL 8033
//! option d): the readable `repo.secret_mark` facts, found by walking the
//! claim type index itself (`Vault::for_each_readable_claim_with_predicate_in_txn`),
//! never a local posting list, with no index, cache or count. One walk
//! serves one request or one materialization: [`RepoMarkFacts`] holds the
//! facts it found while that request runs, and nothing past it, so an erased
//! fact is never read again.
//!
//! Each fact is decoded strictly at the one schema it is written at, and its
//! id is derived again from what it says: a fact under another id, of
//! another shape or another schema is a corrupted index, never a clean blob.
//! A blob's facts are every observation of it, from every source and every
//! push, opaque residue first: a reader asks [`RepoBlobMarks::opaque`] before
//! it reads a byte of the blob.
//!
//! These are restricted facts: a reader learns from them only whether, and
//! how, the bytes it was already admitted to read are masked. No fact, id,
//! handle, store or count of them reaches a reply.

use heed::RoTxn;
use rmpv::Value;

use super::{REPO_SECRET_MARK_PREDICATE, RepoSecretMark, RepoSecretPlacement, RepoSecretSource};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
use crate::credential_door::ReceiveBlobKind;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::GitOid;
use crate::secret_custody::{KeyPlaces, MemberStep};

/// How a reader finds marks. The one way is the authoritative walk of every
/// readable claim (CALL 8033 option d): O(claims) once per request, with no
/// derived index to trust or rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepoSecretMarkLookup {
    ReadableClaims,
}

/// One blob of one served store: the store's id (`lfs_repo_id` of its
/// identity) and the blob's canonical Git OID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoBlobAddress {
    pub(crate) store: EntityId,
    pub(crate) blob: GitOid,
}

/// Every readable mark of one blob, each validated; none for an unmarked
/// blob, which a reader serves exactly as before.
#[derive(Debug, Clone, Default)]
pub(crate) struct RepoBlobMarks {
    marks: Vec<RepoSecretMark>,
}

impl RepoBlobMarks {
    /// No mark: the blob is served as it is stored.
    pub(crate) fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    /// Whether any mark holds residue no span isolates (C5). It wins over
    /// every span mark beside it, and is asked before any byte is read.
    pub(crate) fn opaque(&self) -> bool {
        self.marks
            .iter()
            .any(|mark| mark.placement == RepoSecretPlacement::Opaque)
    }

    /// The marked blob's Git OID, for a reply's source link.
    pub(crate) fn source_blob(&self) -> Option<&GitOid> {
        self.marks.first().map(|mark| &mark.blob_oid)
    }

    /// The BLAKE3 of the whole marked blob, when every mark names the same
    /// one; `None` with no mark, or with marks that disagree.
    pub(crate) fn raw_blake3(&self) -> Option<[u8; 32]> {
        let first = self.marks.first()?.raw_blake3;
        self.marks
            .iter()
            .all(|mark| mark.raw_blake3 == first)
            .then_some(first)
    }

    /// Each place a span mark names, its spans in byte order and once each:
    /// the blob's own bytes for no member steps, else that member.
    pub(crate) fn places(&self) -> KeyPlaces {
        let mut places: KeyPlaces = Vec::new();
        for mark in &self.marks {
            if let RepoSecretPlacement::Span {
                member, start, end, ..
            } = &mark.placement
            {
                add_place(&mut places, member, (*start, *end));
            }
        }
        places
    }

    /// Each mark's id, sorted and once each: what a masked Git copy
    /// records it was made under (FIX 7608 slice 2b-i), never a key.
    ///
    /// # Errors
    /// A failed id derivation.
    pub(crate) fn ids(&self) -> Result<Vec<EntityId>> {
        sorted_ids(&self.marks)
    }

    fn push(&mut self, mark: RepoSecretMark) {
        self.marks.push(mark);
    }

    /// Each span mark's custody record, once each, in mark order: the keys
    /// a real-byte file reveal of this blob asks for (FIX 7608 2b-ii). A
    /// record id, never a value.
    pub(crate) fn custody(&self) -> Vec<EntityId> {
        let mut custody: Vec<EntityId> = Vec::new();
        for mark in &self.marks {
            if let RepoSecretPlacement::Span { custody: id, .. } = &mark.placement
                && !custody.contains(id)
            {
                custody.push(*id);
            }
        }
        custody
    }
}

fn sorted_ids(marks: &[RepoSecretMark]) -> Result<Vec<EntityId>> {
    let mut ids = marks
        .iter()
        .map(RepoSecretMark::id)
        .collect::<Result<Vec<_>>>()?;
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// `span` at `member` in `places`, once.
pub(crate) fn add_place(places: &mut KeyPlaces, member: &[MemberStep], span: (u64, u64)) {
    let at = match places
        .iter()
        .position(|(path, _)| path.as_slice() == member)
    {
        Some(at) => at,
        None => {
            places.push((member.to_vec(), Vec::new()));
            places.len() - 1
        }
    };
    let spans = &mut places[at].1;
    if let Err(index) = spans.binary_search(&span) {
        spans.insert(index, span);
    }
}

/// The readable marks one walk found, held for one request or one
/// materialization and dropped with it.
#[derive(Debug, Default)]
pub(crate) struct RepoMarkFacts {
    marks: Vec<RepoSecretMark>,
}

impl RepoMarkFacts {
    /// Every readable mark, read once in `txn`.
    ///
    /// # Errors
    /// A store failure, or a mark that does not decode.
    pub(crate) fn read_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        lookup: RepoSecretMarkLookup,
    ) -> Result<Self> {
        let mut marks = Vec::new();
        for_each_repo_secret_mark_in_txn(vault, txn, lookup, &mut |mark: RepoSecretMark| {
            marks.push(mark);
            Ok(())
        })?;
        Ok(Self { marks })
    }

    /// No mark anywhere: every reader serves as before.
    pub(crate) fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    /// Every readable mark's id, sorted and once each (FIX 7608 slice
    /// 2b-i): the set a masked Git copy is made under.
    ///
    /// # Errors
    /// A failed id derivation.
    pub(crate) fn ids(&self) -> Result<Vec<EntityId>> {
        sorted_ids(&self.marks)
    }

    /// The marks of the blob whose whole bytes hash to `raw_blake3`, in any
    /// store: the same bytes are the same blob.
    pub(crate) fn for_hash(&self, raw_blake3: &[u8; 32]) -> RepoBlobMarks {
        self.select(|mark| mark.raw_blake3 == *raw_blake3)
    }

    /// The marks of `address`'s blob in its store.
    pub(crate) fn for_blob(&self, address: &RepoBlobAddress) -> RepoBlobMarks {
        self.select(|mark| mark.store_id == address.store && mark.blob_oid == address.blob)
    }

    fn select<F: Fn(&RepoSecretMark) -> bool>(&self, matches: F) -> RepoBlobMarks {
        let mut out = RepoBlobMarks::default();
        for mark in self.marks.iter().filter(|mark| matches(mark)) {
            out.push(mark.clone());
        }
        out
    }
}

/// The marks of the blob whose whole bytes hash to `raw_blake3`, in any
/// store, found by one walk in `txn`.
///
/// # Errors
/// As [`RepoMarkFacts::read_in_txn`].
pub(crate) fn repo_secret_marks_for_hash_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    raw_blake3: &[u8; 32],
) -> Result<RepoBlobMarks> {
    let mut out = RepoBlobMarks::default();
    for_each_repo_secret_mark_in_txn(
        vault,
        txn,
        RepoSecretMarkLookup::ReadableClaims,
        &mut |mark: RepoSecretMark| {
            if mark.raw_blake3 == *raw_blake3 {
                out.push(mark);
            }
            Ok(())
        },
    )?;
    Ok(out)
}

/// Hands each readable mark, in every store, to `visit`, decoded and
/// checked against its own id, in one walk of `txn`. A mark the owner's
/// approval no longer stands behind is not a standing mark, and is skipped.
///
/// # Errors
/// A store failure, `visit`'s own, or a mark that does not decode.
pub(crate) fn for_each_repo_secret_mark_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    lookup: RepoSecretMarkLookup,
    visit: &mut dyn FnMut(RepoSecretMark) -> Result<()>,
) -> Result<()> {
    match lookup {
        RepoSecretMarkLookup::ReadableClaims => vault
            .for_each_readable_claim_with_predicate_in_txn(
                txn,
                REPO_SECRET_MARK_PREDICATE,
                |id, body| match decode_mark(id, &body)? {
                    Some(mark) => visit(mark),
                    None => Ok(()),
                },
            ),
    }
}

fn corrupt() -> Error {
    Error::CorruptedIndex("a repo secret mark does not decode")
}

/// One stored mark, at schema 1 only; `None` for one no approval stands
/// behind.
fn decode_mark(id: EntityId, body: &ClaimBody) -> Result<Option<RepoSecretMark>> {
    if body.predicate != REPO_SECRET_MARK_PREDICATE || body.source != Some(ClaimSource::Observed) {
        return Err(corrupt());
    }
    if body.approval != ClaimApprovalStatus::Approved {
        return Ok(None);
    }
    let ClaimSubject::Edge {
        source: operation,
        kind,
        target: store,
    } = &body.subject
    else {
        return Err(corrupt());
    };
    if *kind != EdgeKind::PartOf {
        return Err(corrupt());
    }
    let map = body.value.as_map().ok_or_else(corrupt)?;
    let schema_version =
        u16::try_from(uint(field(map, "schema_version")?)?).map_err(|_| corrupt())?;
    if schema_version != RepoSecretMark::SCHEMA {
        return Err(corrupt());
    }
    let mark = RepoSecretMark {
        schema_version,
        operation_id: entity(field(map, "operation_id")?)?,
        store_id: entity(field(map, "store_id")?)?,
        store_identity: text(field(map, "store_identity")?)?.to_owned(),
        source: source(field(map, "source")?)?,
        blob_oid: oid(field(map, "blob_oid")?)?,
        raw_blake3: field(map, "raw_blake3")?
            .as_slice()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(corrupt)?,
        path: optional(field(map, "path")?, |value| Ok(text(value)?.to_owned()))?,
        detector_kind: text(field(map, "detector_kind")?)?.to_owned(),
        content_kind: match text(field(map, "content_kind")?)? {
            "text" => ReceiveBlobKind::Text,
            "binary" => ReceiveBlobKind::Binary,
            _ => return Err(corrupt()),
        },
        placement: placement(field(map, "placement")?)?,
        marked_at: uint(field(map, "marked_at")?)?,
    };
    // The fact says exactly what its id was derived from, in its one shape.
    if mark.operation_id != *operation
        || mark.store_id != *store
        || mark.value() != body.value
        || mark.id()? != id
    {
        return Err(corrupt());
    }
    Ok(Some(mark))
}

fn field<'v>(map: &'v [(Value, Value)], key: &str) -> Result<&'v Value> {
    map.iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
        .ok_or_else(corrupt)
}

fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(corrupt)
}

fn uint(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(corrupt)
}

fn small<T: TryFrom<u64>>(value: &Value) -> Result<T> {
    T::try_from(uint(value)?).map_err(|_| corrupt())
}

fn entity(value: &Value) -> Result<EntityId> {
    EntityId::from_hex(text(value)?).map_err(|_| corrupt())
}

fn oid(value: &Value) -> Result<GitOid> {
    GitOid::parse_hex(text(value)?).map_err(|_| corrupt())
}

fn optional<T, F: FnOnce(&Value) -> Result<T>>(value: &Value, read: F) -> Result<Option<T>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        read(value).map(Some)
    }
}

fn source(value: &Value) -> Result<RepoSecretSource> {
    let map = value.as_map().ok_or_else(corrupt)?;
    match text(field(map, "kind")?)? {
        "ref_move" => Ok(RepoSecretSource::RefMove {
            name: text(field(map, "name")?)?.to_owned(),
            old_oid: optional(field(map, "old_oid")?, oid)?,
            new_oid: oid(field(map, "new_oid")?)?,
        }),
        "quarantine" => Ok(RepoSecretSource::Quarantine),
        _ => Err(corrupt()),
    }
}

fn placement(value: &Value) -> Result<RepoSecretPlacement> {
    let map = value.as_map().ok_or_else(corrupt)?;
    match text(field(map, "kind")?)? {
        "span" => {
            let start = uint(field(map, "start")?)?;
            let end = uint(field(map, "end")?)?;
            if start >= end {
                return Err(corrupt());
            }
            Ok(RepoSecretPlacement::Span {
                member: field(map, "member")?
                    .as_array()
                    .ok_or_else(corrupt)?
                    .iter()
                    .map(step)
                    .collect::<Result<Vec<_>>>()?,
                start,
                end,
                custody: entity(field(map, "custody")?)?,
                handle: text(field(map, "handle")?)?.to_owned(),
            })
        }
        "opaque" => Ok(RepoSecretPlacement::Opaque),
        _ => Err(corrupt()),
    }
}

fn step(value: &Value) -> Result<MemberStep> {
    match value.as_array().map(Vec::as_slice).ok_or_else(corrupt)? {
        [kind, entry] if kind.as_str() == Some("zip") => Ok(MemberStep::Zip {
            entry: small(entry)?,
        }),
        [kind] if kind.as_str() == Some("gzip") => Ok(MemberStep::Gzip),
        [kind, object, generation] if kind.as_str() == Some("pdf_stream") => {
            Ok(MemberStep::PdfStream {
                object: small(object)?,
                generation: small(generation)?,
            })
        }
        _ => Err(corrupt()),
    }
}
