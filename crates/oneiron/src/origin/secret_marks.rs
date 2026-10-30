//! A pushed key's mark (FIX 7608, owner ruling SECRETS-IN-REPOS = A): the
//! immutable `repo.secret_mark` facts an admitted receive-pack writes in its
//! intent's own transaction.
//!
//! History stays exact: a pushed blob keeps its bytes, and each key in it is
//! marked, never rewritten. One fact names one source observation and one
//! placed key: the push's operation, the canonical object store, where the
//! door saw the blob (a proposed ref's move, or the quarantine), the blob's
//! canonical OID and the BLAKE3 of its whole bytes, its exact path or none,
//! the detector's reason, how the door read it, and the key's span (in the
//! blob, or in a decoded member by ordinal steps) with the custody record
//! and handle holding it. What no span isolates is one opaque fact beside
//! them (C5), with no custody record and no span. No fact carries a key
//! byte, a hash of one, an excerpt or a member name, and none names an
//! actor.
//!
//! Each fact's id is derived from its whole address
//! (`derived_domains::REPO_SECRET_MARK`), never from its custody, handle or
//! time: the same address in one operation is written once, and another
//! fact under that id refuses the write. A fact is about the edge `operation
//! PartOf store`, because a served store need not be an entity, and keeps
//! the masked-file band. A reader finds a blob's facts by store and OID
//! among the predicate's claims, or its spans by the blob's BLAKE3 in
//! `SECRET_MASK_SPANS`; opaque facts come first, before any raw read. No
//! reader, notice, disposition or door is written here.
//!
//! Quarantine means only that this operation's scan saw the bytes with no
//! proved ref. It covers history-only and unreachable objects alike, and
//! proves neither.

use heed::RwTxn;
use rmpv::Value;

use super::lfs::lfs_repo_id;
use super::smart_http::secret_marks::{ReceiveSecretMarks, ReceiveSecretObservation, ReceiveSeen};
use super::smart_http::{DoorAdmissionStamp, DoorWindowReport, DoorWindowVerdict, RefUpdate};
use crate::Vault;
use crate::batch::secret_scan::{
    RetainedRepoBlobMarks, RetainedRepoCustody, RetainedRepoPlacedKey,
    mark_retained_repo_blob_in_txn,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::credential_door::ReceiveBlobKind;
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, derived_domains};
use crate::error::{Error, Result};
use crate::git_wire::GitOid;
use crate::secret_custody::{CustodyWrite, MASKED_FILE_BAND, MemberStep};
use crate::temporal::TimeRange;

mod carry;
mod read;
pub(crate) use carry::carry_repo_secret_marks_in_txn;
pub(crate) use read::{
    RepoBlobAddress, RepoBlobMarks, RepoMarkFacts, RepoSecretMarkLookup, add_place,
    for_each_repo_secret_mark_in_txn, repo_secret_marks_for_hash_in_txn,
};

/// The predicate of one pushed key's mark.
pub(crate) const REPO_SECRET_MARK_PREDICATE: &str = "repo.secret_mark";

/// One mark: one source observation of one blob and one placed key, or the
/// blob's opaque residue. Value-free, and immutable once written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoSecretMark {
    pub(crate) schema_version: u16,
    /// The receive operation, which is also its admission claim's id.
    pub(crate) operation_id: EntityId,
    /// The served store's id (`lfs_repo_id` of its identity).
    pub(crate) store_id: EntityId,
    /// The canonical object-store identity (hex).
    pub(crate) store_identity: String,
    pub(crate) source: RepoSecretSource,
    pub(crate) blob_oid: GitOid,
    /// The BLAKE3 of the whole stored blob, which its spans are kept under.
    /// Never a hash of a key, and not the Git OID.
    pub(crate) raw_blake3: [u8; 32],
    /// The exact path, when the door knows it.
    pub(crate) path: Option<String>,
    /// A reason code, never an excerpt: the span's for a span, the
    /// residue's for an opaque fact.
    pub(crate) detector_kind: String,
    pub(crate) content_kind: ReceiveBlobKind,
    pub(crate) placement: RepoSecretPlacement,
    pub(crate) marked_at: u64,
}

/// Where the door saw a marked blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoSecretSource {
    /// A proposed ref's move, which the door diffed the blob for.
    RefMove {
        name: String,
        old_oid: Option<GitOid>,
        new_oid: GitOid,
    },
    /// The operation's quarantine scan saw the bytes, with no proved ref.
    Quarantine,
    /// A translated sync copy edit landed these bytes on the marked source
    /// `source`, a blob the operation's door saw before (FIX 10732, L04
    /// 05:5x): no ref and no push proved them, as with the quarantine.
    SyncLanding { source: EntityId },
}

/// What a mark places.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoSecretPlacement {
    /// A key's half-open byte span: in the blob for no member steps, or in
    /// that decoded member.
    Span {
        member: Vec<MemberStep>,
        start: u64,
        end: u64,
        custody: EntityId,
        handle: String,
    },
    /// What no span isolates: the blob is kept and marked whole.
    Opaque,
}

impl RepoSecretMark {
    /// The one schema these facts are written at.
    pub(crate) const SCHEMA: u16 = 1;

    /// The fact's id: its whole address, each alternative a tagged
    /// MessagePack part, under the derivation's own length framing.
    fn id(&self) -> Result<EntityId> {
        let schema = self.schema_version.to_be_bytes();
        let source = packed(&source_part(&self.source))?;
        let path = packed(&self.path.as_deref().map_or(Value::Nil, Value::from))?;
        let placement = packed(&placement_part(&self.placement))?;
        Ok(EntityId::derive(
            derived_domains::REPO_SECRET_MARK,
            &[
                &schema,
                self.operation_id.as_bytes(),
                self.store_identity.as_bytes(),
                &source,
                self.blob_oid.as_str().as_bytes(),
                &path,
                self.detector_kind.as_bytes(),
                content_tag(self.content_kind).as_bytes(),
                &placement,
            ],
        )?)
    }

    fn value(&self) -> Value {
        let source = match &self.source {
            RepoSecretSource::RefMove {
                name,
                old_oid,
                new_oid,
            } => fields(vec![
                ("kind", Value::from("ref_move")),
                ("name", Value::from(name.as_str())),
                ("old_oid", oid_value(old_oid.as_ref())),
                ("new_oid", Value::from(new_oid.as_str())),
            ]),
            RepoSecretSource::Quarantine => fields(vec![("kind", Value::from("quarantine"))]),
            RepoSecretSource::SyncLanding { source } => fields(vec![
                ("kind", Value::from("sync_landing")),
                ("source", Value::from(source.to_hex())),
            ]),
        };
        let placement = match &self.placement {
            RepoSecretPlacement::Span {
                member,
                start,
                end,
                custody,
                handle,
            } => fields(vec![
                ("kind", Value::from("span")),
                ("member", steps_value(member)),
                ("start", Value::from(*start)),
                ("end", Value::from(*end)),
                ("custody", Value::from(custody.to_hex())),
                ("handle", Value::from(handle.as_str())),
            ]),
            RepoSecretPlacement::Opaque => fields(vec![("kind", Value::from("opaque"))]),
        };
        fields(vec![
            ("schema_version", Value::from(self.schema_version)),
            ("operation_id", Value::from(self.operation_id.to_hex())),
            ("store_id", Value::from(self.store_id.to_hex())),
            ("store_identity", Value::from(self.store_identity.as_str())),
            ("source", source),
            ("blob_oid", Value::from(self.blob_oid.as_str())),
            ("raw_blake3", Value::Binary(self.raw_blake3.to_vec())),
            ("path", self.path.as_deref().map_or(Value::Nil, Value::from)),
            ("detector_kind", Value::from(self.detector_kind.as_str())),
            ("content_kind", Value::from(content_tag(self.content_kind))),
            ("placement", placement),
            ("marked_at", Value::from(self.marked_at)),
        ])
    }

    fn claim(&self) -> Result<ClaimBody> {
        let mut body = ClaimBody::new(
            REPO_SECRET_MARK_PREDICATE,
            ClaimSubject::Edge {
                source: self.operation_id,
                kind: EdgeKind::PartOf,
                target: self.store_id,
            },
            self.value(),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?;
        // Engine bookkeeping of one push, never a claim a caller could write,
        // in the band a file with keys in it carries.
        body.source = Some(ClaimSource::Observed);
        body.scope = Some(fields(vec![(
            "sensitivity",
            Value::from(MASKED_FILE_BAND.as_str()),
        )]));
        Ok(body)
    }
}

/// The marks `door` carries when its verdict admitted the push marked,
/// checked to be `stamp`'s before the intent's writer opens; `None` for a
/// clean push, which writes no mark and reads nothing more.
///
/// # Errors
/// Marks of another operation.
pub(crate) fn admitted_marks<'d>(
    door: &'d DoorWindowReport,
    stamp: &DoorAdmissionStamp,
) -> Result<Option<&'d ReceiveSecretMarks>> {
    match &door.verdict {
        DoorWindowVerdict::AdmitMarked { marks }
            if marks.operation_id() == stamp.operation_id() =>
        {
            Ok(Some(marks))
        }
        DoorWindowVerdict::AdmitMarked { .. } => Err(Error::InvariantViolation(
            "a push's receive marks name another operation",
        )),
        _ => Ok(None),
    }
}

/// Writes the facts `marks` spooled, in `wtxn`, the admitted intent's own
/// writer, after its push recheck and before its intent row: each blob's
/// keys go to custody and its spans to its mark (`mark_retained_repo_blob_in_txn`),
/// then one fact per source and placement. `store_identity` is the store
/// the intent is keyed by; `updates` are the push's proposed moves, which a
/// tip blob's facts name. Opens no writer, calls no Git and decides no
/// admission; with no marks it returns before reading anything.
///
/// Returns how many facts this transaction newly wrote (FIX 8032): one per
/// source and placement, spans and opaque residue alike, a fact already
/// under its id not counted again; 0 with no marks. It counts no value,
/// blob or record, and names none.
///
/// # Errors
/// A spool, custody, mark or claim failure, or a fact that contradicts one
/// already under its id: the whole transaction aborts with it.
pub(crate) fn record_receive_secret_marks_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    stamp: &DoorAdmissionStamp,
    store_identity: &str,
    marks: Option<&ReceiveSecretMarks>,
    updates: &[RefUpdate],
) -> Result<u64> {
    let Some(marks) = marks else {
        return Ok(0);
    };
    let operation_id = stamp.operation_id();
    let store_id = lfs_repo_id(store_identity)?;
    let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let write = CustodyWrite::of(vault);
    let mut custody = RetainedRepoCustody::load_in_writer(&vault.store, wtxn)?;
    let mut written: u64 = 0;
    let mut marked_blobs = Vec::new();
    marks.drain(&mut |observation, plan| {
        let placed =
            mark_retained_repo_blob_in_txn(&write, wtxn, &mut custody, plan, operation_id, at)?;
        marked_blobs.push(placed.raw_blake3);
        let placements = placements(&placed);
        for (source, path) in sources(&observation, updates) {
            for (placement, detector_kind) in &placements {
                let mark = RepoSecretMark {
                    schema_version: RepoSecretMark::SCHEMA,
                    operation_id,
                    store_id,
                    store_identity: store_identity.to_owned(),
                    source: source.clone(),
                    blob_oid: observation.blob_oid.clone(),
                    raw_blake3: placed.raw_blake3,
                    path: path.clone(),
                    detector_kind: detector_kind.clone(),
                    content_kind: observation.content_kind,
                    placement: placement.clone(),
                    marked_at: at,
                };
                if put_repo_secret_mark_in_txn(vault, wtxn, &mark)? {
                    written = written
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow("a push's repo secret marks"))?;
                }
            }
        }
        Ok(())
    })?;
    // The index copies these blobs already derive are refreshed under their
    // new marks, once for the batch (FIX 7608 slice 3).
    if written > 0 {
        crate::origin::secret_projection::index::refresh_repo_index_projection_in_txn(
            vault,
            wtxn,
            &marked_blobs,
        )?;
    }
    Ok(written)
}

/// Each source `observation` names, with the path its facts carry: one per
/// proposed ref making its move, with its exact path; otherwise the
/// quarantine, with none.
fn sources(
    observation: &ReceiveSecretObservation,
    updates: &[RefUpdate],
) -> Vec<(RepoSecretSource, Option<String>)> {
    let quarantine = || vec![(RepoSecretSource::Quarantine, None)];
    let ReceiveSeen::RefMove { old, new } = &observation.seen else {
        return quarantine();
    };
    let moved: Vec<(RepoSecretSource, Option<String>)> = updates
        .iter()
        .filter(|update| update.old_oid == *old && update.new_oid.as_ref() == Some(new))
        .map(|update| {
            let source = RepoSecretSource::RefMove {
                name: update.name.clone(),
                old_oid: old.clone(),
                new_oid: new.clone(),
            };
            (source, observation.path.clone())
        })
        .collect();
    if moved.is_empty() {
        quarantine()
    } else {
        moved
    }
}

/// Each placement one blob's mark holds, with its reason: each key's span,
/// then the opaque residue when something is left.
fn placements(placed: &RetainedRepoBlobMarks) -> Vec<(RepoSecretPlacement, String)> {
    let mut out: Vec<(RepoSecretPlacement, String)> = placed
        .keys
        .iter()
        .map(|key| (span_of(key), key.reason.clone()))
        .collect();
    if let Some(reason) = placed.opaque {
        out.push((RepoSecretPlacement::Opaque, reason.to_owned()));
    }
    out
}

fn span_of(key: &RetainedRepoPlacedKey) -> RepoSecretPlacement {
    RepoSecretPlacement::Span {
        member: key.member.clone(),
        start: key.start,
        end: key.end,
        custody: key.custody,
        handle: key.handle.clone(),
    }
}

/// The marks a projection-bound push's ingress recorded, carried to the
/// canonical store `store_id` (identity `store_identity`) when the push is
/// forwarded exactly (FIX 7608 2b-ii): the same placements and opaque
/// facts, still linked to the ingress operation that saw the bytes, with no
/// scan and no second custody mint, before the canonical publication.
/// Gives each forwarded mark's id, sorted and once each.
///
/// # Errors
/// A store failure, or another record under a mark's id.
#[allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the exact forward calls it in 2b-ii-B"
)]
pub(crate) fn readdress_forward_secret_marks_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    marks: &[RepoSecretMark],
    store_id: EntityId,
    store_identity: &str,
) -> Result<Vec<EntityId>> {
    let mut forwarded_ids = Vec::with_capacity(marks.len());
    for mark in marks {
        let mut forwarded = mark.clone();
        forwarded.store_id = store_id;
        forwarded.store_identity = store_identity.to_owned();
        put_repo_secret_mark_in_txn(vault, wtxn, &forwarded)?;
        forwarded_ids.push(forwarded.id()?);
    }
    forwarded_ids.sort_unstable();
    forwarded_ids.dedup();
    Ok(forwarded_ids)
}

/// Writes `mark` once at its id, and says whether it wrote it: the same
/// fact again writes nothing; any other record under the id refuses.
fn put_repo_secret_mark_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    mark: &RepoSecretMark,
) -> Result<bool> {
    let id = mark.id()?;
    let body = mark.claim()?;
    match vault.get_claim_in_txn(wtxn, &id)? {
        Some(stored)
            if stored.predicate == body.predicate
                && stored.subject == body.subject
                && stored.value == body.value =>
        {
            return Ok(false);
        }
        Some(_) => {
            return Err(Error::CorruptedIndex(
                "a repo secret mark's id holds another fact",
            ));
        }
        None if vault.get_raw_in(wtxn, &id)?.is_some() => {
            return Err(Error::CorruptedIndex(
                "a repo secret mark's id holds another record",
            ));
        }
        None => {}
    }
    let occurred = TimeRange {
        start: mark.marked_at,
        end: mark.marked_at,
    };
    vault.put_reserved_claim_in_txn(wtxn, &id, &body, occurred, mark.marked_at)?;
    Ok(true)
}

fn fields(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

fn oid_value(oid: Option<&GitOid>) -> Value {
    oid.map_or(Value::Nil, |oid| Value::from(oid.as_str()))
}

const fn content_tag(kind: ReceiveBlobKind) -> &'static str {
    match kind {
        ReceiveBlobKind::Text => "text",
        ReceiveBlobKind::Binary => "binary",
    }
}

fn steps_value(member: &[MemberStep]) -> Value {
    Value::Array(
        member
            .iter()
            .map(|step| match *step {
                MemberStep::Zip { entry } => {
                    Value::Array(vec![Value::from("zip"), Value::from(entry)])
                }
                MemberStep::Gzip => Value::Array(vec![Value::from("gzip")]),
                // FIX 2471: a tar entry and an xz payload.
                MemberStep::Tar { entry } => {
                    Value::Array(vec![Value::from("tar"), Value::from(entry)])
                }
                MemberStep::Xz => Value::Array(vec![Value::from("xz")]),
                MemberStep::PdfStream { object, generation } => Value::Array(vec![
                    Value::from("pdf_stream"),
                    Value::from(object),
                    Value::from(generation),
                ]),
                MemberStep::PdfStrings { object, generation } => Value::Array(vec![
                    Value::from("pdf_strings"),
                    Value::from(object),
                    Value::from(generation),
                ]),
            })
            .collect(),
    )
}

/// The source as an id part: `["ref_move", name, old or nil, new]`,
/// `["quarantine"]` or `["sync_landing", source]`.
fn source_part(source: &RepoSecretSource) -> Value {
    match source {
        RepoSecretSource::RefMove {
            name,
            old_oid,
            new_oid,
        } => Value::Array(vec![
            Value::from("ref_move"),
            Value::from(name.as_str()),
            oid_value(old_oid.as_ref()),
            Value::from(new_oid.as_str()),
        ]),
        RepoSecretSource::Quarantine => Value::Array(vec![Value::from("quarantine")]),
        RepoSecretSource::SyncLanding { source } => Value::Array(vec![
            Value::from("sync_landing"),
            Value::from(source.to_hex()),
        ]),
    }
}

/// The placement as an id part: `["span", steps, start, end]` or
/// `["opaque"]`. Its custody record and handle are no part of it.
fn placement_part(placement: &RepoSecretPlacement) -> Value {
    match placement {
        RepoSecretPlacement::Span {
            member, start, end, ..
        } => Value::Array(vec![
            Value::from("span"),
            steps_value(member),
            Value::from(*start),
            Value::from(*end),
        ]),
        RepoSecretPlacement::Opaque => Value::Array(vec![Value::from("opaque")]),
    }
}

fn packed(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| Error::InvariantViolation("a repo secret mark part did not encode"))?;
    Ok(out)
}
