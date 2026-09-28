//! Key builders, journal row codec, bounded-failure helper, and deterministic ids and claim builders.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::git_wire::{GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefName};
use crate::origin::lfs::LfsOid;
use crate::side_table::{self, Named, Raw, SideKey, SideTable};
use crate::temporal::TimeRange;

use super::publication_types::{
    ORIGIN_PUBLICATION_CLAIM_ID_DOMAIN, ORIGIN_PUBLICATION_COMMIT_ID_DOMAIN,
    ORIGIN_PUBLICATION_ID_DOMAIN, ORIGIN_PUBLICATION_INTENT_PREDICATE,
    ORIGIN_PUBLICATION_MAX_FAILURE_BYTES, ORIGIN_PUBLICATION_PREDICATE,
    ORIGIN_PUBLICATION_SCHEMA_VERSION, ORIGIN_PUBLICATION_VALUE_KEYS, OriginKeepRefKind,
    OriginPublicationRecord, OriginPublicationRequest, OriginPublicationStatus,
};
// ---------------------------------------------------------------------------
// Keys, tables and rows
// ---------------------------------------------------------------------------

/// Durable journal row for one origin ref-publication attempt. Key: publication id.
pub(super) const PUBLICATIONS: SideTable<EntityId, OriginPublicationRow, Named> =
    SideTable::new(&side_table::ORIGIN_PUBLICATION_RECORD);

/// One in-flight owner of `(repo, ref, expected, new)`, independent of provenance (value =
/// owning publication id). Key: repo id "\x00" ref_name "\x00" expected_old_oid "\x00" new_oid.
pub(super) const CAS_INTENT: SideTable<CasIntentKey, EntityId, Raw> =
    SideTable::new(&side_table::ORIGIN_CAS_INTENT);

/// The publication currently advertised for one repository's ref name (value = publication id).
/// Key: repo id "\x00" ref_name.
pub(super) const VISIBLE_REF: SideTable<VisibleRefKey, EntityId, Raw> =
    SideTable::new(&side_table::ORIGIN_VISIBLE_REF);

/// One logical owner's reservation of a physical git keep-ref (value = u64be learned_at)... the
/// value is actually u64 LE, unchanged from the pre-side-table row. Key: repo id "\x00" oid
/// "\x00" kind "\x00" owner_key.
pub(super) const KEEP_OWNER: SideTable<KeepOwnerKey, [u8; 8], Raw> =
    SideTable::new(&side_table::ORIGIN_KEEP_OWNER);

/// `origin:cas_intent:v1:` key shape: repo id, then three NUL-framed text fields. Neither a ref
/// name nor a lower-hex object id can carry a NUL, so every field stays unambiguously framed.
pub(super) struct CasIntentKey {
    pub(super) repo_id: EntityId,
    ref_name: String,
    expected_old_oid: String,
    new_oid: String,
}

impl CasIntentKey {
    pub(super) fn new(record: &OriginPublicationRecord) -> Self {
        Self {
            repo_id: record.repo_id,
            ref_name: record.ref_name.as_str().to_owned(),
            expected_old_oid: record
                .expected_old_oid
                .as_ref()
                .map_or_else(String::new, |oid| oid.as_str().to_owned()),
            new_oid: record.new_oid.as_str().to_owned(),
        }
    }
}

impl PartialEq for CasIntentKey {
    fn eq(&self, other: &Self) -> bool {
        self.repo_id == other.repo_id
            && self.ref_name == other.ref_name
            && self.expected_old_oid == other.expected_old_oid
            && self.new_oid == other.new_oid
    }
}

impl SideKey for CasIntentKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.repo_id.encode_into(out);
        for field in [&self.ref_name, &self.expected_old_oid, &self.new_oid] {
            out.push(0);
            out.extend_from_slice(field.as_bytes());
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (repo_bytes, rest) = bytes.split_at_checked(ENTITY_ID_LEN)?;
        let rest = rest.strip_prefix(&[0][..])?;
        let text = std::str::from_utf8(rest).ok()?;
        let mut parts = text.splitn(3, '\0');
        let ref_name = parts.next()?.to_owned();
        let expected_old_oid = parts.next()?.to_owned();
        let new_oid = parts.next()?.to_owned();
        Some(Self {
            repo_id: EntityId::decode_key(repo_bytes)?,
            ref_name,
            expected_old_oid,
            new_oid,
        })
    }
}

/// `origin:visible_ref:v1:` key shape: repo id, then a NUL-framed ref name.
pub(super) struct VisibleRefKey {
    repo_id: EntityId,
    ref_name: String,
}

impl SideKey for VisibleRefKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.repo_id.encode_into(out);
        out.push(0);
        out.extend_from_slice(self.ref_name.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (repo_bytes, rest) = bytes.split_at_checked(ENTITY_ID_LEN)?;
        let rest = rest.strip_prefix(&[0][..])?;
        Some(Self {
            repo_id: EntityId::decode_key(repo_bytes)?,
            ref_name: String::from_utf8(rest.to_vec()).ok()?,
        })
    }
}

pub(super) fn visible_ref_key(repo_id: &EntityId, ref_name: &GitRefName) -> VisibleRefKey {
    VisibleRefKey {
        repo_id: *repo_id,
        ref_name: ref_name.as_str().to_owned(),
    }
}

/// `origin:keep_owner:v1:` key shape: repo id, then three NUL-framed text fields (oid, kind,
/// owner key).
pub(super) struct KeepOwnerKey {
    repo_id: EntityId,
    pub(super) oid: String,
    pub(super) kind: String,
    pub(super) owner_key: String,
}

impl SideKey for KeepOwnerKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.repo_id.encode_into(out);
        for field in [&self.oid, &self.kind, &self.owner_key] {
            out.push(0);
            out.extend_from_slice(field.as_bytes());
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (repo_bytes, rest) = bytes.split_at_checked(ENTITY_ID_LEN)?;
        let rest = rest.strip_prefix(&[0][..])?;
        let text = std::str::from_utf8(rest).ok()?;
        let mut parts = text.splitn(3, '\0');
        let oid = parts.next()?.to_owned();
        let kind = parts.next()?.to_owned();
        let owner_key = parts.next()?.to_owned();
        Some(Self {
            repo_id: EntityId::decode_key(repo_bytes)?,
            oid,
            kind,
            owner_key,
        })
    }
}

pub(super) fn keep_owner_key(
    repo_id: &EntityId,
    oid: &GitOid,
    kind: OriginKeepRefKind,
    owner_key: &str,
) -> KeepOwnerKey {
    KeepOwnerKey {
        repo_id: *repo_id,
        oid: oid.as_str().to_owned(),
        kind: kind.as_str().to_owned(),
        owner_key: owner_key.to_owned(),
    }
}

/// The bytes after `KEEP_OWNER`'s prefix that name every row for one repo+oid, regardless of
/// kind or owner key.
pub(super) fn keep_owner_oid_scan_prefix(repo_id: &EntityId, oid: &GitOid) -> Vec<u8> {
    let mut out = repo_id.as_bytes().to_vec();
    out.push(0);
    out.extend_from_slice(oid.as_str().as_bytes());
    out.push(0);
    out
}

/// The physical keep-ref that pins one object.
///
/// The spelling follows the LANDED [`GIT_WIRE_KEEP_REF_PREFIX`] shape that
/// [`GitWire::write_keep_ref`](crate::git_wire::GitWire::write_keep_ref) writes, because the physical root must be the
/// one GitWire owns rather than a second name meaning the same thing.
pub fn origin_keep_ref_name(oid: &GitOid) -> Result<GitRefName> {
    GitRefName::parse_full(format!("{GIT_WIRE_KEEP_REF_PREFIX}object/{}", oid.as_str()))
}

/// The wire shape of a publication journal row: the side table stores exactly the bytes
/// `rmp_serde::to_vec_named` on this struct has always spelled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct OriginPublicationRow {
    schema_version: u8,
    publication_id: [u8; ENTITY_ID_LEN],
    repo_id: [u8; ENTITY_ID_LEN],
    ref_name: String,
    expected_old_oid: Option<String>,
    new_oid: String,
    required_objects: Vec<String>,
    required_lfs_oids: Vec<(String, u64)>,
    provenance_claim_id: [u8; ENTITY_ID_LEN],
    publication_claim_id: Option<[u8; ENTITY_ID_LEN]>,
    actor_id: [u8; ENTITY_ID_LEN],
    status: String,
    failure: Option<String>,
    occurred_start: u64,
    occurred_end: u64,
    created_at: u64,
    finished_at: Option<u64>,
}

impl OriginPublicationRow {
    pub(super) fn from_record(record: &OriginPublicationRecord) -> Self {
        Self {
            schema_version: ORIGIN_PUBLICATION_SCHEMA_VERSION,
            publication_id: *record.publication_id.as_bytes(),
            repo_id: *record.repo_id.as_bytes(),
            ref_name: record.ref_name.as_str().to_owned(),
            expected_old_oid: record
                .expected_old_oid
                .as_ref()
                .map(|oid| oid.as_str().to_owned()),
            new_oid: record.new_oid.as_str().to_owned(),
            required_objects: record
                .required_objects
                .iter()
                .map(|oid| oid.as_str().to_owned())
                .collect(),
            required_lfs_oids: record
                .required_lfs_oids
                .iter()
                .map(|(oid, size)| (oid.to_hex(), *size))
                .collect(),
            provenance_claim_id: *record.provenance_claim_id.as_bytes(),
            publication_claim_id: record.publication_claim_id.map(|id| *id.as_bytes()),
            actor_id: *record.actor_id.as_bytes(),
            status: record.status.as_str().to_owned(),
            failure: record.failure.clone(),
            occurred_start: record.occurred.start,
            occurred_end: record.occurred.end,
            created_at: record.created_at,
            finished_at: record.finished_at,
        }
    }

    pub(super) fn into_record(self) -> Result<OriginPublicationRecord> {
        if self.schema_version != ORIGIN_PUBLICATION_SCHEMA_VERSION {
            return Err(Error::CorruptedIndex("origin publication schema version"));
        }
        let mut required_objects = Vec::with_capacity(self.required_objects.len());
        for oid in self.required_objects {
            required_objects.push(GitOid::parse_hex(oid)?);
        }
        let mut required_lfs_oids = Vec::with_capacity(self.required_lfs_oids.len());
        for (oid, size) in self.required_lfs_oids {
            required_lfs_oids.push((LfsOid::parse_hex(&oid)?, size));
        }
        Ok(OriginPublicationRecord {
            publication_id: row_entity_id(self.publication_id)?,
            repo_id: row_entity_id(self.repo_id)?,
            ref_name: GitRefName::parse_full(self.ref_name)?,
            expected_old_oid: self.expected_old_oid.map(GitOid::parse_hex).transpose()?,
            new_oid: GitOid::parse_hex(self.new_oid)?,
            required_objects,
            required_lfs_oids,
            provenance_claim_id: row_entity_id(self.provenance_claim_id)?,
            publication_claim_id: self.publication_claim_id.map(row_entity_id).transpose()?,
            actor_id: row_entity_id(self.actor_id)?,
            status: OriginPublicationStatus::parse(&self.status)?,
            failure: self.failure,
            occurred: TimeRange {
                start: self.occurred_start,
                end: self.occurred_end,
            },
            created_at: self.created_at,
            finished_at: self.finished_at,
        })
    }
}

fn row_entity_id(bytes: [u8; ENTITY_ID_LEN]) -> Result<EntityId> {
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex("origin publication entity id"))
}

/// Truncates failure text to the pinned bound on a character boundary.
pub(super) fn bounded_failure(text: impl Into<String>) -> String {
    let mut text = text.into();
    if text.len() <= ORIGIN_PUBLICATION_MAX_FAILURE_BYTES {
        return text;
    }
    let mut cut = ORIGIN_PUBLICATION_MAX_FAILURE_BYTES;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text
}

// ---------------------------------------------------------------------------
// Deterministic identities
// ---------------------------------------------------------------------------

/// The deterministic id of one publication.
///
/// Derived from everything that makes the advance the SAME advance, so an
/// identical replay addresses the identical row instead of minting a second
/// publication of one push.
pub fn origin_publication_id(request: &OriginPublicationRequest) -> Result<EntityId> {
    let expected = request.expected_old_oid.as_ref().map_or("", GitOid::as_str);
    entity_id_from_hash_material(
        ORIGIN_PUBLICATION_ID_DOMAIN,
        &[
            request.repo_id.as_bytes(),
            request.ref_name.as_str().as_bytes(),
            expected.as_bytes(),
            request.new_oid.as_str().as_bytes(),
            request.provenance_claim_id.as_bytes(),
        ],
    )
}

/// The deterministic id of the `repo.publication` claim one record asserts.
///
/// Deterministic on purpose: a census finalizing a crashed publication writes
/// the SAME claim id the first attempt would have, so "exactly one active
/// claim per publication" survives recovery.
pub fn origin_publication_claim_id(publication_id: &EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(
        ORIGIN_PUBLICATION_CLAIM_ID_DOMAIN,
        &[publication_id.as_bytes()],
    )
}

/// The commit-keyed entity one publication's claim is anchored on (RA5).
pub fn origin_published_commit_id(oid: &GitOid) -> Result<EntityId> {
    entity_id_from_hash_material(
        ORIGIN_PUBLICATION_COMMIT_ID_DOMAIN,
        &[oid.as_str().as_bytes()],
    )
}

/// The claim body one successful publication asserts.
///
/// The subject is the commit-keyed EdgeRef `commit -PartOf-> repo`, which is
/// the RA5 anchor that needs no entity row to exist: a repository receiving its
/// first push has no durable entity yet, and a protocol that minted one would
/// be inventing an identity it does not own. `sensitivity: public` is stamped
/// because an advertised ref IS public repository metadata; leaving it
/// unstamped would read as band 2 at the write gate and refuse the push for a
/// reason that has nothing to do with publication.
pub(super) fn publication_claim_body(record: &OriginPublicationRecord) -> Result<ClaimBody> {
    let mut body = ClaimBody::new(
        ORIGIN_PUBLICATION_PREDICATE,
        ClaimSubject::Edge {
            source: origin_published_commit_id(&record.new_oid)?,
            kind: EdgeKind::PartOf,
            target: record.repo_id,
        },
        publication_claim_value(record),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    Ok(body)
}

/// Builds the exact source statement required by the generic publication door.
/// The caller must durably write this claim before requesting publication.
/// A generic active claim, or a statement about a different target, is not authority.
pub fn origin_publication_intent_claim(request: &OriginPublicationRequest) -> Result<ClaimBody> {
    let fields = vec![
        ("repo_id", Value::from(request.repo_id.to_hex())),
        ("actor_id", Value::from(request.actor_id.to_hex())),
        ("ref_name", Value::from(request.ref_name.as_str())),
        (
            "expected_old_oid",
            request
                .expected_old_oid
                .as_ref()
                .map_or(Value::Nil, |oid| Value::from(oid.as_str())),
        ),
        ("new_oid", Value::from(request.new_oid.as_str())),
        (
            "required_objects",
            Value::Array(
                request
                    .required_objects
                    .iter()
                    .map(|oid| Value::from(oid.as_str()))
                    .collect(),
            ),
        ),
        (
            "required_lfs_oids",
            Value::Array(
                request
                    .required_lfs_oids
                    .iter()
                    .map(|(oid, size)| {
                        Value::Array(vec![Value::from(oid.to_hex()), Value::from(*size)])
                    })
                    .collect(),
            ),
        ),
    ];
    let mut body = ClaimBody::new(
        ORIGIN_PUBLICATION_INTENT_PREDICATE,
        ClaimSubject::Edge {
            source: request.actor_id,
            kind: EdgeKind::PartOf,
            target: request.repo_id,
        },
        Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        ),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    Ok(body)
}

fn publication_claim_value(record: &OriginPublicationRecord) -> Value {
    let expected = record
        .expected_old_oid
        .as_ref()
        .map_or(Value::Nil, |oid| Value::from(oid.as_str()));
    let objects = record
        .required_objects
        .iter()
        .map(|oid| Value::from(oid.as_str()))
        .collect::<Vec<_>>();
    let lfs = record
        .required_lfs_oids
        .iter()
        .map(|(oid, size)| Value::Array(vec![Value::from(oid.to_hex()), Value::from(*size)]))
        .collect::<Vec<_>>();
    let fields: [Value; 10] = [
        Value::from(u32::from(ORIGIN_PUBLICATION_SCHEMA_VERSION)),
        Value::from(record.publication_id.to_hex()),
        Value::from(record.ref_name.as_str()),
        expected,
        Value::from(record.new_oid.as_str()),
        Value::from(record.provenance_claim_id.to_hex()),
        Value::Array(objects),
        Value::Array(lfs),
        Value::from(record.actor_id.to_hex()),
        Value::from(record.created_at),
    ];
    Value::Map(
        ORIGIN_PUBLICATION_VALUE_KEYS
            .into_iter()
            .zip(fields)
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}
