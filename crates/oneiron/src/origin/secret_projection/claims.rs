//! A masked Git copy's record (FIX 7608 slice 2b-i, CALL M): value-free
//! `repo.secret_projection` claims at schema 1, one claim per record, no
//! table and no restore row.
//!
//! The graph record names the copy: the canonical store, the frozen roots
//! it copies (each Published ref's original, and a lease's private original
//! when one is admitted), the audience, the payload policy and lifetime,
//! and every readable mark it was made under. Its id is derived from all of
//! that, so a copy made under other roots or other marks is another copy.
//! Its subject is the edge `graph PartOf store`, as a mark's is, in the
//! masked-file band. Every other record (an object's original and copy, a
//! root ref's copy, the private root's copy, and each place a changed
//! object occurs in a changed parent) is about the graph claim itself, so
//! the graph's erasure reaches each of them, and each is idempotent at its
//! derived id: the same record writes nothing, another under its id
//! refuses.
//!
//! No record carries a secret byte, an excerpt, a hash of a key, or a hash
//! of any content: object ids, ref names, tree entry names, mark ids and
//! the store identity only. Identity mappings are recorded too, so every
//! copy object names its original; a copy object may stand for several
//! originals, and nothing reads a newest or equal-content guess into it.

#![allow(
    dead_code,
    reason = "FIX 7608 slice 2b-i: preparation only; slice 2b-ii is the first caller"
)]

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitObjectKind, GitOid};
use crate::secret_custody::MASKED_FILE_BAND;
use crate::temporal::TimeRange;

/// The predicate of every masked Git copy record.
pub(crate) const REPO_SECRET_PROJECTION_PREDICATE: &str = "repo.secret_projection";

/// The derivation domain of a record's id.
const REPO_SECRET_PROJECTION_DOMAIN: &[u8] = b"oneiron:repo-secret-projection:v1";

/// The one audience a copy serves today: every masked reader.
const AUDIENCE_MASKED: &str = "masked";

/// CALL P2, as a record names it.
const POLICY_PRESERVE_PAYLOAD: &str = "preserve_payload";

/// CALL P3, as a record names it.
const LIFETIME_SOURCE_BOUND: &str = "source_bound";

/// Where a changed object occurs in a changed parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoProjectionPlace {
    /// A tree entry, by its stored mode and name bytes.
    TreeEntry { mode: u32, name: Vec<u8> },
    /// A commit's tree.
    CommitTree,
    /// A commit's parent at this position.
    CommitParent { index: u32 },
    /// A tag's target.
    TagTarget,
}

/// One record of a masked copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoProjectionRecord {
    /// The copy itself.
    Graph {
        store_identity: String,
        store_id: EntityId,
        /// Each Published root ref and the original it was frozen at,
        /// sorted by name.
        roots: Vec<(String, GitOid)>,
        /// An admitted lease's original pin, copied as a private root.
        private_root: Option<GitOid>,
        /// Every readable mark the copy was made under, sorted.
        marks: Vec<EntityId>,
    },
    /// One object's copy, the original's own id when nothing it names
    /// changed.
    Object {
        original: GitOid,
        copy: GitOid,
        kind: GitObjectKind,
        signature_not_preserved: bool,
        /// The marks its copy masks (a blob's), sorted.
        marks: Vec<EntityId>,
    },
    /// One root ref's copy, fenced by the original it was frozen at.
    Ref {
        name: String,
        original: GitOid,
        copy: GitOid,
    },
    /// The private root's copy.
    PrivateRoot { original: GitOid, copy: GitOid },
    /// One place a changed object occurs in a changed parent.
    Link {
        parent: GitOid,
        place: RepoProjectionPlace,
        child_original: GitOid,
        child_copy: GitOid,
    },
}

/// One record as it is kept: its graph (its own id, for the graph record)
/// and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionClaim {
    pub(crate) graph: EntityId,
    pub(crate) record: RepoProjectionRecord,
}

impl RepoProjectionClaim {
    /// The one schema these records are written at (CALL M).
    pub(crate) const SCHEMA: u16 = 1;

    /// The graph record, its graph id derived from what it says.
    ///
    /// # Errors
    /// A failed derivation, or a record that is not a graph record.
    pub(crate) fn graph(record: RepoProjectionRecord) -> Result<Self> {
        if !matches!(record, RepoProjectionRecord::Graph { .. }) {
            return Err(Error::InvariantViolation(
                "a masked copy's graph claim must hold its graph record",
            ));
        }
        let graph = derive_id(None, &identity_part(&record))?;
        Ok(Self { graph, record })
    }

    /// A record about the graph `graph`.
    pub(crate) const fn of(graph: EntityId, record: RepoProjectionRecord) -> Self {
        Self { graph, record }
    }

    /// The record's id: the graph's own, or derived from its graph and its
    /// key.
    ///
    /// # Errors
    /// A failed derivation.
    pub(crate) fn id(&self) -> Result<EntityId> {
        match self.record {
            RepoProjectionRecord::Graph { .. } => Ok(self.graph),
            _ => derive_id(Some(&self.graph), &identity_part(&self.record)),
        }
    }

    fn value(&self) -> Value {
        let mut entries = vec![
            ("schema_version", Value::from(Self::SCHEMA)),
            ("graph", Value::from(self.graph.to_hex())),
        ];
        entries.extend(record_fields(&self.record));
        fields(entries)
    }

    fn claim(&self) -> Result<ClaimBody> {
        let subject = match &self.record {
            RepoProjectionRecord::Graph { store_id, .. } => ClaimSubject::Edge {
                source: self.graph,
                kind: EdgeKind::PartOf,
                target: *store_id,
            },
            _ => ClaimSubject::Entity(self.graph),
        };
        let mut body = ClaimBody::new(
            REPO_SECRET_PROJECTION_PREDICATE,
            subject,
            self.value(),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?;
        // Engine bookkeeping of a copy, never a claim a caller writes, in
        // the band its marks carry.
        body.source = Some(ClaimSource::Observed);
        body.scope = Some(fields(vec![(
            "sensitivity",
            Value::from(MASKED_FILE_BAND.as_str()),
        )]));
        Ok(body)
    }

    /// Writes the record once at its id, and says whether it wrote it: the
    /// same record again writes nothing; anything else under its id
    /// refuses.
    ///
    /// # Errors
    /// A store failure, or another record under the id.
    pub(crate) fn put_in_txn(&self, vault: &Vault, wtxn: &mut RwTxn<'_>, at: u64) -> Result<bool> {
        let id = self.id()?;
        let body = self.claim()?;
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
                    "a masked copy record's id holds another fact",
                ));
            }
            None if vault.get_raw_in(wtxn, &id)?.is_some() => {
                return Err(Error::CorruptedIndex(
                    "a masked copy record's id holds another record",
                ));
            }
            None => {}
        }
        let occurred = TimeRange { start: at, end: at };
        vault.put_reserved_claim_in_txn(wtxn, &id, &body, occurred, at)?;
        Ok(true)
    }

    /// The graph record stored at `graph`, decoded strictly at schema 1 and
    /// checked against its own id; `None` when none stands there (absent,
    /// unreadable here, or no longer approved).
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn load_graph_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        graph: &EntityId,
    ) -> Result<Option<Self>> {
        let Some(body) = vault.get_claim_in_txn(txn, graph)? else {
            return Ok(None);
        };
        if body.approval != ClaimApprovalStatus::Approved
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            return Ok(None);
        }
        let claim = decode_graph(graph, &body)?;
        Ok(Some(claim))
    }
}

fn corrupt() -> Error {
    Error::CorruptedIndex("a masked copy record does not decode")
}

fn derive_id(graph: Option<&EntityId>, identity: &Value) -> Result<EntityId> {
    let schema = RepoProjectionClaim::SCHEMA.to_be_bytes();
    let graph: &[u8] = match graph {
        Some(graph) => graph.as_bytes(),
        None => &[],
    };
    entity_id_from_hash_material(
        REPO_SECRET_PROJECTION_DOMAIN,
        &[&schema, graph, &packed(identity)?],
    )
}

/// What a record's id is derived from: the whole graph record, or the key
/// that makes another record one per graph.
fn identity_part(record: &RepoProjectionRecord) -> Value {
    match record {
        RepoProjectionRecord::Graph { .. } => fields(record_fields(record)),
        RepoProjectionRecord::Object { original, .. } => {
            Value::Array(vec![Value::from("object"), oid(original)])
        }
        RepoProjectionRecord::Ref { name, .. } => {
            Value::Array(vec![Value::from("ref"), Value::from(name.as_str())])
        }
        RepoProjectionRecord::PrivateRoot { .. } => Value::Array(vec![Value::from("private_root")]),
        RepoProjectionRecord::Link {
            parent,
            place,
            child_original,
            ..
        } => Value::Array(vec![
            Value::from("link"),
            oid(parent),
            place_value(place),
            oid(child_original),
        ]),
    }
}

fn record_fields(record: &RepoProjectionRecord) -> Vec<(&'static str, Value)> {
    match record {
        RepoProjectionRecord::Graph {
            store_identity,
            store_id,
            roots,
            private_root,
            marks,
        } => vec![
            ("kind", Value::from("graph")),
            ("store_identity", Value::from(store_identity.as_str())),
            ("store_id", Value::from(store_id.to_hex())),
            ("audience", Value::from(AUDIENCE_MASKED)),
            ("policy", Value::from(POLICY_PRESERVE_PAYLOAD)),
            ("lifetime", Value::from(LIFETIME_SOURCE_BOUND)),
            (
                "roots",
                Value::Array(
                    roots
                        .iter()
                        .map(|(name, original)| {
                            Value::Array(vec![Value::from(name.as_str()), oid(original)])
                        })
                        .collect(),
                ),
            ),
            (
                "private_root",
                private_root.as_ref().map_or(Value::Nil, oid),
            ),
            ("marks", ids(marks)),
        ],
        RepoProjectionRecord::Object {
            original,
            copy,
            kind,
            signature_not_preserved,
            marks,
        } => vec![
            ("kind", Value::from("object")),
            ("original", oid(original)),
            ("copy", oid(copy)),
            ("object_type", Value::from(kind.as_str())),
            (
                "signature_not_preserved",
                Value::from(*signature_not_preserved),
            ),
            ("marks", ids(marks)),
        ],
        RepoProjectionRecord::Ref {
            name,
            original,
            copy,
        } => vec![
            ("kind", Value::from("ref")),
            ("name", Value::from(name.as_str())),
            ("original", oid(original)),
            ("copy", oid(copy)),
        ],
        RepoProjectionRecord::PrivateRoot { original, copy } => vec![
            ("kind", Value::from("private_root")),
            ("original", oid(original)),
            ("copy", oid(copy)),
        ],
        RepoProjectionRecord::Link {
            parent,
            place,
            child_original,
            child_copy,
        } => vec![
            ("kind", Value::from("link")),
            ("parent", oid(parent)),
            ("place", place_value(place)),
            ("child_original", oid(child_original)),
            ("child_copy", oid(child_copy)),
        ],
    }
}

fn place_value(place: &RepoProjectionPlace) -> Value {
    match place {
        RepoProjectionPlace::TreeEntry { mode, name } => Value::Array(vec![
            Value::from("tree_entry"),
            Value::from(*mode),
            Value::Binary(name.clone()),
        ]),
        RepoProjectionPlace::CommitTree => Value::Array(vec![Value::from("commit_tree")]),
        RepoProjectionPlace::CommitParent { index } => {
            Value::Array(vec![Value::from("commit_parent"), Value::from(*index)])
        }
        RepoProjectionPlace::TagTarget => Value::Array(vec![Value::from("tag_target")]),
    }
}

fn oid(oid: &GitOid) -> Value {
    Value::from(oid.as_str())
}

fn ids(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect())
}

fn fields(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

fn packed(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| Error::InvariantViolation("a masked copy record part did not encode"))?;
    Ok(out)
}

/// The graph record at `id`, at schema 1 only, rebuilt and checked against
/// both its stored value and its id.
fn decode_graph(id: &EntityId, body: &ClaimBody) -> Result<RepoProjectionClaim> {
    if body.predicate != REPO_SECRET_PROJECTION_PREDICATE
        || body.source != Some(ClaimSource::Observed)
    {
        return Err(corrupt());
    }
    let map = body.value.as_map().ok_or_else(corrupt)?;
    let schema = field(map, "schema_version")?.as_u64().ok_or_else(corrupt)?;
    if schema != u64::from(RepoProjectionClaim::SCHEMA) || text(field(map, "kind")?)? != "graph" {
        return Err(corrupt());
    }
    let roots = field(map, "roots")?
        .as_array()
        .ok_or_else(corrupt)?
        .iter()
        .map(|root| match root.as_array().map(Vec::as_slice) {
            Some([name, original]) => Ok((text(name)?.to_owned(), git_oid(original)?)),
            _ => Err(corrupt()),
        })
        .collect::<Result<Vec<_>>>()?;
    let private_root = match field(map, "private_root")? {
        Value::Nil => None,
        value => Some(git_oid(value)?),
    };
    let marks = field(map, "marks")?
        .as_array()
        .ok_or_else(corrupt)?
        .iter()
        .map(entity)
        .collect::<Result<Vec<_>>>()?;
    let record = RepoProjectionRecord::Graph {
        store_identity: text(field(map, "store_identity")?)?.to_owned(),
        store_id: entity(field(map, "store_id")?)?,
        roots,
        private_root,
        marks,
    };
    let claim = RepoProjectionClaim::graph(record)?;
    if claim.graph != *id || claim.value() != body.value || claim.claim()?.subject != body.subject {
        return Err(corrupt());
    }
    Ok(claim)
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

fn entity(value: &Value) -> Result<EntityId> {
    EntityId::from_hex(text(value)?).map_err(|_| corrupt())
}

fn git_oid(value: &Value) -> Result<GitOid> {
    GitOid::parse_hex(text(value)?).map_err(|_| corrupt())
}
