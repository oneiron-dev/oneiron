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
    reason = "FIX 7608: some records are read only by later slices"
)]

use heed::{RoTxn, RwTxn};

mod codec;
mod lookup;
use rmpv::Value;

use self::codec::{
    decode_graph, decode_place, digest_of, digest_value, entity, field, fields, git_oid,
    occurrence_value, oid, optional_binding, packed, place_value, record_fields, text,
};
pub(crate) use self::lookup::RepoProjectionLinks;
use super::recipient::RepoProjectionRevealBinding;

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
        /// Who the copy serves (FIX 9328).
        audience: RepoProjectionAudience,
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
        /// A recipient copy's tree or blob, by the byte path it occurs at
        /// (FIX 9328): one copy per occurrence. `None` in a masked copy,
        /// and for every commit and tag.
        occurrence: Option<Vec<u8>>,
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
        /// The parent's occurrence, as its object record names it.
        parent_occurrence: Option<Vec<u8>>,
        place: RepoProjectionPlace,
        child_original: GitOid,
        child_copy: GitOid,
    },
    /// A push received into a private ingress seeded from this copy (FIX
    /// 7608 2b-ii): the proof its admission binds.
    Ingress(RepoProjectionIngress),
    /// A received copy change translated onto the ORIGINAL.
    Translation(RepoProjectionTranslation),
    /// The owner's settlement of one held projected edit, exactly.
    Clearance(RepoProjectionClearance),
    /// A projection-bound update proved not copy-derived, forwarded as it
    /// was pushed.
    ExactForward(RepoProjectionExactForward),
    /// A checkout lease bound to this copy (FIX 7608 2b-ii-B2).
    Checkout(RepoProjectionCheckout),
    /// The private ingress seeded from this copy (FIX 7608 2b-ii-B2).
    IngressStore(RepoProjectionIngressStore),
}

/// Who a masked copy serves (FIX 7608 pre-flip, FIX 9328, CALL
/// GIT-REVEAL-OPT-IN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoProjectionAudience {
    /// Every masked reader: each marked blob masked.
    Masked,
    /// One proven recipient whose explicit reason a live grant answered:
    /// each released file (its exact byte path and ORIGINAL blob, sorted)
    /// at its stored bytes, every other marked blob masked. Never a why or
    /// a receipt: the same recipient and release set is the same copy.
    Recipient {
        binding: RepoProjectionRevealBinding,
        released: Vec<(Vec<u8>, GitOid)>,
    },
}

/// A checkout lease bound to a copy: the lease's checkout and epoch, its
/// holder, the ORIGINAL it pins and the copy commit it checks out. Its id
/// is derived from the checkout and epoch alone, so the lease finds it;
/// it is about the graph, so the graph's erasure reaches it. Ids only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionCheckout {
    pub(crate) checkout: String,
    pub(crate) epoch: u64,
    pub(crate) holder: String,
    pub(crate) original: GitOid,
    pub(crate) copy: GitOid,
}

/// The private ingress seeded from a copy: its object-store identity and
/// the canonical store it stands for. Its id is derived from the ingress
/// identity alone, so a received row's store finds its copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionIngressStore {
    pub(crate) ingress_store: String,
    pub(crate) canonical_store: EntityId,
}

/// The ingress proof's record: the receive operation, the canonical store
/// the copy stands for, the private ingress store it was received into and
/// a digest of the canonical authority its admission bound (repo, CODE,
/// project, actor, G1 arm, Grant, lease epoch, holder and attempt, host
/// authority). Ids and digests only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionIngress {
    pub(crate) operation: EntityId,
    pub(crate) canonical_store: EntityId,
    pub(crate) ingress_store: String,
    pub(crate) authority: [u8; 32],
    /// The recipient its host proved for the push, when it proved one
    /// (FIX 10271): what a live grant's clearance of its held files names.
    /// Never authority.
    pub(crate) reveal: Option<RepoProjectionRevealBinding>,
}

/// A received copy change's translation: its candidate and operation, the
/// submitted COPY tip, the ORIGINAL base it maps onto, the canonical
/// target tree it resolved (none while it holds) and its pins' digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionTranslation {
    pub(crate) candidate: EntityId,
    pub(crate) operation: EntityId,
    pub(crate) submitted_new: GitOid,
    pub(crate) canonical_base: GitOid,
    pub(crate) canonical_target: Option<GitOid>,
    pub(crate) pins: [u8; 32],
}

/// The owner's settlement of one held projected edit: the candidate, the
/// cause, the digest of the exact file set it settles, the canonical
/// target it approved and the owner who approved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionClearance {
    pub(crate) candidate: EntityId,
    pub(crate) cause: String,
    pub(crate) files: [u8; 32],
    pub(crate) target: Option<GitOid>,
    pub(crate) owner: EntityId,
}

/// One exact forward: the receive operation, the ref, its canonical old
/// and new tips and the marks carried to the canonical store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionExactForward {
    pub(crate) operation: EntityId,
    pub(crate) ref_name: String,
    pub(crate) old: Option<GitOid>,
    pub(crate) new: GitOid,
    pub(crate) marks: Vec<EntityId>,
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
            // Found from the lease or the ingress alone, never the graph.
            RepoProjectionRecord::Checkout(_) | RepoProjectionRecord::IngressStore(_) => {
                derive_id(None, &identity_part(&self.record))
            }
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

    /// Whether this exact record stands at its id: approved, active and
    /// saying exactly this, about exactly its subject.
    ///
    /// # Errors
    /// A store failure, or a failed id derivation.
    pub(crate) fn stands_in_txn(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
        let Some(stored) = vault.get_claim_in_txn(txn, &self.id()?)? else {
            return Ok(false);
        };
        let body = self.claim()?;
        Ok(stored.approval == ClaimApprovalStatus::Approved
            && stored.lifecycle == ClaimLifecycleStatus::Active
            && stored.predicate == body.predicate
            && stored.subject == body.subject
            && stored.value == body.value)
    }

    /// The ingress record of `operation` under `graph`, decoded strictly
    /// and checked against its id and stored value; `None` when none
    /// stands.
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn load_ingress_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        graph: &EntityId,
        operation: &EntityId,
    ) -> Result<Option<RepoProjectionIngress>> {
        let key = Value::Array(vec![
            Value::from("ingress"),
            Value::from(operation.to_hex()),
        ]);
        let id = derive_id(Some(graph), &key)?;
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            return Ok(None);
        };
        if body.approval != ClaimApprovalStatus::Approved
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            return Ok(None);
        }
        let map = body.value.as_map().ok_or_else(corrupt)?;
        if text(field(map, "kind")?)? != "ingress" {
            return Err(corrupt());
        }
        let ingress = RepoProjectionIngress {
            operation: *operation,
            canonical_store: entity(field(map, "canonical_store")?)?,
            ingress_store: text(field(map, "ingress_store")?)?.to_owned(),
            authority: digest_of(field(map, "authority")?)?,
            reveal: optional_binding(field(map, "reveal")?)?,
        };
        let claim = Self::of(*graph, RepoProjectionRecord::Ingress(ingress.clone()));
        if claim.value() != body.value || claim.claim()?.subject != body.subject {
            return Err(corrupt());
        }
        Ok(Some(ingress))
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
        RepoProjectionRecord::Object {
            original,
            occurrence,
            ..
        } => Value::Array(vec![
            Value::from("object"),
            oid(original),
            occurrence_value(occurrence.as_deref()),
        ]),
        RepoProjectionRecord::Ref { name, .. } => {
            Value::Array(vec![Value::from("ref"), Value::from(name.as_str())])
        }
        RepoProjectionRecord::PrivateRoot { .. } => Value::Array(vec![Value::from("private_root")]),
        RepoProjectionRecord::Link {
            parent,
            parent_occurrence,
            place,
            child_original,
            ..
        } => Value::Array(vec![
            Value::from("link"),
            oid(parent),
            occurrence_value(parent_occurrence.as_deref()),
            place_value(place),
            oid(child_original),
        ]),
        RepoProjectionRecord::Ingress(ingress) => Value::Array(vec![
            Value::from("ingress"),
            Value::from(ingress.operation.to_hex()),
        ]),
        RepoProjectionRecord::Translation(translation) => Value::Array(vec![
            Value::from("translation"),
            Value::from(translation.candidate.to_hex()),
        ]),
        RepoProjectionRecord::Clearance(clearance) => Value::Array(vec![
            Value::from("clearance"),
            Value::from(clearance.candidate.to_hex()),
            Value::from(clearance.cause.as_str()),
            digest_value(&clearance.files),
            clearance.target.as_ref().map_or(Value::Nil, oid),
        ]),
        RepoProjectionRecord::ExactForward(forward) => Value::Array(vec![
            Value::from("exact_forward"),
            Value::from(forward.operation.to_hex()),
            Value::from(forward.ref_name.as_str()),
        ]),
        RepoProjectionRecord::Checkout(checkout) => {
            checkout_key(&checkout.checkout, checkout.epoch)
        }
        RepoProjectionRecord::IngressStore(ingress) => ingress_store_key(&ingress.ingress_store),
    }
}

/// The identity a checkout binding's id is derived from.
fn checkout_key(checkout: &str, epoch: u64) -> Value {
    Value::Array(vec![
        Value::from("checkout"),
        Value::from(checkout),
        Value::from(epoch),
    ])
}

/// The identity an ingress store's record id is derived from.
fn ingress_store_key(ingress_store: &str) -> Value {
    Value::Array(vec![
        Value::from("ingress_store"),
        Value::from(ingress_store),
    ])
}
