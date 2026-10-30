//! The strict codec of a masked copy's records (FIX 7608 slice 2b-i,
//! CALL M): each record's fields at schema 1, the graph record's strict
//! decoder, and the value helpers every reader shares. Moved out of
//! `claims.rs` whole.

use rmpv::Value;

use super::{
    REPO_SECRET_PROJECTION_PREDICATE, RepoProjectionAudience, RepoProjectionClaim,
    RepoProjectionPlace, RepoProjectionRecord, RepoProjectionRevealBinding, corrupt,
};
use crate::claim::{ClaimBody, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::GitOid;

/// A copy every masked reader is served, as a record names it.
const AUDIENCE_MASKED: &str = "masked";

/// A copy one proven recipient is served (FIX 9328), as a record names it.
const AUDIENCE_RECIPIENT: &str = "recipient";

/// CALL P2, as a record names it.
const POLICY_PRESERVE_PAYLOAD: &str = "preserve_payload";

/// CALL P3, as a record names it.
const LIFETIME_SOURCE_BOUND: &str = "source_bound";

pub(super) fn record_fields(record: &RepoProjectionRecord) -> Vec<(&'static str, Value)> {
    match record {
        RepoProjectionRecord::Graph {
            store_identity,
            store_id,
            roots,
            private_root,
            marks,
            audience,
        } => vec![
            ("kind", Value::from("graph")),
            ("store_identity", Value::from(store_identity.as_str())),
            ("store_id", Value::from(store_id.to_hex())),
            ("audience", audience_value(audience)),
            ("recipient", audience_binding(audience)),
            ("released", released_value(audience)),
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
            occurrence,
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
            ("occurrence", occurrence_value(occurrence.as_deref())),
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
            parent_occurrence,
            place,
            child_original,
            child_copy,
        } => vec![
            ("kind", Value::from("link")),
            ("parent", oid(parent)),
            (
                "parent_occurrence",
                occurrence_value(parent_occurrence.as_deref()),
            ),
            ("place", place_value(place)),
            ("child_original", oid(child_original)),
            ("child_copy", oid(child_copy)),
        ],
        RepoProjectionRecord::Ingress(ingress) => vec![
            ("kind", Value::from("ingress")),
            ("operation", Value::from(ingress.operation.to_hex())),
            (
                "canonical_store",
                Value::from(ingress.canonical_store.to_hex()),
            ),
            ("ingress_store", Value::from(ingress.ingress_store.as_str())),
            ("authority", digest_value(&ingress.authority)),
            (
                "reveal",
                ingress
                    .reveal
                    .as_ref()
                    .map_or(Value::Nil, RepoProjectionRevealBinding::value),
            ),
        ],
        RepoProjectionRecord::Translation(translation) => vec![
            ("kind", Value::from("translation")),
            ("candidate", Value::from(translation.candidate.to_hex())),
            ("operation", Value::from(translation.operation.to_hex())),
            ("submitted_new", oid(&translation.submitted_new)),
            ("canonical_base", oid(&translation.canonical_base)),
            (
                "canonical_target",
                translation
                    .canonical_target
                    .as_ref()
                    .map_or(Value::Nil, oid),
            ),
            ("pins", digest_value(&translation.pins)),
        ],
        RepoProjectionRecord::Clearance(clearance) => vec![
            ("kind", Value::from("clearance")),
            ("candidate", Value::from(clearance.candidate.to_hex())),
            ("cause", Value::from(clearance.cause.as_str())),
            ("files", digest_value(&clearance.files)),
            ("target", clearance.target.as_ref().map_or(Value::Nil, oid)),
            ("owner", Value::from(clearance.owner.to_hex())),
        ],
        RepoProjectionRecord::ExactForward(forward) => vec![
            ("kind", Value::from("exact_forward")),
            ("operation", Value::from(forward.operation.to_hex())),
            ("ref_name", Value::from(forward.ref_name.as_str())),
            ("old", forward.old.as_ref().map_or(Value::Nil, oid)),
            ("new", oid(&forward.new)),
            ("marks", ids(&forward.marks)),
        ],
        RepoProjectionRecord::Checkout(checkout) => vec![
            ("kind", Value::from("checkout")),
            ("checkout", Value::from(checkout.checkout.as_str())),
            ("epoch", Value::from(checkout.epoch)),
            ("holder", Value::from(checkout.holder.as_str())),
            ("original", oid(&checkout.original)),
            ("copy", oid(&checkout.copy)),
        ],
        RepoProjectionRecord::CheckoutRecipient(recipient) => vec![
            ("kind", Value::from("checkout_recipient")),
            ("checkout", Value::from(recipient.checkout.as_str())),
            ("epoch", Value::from(recipient.epoch)),
            ("reveal", recipient.reveal.value()),
        ],
        RepoProjectionRecord::IngressStore(ingress) => vec![
            ("kind", Value::from("ingress_store")),
            ("ingress_store", Value::from(ingress.ingress_store.as_str())),
            (
                "canonical_store",
                Value::from(ingress.canonical_store.to_hex()),
            ),
        ],
        RepoProjectionRecord::CommitOriginals { copy, originals } => vec![
            ("kind", Value::from("commit_originals")),
            ("copy", oid(copy)),
            (
                "originals",
                Value::Array(originals.iter().map(oid).collect()),
            ),
        ],
    }
}

pub(super) fn place_value(place: &RepoProjectionPlace) -> Value {
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

fn audience_value(audience: &RepoProjectionAudience) -> Value {
    Value::from(match audience {
        RepoProjectionAudience::Masked => AUDIENCE_MASKED,
        RepoProjectionAudience::Recipient { .. } => AUDIENCE_RECIPIENT,
    })
}

fn audience_binding(audience: &RepoProjectionAudience) -> Value {
    match audience {
        RepoProjectionAudience::Masked => Value::Nil,
        RepoProjectionAudience::Recipient { binding, .. } => binding.value(),
    }
}

fn released_value(audience: &RepoProjectionAudience) -> Value {
    let released = match audience {
        RepoProjectionAudience::Masked => &[][..],
        RepoProjectionAudience::Recipient { released, .. } => released.as_slice(),
    };
    Value::Array(
        released
            .iter()
            .map(|(path, blob)| Value::Array(vec![Value::Binary(path.clone()), oid(blob)]))
            .collect(),
    )
}

/// The place `value` names, as [`place_value`] wrote it.
pub(super) fn decode_place(value: &Value) -> Result<RepoProjectionPlace> {
    let parts = value.as_array().ok_or_else(corrupt)?;
    let number = |value: &Value| {
        value
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or_else(corrupt)
    };
    match (parts.first().and_then(Value::as_str), parts.as_slice()) {
        (Some("tree_entry"), [_, mode, Value::Binary(name)]) => {
            Ok(RepoProjectionPlace::TreeEntry {
                mode: number(mode)?,
                name: name.clone(),
            })
        }
        (Some("commit_tree"), [_]) => Ok(RepoProjectionPlace::CommitTree),
        (Some("commit_parent"), [_, index]) => Ok(RepoProjectionPlace::CommitParent {
            index: number(index)?,
        }),
        (Some("tag_target"), [_]) => Ok(RepoProjectionPlace::TagTarget),
        _ => Err(corrupt()),
    }
}

/// An object's or a parent's occurrence: its byte path, or `nil`.
pub(super) fn occurrence_value(occurrence: Option<&[u8]>) -> Value {
    occurrence.map_or(Value::Nil, |path| Value::Binary(path.to_vec()))
}

/// An optional recipient binding, `nil` when none was proved.
pub(super) fn optional_binding(value: &Value) -> Result<Option<RepoProjectionRevealBinding>> {
    match value {
        Value::Nil => Ok(None),
        value => RepoProjectionRevealBinding::decode(value).map(Some),
    }
}

pub(super) fn oid(oid: &GitOid) -> Value {
    Value::from(oid.as_str())
}

pub(super) fn ids(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect())
}

pub(super) fn fields(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

pub(super) fn packed(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| Error::InvariantViolation("a masked copy record part did not encode"))?;
    Ok(out)
}

/// The graph record at `id`, at schema 1 only, rebuilt and checked against
/// both its stored value and its id.
pub(super) fn decode_graph(id: &EntityId, body: &ClaimBody) -> Result<RepoProjectionClaim> {
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
    let audience = match text(field(map, "audience")?)? {
        AUDIENCE_MASKED => RepoProjectionAudience::Masked,
        AUDIENCE_RECIPIENT => RepoProjectionAudience::Recipient {
            binding: RepoProjectionRevealBinding::decode(field(map, "recipient")?)?,
            released: field(map, "released")?
                .as_array()
                .ok_or_else(corrupt)?
                .iter()
                .map(|file| match file.as_array().map(Vec::as_slice) {
                    Some([Value::Binary(path), blob]) => Ok((path.clone(), git_oid(blob)?)),
                    _ => Err(corrupt()),
                })
                .collect::<Result<Vec<_>>>()?,
        },
        _ => return Err(corrupt()),
    };
    let record = RepoProjectionRecord::Graph {
        store_identity: text(field(map, "store_identity")?)?.to_owned(),
        store_id: entity(field(map, "store_id")?)?,
        roots,
        private_root,
        marks,
        audience,
    };
    let claim = RepoProjectionClaim::graph(record)?;
    if claim.graph != *id || claim.value() != body.value || claim.claim()?.subject != body.subject {
        return Err(corrupt());
    }
    Ok(claim)
}

pub(super) fn field<'v>(map: &'v [(Value, Value)], key: &str) -> Result<&'v Value> {
    map.iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
        .ok_or_else(corrupt)
}

pub(super) fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(corrupt)
}

pub(super) fn entity(value: &Value) -> Result<EntityId> {
    EntityId::from_hex(text(value)?).map_err(|_| corrupt())
}

pub(super) fn digest_value(digest: &[u8; 32]) -> Value {
    Value::from(crate::entity_id::bytes_to_hex_lower(digest))
}

pub(super) fn digest_of(value: &Value) -> Result<[u8; 32]> {
    let hex = text(value)?.as_bytes();
    let mut digest = [0_u8; 32];
    if hex.len() != 64 {
        return Err(corrupt());
    }
    for (at, pair) in hex.chunks(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| corrupt())?;
        digest[at] = u8::from_str_radix(pair, 16).map_err(|_| corrupt())?;
    }
    Ok(digest)
}

pub(super) fn git_oid(value: &Value) -> Result<GitOid> {
    GitOid::parse_hex(text(value)?).map_err(|_| corrupt())
}
