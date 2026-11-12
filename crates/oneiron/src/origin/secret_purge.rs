//! The owner's purge of marked keys from a served repository's history (FIX
//! 7608 slice 10, owner ruling SECRETS-IN-REPOS = A: "Purge is vault-local
//! for the selected findings, shows what it affects before he confirms, and
//! never force-pushes automatically").
//!
//! The request (`plan`) reads the served store's published refs, writes the
//! masked copy of every object their histories reach beside the originals
//! (the masked Git copy's own engine, `copy_repo_projection_objects`, with
//! the served store as its copy store), and freezes what a confirmation
//! does as one `repo.secret_purge` claim: each ref's move, the purged
//! blobs, how many signed objects lose their signature, the keep-ref owners
//! that root a purged blob, and what the purge never reaches. No ref moves.
//!
//! The owner's execute (`execute`) of that plan moves each ref through the
//! origin publication protocol with the plan's CAS, releases the
//! change-index owners the plan lists, drops the reflogs and collects every
//! object no ref reaches, and files one `repo.secret_purge_receipt` claim:
//! `complete_local` when no purged blob is left in the store, `partial`
//! when one is, and `stale` when a ref or a mark moved since the plan. An
//! execute of a plan with a receipt returns that receipt. No remote is
//! pushed; backups, checkpoints and copies outside the store are named in
//! every plan and receipt, never reported erased.
//!
//! Plan and receipt name refs, object ids, mark ids and owner keys only:
//! never a value, span or excerpt.

mod execute;
mod plan;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::MASKED_FILE_BAND;
use crate::store::code_snapshot::entity_id_from_hash_material;
use crate::temporal::TimeRange;

/// The predicate of one frozen purge plan.
pub(crate) const REPO_SECRET_PURGE_PREDICATE: &str = "repo.secret_purge";

/// The predicate of one purge plan's receipt.
pub(crate) const REPO_SECRET_PURGE_RECEIPT_PREDICATE: &str = "repo.secret_purge_receipt";

/// The one schema plans and receipts are written at.
const PURGE_SCHEMA: u16 = 1;

/// The hash domain a plan's id is derived under.
const PLAN_ID_DOMAIN: &[u8] = b"oneiron:repo-secret-purge-plan:v1";

/// The hash domain a receipt's id is derived under, from its plan.
const RECEIPT_ID_DOMAIN: &[u8] = b"oneiron:repo-secret-purge-receipt:v1";

/// What no purge reaches, named in every plan and receipt.
const OUTSTANDING: [RepoSecretPurgeOutstanding; 5] = [
    RepoSecretPurgeOutstanding::BackupsAndCheckpoints,
    RepoSecretPurgeOutstanding::OutsideCopies,
    RepoSecretPurgeOutstanding::RepoSnapshots,
    RepoSecretPurgeOutstanding::CodeDocuments,
    RepoSecretPurgeOutstanding::LfsObjects,
];

#[doc(hidden)]
pub use oneiron_verb_wire::origin::secret_purge::{
    RepoSecretPurgeIdRequest, RepoSecretPurgeKeepRoot, RepoSecretPurgeOutstanding,
    RepoSecretPurgePlan, RepoSecretPurgeReceipt, RepoSecretPurgeRefMove, RepoSecretPurgeRefOutcome,
    RepoSecretPurgeRequest, RepoSecretPurgeState, RepoSecretPurgeView,
};

impl Vault {
    /// The purge plan `plan` and its receipt. `None` when no plan has that
    /// id.
    ///
    /// # Errors
    /// A store failure, or a plan or receipt that does not decode.
    pub(crate) fn repo_secret_purge(&self, plan: EntityId) -> Result<Option<RepoSecretPurgeView>> {
        let Some(found) = self.repo_secret_purge_plan(plan)? else {
            return Ok(None);
        };
        let receipt = self.repo_secret_purge_receipt(plan)?;
        Ok(Some(RepoSecretPurgeView {
            plan: found,
            receipt,
        }))
    }

    fn repo_secret_purge_plan(&self, plan: EntityId) -> Result<Option<RepoSecretPurgePlan>> {
        let Some(body) = self.get_claim(&plan)? else {
            return Ok(None);
        };
        if body.predicate != REPO_SECRET_PURGE_PREDICATE {
            return Ok(None);
        }
        decode_plan(plan, &body.value).map(Some)
    }

    fn repo_secret_purge_receipt(&self, plan: EntityId) -> Result<Option<RepoSecretPurgeReceipt>> {
        let id = receipt_id(plan)?;
        let Some(body) = self.get_claim(&id)? else {
            return Ok(None);
        };
        if body.predicate != REPO_SECRET_PURGE_RECEIPT_PREDICATE {
            return Err(Error::CorruptedIndex(
                "a repo secret purge receipt's id holds another claim",
            ));
        }
        decode_receipt(id, plan, &body.value).map(Some)
    }
}

/// A plan's id: its owner, its store, its sorted marks and each moved
/// ref's name and old object, so the same purge of the same refs by the
/// same owner plans once.
fn plan_id(
    owner: EntityId,
    store: EntityId,
    marks: &[EntityId],
    moves: &[RepoSecretPurgeRefMove],
) -> Result<EntityId> {
    let mut parts: Vec<Vec<u8>> = vec![owner.as_bytes().to_vec(), store.as_bytes().to_vec()];
    parts.push(marks.len().to_be_bytes().to_vec());
    parts.extend(marks.iter().map(|mark| mark.as_bytes().to_vec()));
    for step in moves {
        parts.push(step.ref_name.as_bytes().to_vec());
        parts.push(step.old_oid.as_bytes().to_vec());
    }
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    entity_id_from_hash_material(PLAN_ID_DOMAIN, &parts)
}

/// The id of `plan`'s one receipt.
fn receipt_id(plan: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(RECEIPT_ID_DOMAIN, &[plan.as_bytes().as_slice()])
}

/// The claim body of one plan or receipt: engine bookkeeping, on the edge
/// from the owner to the store, in the band of the files whose keys it
/// names.
fn purge_claim(
    predicate: &str,
    owner: EntityId,
    store: EntityId,
    value: Value,
) -> Result<ClaimBody> {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Edge {
            source: owner,
            kind: EdgeKind::PartOf,
            target: store,
        },
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    body.scope = Some(fields(vec![(
        "sensitivity",
        Value::from(MASKED_FILE_BAND.as_str()),
    )]));
    Ok(body)
}

/// Writes `body` at `id` once, in its own writer, while `owner`'s proof is
/// live and names `actor`: the same id again writes nothing, and the id
/// holding another record is a corrupt store.
fn put_purge_claim(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    actor: EntityId,
    id: EntityId,
    body: &ClaimBody,
    at: u64,
) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        require_owner_in_txn(vault, owner, actor, wtxn)?;
        if vault.get_claim_in_txn(wtxn, &id)?.is_some() {
            return Ok(());
        }
        if vault.get_raw_in(wtxn, &id)?.is_some() {
            return Err(Error::CorruptedIndex(
                "a repo secret purge claim's id holds another record",
            ));
        }
        let occurred = TimeRange { start: at, end: at };
        vault.put_reserved_claim_in_txn(wtxn, &id, body, occurred, at)
    })
}

/// Refuses unless `owner`'s proof is live in `txn` and names `actor`: a
/// purge acts only as the owner who asked for it.
fn require_owner_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    actor: EntityId,
    txn: &heed::RoTxn<'_>,
) -> Result<()> {
    if owner.revalidate_in_txn(vault, txn)? != actor {
        return Err(Error::Refused(
            "a repo secret purge acts as the owner who asked for it".to_owned(),
        ));
    }
    Ok(())
}

fn plan_value(plan: &RepoSecretPurgePlan) -> Value {
    let moves = plan
        .moves
        .iter()
        .map(|step| {
            Value::Array(vec![
                Value::from(step.ref_name.as_str()),
                Value::from(step.old_oid.as_str()),
                Value::from(step.new_oid.as_str()),
            ])
        })
        .collect();
    fields(vec![
        ("schema_version", Value::from(PURGE_SCHEMA)),
        ("owner", Value::from(plan.owner.to_hex())),
        ("repo", Value::from(plan.repo.as_str())),
        ("store", Value::from(plan.store.to_hex())),
        ("marks", ids_value(&plan.marks)),
        ("moves", Value::Array(moves)),
        ("purged_blobs", texts_value(&plan.purged_blobs)),
        ("rewritten_objects", Value::from(plan.rewritten_objects)),
        ("signatures_dropped", Value::from(plan.signatures_dropped)),
        ("keep_roots", roots_value(&plan.keep_roots)),
        ("planned_at", Value::from(plan.planned_at)),
    ])
}

fn decode_plan(plan: EntityId, value: &Value) -> Result<RepoSecretPurgePlan> {
    let map = map_of(value)?;
    schema(map)?;
    let moves = array_of(field(map, "moves")?)?
        .iter()
        .map(|row| {
            let [ref_name, old_oid, new_oid] = row_of::<3>(row)?;
            Ok(RepoSecretPurgeRefMove {
                ref_name: text_of(ref_name)?,
                old_oid: text_of(old_oid)?,
                new_oid: text_of(new_oid)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(RepoSecretPurgePlan {
        plan,
        owner: id_of(field(map, "owner")?)?,
        repo: text_of(field(map, "repo")?)?,
        store: id_of(field(map, "store")?)?,
        marks: ids_of(field(map, "marks")?)?,
        moves,
        purged_blobs: texts_of(field(map, "purged_blobs")?)?,
        rewritten_objects: u64_of(field(map, "rewritten_objects")?)?,
        signatures_dropped: u64_of(field(map, "signatures_dropped")?)?,
        keep_roots: roots_of(field(map, "keep_roots")?)?,
        outstanding: OUTSTANDING.to_vec(),
        planned_at: u64_of(field(map, "planned_at")?)?,
    })
}

fn receipt_value(receipt: &RepoSecretPurgeReceipt) -> Value {
    let refs = receipt
        .refs
        .iter()
        .map(|outcome| {
            Value::Array(vec![
                Value::from(outcome.ref_name.as_str()),
                Value::from(outcome.old_oid.as_str()),
                Value::from(outcome.new_oid.as_str()),
                Value::from(outcome.moved),
                outcome.failure.as_deref().map_or(Value::Nil, Value::from),
            ])
        })
        .collect();
    fields(vec![
        ("schema_version", Value::from(PURGE_SCHEMA)),
        ("plan", Value::from(receipt.plan.to_hex())),
        ("state", Value::from(state_name(receipt.state))),
        ("refs", Value::Array(refs)),
        ("released", roots_value(&receipt.released)),
        ("still_present", texts_value(&receipt.still_present)),
        ("executed_at", Value::from(receipt.executed_at)),
    ])
}

fn decode_receipt(
    receipt: EntityId,
    plan: EntityId,
    value: &Value,
) -> Result<RepoSecretPurgeReceipt> {
    let map = map_of(value)?;
    schema(map)?;
    if id_of(field(map, "plan")?)? != plan {
        return Err(Error::CorruptedIndex(
            "a repo secret purge receipt names another plan",
        ));
    }
    let state = match text_of(field(map, "state")?)?.as_str() {
        "complete_local" => RepoSecretPurgeState::CompleteLocal,
        "partial" => RepoSecretPurgeState::Partial,
        "stale" => RepoSecretPurgeState::Stale,
        _ => return Err(corrupt()),
    };
    let refs = array_of(field(map, "refs")?)?
        .iter()
        .map(|row| {
            let [ref_name, old_oid, new_oid, moved, failure] = row_of::<5>(row)?;
            Ok(RepoSecretPurgeRefOutcome {
                ref_name: text_of(ref_name)?,
                old_oid: text_of(old_oid)?,
                new_oid: text_of(new_oid)?,
                moved: moved.as_bool().ok_or_else(corrupt)?,
                failure: if failure.is_nil() {
                    None
                } else {
                    Some(text_of(failure)?)
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(RepoSecretPurgeReceipt {
        receipt,
        plan,
        state,
        refs,
        released: roots_of(field(map, "released")?)?,
        still_present: texts_of(field(map, "still_present")?)?,
        outstanding: OUTSTANDING.to_vec(),
        executed_at: u64_of(field(map, "executed_at")?)?,
    })
}

const fn state_name(state: RepoSecretPurgeState) -> &'static str {
    match state {
        RepoSecretPurgeState::CompleteLocal => "complete_local",
        RepoSecretPurgeState::Partial => "partial",
        RepoSecretPurgeState::Stale => "stale",
    }
}

fn roots_value(roots: &[RepoSecretPurgeKeepRoot]) -> Value {
    Value::Array(
        roots
            .iter()
            .map(|root| {
                Value::Array(vec![
                    Value::from(root.kind.as_str()),
                    Value::from(root.owner.as_str()),
                    Value::from(root.oid.as_str()),
                    Value::from(root.releases),
                ])
            })
            .collect(),
    )
}

fn roots_of(value: &Value) -> Result<Vec<RepoSecretPurgeKeepRoot>> {
    array_of(value)?
        .iter()
        .map(|row| {
            let [kind, owner, oid, releases] = row_of::<4>(row)?;
            Ok(RepoSecretPurgeKeepRoot {
                kind: text_of(kind)?,
                owner: text_of(owner)?,
                oid: text_of(oid)?,
                releases: releases.as_bool().ok_or_else(corrupt)?,
            })
        })
        .collect()
}

fn ids_value(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect())
}

fn ids_of(value: &Value) -> Result<Vec<EntityId>> {
    array_of(value)?.iter().map(id_of).collect()
}

fn texts_value(texts: &[String]) -> Value {
    Value::Array(
        texts
            .iter()
            .map(|text| Value::from(text.as_str()))
            .collect(),
    )
}

fn texts_of(value: &Value) -> Result<Vec<String>> {
    array_of(value)?.iter().map(text_of).collect()
}

fn schema(map: &[(Value, Value)]) -> Result<()> {
    if u64_of(field(map, "schema_version")?)? != u64::from(PURGE_SCHEMA) {
        return Err(corrupt());
    }
    Ok(())
}

fn field<'v>(map: &'v [(Value, Value)], key: &str) -> Result<&'v Value> {
    map.iter()
        .find_map(|(name, value)| (name.as_str() == Some(key)).then_some(value))
        .ok_or_else(corrupt)
}

fn map_of(value: &Value) -> Result<&[(Value, Value)]> {
    value.as_map().map(Vec::as_slice).ok_or_else(corrupt)
}

fn array_of(value: &Value) -> Result<&[Value]> {
    value.as_array().map(Vec::as_slice).ok_or_else(corrupt)
}

fn row_of<const N: usize>(value: &Value) -> Result<&[Value; N]> {
    array_of(value)?.try_into().map_err(|_| corrupt())
}

fn text_of(value: &Value) -> Result<String> {
    value.as_str().map(str::to_owned).ok_or_else(corrupt)
}

fn u64_of(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(corrupt)
}

fn id_of(value: &Value) -> Result<EntityId> {
    EntityId::from_hex(value.as_str().ok_or_else(corrupt)?)
}

fn corrupt() -> Error {
    Error::CorruptedIndex("a repo secret purge claim does not decode")
}

fn fields(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}
