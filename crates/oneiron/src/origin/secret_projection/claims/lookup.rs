//! Strict readers of a masked copy's records (FIX 7608 slice 2b-ii-B2): a
//! checkout binding found from its lease, an ingress store found from its
//! identity, a graph's object records walked by occurrence (FIX 9235), and
//! every record about a graph, for its disposal (FIX 9107). Each record is
//! decoded at schema 1 and checked against its stored value, subject and
//! id; one that is gone or no longer active reads as `None`.

use heed::RoTxn;

use std::collections::{HashMap, HashSet};

use super::{
    REPO_SECRET_PROJECTION_PREDICATE, RepoProjectionCheckout, RepoProjectionCheckoutRecipient,
    RepoProjectionClaim, RepoProjectionIngressStore, RepoProjectionPlace, RepoProjectionRecord,
    RepoProjectionRevealBinding, checkout_key, checkout_recipient_key, corrupt, decode_graph,
    decode_place, derive_id, entity, field, git_oid, ingress_store_key, text,
};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{GitObjectKind, GitOid};

fn active(body: &ClaimBody) -> bool {
    body.predicate == REPO_SECRET_PROJECTION_PREDICATE
        && body.approval == ClaimApprovalStatus::Approved
        && body.lifecycle == ClaimLifecycleStatus::Active
}

/// The projection record standing at `id`, or `None`.
fn standing(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<ClaimBody>> {
    Ok(vault.get_claim_in_txn(txn, id)?.filter(active))
}

/// The graph a non-graph record is about.
fn about_graph(body: &ClaimBody) -> Result<EntityId> {
    match body.subject {
        ClaimSubject::Entity(graph) => Ok(graph),
        _ => Err(corrupt()),
    }
}

fn kind_of(body: &ClaimBody) -> Result<&str> {
    let map = body.value.as_map().ok_or_else(corrupt)?;
    text(field(map, "kind")?)
}

/// Checks `record` about `graph` is exactly what `body` holds.
fn rebuilt(graph: EntityId, record: RepoProjectionRecord, body: &ClaimBody) -> Result<()> {
    let claim = RepoProjectionClaim::of(graph, record);
    if claim.value() != body.value || claim.claim()?.subject != body.subject {
        return Err(corrupt());
    }
    Ok(())
}

/// A masked copy's changed links and marked blobs, from its records alone
/// (FIX 9328): every place a changed object occurs in a changed parent,
/// by parent, and every ORIGINAL blob a mark masks.
#[derive(Debug, Default)]
pub(crate) struct RepoProjectionLinks {
    pub(crate) links: HashMap<GitOid, Vec<(RepoProjectionPlace, GitOid)>>,
    pub(crate) marked_blobs: HashSet<GitOid>,
}

impl RepoProjectionClaim {
    /// The changed links and marked blobs the masked copy `graph`'s
    /// standing records name, each once; a recipient copy's occurrence
    /// records are not a masked copy's and are left out.
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn masked_links_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        graph: &EntityId,
    ) -> Result<RepoProjectionLinks> {
        let mut found = RepoProjectionLinks::default();
        for id in vault.claims_for_subject_in_txn(txn, graph)? {
            let Some(body) = standing(vault, txn, &id)? else {
                continue;
            };
            let map = body.value.as_map().ok_or_else(corrupt)?;
            match kind_of(&body)? {
                "link" if field(map, "parent_occurrence")?.is_nil() => {
                    found
                        .links
                        .entry(git_oid(field(map, "parent")?)?)
                        .or_default()
                        .push((
                            decode_place(field(map, "place")?)?,
                            git_oid(field(map, "child_original")?)?,
                        ));
                }
                "object"
                    if field(map, "occurrence")?.is_nil()
                        && text(field(map, "object_type")?)? == GitObjectKind::Blob.as_str()
                        && !field(map, "marks")?
                            .as_array()
                            .ok_or_else(corrupt)?
                            .is_empty() =>
                {
                    found.marked_blobs.insert(git_oid(field(map, "original")?)?);
                }
                _ => {}
            }
        }
        Ok(found)
    }

    /// The checkout binding of the lease `checkout` at `epoch`, with the
    /// graph it binds; `None` when the lease checks out no copy.
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn load_checkout_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        checkout: &str,
        epoch: u64,
    ) -> Result<Option<(EntityId, RepoProjectionCheckout)>> {
        let id = derive_id(None, &checkout_key(checkout, epoch))?;
        let Some(body) = standing(vault, txn, &id)? else {
            return Ok(None);
        };
        let graph = about_graph(&body)?;
        let map = body.value.as_map().ok_or_else(corrupt)?;
        if text(field(map, "kind")?)? != "checkout" {
            return Err(corrupt());
        }
        let record = RepoProjectionCheckout {
            checkout: checkout.to_owned(),
            epoch,
            holder: text(field(map, "holder")?)?.to_owned(),
            original: git_oid(field(map, "original")?)?,
            copy: git_oid(field(map, "copy")?)?,
        };
        rebuilt(graph, RepoProjectionRecord::Checkout(record.clone()), &body)?;
        Ok(Some((graph, record)))
    }

    /// The recipient the lease `checkout` at `epoch` was bound for, with
    /// the graph its checkout binding names (FIX 10271); `None` when its
    /// run bound none.
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn load_checkout_recipient_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        checkout: &str,
        epoch: u64,
    ) -> Result<Option<(EntityId, RepoProjectionRevealBinding)>> {
        let id = derive_id(None, &checkout_recipient_key(checkout, epoch))?;
        let Some(body) = standing(vault, txn, &id)? else {
            return Ok(None);
        };
        let graph = about_graph(&body)?;
        let map = body.value.as_map().ok_or_else(corrupt)?;
        if text(field(map, "kind")?)? != "checkout_recipient" {
            return Err(corrupt());
        }
        let record = RepoProjectionCheckoutRecipient {
            checkout: checkout.to_owned(),
            epoch,
            reveal: RepoProjectionRevealBinding::decode(field(map, "reveal")?)?,
        };
        let reveal = record.reveal.clone();
        rebuilt(
            graph,
            RepoProjectionRecord::CheckoutRecipient(record),
            &body,
        )?;
        Ok(Some((graph, reveal)))
    }

    /// The ingress store record of the private ingress `ingress_store`,
    /// with the graph it was seeded from; `None` for any other store.
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn load_ingress_store_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        ingress_store: &str,
    ) -> Result<Option<(EntityId, RepoProjectionIngressStore)>> {
        let id = derive_id(None, &ingress_store_key(ingress_store))?;
        let Some(body) = standing(vault, txn, &id)? else {
            return Ok(None);
        };
        let graph = about_graph(&body)?;
        let map = body.value.as_map().ok_or_else(corrupt)?;
        if text(field(map, "kind")?)? != "ingress_store" {
            return Err(corrupt());
        }
        let record = RepoProjectionIngressStore {
            ingress_store: ingress_store.to_owned(),
            canonical_store: entity(field(map, "canonical_store")?)?,
        };
        rebuilt(
            graph,
            RepoProjectionRecord::IngressStore(record.clone()),
            &body,
        )?;
        Ok(Some((graph, record)))
    }

    /// Every ORIGINAL of `kind` whose copy in `graph` is `copy`, by its
    /// object record (FIX 9235): sorted and once each. A copy may stand
    /// for several originals; nothing picks a newest or equal one.
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn originals_of_copy_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        graph: &EntityId,
        copy: &GitOid,
        kind: GitObjectKind,
    ) -> Result<Vec<GitOid>> {
        let mut originals = Vec::new();
        for id in vault.claims_for_subject_in_txn(txn, graph)? {
            let Some(body) = standing(vault, txn, &id)? else {
                continue;
            };
            if kind_of(&body)? != "object" {
                continue;
            }
            let map = body.value.as_map().ok_or_else(corrupt)?;
            if git_oid(field(map, "copy")?)? != *copy
                || text(field(map, "object_type")?)? != kind.as_str()
            {
                continue;
            }
            originals.push(git_oid(field(map, "original")?)?);
        }
        originals.sort();
        originals.dedup();
        Ok(originals)
    }

    /// The id and kind of every projection record about `graph`, standing
    /// or not, for its disposal.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn records_about_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        graph: &EntityId,
    ) -> Result<Vec<(EntityId, String)>> {
        let mut records = Vec::new();
        for id in vault.claims_for_subject_in_txn(txn, graph)? {
            let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
                continue;
            };
            if body.predicate != REPO_SECRET_PROJECTION_PREDICATE {
                continue;
            }
            let kind = body
                .value
                .as_map()
                .and_then(|map| field(map, "kind").ok())
                .and_then(|kind| kind.as_str())
                .unwrap_or_default()
                .to_owned();
            records.push((id, kind));
        }
        Ok(records)
    }

    /// The checkout and epoch of every standing checkout binding about
    /// `graph`.
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn checkouts_about_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        graph: &EntityId,
    ) -> Result<Vec<(String, u64)>> {
        let mut checkouts = Vec::new();
        for id in vault.claims_for_subject_in_txn(txn, graph)? {
            let Some(body) = standing(vault, txn, &id)? else {
                continue;
            };
            if kind_of(&body)? != "checkout" {
                continue;
            }
            let map = body.value.as_map().ok_or_else(corrupt)?;
            let epoch = field(map, "epoch")?.as_u64().ok_or_else(corrupt)?;
            checkouts.push((text(field(map, "checkout")?)?.to_owned(), epoch));
        }
        Ok(checkouts)
    }

    /// Hands each standing graph record to `visit`, in the claim type
    /// index's order, with nothing held between them.
    ///
    /// # Errors
    /// A store failure, a record that does not decode, or `visit`'s.
    pub(crate) fn for_each_graph_in_txn<F>(
        vault: &Vault,
        txn: &RoTxn<'_>,
        mut visit: F,
    ) -> Result<()>
    where
        F: FnMut(&Self) -> Result<()>,
    {
        vault.for_each_claim_with_predicate_in_txn(
            txn,
            REPO_SECRET_PROJECTION_PREDICATE,
            |id, body| {
                if !active(&body) || kind_of(&body)? != "graph" {
                    return Ok(());
                }
                visit(&decode_graph(&id, &body)?)
            },
        )
    }
}
