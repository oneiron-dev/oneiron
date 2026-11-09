//! Doors to the derivation transaction (untangle 6.7a): commit a batch of
//! claims as an actor, read its batch record back, and ask the derive
//! verdict.

use crate::claim::ClaimSource;
use crate::derive::{
    DerivationBatch, DerivationItem, DerivationStamp, DerivedClaim, DerivedSupersede,
    ItemOutcome, ItemRef,
};
use crate::error::Result;
use crate::gate::{DeriveCapability, DeriveRefusal};
use crate::write_envelope::{SourceLineage, WriteActor};
use crate::{EdgeActorClass, EntityId, Vault};

/// A row a door claim names: a stored one, or an earlier item's.
#[derive(Debug, Clone)]
pub enum Named {
    /// A stored row.
    Stored(EntityId),
    /// The row an earlier item of the batch lands, by its local name.
    Local(&'static str),
}

/// One derived claim for a door batch.
#[derive(Debug, Clone)]
pub struct Claim {
    pub local: &'static str,
    pub predicate: &'static str,
    pub subject: Named,
    pub value: serde_json::Value,
    pub evidence: Vec<Named>,
}

/// A supersession for a door batch: `new` replaces `old`.
#[derive(Debug, Clone)]
pub struct Supersede {
    pub local: &'static str,
    pub new: Named,
    pub old: Named,
}

/// One item of a door batch.
#[derive(Debug, Clone)]
pub enum Derived {
    Claim(Claim),
    Supersede(Supersede),
}

/// One item's outcome, as the commit answered it or the batch record keeps
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub local: String,
    pub kind: String,
    pub landed: bool,
    pub rows: Vec<EntityId>,
    /// `auto` or `proposed` for a landed claim.
    pub approval: Option<String>,
    pub reasons: Vec<String>,
}

/// What a door commit did.
#[derive(Debug, Clone)]
pub struct Committed {
    pub batch: EntityId,
    pub items: Vec<Item>,
}

fn named(named: &Named) -> ItemRef {
    match named {
        Named::Stored(id) => ItemRef::Stored(*id),
        Named::Local(name) => ItemRef::Local((*name).to_owned()),
    }
}

/// Commits `claims` as one batch by `actor` of `class`, in run `run`.
///
/// # Errors
///
/// The commit's: a malformed batch or a storage error.
pub fn commit_claims(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    run: &str,
    claims: &[Claim],
) -> Result<Committed> {
    let items: Vec<Derived> = claims.iter().cloned().map(Derived::Claim).collect();
    commit(vault, actor, class, run, &items)
}

/// Commits `items` as one batch by `actor` of `class`, in run `run`.
///
/// # Errors
///
/// The commit's: a malformed batch or a storage error.
pub fn commit(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    run: &str,
    items: &[Derived],
) -> Result<Committed> {
    let stamp = DerivationStamp {
        actor: WriteActor::new(actor, class),
        run: Some(run.to_owned()),
        lineage: SourceLineage::of(ClaimSource::Generated),
    };
    let batch = DerivationBatch {
        items: items
            .iter()
            .map(|item| match item {
                Derived::Claim(claim) => DerivationItem::Claim(DerivedClaim {
                    local: claim.local.to_owned(),
                    predicate: claim.predicate.to_owned(),
                    subject: named(&claim.subject),
                    value: claim.value.clone(),
                    confidence: 0.9,
                    evidence: claim.evidence.iter().map(named).collect(),
                }),
                Derived::Supersede(supersede) => DerivationItem::Supersede(DerivedSupersede {
                    local: supersede.local.to_owned(),
                    new: named(&supersede.new),
                    old: named(&supersede.old),
                }),
            })
            .collect(),
    };
    let receipt = vault.derive_commit(&stamp, &batch)?;
    Ok(Committed {
        batch: receipt.batch,
        items: receipt
            .items
            .into_iter()
            .map(|item| match item.outcome {
                ItemOutcome::Landed { rows, approval, .. } => Item {
                    local: item.local,
                    kind: item.kind.to_owned(),
                    landed: true,
                    rows,
                    approval: approval.map(|approval| approval.as_str().to_owned()),
                    reasons: Vec::new(),
                },
                ItemOutcome::Refused { reasons, .. } => Item {
                    local: item.local,
                    kind: item.kind.to_owned(),
                    landed: false,
                    rows: Vec::new(),
                    approval: None,
                    reasons,
                },
            })
            .collect(),
    })
}

/// The lifecycle status of the claim `id` (`active`, `superseded`, ...),
/// when it is a stored claim.
///
/// # Errors
///
/// The vault's.
pub fn claim_lifecycle(vault: &Vault, id: EntityId) -> Result<Option<String>> {
    let Some(raw) = vault.get(&id)? else {
        return Ok(None);
    };
    Ok(crate::claim::decode_claim_body(&raw, true)
        .ok()
        .map(|body| body.lifecycle.as_str().to_owned()))
}

/// The items of the committed batch `batch`, as its record keeps them.
///
/// # Errors
///
/// The vault's.
pub fn batch_items(vault: &Vault, batch: EntityId) -> Result<Option<Vec<Item>>> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::derive::batch_record_in_txn(vault, &txn, batch)?.map(|record| {
        record
            .items
            .into_iter()
            .map(|item| Item {
                local: item.local,
                kind: item.kind,
                landed: item.landed,
                rows: item.rows,
                approval: item.approval,
                reasons: item.reasons,
            })
            .collect()
    }))
}

/// The batches `actor` committed, oldest first.
///
/// # Errors
///
/// The vault's.
pub fn batches_of(vault: &Vault, actor: EntityId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::derive::batches_of_actor_in_txn(vault, &txn, actor)
}

/// The reason tokens of the refusal receipt the batch record names for its
/// item `local`; `None` when the item has no refusal receipt.
///
/// # Errors
///
/// The vault's.
pub fn refusal_receipt(
    vault: &Vault,
    batch: EntityId,
    local: &str,
) -> Result<Option<Vec<String>>> {
    let txn = vault.store.env.read_txn()?;
    let Some(record) = crate::derive::batch_record_in_txn(vault, &txn, batch)? else {
        return Ok(None);
    };
    let Some(receipt) = record
        .items
        .iter()
        .find(|item| item.local == local)
        .and_then(|item| item.receipt)
    else {
        return Ok(None);
    };
    Ok(vault
        .store
        .gate_decision_in_txn(&txn, crate::store::GateDecisionId::from_bytes(receipt))?
        .filter(|decision| {
            decision.content_kind == crate::derive::DERIVE_ITEM_CONTENT_KIND
                && decision.outcome == "deny"
        })
        .map(|decision| decision.reason_codes))
}

/// The derive verdict for `actor` of `class` doing `capability` (`archive`
/// when `archive`, else `derive`) to `target`: the grant it was judged by,
/// or the refusal's token.
///
/// # Errors
///
/// The vault's.
pub fn derive_verdict(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    archive: bool,
    target: Option<EntityId>,
) -> Result<std::result::Result<String, &'static str>> {
    let capability = if archive {
        DeriveCapability::Archive
    } else {
        DeriveCapability::Derive
    };
    let txn = vault.store.env.read_txn()?;
    Ok(crate::gate::derive_verdict_in_txn(
        &vault.store,
        &txn,
        WriteActor::new(actor, class),
        capability,
        target,
    )?
    .map(|allowed| allowed.grant_ref)
    .map_err(DeriveRefusal::token))
}

/// Every refusal token of the derive verdict.
#[must_use]
pub fn refusal_tokens() -> Vec<&'static str> {
    DeriveRefusal::ALL.iter().map(|refusal| refusal.token()).collect()
}
