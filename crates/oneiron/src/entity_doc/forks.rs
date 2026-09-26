//! Durable divergences, entity-bound grant admission and atomic fork-set settlement.

use super::document::decode_frontier;
use super::side_keys::HexPair;
use super::{AnchoredEdit, EntityDoc, invalid, storage};
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, HexId, Named, Raw, SideTable};
use crate::store::Store;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

/// Authorization is separate from attribution. Owner evidence is opaque;
/// automated writes resolve a live DEC-0006 entity-bound action grant in-txn.
#[derive(Debug, Clone, Copy)]
pub enum DocAuthorization<'a> {
    /// An explicitly authenticated owner action.
    Owner(&'a AuthenticatedOwner),
    /// Require an active `entity.text.edit` grant for each exact target entity.
    StandingGrant,
    /// Retain output for review without authority to change the live head.
    ProposeOnly,
}

/// A fork's mutation, opened against an explicit causal base.
#[derive(Debug, Clone)]
pub struct ForkRequest {
    /// Target entity.
    pub entity: EntityId,
    /// Version where this divergence starts.
    pub base: Vec<u8>,
    /// Writer, bound independently from grant authorization.
    pub actor: WriteActor,
    /// Small actor-stamped edits. Cannot be combined with a rewrite.
    pub edits: Vec<AnchoredEdit>,
    /// Declared disruptive rewrite; published only by explicit SWITCH.
    pub rewrite: Option<String>,
}

/// A consume-once fork's durable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkStatus {
    Pending,
    Merged,
    Switched,
    Rejected,
}
/// Explicit settle verbs. Only SWITCH has a stale-base refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettleVerb {
    Merge,
    Switch,
    Reject,
}

/// Durable fork identity and provenance, recorded at the moment it joins a set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkRecord {
    pub fork: String,
    pub proposal: String,
    pub entity: String,
    pub parent_document: String,
    pub base: Vec<u8>,
    pub actor: String,
    pub opened_at: u64,
    pub rewrite: bool,
    pub status: ForkStatus,
}

/// One review bundle, never inferred from author or time proximity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalBundle {
    pub proposal: String,
    pub author: String,
    pub forks: Vec<ForkRecord>,
    pub settled: bool,
}
impl ProposalBundle {
    /// Forks still waiting for the bundle's single verdict.
    pub fn pending(&self) -> impl Iterator<Item = &ForkRecord> {
        self.forks
            .iter()
            .filter(|fork| fork.status == ForkStatus::Pending)
    }
}

/// A durable receipt minted in the same transaction as the head or verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextReceipt {
    pub receipt: String,
    pub proposal: String,
    pub fork: String,
    pub entity: String,
    pub actor: String,
    pub verb: SettleVerb,
    pub at: u64,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

/// Durable identity/provenance/status of one open or settled document fork.
const ENTITY_DOC_FORK: SideTable<String, ForkRecord, Named> =
    SideTable::new(&side_table::ENTITY_DOC_FORK);
/// Shallow Loro snapshot of a fork's diverged content at its opening base.
const ENTITY_DOC_FORK_SNAPSHOT: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::ENTITY_DOC_FORK_SNAPSHOT);
/// Review bundle of every fork opened under one text-edit proposal.
const ENTITY_DOC_PROPOSAL_BUNDLE: SideTable<String, ProposalBundle, Named> =
    SideTable::new(&side_table::ENTITY_DOC_PROPOSAL_BUNDLE);
/// Durable settlement receipt for one fork's merge/switch/reject verdict,
/// keyed by entity then receipt id.
const ENTITY_DOC_RECEIPT: SideTable<HexPair, TextReceipt, Named> =
    SideTable::new(&side_table::ENTITY_DOC_RECEIPT);

pub(super) fn validate_actor(vault: &Vault, txn: &RoTxn<'_>, actor: WriteActor) -> Result<()> {
    storage::require_live(&vault.store, txn, &actor.entity_ref())?;
    crate::memory::verify_actor_binding_in_txn(vault, txn, actor.entity_ref(), actor.actor_class())
        .map_err(|_| invalid("document actor class does not match store truth"))?;
    if vault.entity_lifecycle_state_in_txn(txn, &actor.entity_ref())?
        != crate::identity_topology::EntityLifecycleState::Active
    {
        return Err(invalid("document actor is not active"));
    }
    Ok(())
}

/// Same actor.peer_binding CLAIM substrate used by proposal attribution. The
/// caller gives each authored operation a fresh writing peer, so same-second
/// actor changes never create ambiguous temporal bindings.
pub(super) fn bind_actor(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    doc: &EntityDoc,
    actor: WriteActor,
    at: u64,
) -> Result<()> {
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
        PREDICATE_ACTOR_PEER_BINDING,
    };
    let mut body = ClaimBody::new(
        PREDICATE_ACTOR_PEER_BINDING,
        ClaimSubject::Entity(actor.entity_ref()),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("peer"),
                rmpv::Value::from(doc.doc.peer_id()),
            ),
            (
                rmpv::Value::from("class"),
                rmpv::Value::from(crate::edit_distance::actor_class_token(actor.actor_class())),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.valid_from = Some(at);
    body.source = Some(ClaimSource::Observed);
    vault.put_reserved_claim_in_txn(
        txn,
        &EntityId::now(),
        &body,
        crate::temporal::TimeRange { start: at, end: at },
        at,
    )
}

pub(super) fn owner_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> Result<()> {
    let actor = WriteActor::new(owner.actor(), crate::edge::EdgeActorClass::Human);
    validate_actor(vault, txn, actor)?;
    crate::memory::verify_owner_actor_binding_in_txn(vault, txn, owner.actor())
        .map_err(|_| invalid("owner authority is no longer active"))?;
    let header = vault
        .store
        .entities
        .get(txn, owner.actor().as_bytes())?
        .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw));
    if header.is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_PERSON) {
        return Err(Error::Artifact(ArtifactError::SettleNotAuthorized(
            "owner is not a live human",
        )));
    }
    Ok(())
}

pub(super) fn covered(
    vault: &Vault,
    txn: &RoTxn<'_>,
    auth: &DocAuthorization<'_>,
    entity: &EntityId,
    actor: WriteActor,
) -> Result<bool> {
    validate_actor(vault, txn, actor)?;
    match auth {
        DocAuthorization::Owner(owner) => {
            owner_in_txn(vault, txn, owner)?;
            Ok(owner.actor() == actor.entity_ref()
                && actor.actor_class() == crate::edge::EdgeActorClass::Human)
        }
        DocAuthorization::ProposeOnly => Ok(false),
        DocAuthorization::StandingGrant => {
            let target = format!("entity:{}", entity.to_hex());
            let required = GrantBound::action(
                ActorBound::new(actor.entity_ref().to_hex())?,
                ActionClass::new("entity.text.edit")?,
                ActionEnvelope::new([target.clone()])?.with_target(target)?,
            )?;
            Ok(vault
                .active_standing_consent_grants_in_txn(txn)?
                .iter()
                .any(|grant| grant.bound().contains(&required)))
        }
    }
}

pub(super) fn authorize(
    vault: &Vault,
    txn: &RoTxn<'_>,
    auth: &DocAuthorization<'_>,
    entity: &EntityId,
    actor: WriteActor,
) -> Result<()> {
    if covered(vault, txn, auth, entity, actor)? {
        Ok(())
    } else {
        Err(Error::Artifact(ArtifactError::SettleNotAuthorized(
            "no entity-bound text write authority",
        )))
    }
}

impl Vault {
    /// Opens a set of durable forks. Each entity's grant is resolved separately
    /// inside the write transaction. Authorized small edits merge immediately;
    /// all other forks stay together in one review bundle. A rewrite never moves
    /// the head implicitly, even when its actor has an automatic grant.
    pub fn open_text_proposal(
        &self,
        proposal: &EntityId,
        requests: &[ForkRequest],
        authorization: &DocAuthorization<'_>,
        at: u64,
    ) -> Result<ProposalBundle> {
        if requests.is_empty() || requests.len() > 50 {
            return Err(invalid("proposal requires 1 to 50 forks"));
        }
        if requests.iter().map(|req| req.edits.len()).sum::<usize>() > 50 {
            return Err(invalid("at most 50 text operations are allowed"));
        }
        for req in requests {
            super::verbs::validate_edits(&req.edits)?;
            if req.rewrite.is_some() && !req.edits.is_empty() {
                return Err(invalid("rewrite cannot contain anchored edits"));
            }
            if req.edits.iter().any(|op| op.actor != Some(req.actor)) {
                return Err(invalid("fork operation actor mismatch"));
            }
        }
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        let out = self.with_write_txn(|txn| {
            for req in requests {
                validate_actor(self, txn, req.actor)?;
                let h = storage::head(&self.store, txn, &req.entity)?;
                let live = storage::load(&self.store, txn, &h)?;
                let mut fork = live.fork(&req.base)?;
                bind_actor(self, txn, &fork, req.actor, at)?;
                if let Some(text) = &req.rewrite {
                    crate::batch::secret_scan::scan_metadata_field(text)?;
                    fork.edit_as(req.actor, at, |body| {
                        body.delete(0, body.len_unicode())
                            .map_err(|_| invalid("fork rewrite delete"))?;
                        body.insert(0, text)
                            .map_err(|_| invalid("fork rewrite insert"))
                    })?;
                } else {
                    for op in &req.edits {
                        super::verbs::apply(&mut fork, req.entity, op, at)?;
                    }
                }
                let id = EntityId::now();
                retain_fork(
                    self,
                    txn,
                    *proposal,
                    id,
                    req,
                    &h,
                    &fork,
                    ForkStatus::Pending,
                    at,
                )?;
                if req.rewrite.is_none()
                    && covered(self, txn, authorization, &req.entity, req.actor)?
                {
                    settle_one(self, txn, &id.to_hex(), SettleVerb::Merge, req.actor, at)?;
                }
            }
            read_bundle(&self.store, txn, proposal)
        })?;
        registry.clear();
        Ok(out)
    }

    /// Reads one fork by its durable identity. A second divergence has its own
    /// row and base; it cannot shift the first fork's opening frontier.
    pub fn entity_text_fork(&self, fork: &EntityId) -> Result<Option<ForkRecord>> {
        let txn = self.store.env.read_txn()?;
        ENTITY_DOC_FORK.get(&self.store, &txn, &fork.to_hex())
    }

    /// Reads retained fork output, including the full text of a timed-out update.
    pub fn entity_text_fork_text(&self, fork: &EntityId) -> Result<Option<String>> {
        let txn = self.store.env.read_txn()?;
        let Some(row) = ENTITY_DOC_FORK.get(&self.store, &txn, &fork.to_hex())? else {
            return Ok(None);
        };
        storage::require_live(&self.store, &txn, &EntityId::from_hex(&row.entity)?)?;
        ENTITY_DOC_FORK_SNAPSHOT
            .get(&self.store, &txn, &fork.to_hex())?
            .map(|raw| EntityDoc::from_snapshot(&raw).map(|doc| doc.text()))
            .transpose()
    }

    /// Reads the complete proposal set and its pending review bundle.
    pub fn entity_text_proposal(&self, proposal: &EntityId) -> Result<ProposalBundle> {
        let txn = self.store.env.read_txn()?;
        read_bundle(&self.store, &txn, proposal)
    }

    /// Accepts or rejects the entire remaining set in one transaction. MERGE
    /// preserves concurrent head edits. SWITCH compares the exact causal base
    /// and parent pointer before moving it. A stale member rolls back the set.
    pub fn settle_text_proposal(
        &self,
        proposal: &EntityId,
        verb: SettleVerb,
        authorization: &DocAuthorization<'_>,
        actor: WriteActor,
        at: u64,
    ) -> Result<ProposalBundle> {
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        let out = self.with_write_txn(|txn| {
            let bundle = read_bundle(&self.store, txn, proposal)?;
            if bundle.settled {
                return Err(Error::Artifact(ArtifactError::EditProposalAlreadySettled {
                    outcome: "settled",
                }));
            }
            for fork in bundle.pending() {
                let entity = EntityId::from_hex(&fork.entity)?;
                authorize(self, txn, authorization, &entity, actor)?;
                settle_one(self, txn, &fork.fork, verb, actor, at)?;
            }
            let mut bundle = read_bundle(&self.store, txn, proposal)?;
            bundle.settled = true;
            ENTITY_DOC_PROPOSAL_BUNDLE.put(&self.store, txn, &proposal.to_hex(), &bundle)?;
            Ok(bundle)
        })?;
        registry.clear();
        Ok(out)
    }

    /// Receipts are read from the same durable rows written with settlement.
    pub fn entity_text_receipts(&self, entity: &EntityId) -> Result<Vec<TextReceipt>> {
        let txn = self.store.env.read_txn()?;
        receipts(&self.store, &txn, entity)
    }
}

pub(super) fn read_bundle(
    store: &Store,
    txn: &RoTxn<'_>,
    proposal: &EntityId,
) -> Result<ProposalBundle> {
    ENTITY_DOC_PROPOSAL_BUNDLE
        .get(store, txn, &proposal.to_hex())?
        .ok_or(Error::EntityNotFound)
}

#[expect(
    clippy::too_many_arguments,
    reason = "one atomic divergence record binds identity, base, output and admission"
)]
pub(super) fn retain_fork(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    proposal: EntityId,
    id: EntityId,
    req: &ForkRequest,
    h: &storage::Head,
    doc: &EntityDoc,
    status: ForkStatus,
    at: u64,
) -> Result<()> {
    let key = proposal.to_hex();
    let mut bundle = match ENTITY_DOC_PROPOSAL_BUNDLE.get(&vault.store, txn, &key)? {
        Some(bundle) => bundle,
        None => ProposalBundle {
            proposal: proposal.to_hex(),
            author: req.actor.entity_ref().to_hex(),
            forks: Vec::new(),
            settled: false,
        },
    };
    if bundle.settled || bundle.author != req.actor.entity_ref().to_hex() {
        return Err(invalid("proposal is closed or belongs to another actor"));
    }
    if bundle.forks.len() >= 256 {
        return Err(invalid("proposal fork set exceeds bound"));
    }
    let record = ForkRecord {
        fork: id.to_hex(),
        proposal: proposal.to_hex(),
        entity: req.entity.to_hex(),
        parent_document: h.document.clone(),
        base: req.base.clone(),
        actor: req.actor.entity_ref().to_hex(),
        opened_at: at,
        rewrite: req.rewrite.is_some(),
        status,
    };
    ENTITY_DOC_FORK.put(&vault.store, txn, &id.to_hex(), &record)?;
    // A fork is its own shallow document, not a second complete history copy.
    ENTITY_DOC_FORK_SNAPSHOT.put(
        &vault.store,
        txn,
        &id.to_hex(),
        &doc.shallow_snapshot(&req.base)?,
    )?;
    bundle.forks.push(record);
    ENTITY_DOC_PROPOSAL_BUNDLE.put(&vault.store, txn, &key, &bundle)?;
    Ok(())
}

pub(super) fn merge_into(live: &EntityDoc, fork: &EntityDoc, base: &[u8]) -> Result<()> {
    let base = decode_frontier(base)?;
    let vv = fork
        .doc
        .frontiers_to_vv(&base)
        .ok_or(invalid("fork base unavailable"))?;
    let updates = fork
        .doc
        .export(loro::ExportMode::updates(&vv))
        .map_err(|_| invalid("fork export"))?;
    let status = live
        .doc
        .import(&updates)
        .map_err(|_| invalid("fork merge"))?;
    if status.pending.is_some() {
        return Err(invalid("fork dependencies absent from live head"));
    }
    Ok(())
}

fn settle_one(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    fork_id: &str,
    verb: SettleVerb,
    actor: WriteActor,
    at: u64,
) -> Result<()> {
    let mut record = ENTITY_DOC_FORK
        .get(&vault.store, txn, &fork_id.to_owned())?
        .ok_or(Error::EntityNotFound)?;
    if record.status != ForkStatus::Pending {
        return Err(Error::Artifact(ArtifactError::EditProposalAlreadySettled {
            outcome: "settled",
        }));
    }
    let entity = EntityId::from_hex(&record.entity)?;
    let mut h = storage::head(&vault.store, txn, &entity)?;
    let live = storage::load(&vault.store, txn, &h)?;
    let before = live.frontier();
    let after = match verb {
        SettleVerb::Reject => {
            record.status = ForkStatus::Rejected;
            before.clone()
        }
        SettleVerb::Merge => {
            let fork = EntityDoc::from_snapshot(
                &ENTITY_DOC_FORK_SNAPSHOT
                    .get(&vault.store, txn, &fork_id.to_owned())?
                    .ok_or(Error::EntityNotFound)?,
            )?;
            let vv = live.doc.oplog_vv();
            merge_into(&live, &fork, &record.base)?;
            storage::persist(vault, txn, &entity, &mut h, &live, Some(&vv))?;
            record.status = ForkStatus::Merged;
            live.frontier()
        }
        SettleVerb::Switch => {
            if h.document != record.parent_document
                || decode_frontier(&before)? != decode_frontier(&record.base)?
            {
                return Err(Error::Artifact(ArtifactError::EditProposalStale));
            }
            let fork = EntityDoc::from_snapshot(
                &ENTITY_DOC_FORK_SNAPSHOT
                    .get(&vault.store, txn, &fork_id.to_owned())?
                    .ok_or(Error::EntityNotFound)?,
            )?;
            // The retained fork is shallow at its base. Import only its ops into
            // a full live scratch doc before switching, retaining pinned history.
            merge_into(&live, &fork, &record.base)?;
            let old_document = h.document.clone();
            h.document = record.fork.clone();
            storage::move_pointer(&vault.store, txn, &entity, &h.document)?;
            storage::persist(vault, txn, &entity, &mut h, &live, None)?;
            storage::drop_document(&vault.store, txn, &old_document)?;
            record.status = ForkStatus::Switched;
            live.frontier()
        }
    };
    ENTITY_DOC_FORK.put(&vault.store, txn, &fork_id.to_owned(), &record)?;
    ENTITY_DOC_FORK_SNAPSHOT.delete(&vault.store, txn, &fork_id.to_owned())?;
    let proposal = EntityId::from_hex(&record.proposal)?;
    let mut bundle = read_bundle(&vault.store, txn, &proposal)?;
    let slot = bundle
        .forks
        .iter_mut()
        .find(|f| f.fork == record.fork)
        .ok_or(Error::CorruptedIndex("fork absent from proposal"))?;
    *slot = record.clone();
    ENTITY_DOC_PROPOSAL_BUNDLE.put(&vault.store, txn, &proposal.to_hex(), &bundle)?;
    write_receipt(
        vault,
        txn,
        proposal,
        EntityId::from_hex(fork_id)?,
        entity,
        actor,
        verb,
        at,
        &before,
        &after,
    )?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "receipt binds before/after causal state to one authorized verdict"
)]
pub(super) fn write_receipt(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    proposal: EntityId,
    fork: EntityId,
    entity: EntityId,
    actor: WriteActor,
    verb: SettleVerb,
    at: u64,
    before: &[u8],
    after: &[u8],
) -> Result<TextReceipt> {
    let receipt_id = EntityId::now();
    let receipt = TextReceipt {
        receipt: receipt_id.to_hex(),
        proposal: proposal.to_hex(),
        fork: fork.to_hex(),
        entity: entity.to_hex(),
        actor: actor.entity_ref().to_hex(),
        verb,
        at,
        before: before.to_vec(),
        after: after.to_vec(),
    };
    ENTITY_DOC_RECEIPT.put(
        &vault.store,
        txn,
        &HexPair(HexId(entity), HexId(receipt_id)),
        &receipt,
    )?;
    Ok(receipt)
}

pub(super) fn receipts(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
) -> Result<Vec<TextReceipt>> {
    Ok(ENTITY_DOC_RECEIPT
        .scan_from(store, txn, format!("{}:", entity.to_hex()).as_bytes())?
        .into_iter()
        .map(|(_, receipt)| receipt)
        .collect())
}

pub(super) fn all_forks(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
) -> Result<Vec<ForkRecord>> {
    let mut forks = Vec::new();
    for (_, fork) in ENTITY_DOC_FORK.scan(store, txn)? {
        if fork.entity == entity.to_hex() {
            forks.push(fork);
        }
    }
    Ok(forks)
}

pub(super) fn erase_forks(store: &Store, txn: &mut RwTxn<'_>, entity: &EntityId) -> Result<()> {
    for fork in all_forks(store, txn, entity)? {
        ENTITY_DOC_FORK_SNAPSHOT.delete(store, txn, &fork.fork)?;
        ENTITY_DOC_FORK.delete(store, txn, &fork.fork)?;
        let id = EntityId::from_hex(&fork.proposal)?;
        let mut bundle = read_bundle(store, txn, &id)?;
        bundle.forks.retain(|row| row.entity != entity.to_hex());
        ENTITY_DOC_PROPOSAL_BUNDLE.put(store, txn, &id.to_hex(), &bundle)?;
    }
    Ok(())
}
