//! The owner act and call-scoped source permit for a whole-vault archive restore.

use super::super::WholeVaultDocumentManifest;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{POLICY_SCHEMA_VERSION, resolve_policy_manifest};
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::write_envelope::WriteActor;

/// The call-scoped permit the owner's own whole-vault restore carries for its expression rows.
/// Minted only after the bound-owner check and receipt append, held only for the synchronous
/// import call, never stored.
#[derive(Debug, Clone)]
pub(crate) struct OwnerArchiveRestorePermit {
    owner: EntityId,
    receipt: GateDecisionId,
}

impl OwnerArchiveRestorePermit {
    pub(super) fn mint(owner: EntityId, receipt: GateDecisionId) -> Self {
        Self { owner, receipt }
    }

    pub(crate) fn owner(&self) -> EntityId {
        self.owner
    }

    pub(super) fn receipt_ref(&self) -> String {
        format!("gate:{}", self.receipt.to_hex())
    }
}

impl Vault {
    /// Read-only probe using the same owner check the archive restore runs in its writer.
    /// At this snapshot, `Ok(())` means [`Self::import_whole_vault_archive_from_as_owner`]
    /// will not refuse for owner authorization. The CLI uses this to choose its restore door;
    /// the restore rechecks in its writer. This writes no rows or receipt.
    pub fn verify_archive_restore_owner(&self, owner: &AuthenticatedOwner) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        owner_archive_restore_actor_in_txn(self, &txn, owner).map(|_| ())
    }
}

pub(super) fn owner_archive_restore_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> Result<WriteActor> {
    let owner_id = owner.revalidate_in_txn(vault, txn)?;
    let actor = WriteActor::new(owner_id, EdgeActorClass::Human);
    vault.verify_owner_write_actor_in_txn(txn, &actor)?;
    super::super::expression_import::validate_local_actor(vault, txn, &actor)?;
    Ok(actor)
}

pub(super) fn record_owner_archive_restore_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    manifest_digest: [u8; 32],
) -> Result<GateDecisionId> {
    let digest = blake3::Hash::from_bytes(manifest_digest).to_hex();
    let mut receipt = GateDecisionRecord {
        version: crate::store::GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: "allow".to_owned(),
        reason_codes: vec!["gate.allow".to_owned()],
        receipt_reasons: vec![format!("gate.allow.owner_archive_restore.{digest}")],
        system_notices: Vec::new(),
        actor_class: actor.actor_class().gate_actor_class().to_owned(),
        actor_ref: Some(actor.entity_ref().to_hex()),
        content_kind: "owner_archive_restore".to_owned(),
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: None,
        grant_ref: Some(format!("archive_restore:{digest}")),
        diff_handle: manifest_digest.to_vec(),
        read_frontier_hash: resolve_policy_manifest(&vault.store, txn)?.read_frontier_hash()?,
        context: Default::default(),
        redacted_at: None,
    };
    vault
        .store
        .append_fresh_gate_decision_in_txn(txn, &mut receipt)?;
    Ok(receipt.decision_id)
}

/// Digest of the parsed full document manifest, which lists every member's digest;
/// not the storage-only digest used for import authority classification.
pub(super) fn full_manifest_digest(manifest: &WholeVaultDocumentManifest) -> Result<[u8; 32]> {
    let encoded = serde_json::to_vec(manifest).map_err(|error| {
        Error::InvalidConfig(format!(
            "owner archive restore manifest serialization: {error}"
        ))
    })?;
    Ok(*blake3::hash(&encoded).as_bytes())
}
