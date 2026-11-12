//! The owner act and call-scoped source permit for a whole-vault archive restore,
//! and the claims that restore brings back through the generic claim door.

use rmpv::Value;

use super::super::WholeVaultDocumentManifest;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{POLICY_SCHEMA_VERSION, resolve_policy_manifest};
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::write_envelope::claim_body::ClaimBody;
use crate::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WriteActor,
};
use oneiron_contracts::claim::ClaimSource;

/// Gate `content_kind` of the owner's archive-restore receipt.
const OWNER_ARCHIVE_RESTORE_CONTENT_KIND: &str = "owner_archive_restore";

/// Top-level claim evidence key naming the owner restore that brought a stamped claim
/// back: the restore receipt's `gate:<id>` ref. Only the owner door writes it.
const OWNER_RESTORE_RECEIPT_KEY: &str = "owner_restore_receipt";

/// Top-level claim evidence key holding a MACHINE-signed claim's archived author, inert:
/// `machine` (hex text), `actor_class`, `machine_proof` and `source_vault`. No verifier
/// reads a nested key, and hex text is no id slot.
const ARCHIVED_AUTHOR_KEY: &str = "archived_author";

/// The evidence key of a write's authority frontier, which binds its source vault.
const AUTHORITY_FRONTIER_KEY: &str = "authority_frontier";

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
        content_kind: OWNER_ARCHIVE_RESTORE_CONTENT_KIND.to_owned(),
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

/// The owner's restore act, as each row it restores reads it.
#[derive(Debug, Clone, Copy)]
pub(super) struct OwnerRestore<'a> {
    /// The bound owner, the restore's actor.
    pub(super) actor: WriteActor,
    /// The restore receipt's `gate:<id>` ref.
    pub(super) receipt_ref: &'a str,
    /// Whether the destination was proved fresh before any import write: only such a
    /// restore sets the default facet.
    pub(super) fresh: bool,
    /// The source vault id the archive's manifest names.
    pub(super) source_vault: Option<&'a str>,
}

/// The claim the owner's restore writes through the generic claim door (RULING 00:08
/// 13 Nov, NOTE ARCHIVE-MACHINE-RESTORE-DESIGN D2, D3, D5). Only a claim of an
/// unreserved predicate whose evidence is a map changes; the import has already made it
/// Imported and Proposed (Rejected stays Rejected).
///
/// - Evidence carrying a MACHINE signature is rewritten as the owner's restore: its
///   top-level actor becomes the restoring owner (class Human), and the MACHINE actor,
///   its class, its signature and its authority frontier, which bind the source vault,
///   leave the top level. They ride inert in [`ARCHIVED_AUTHOR_KEY`] with the source
///   vault id, so the claim never reads as a signed write and no proof of it is ever
///   verified here. Provenance, lineage, candidate and carried evidence stay.
/// - Evidence that names a write-envelope actor (every stamped body, a rewritten one
///   included) gains [`OWNER_RESTORE_RECEIPT_KEY`], this restore's receipt; an earlier
///   restore's is replaced. Settle reads it to leave the restoring owner out of the
///   proposal's openers ([`owner_restore_opened_claim_in_txn`]).
pub(super) fn owner_restored_claim(claim: &mut ClaimBody, restore: OwnerRestore<'_>) {
    if crate::write_envelope::claim_predicate::is_reserved_predicate(&claim.predicate) {
        return;
    }
    let Some(Value::Map(entries)) = claim.evidence.as_mut() else {
        return;
    };
    if let Some(proof) = named(entries, crate::authority::MACHINE_SIGNATURE_KEY) {
        let machine = match named(entries, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) {
            Some(Value::Binary(bytes)) => Value::from(crate::entity_id::bytes_to_hex_lower(&bytes)),
            Some(other) => other,
            None => Value::Nil,
        };
        let archived_author = Value::Map(vec![
            (Value::from("machine"), machine),
            (
                Value::from("actor_class"),
                named(entries, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY).unwrap_or(Value::Nil),
            ),
            (Value::from("machine_proof"), proof),
            (
                Value::from("source_vault"),
                restore.source_vault.map_or(Value::Nil, Value::from),
            ),
        ]);
        entries.retain(|(name, _)| {
            !matches!(
                name.as_str(),
                Some(
                    WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY
                        | WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY
                        | crate::authority::MACHINE_SIGNATURE_KEY
                        | AUTHORITY_FRONTIER_KEY
                        | ARCHIVED_AUTHOR_KEY
                )
            )
        });
        entries.insert(
            0,
            (
                Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY),
                Value::from(EdgeActorClass::Human as u8),
            ),
        );
        entries.insert(
            0,
            (
                Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
                Value::Binary(restore.actor.entity_ref().as_bytes().to_vec()),
            ),
        );
        entries.push((Value::from(ARCHIVED_AUTHOR_KEY), archived_author));
    }
    if named(entries, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY).is_none() {
        return;
    }
    entries.retain(|(name, _)| name.as_str() != Some(OWNER_RESTORE_RECEIPT_KEY));
    entries.push((
        Value::from(OWNER_RESTORE_RECEIPT_KEY),
        Value::from(restore.receipt_ref),
    ));
}

/// The first value `entries` holds under `key`.
fn named(entries: &[(Value, Value)], key: &str) -> Option<Value> {
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value.clone())
}

/// `body` with its evidence's [`OWNER_RESTORE_RECEIPT_KEY`] left out, so a claim an
/// earlier owner restore brought back compares with this restore's body apart from the
/// receipt each stamps. A body that names none, or is not a claim, comes back as it is.
pub(super) fn without_owner_restore_receipt(body: &[u8]) -> Result<Vec<u8>> {
    let Ok(mut claim) = crate::write_envelope::claim_body::decode_claim_body(body, true) else {
        return Ok(body.to_vec());
    };
    let Some(Value::Map(entries)) = claim.evidence.as_mut() else {
        return Ok(body.to_vec());
    };
    let before = entries.len();
    entries.retain(|(name, _)| name.as_str() != Some(OWNER_RESTORE_RECEIPT_KEY));
    if entries.len() == before {
        return Ok(body.to_vec());
    }
    crate::write_envelope::claim_body::encode_claim_body(&claim)
}

/// Whether the owner's whole-vault restore opened the proposal `body`, whose envelope
/// names `actor` (D5): the claim is Imported, and its evidence's
/// [`OWNER_RESTORE_RECEIPT_KEY`] names a stored, allowed owner archive-restore receipt
/// whose actor is `actor`. Settle then leaves `actor` out of the proposal's openers: the
/// restore act opened it, not the owner. No agent can forge this: the receipt is a gate
/// row only the owner door mints, for the bound owner, and an agent's write stamps the
/// agent as its actor. The owner gains nothing new, since the owner may write the claim
/// Approved directly. A receipt pruned from the ledger, or whose actor was erased, ends
/// the exemption.
pub(crate) fn owner_restore_opened_claim_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
    actor: EntityId,
) -> Result<bool> {
    if body.source != Some(ClaimSource::Imported) {
        return Ok(false);
    }
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return Ok(false);
    };
    let mut receipts = entries
        .iter()
        .filter(|(name, _)| name.as_str() == Some(OWNER_RESTORE_RECEIPT_KEY));
    let (Some((_, receipt)), None) = (receipts.next(), receipts.next()) else {
        return Ok(false);
    };
    let Some(decision) = receipt
        .as_str()
        .and_then(|text| text.strip_prefix("gate:"))
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .map(|id| GateDecisionId::from_bytes(*id.as_bytes()))
    else {
        return Ok(false);
    };
    Ok(store
        .gate_decision_in_txn(txn, decision)?
        .is_some_and(|record| {
            record.content_kind == OWNER_ARCHIVE_RESTORE_CONTENT_KIND
                && record.outcome == "allow"
                && record.actor_ref.as_deref() == Some(actor.to_hex().as_str())
        }))
}
