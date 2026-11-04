//! Actor erasure for the made_by receipt a blob artifact version carries.
//! Both the version and head copies change with their bound `blob.version`
//! claim in the purge's one transaction; public views also project an actor
//! erased on this vault after raw record/claim binding has succeeded (FIX 9619).

use heed::{RoTxn, RwTxn};

use super::made_by::made_by_text;
use super::provenance::blob_version_claim_value;
use super::versions::{BlobArtifactVersion, HEAD, VERSIONS};
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

const ERASED_PRODUCER_DOMAIN: &[u8] = b"oneiron:erased-producer:v1";

/// The valid, deterministic id an erased producer keeps in the typed envelope.
/// An ordinary hex actor is not reused: views can never mistake it for a live one.
pub(super) fn erased_producer() -> Result<EntityId> {
    Ok(EntityId::derive(ERASED_PRODUCER_DOMAIN, &[])?)
}

/// Projects one already-bound stored record to this vault's current erase state.
/// Raw record reads stay byte-exact so their persisted claim comparison still holds.
pub(crate) fn project_version_erased_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    record: &BlobArtifactVersion,
) -> Result<BlobArtifactVersion> {
    let mut projected = record.clone();
    let actor = projected.made_by.process.actor;
    if actor != erased_producer()? && vault.carrier_actor_erased_in_txn(txn, &actor)? {
        projected.made_by.process.actor = erased_producer()?;
    }
    Ok(projected)
}

/// Whether a version claim stands under a customer hold alone. The check is
/// fail-safe: a storage error reads as held, so the pair is preserved, never
/// half-scrubbed.
fn version_claim_held_in_txn(vault: &Vault, wtxn: &RwTxn<'_>, claim: &EntityId) -> Result<bool> {
    Ok(!crate::store::legal_hold::holds_on_in_txn(
        &vault.store,
        wtxn,
        &crate::deletion::LegalHoldTarget::Record(*claim),
    )?
    .is_empty())
}

/// Erases `actor` from every retained version and head made_by receipt and
/// from the claim each receipt is bound to. Other attribution, content,
/// versions, triggers and timestamps stay unchanged (FIX 9619).
pub(crate) fn erase_blob_artifact_version_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let erased = erased_producer()?;
    let mut versions = Vec::new();
    for (key, mut record) in VERSIONS.scan(&vault.store, wtxn)? {
        if record.made_by.process.actor == *actor {
            record.made_by.process.actor = erased;
            versions.push((key, record));
        }
    }
    let mut heads = Vec::new();
    for (artifact, mut record) in HEAD.scan(&vault.store, wtxn)? {
        if record.made_by.process.actor == *actor {
            record.made_by.process.actor = erased;
            heads.push((artifact, record));
        }
    }
    // A customer hold on a version claim alone preserves its claim, record
    // and revision history: the pair's scrub defers while the hold stands
    // (holds mandate preservation), and only hold-free pairs are rewritten
    // below. The deferred pair settles when the hold lifts (follow-up).
    versions.retain(|(_, record)| {
        !version_claim_held_in_txn(vault, wtxn, &record.claim_id).unwrap_or(true)
    });
    heads.retain(|(_, record)| {
        !version_claim_held_in_txn(vault, wtxn, &record.claim_id).unwrap_or(true)
    });
    for (key, record) in versions {
        rewrite_version_claim_in_txn(vault, wtxn, &record)?;
        VERSIONS.put(&vault.store, wtxn, &key, &record)?;
    }
    for (artifact, record) in heads {
        HEAD.put(&vault.store, wtxn, &artifact, &record)?;
    }
    Ok(())
}

/// Rewrites the one claim bound to `record`, retaining its id and header times
/// and restarting its local revision history from the erased body.
fn rewrite_version_claim_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    record: &BlobArtifactVersion,
) -> Result<()> {
    // A MACHINE-signed version claim carries an authenticated history pin
    // that rejects an ordinary reserved rewrite (InvalidMachineClaimProof),
    // and its resident signature keeps every later read on the retired
    // history (MachineClaimHistoryIncomplete). The claim is read while its
    // projection still resolves, the pin and its controls are retired
    // through the authorized erasure path, and the redacted body replaces
    // the signed provenance: without the machine signature and proof actor
    // it stands under vault erasure authority, so the ordinary reserved put
    // admits it. The retired controls embed the born content, so they leave
    // the indexes with it.
    let raw = vault
        .get_raw_in(wtxn, &record.claim_id)?
        .ok_or(Error::CorruptedIndex("blob artifact version claim header"))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("blob artifact version claim header"))?;
    let mut claim = vault
        .get_claim_in_txn(wtxn, &record.claim_id)?
        .ok_or(Error::CorruptedIndex("blob artifact version claim"))?;
    let controls = crate::claim::history_store::retire_machine_history_for_delete(
        &vault.store,
        wtxn,
        record.claim_id,
    )?;
    claim.value = blob_version_claim_value(
        record.version,
        &record.content_hash,
        &record.provenance,
        record.parent_version,
        record.fork_of_version,
        record.calc_engine.as_ref(),
        &made_by_text(&record.made_by)?,
    );
    if let Some(rmpv::Value::Map(entries)) = claim.evidence.as_mut() {
        entries.retain(|(key, _)| {
            key.as_str() != Some("machine_signature")
                && key.as_str()
                    != Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)
        });
    }
    vault.put_reserved_claim_in_txn(
        wtxn,
        &record.claim_id,
        &claim,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    )?;
    for control in &controls {
        let _ = crate::batch::deindex_entity(&vault.store, wtxn, control)?;
    }
    crate::vault::entity_revision::remove_entity_revisions(&vault.store, wtxn, &record.claim_id)?;
    let raw = vault
        .get_raw_in(wtxn, &record.claim_id)?
        .ok_or(Error::CorruptedIndex("blob artifact version claim"))?;
    crate::vault::entity_revision::capture_entity_revision(
        &vault.store,
        wtxn,
        &record.claim_id,
        &raw,
    )
}
