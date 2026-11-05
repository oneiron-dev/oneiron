//! Whether this device attested an erase receipt (FIX 2596, OF-470).
//!
//! An erase receipt replicates, and a replicated one names the same scope as
//! the job this device scrubs for its erase. This device attests only the
//! receipts it made: it appends their completion and final rows, and the
//! sweep's audit counts one of them dropped. The scrub itself is never
//! restricted. A receipt is this device's when its `att_client` and `att_pk`
//! are this install's cached client id and device key, or a predecessor's
//! the owner named this install's machine to succeed (FIX 11135), and its
//! signature verifies under that attested key over the transcript its signer
//! signed (OD-6).

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;

use super::receipt::{
    ATT_EMPTY_MAP_BYTE, ATT_KEY_CLIENT, ATT_KEY_PK, ATT_KEY_SIG, RECEIPT_ATT_DOMAIN,
    RedactionAuditReceipt, decode_redaction_audit_receipt, is_corrupt_claim_repair_event,
    receipt_attestation_splice, receipt_envelope_header,
};
use super::receipt_completion::redaction_sweep_completion_in_txn;
use super::receipt_grammar::is_lower_hex;
use super::sweep_queue::{
    HARD_ERASE_SWEEP_PREFIX, HardEraseSweepExtras, decode_hard_erase_sweep_job,
    decode_hard_erase_sweep_seq,
};

/// Whether this device attested the erase receipt `receipt`, stored at
/// `receipt_id`. An install with no cached identity attested none. A receipt
/// whose attestation names another client or key, or does not verify, is
/// another device's, unless the owner named this install's machine the
/// successor of that client and key (FIX 11135): it is then this device's,
/// verified under the key it names.
///
/// # Errors
///
/// Storage errors reading the cached identity or the stored row, and a
/// cached row of the wrong length.
pub(crate) fn receipt_attested_by_this_device_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt_id: &EntityId,
    receipt: &RedactionAuditReceipt,
) -> Result<bool> {
    let (Some(client_id), Some(device_pk)) = (
        crate::store::install_identity::read_client_id_in_txn(vault, txn)?,
        crate::store::install_identity::read_device_verifying_key_in_txn(vault, txn)?,
    ) else {
        return Ok(false);
    };
    let Some((client, key)) = verified_attesting_pair_in_txn(vault, txn, receipt_id, receipt)?
    else {
        return Ok(false);
    };
    attesting_pair_is_this_device_in_txn(vault, txn, (client_id, device_pk), (client, &key))
}

/// The pair (client id, device key) that attested the erase receipt
/// `receipt`, stored at `receipt_id`, when its signature verifies under that
/// key; `None` when it names no well-formed pair or does not verify.
///
/// The signature is verified over the STORED bytes — the stored header and
/// the stored body spliced at the `verification` value, exactly as the sync
/// lease path verifies a receipt (OD-6) — never over a re-encode, so a
/// stored body in another valid encoding still verifies. Only when no row is
/// stored, or the stored header is a later rewrite the signer never signed,
/// does the signer's re-encoded transcript below stand in.
fn verified_attesting_pair_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt_id: &EntityId,
    receipt: &RedactionAuditReceipt,
) -> Result<Option<(u64, [u8; 32])>> {
    // Every caller passes an initial receipt decoded from the row at
    // `receipt_id`, which the mint stored (or sync replayed byte-exactly)
    // under the point envelope stamped `hard_purge_complete_at`: the
    // signer's own transcript, header and body both.
    if let Some(raw) = vault.get_raw_in(txn, receipt_id)? {
        let signed = receipt_envelope_header(receipt.hard_purge_complete_at);
        if raw.len() >= ENTITY_METADATA_HEADER_LEN && raw[..ENTITY_METADATA_HEADER_LEN] == signed {
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let Some(parts) = receipt_attestation_splice(body) else {
                return Ok(None);
            };
            let Ok(key) = VerifyingKey::from_bytes(&parts.pubkey) else {
                return Ok(None);
            };
            let mut message = Vec::with_capacity(
                RECEIPT_ATT_DOMAIN.len()
                    + 16
                    + ENTITY_METADATA_HEADER_LEN
                    + parts.verification_value_offset
                    + 1,
            );
            message.extend_from_slice(RECEIPT_ATT_DOMAIN);
            message.extend_from_slice(receipt_id.as_bytes());
            message.extend_from_slice(&raw[..ENTITY_METADATA_HEADER_LEN]);
            message.extend_from_slice(&body[..parts.verification_value_offset]);
            message.push(ATT_EMPTY_MAP_BYTE);
            let signature = Signature::from_bytes(&parts.signature);
            return Ok(key
                .verify_strict(&message, &signature)
                .is_ok()
                .then_some((parts.client_id, parts.pubkey)));
        }
    }
    let attested = |key: &str| receipt.verification.get(key).map(String::as_str);
    let (Some(attested_client), Some(attested_pk)) = (
        attested(ATT_KEY_CLIENT).and_then(client_from_hex),
        attested(ATT_KEY_PK).and_then(key_from_hex),
    ) else {
        return Ok(None);
    };
    let (Some(signature), Ok(key)) = (
        attested(ATT_KEY_SIG).and_then(signature_from_hex),
        VerifyingKey::from_bytes(&attested_pk),
    ) else {
        return Ok(None);
    };
    // No stored row, or a stored header the signer never signed: fall back
    // to the signer's transcript, the body with `verification` empty, under
    // the point envelope an initial receipt is stored with.
    let unsigned = RedactionAuditReceipt {
        verification: BTreeMap::new(),
        ..receipt.clone()
    };
    let body = rmp_serde::to_vec_named(&unsigned)
        .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))?;
    let header = receipt_envelope_header(receipt.hard_purge_complete_at);
    let mut message = Vec::with_capacity(RECEIPT_ATT_DOMAIN.len() + 16 + header.len() + body.len());
    message.extend_from_slice(RECEIPT_ATT_DOMAIN);
    message.extend_from_slice(receipt_id.as_bytes());
    message.extend_from_slice(&header);
    message.extend_from_slice(&body);
    Ok(key
        .verify_strict(&message, &signature)
        .is_ok()
        .then_some((attested_client, attested_pk)))
}

/// Owes again what each erase receipt the predecessor `predecessor` (client
/// id, device key) attested still waits on, once the owner named this
/// install its successor (FIX 11135): an initial receipt whose sweep was
/// queued, with no linked completion, that no pending `h:` row of its exact
/// scope (the one a finalize completes it from) and no owed `hc:` compaction
/// covers. A pass run before the naming skipped such a receipt as another
/// device's and retired what it waited on. Each gets back the obligation its
/// erase made: an erased audience edit, which stays live, the compaction of
/// the window carrying it (FIX 10234), so the next pass completes it without
/// a hard erase; any other receipt a fresh job over its own scope, its
/// deadline still counted from the erase's request. Returns how many it owed
/// again.
///
/// # Errors
///
/// Storage errors, and a stored receipt row shorter than its header.
pub(crate) fn requeue_successor_sweeps_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    predecessor: (u64, [u8; 32]),
    now: u64,
) -> Result<usize> {
    let owed = {
        let txn: &heed::RoTxn<'_> = wtxn;
        let mut job_scopes: Vec<BTreeSet<String>> = Vec::new();
        for row in vault
            .store
            .sync_queue
            .prefix_iter(txn, HARD_ERASE_SWEEP_PREFIX)?
        {
            let (key, value) = row?;
            if decode_hard_erase_sweep_seq(&key).is_none() {
                continue;
            }
            // An undecodable row covers nothing, as the sweep's audit reads it.
            if let Ok(job) = decode_hard_erase_sweep_job(&value) {
                job_scopes.push(job.scope.entity_ids.into_iter().collect());
            }
        }
        #[cfg(feature = "sync")]
        let compacting = crate::sweep::owed::receipts_owed_compaction_in_txn(vault, txn)?;
        let mut owed = Vec::new();
        for id in vault
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_REDACTION_AUDIT, None)?
        {
            let id = id?;
            let Some(raw) = vault.store.port_entity_raw(txn, &id)? else {
                continue;
            };
            let body = raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("entity metadata"))?;
            if is_corrupt_claim_repair_event(body) {
                continue;
            }
            // An unreadable receipt is the sweep audit's to report.
            let Ok(receipt) = decode_redaction_audit_receipt(body) else {
                continue;
            };
            if receipt.sweep_queued_at.is_none() || !receipt.is_initial() {
                continue;
            }
            match redaction_sweep_completion_in_txn(&vault.store, txn, &id, &receipt) {
                Ok(Some(_)) => continue,
                Ok(None) | Err(Error::CorruptedIndex("redaction audit receipt body")) => {}
                Err(err) => return Err(err),
            }
            // A finalize completes a receipt only from a job of its exact
            // scope, so a wider one covers nothing here.
            let needed: BTreeSet<String> = receipt.scope.entity_ids.iter().cloned().collect();
            if job_scopes.contains(&needed) {
                continue;
            }
            #[cfg(feature = "sync")]
            if compacting.contains(&id) {
                continue;
            }
            if verified_attesting_pair_in_txn(vault, txn, &id, &receipt)? != Some(predecessor) {
                continue;
            }
            owed.extend(owed_again_in_txn(vault, txn, id, receipt)?);
        }
        owed
    };
    for obligation in &owed {
        match obligation {
            Owed::Sweep(receipt) => {
                let extras = HardEraseSweepExtras {
                    capture_failures: receipt.capture_failures.clone(),
                    ..HardEraseSweepExtras::default()
                };
                vault.enqueue_hard_erase_sweep_in_txn(
                    wtxn,
                    receipt.scope.clone(),
                    extras,
                    now,
                    receipt.requested_at,
                )?;
            }
            #[cfg(feature = "sync")]
            Owed::Compaction(id, window) => {
                super::owed_window_compaction::owe_window_compaction_for_receipt_in_txn(
                    vault, wtxn, window, id,
                )?;
            }
        }
    }
    Ok(owed.len())
}

/// What one inherited receipt waits on again.
enum Owed {
    /// A hard-erase sweep over the receipt's own scope.
    Sweep(RedactionAuditReceipt),
    /// The compaction of the window carrying the erased audience edit the
    /// receipt at `.0` names (FIX 10234).
    #[cfg(feature = "sync")]
    Compaction(EntityId, crate::sync::types::WindowKey),
}

/// What the receipt `receipt`, stored at `id`, waits on again: the
/// obligation its erase made. An erased audience edit stays a live TURN, so
/// its erase owed the compaction of the window carrying it, never a hard
/// erase; a build without sync windows owed it nothing (`None`). Any other
/// receipt owes the sweep over its own scope.
fn owed_again_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    receipt: RedactionAuditReceipt,
) -> Result<Option<Owed>> {
    let edit = match receipt.scope.entity_ids.as_slice() {
        [edit] => EntityId::from_hex(edit)?,
        _ => return Ok(Some(Owed::Sweep(receipt))),
    };
    let row = crate::vault::live_entity_row_in_txn(&vault.store, txn, &edit)?;
    if !crate::workspace_roster::is_audience_edit_row(&row) {
        return Ok(Some(Owed::Sweep(receipt)));
    }
    #[cfg(feature = "sync")]
    {
        let raw = vault.get_raw_in(txn, &edit)?.ok_or(Error::EntityNotFound)?;
        let window = crate::sync::residence::residence_window_for_blob(&raw)?;
        Ok(Some(Owed::Compaction(id, window)))
    }
    #[cfg(not(feature = "sync"))]
    {
        let _ = id;
        Ok(None)
    }
}

/// Whether the attesting pair `attested` (client id, device key) is this
/// device's: its own cached pair `own`, or a predecessor whose succession in
/// force, as this install counts the owner's acts, names this install's
/// machine (FIX 11135). An install with no machine id succeeds no one.
fn attesting_pair_is_this_device_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    own: (u64, [u8; 32]),
    attested: (u64, &[u8; 32]),
) -> Result<bool> {
    let (client, key) = attested;
    if (client, *key) == own {
        return Ok(true);
    }
    let Some(machine) = crate::identity::read_machine_id_in_txn(vault, txn)? else {
        return Ok(false);
    };
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    Ok(fold.device_successor(client, key)? == Some(machine))
}

/// The client id a receipt's `att_client` spells: 16 lowercase hex digits,
/// as the mint writes it; `None` for any other text.
fn client_from_hex(hex: &str) -> Option<u64> {
    if hex.len() != 16 || !is_lower_hex(hex) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// The device key a receipt's `att_pk` spells: 64 lowercase hex digits;
/// `None` for any other text.
fn key_from_hex(hex: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    if hex.len() != bytes.len() * 2 || !is_lower_hex(hex) {
        return None;
    }
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(bytes)
}

/// The signature a lowercase-hex `att_sig` spells; `None` for any other text.
fn signature_from_hex(hex: &str) -> Option<Signature> {
    let mut bytes = [0u8; 64];
    if hex.len() != bytes.len() * 2 || !is_lower_hex(hex) {
        return None;
    }
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(Signature::from_bytes(&bytes))
}
