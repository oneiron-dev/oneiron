//! Whether this device attested an erase receipt (FIX 2596, OF-470).
//!
//! An erase receipt replicates, and a replicated one names the same scope as
//! the job this device scrubs for its erase. This device attests only the
//! receipts it made: it appends their completion and final rows, and the
//! sweep's audit counts one of them dropped. The scrub itself is never
//! restricted. A receipt is this device's when its `att_client` and `att_pk`
//! are this install's cached client id and device key, and its signature
//! verifies under that key over the transcript its signer signed (OD-6).

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::receipt::{
    ATT_EMPTY_MAP_BYTE, ATT_KEY_CLIENT, ATT_KEY_PK, ATT_KEY_SIG, RECEIPT_ATT_DOMAIN,
    RedactionAuditReceipt, hex_lower, receipt_attestation_splice, receipt_envelope_header,
};
use super::receipt_grammar::is_lower_hex;

/// Whether this device attested the erase receipt `receipt`, stored at
/// `receipt_id`. An install with no cached identity attested none. A receipt
/// whose attestation names another client or key, or does not verify, is
/// another device's.
///
/// The signature is verified over the STORED bytes — the stored header and
/// the stored body spliced at the `verification` value, exactly as the sync
/// lease path verifies a receipt (OD-6) — never over a re-encode, so a
/// stored body in another valid encoding still reads as this device's. Only
/// when no row is stored, or the stored header is a later rewrite the
/// signer never signed, does the signer's re-encoded transcript below stand
/// in.
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
        crate::identity::read_client_id_in_txn(vault, txn)?,
        crate::identity::read_device_verifying_key_in_txn(vault, txn)?,
    ) else {
        return Ok(false);
    };
    // Every caller passes an initial receipt decoded from the row at
    // `receipt_id`, which the mint stored (or sync replayed byte-exactly)
    // under the point envelope stamped `hard_purge_complete_at`: the
    // signer's own transcript, header and body both.
    if let Some(raw) = vault.get_raw_in(txn, receipt_id)? {
        let signed = receipt_envelope_header(receipt.hard_purge_complete_at);
        if raw.len() >= ENTITY_METADATA_HEADER_LEN && raw[..ENTITY_METADATA_HEADER_LEN] == signed {
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let Some(parts) = receipt_attestation_splice(body) else {
                return Ok(false);
            };
            if parts.client_id != client_id || parts.pubkey != device_pk {
                return Ok(false);
            }
            let Ok(key) = VerifyingKey::from_bytes(&device_pk) else {
                return Ok(false);
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
            return Ok(key.verify_strict(&message, &signature).is_ok());
        }
    }
    let attested = |key: &str| receipt.verification.get(key).map(String::as_str);
    if attested(ATT_KEY_CLIENT) != Some(format!("{client_id:016x}").as_str())
        || attested(ATT_KEY_PK) != Some(hex_lower(&device_pk).as_str())
    {
        return Ok(false);
    }
    let (Some(signature), Ok(key)) = (
        attested(ATT_KEY_SIG).and_then(signature_from_hex),
        VerifyingKey::from_bytes(&device_pk),
    ) else {
        return Ok(false);
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
    Ok(key.verify_strict(&message, &signature).is_ok())
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
