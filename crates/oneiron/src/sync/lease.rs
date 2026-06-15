//! Device-lease registry for the REDACTION_AUDIT stream (ONE-1140).
//!
//! ARCH-0023b pins the audit/guardrail stream class as "fail-closed ·
//! single-writer-leased". M4's per-node receipts (N replicas erasing one
//! request = N receipts) make a single STREAM writer impossible, so the
//! lease is per-DEVICE and "single-writer" is satisfied per-RECORD: each
//! receipt has exactly one writer, cryptographically bound (OD-6) and
//! immutable thereafter (M4-07).
//!
//! Registry residence (OD-3): the server is the issuer; the root doc gains
//! a `leases` LoroMap (server-write-only by the existing client-root-update
//! rejection) mirrored into local `ls:` LMDB rows on every root import.
//!
//! Record encoding (OD-4) — ONE encoding on both surfaces (root-doc map
//! value ≡ `ls:` row value, byte-identical, 58 B):
//!
//! ```text
//! [ver:1 = 0x01][status:1  0x01 active | 0x02 expired | 0x03 revoked]
//! [pubkey:32][granted_at:8 LE][renewed_at:8 LE][expires_at:8 LE]
//! ```
//!
//! Key (both surfaces): `client_id_hex` = `{client_id:016x}` — 16 lowercase
//! hex chars, BE nibble order ⇒ lexically sortable (convention: BE for
//! sortable key material). LMDB key = `ls:` + client_id_hex (19 B). Value
//! timestamps LE (opaque-value convention, `dt:` precedent). The docs'
//! baseline `ls:` = bare "u64 LE last-seen" is superseded: the door needs
//! pubkey + status, and `renewed_at` carries the last-seen semantic
//! (ARCH-0023b amendment queued per OD-4).
//!
//! Door enforcement (OD-7): status only — `revoked` rejects, `active` and
//! `expired` accept. Devices have no trustworthy shared clock and
//! signed-time backdating defeats any time bound (residual R2), so expiry
//! is server-side liveness bookkeeping, never a door predicate.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use loro::LoroDoc;

use crate::Vault;
use crate::deletion::{ATT_EMPTY_MAP_BYTE, RECEIPT_ATT_DOMAIN, receipt_attestation_parts};
use crate::error::{Error, Result};
use crate::sync::quarantine::{self, QuarantineContainer};
use crate::types::EntityId;

/// LMDB `sync_state` key prefix for lease-registry mirror rows.
pub const LEASE_KEY_PREFIX: &str = "ls:";
/// Pinned lease-record length (OD-4).
pub const LEASE_RECORD_LEN: usize = 58;
/// Lease-record version byte (OD-4).
pub const LEASE_RECORD_VERSION: u8 = 0x01;
/// 90-day lease: `expires_at = renewed_at + LEASE_DURATION_SECS` (OD-4).
pub const LEASE_DURATION_SECS: u64 = 7_776_000;
/// Proof-of-possession transcript domain separator (OD-6 literal):
/// `msg = LEASE_POP_DOMAIN || client_id:8 BE || pubkey:32`.
pub const LEASE_POP_DOMAIN: &[u8] = b"oneiron/lease-pop/v1";
/// Root-doc container holding the lease registry (OD-3).
pub const ROOT_LEASES_MAP: &str = "leases";
/// `QuarantineRecord.window_key` literal for root-doc lease quarantines
/// (the registry rides the ROOT doc, which has no YYYY-MM window).
pub const LEASE_QUARANTINE_WINDOW: &str = "root";

/// Lease binding status (OD-4 wire bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeaseStatus {
    Active = 0x01,
    /// Liveness bookkeeping only — receipts from expired bindings still
    /// verify at the doors (OD-7).
    Expired = 0x02,
    /// Terminal for the binding (OD-8). The only door-rejecting status.
    Revoked = 0x03,
}

impl LeaseStatus {
    #[must_use]
    pub fn from_wire_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Active),
            0x02 => Some(Self::Expired),
            0x03 => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// A decoded lease-registry record (OD-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseRecord {
    pub status: LeaseStatus,
    pub pubkey: [u8; 32],
    pub granted_at: u64,
    pub renewed_at: u64,
    pub expires_at: u64,
}

/// `{client_id:016x}` — the registry key on both surfaces.
#[must_use]
pub fn client_id_hex(client_id: u64) -> String {
    format!("{client_id:016x}")
}

/// `ls:{client_id_hex}` — the LMDB mirror-row key (19 B).
#[must_use]
pub fn lease_key(client_id: u64) -> String {
    format!("{LEASE_KEY_PREFIX}{}", client_id_hex(client_id))
}

/// Encodes the pinned 58 B lease record (OD-4).
#[must_use]
pub fn encode_lease_record(record: &LeaseRecord) -> [u8; LEASE_RECORD_LEN] {
    let mut out = [0u8; LEASE_RECORD_LEN];
    out[0] = LEASE_RECORD_VERSION;
    out[1] = record.status as u8;
    out[2..34].copy_from_slice(&record.pubkey);
    out[34..42].copy_from_slice(&record.granted_at.to_le_bytes());
    out[42..50].copy_from_slice(&record.renewed_at.to_le_bytes());
    out[50..58].copy_from_slice(&record.expires_at.to_le_bytes());
    out
}

/// Decodes a pinned 58 B lease record. Fail-closed: exact length, known
/// version byte, known status byte — anything else is a typed error, never
/// a best-effort partial decode.
pub fn decode_lease_record(raw: &[u8]) -> Result<LeaseRecord> {
    if raw.len() != LEASE_RECORD_LEN {
        return Err(Error::CorruptedIndex("lease record length"));
    }
    if raw[0] != LEASE_RECORD_VERSION {
        return Err(Error::CorruptedIndex("lease record version"));
    }
    let status =
        LeaseStatus::from_wire_byte(raw[1]).ok_or(Error::CorruptedIndex("lease record status"))?;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&raw[2..34]);
    Ok(LeaseRecord {
        status,
        pubkey,
        granted_at: u64::from_le_bytes(raw[34..42].try_into().expect("length checked")),
        renewed_at: u64::from_le_bytes(raw[42..50].try_into().expect("length checked")),
        expires_at: u64::from_le_bytes(raw[50..58].try_into().expect("length checked")),
    })
}

/// Assembles the lease proof-of-possession transcript (OD-6):
/// `LEASE_POP_DOMAIN || client_id:8 BE || pubkey:32`. The transcript binds
/// BOTH the claimed client id and the key, so binding someone else's pubkey
/// requires their signature over YOUR client id — no challenge round.
#[must_use]
pub fn lease_pop_transcript(client_id: u64, pubkey: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(LEASE_POP_DOMAIN.len() + 8 + 32);
    msg.extend_from_slice(LEASE_POP_DOMAIN);
    msg.extend_from_slice(&client_id.to_be_bytes());
    msg.extend_from_slice(pubkey);
    msg
}

/// Verifies a TAG_LEASE_REQUEST proof-of-possession signature.
#[must_use]
pub fn verify_lease_pop(client_id: u64, pubkey: &[u8; 32], pop_sig: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let msg = lease_pop_transcript(client_id, pubkey);
    key.verify(&msg, &Signature::from_bytes(pop_sig)).is_ok()
}

/// The ONE-1140 origin predicate for a NEW receipt at a replay door
/// (door steps 3–5; steps 1–2 — structural validation and the
/// immutability/divergence gate — run in the caller, in that order):
///
/// 3. Ed25519-verify the attestation transcript against the embedded
///    `att_pk` → fail = [`Error::ReceiptAttestationInvalid`].
/// 4. `ls:{att_client}` point-read in the CALLER's txn: row absent →
///    [`Error::ReceiptLeaseUnknown`]; registry pubkey ≠ `att_pk` →
///    [`Error::ReceiptAttestationInvalid`]; the CLAIMED row's status revoked
///    → [`Error::ReceiptLeaseRevoked`] (checked FIRST, preserving its
///    precedence); active | expired → fall through to step 5 (OD-7).
/// 5. Pubkey-bound revocation FLOOR (OD-8 amended, RULING C). The kill
///    switch binds to the Ed25519 PUBKEY, not the mintable `att_client`:
///    scan EVERY `ls:` row and reject with [`Error::ReceiptLeaseRevoked`] if
///    this signing pubkey appears in ANY revoked binding — so a revoked
///    pubkey is terminal across ALL client_ids, and a device that rotates
///    client_id while reusing its key cannot recover (intended; recovery
///    requires a fresh KEYPAIR, never key reuse). Runs on BOTH accept arms
///    (active AND expired) and even on the `att_client`==claimed path,
///    catching a same-key rebind under a fresh id. The `(vault, pubkey)`
///    multi-user dimension is out of scope here (deferred to ONE-1161).
///
/// The four remote rejections (attestation-invalid, lease-unknown,
/// lease-revoked — claimed-row OR pubkey floor) classify as REMOTE via
/// `remote_rejection_reason` (quarantine-and-continue at the callers). A
/// malformed `ls:` row — the claimed point-read OR any sibling reached by
/// the floor scan — is LOCAL corruption (our own mirror wrote it) and
/// propagates fail-closed, failing the door GLOBALLY (wider blast radius
/// than the single receipt, but correct: never a best-effort skip).
///
/// `blob` is the full stored envelope (25 B header + body): the transcript
/// binds the entity id and the EXACT header bytes, so a valid receipt
/// transplanted under another id or a shifted envelope fails step 3.
pub(crate) fn verify_new_receipt_origin_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    blob: &[u8],
) -> Result<()> {
    use crate::batch::ENTITY_METADATA_HEADER_LEN;

    if blob.len() < ENTITY_METADATA_HEADER_LEN {
        return Err(Error::InvalidRedactionReceiptBody(
            "envelope shorter than the pinned header",
        ));
    }
    let (header, body) = blob.split_at(ENTITY_METADATA_HEADER_LEN);
    let parts = receipt_attestation_parts(body)?;

    // Step 3 — transcript verification (OD-6 tail-splice).
    let verifying_key = VerifyingKey::from_bytes(&parts.pubkey)
        .map_err(|_| Error::ReceiptAttestationInvalid { id: *id })?;
    let mut msg = Vec::with_capacity(
        RECEIPT_ATT_DOMAIN.len() + 16 + header.len() + parts.verification_value_offset + 1,
    );
    msg.extend_from_slice(RECEIPT_ATT_DOMAIN);
    msg.extend_from_slice(id.as_bytes());
    msg.extend_from_slice(header);
    msg.extend_from_slice(&body[..parts.verification_value_offset]);
    msg.push(ATT_EMPTY_MAP_BYTE);
    verifying_key
        .verify(&msg, &Signature::from_bytes(&parts.signature))
        .map_err(|_| Error::ReceiptAttestationInvalid { id: *id })?;

    // Step 4 — claimed-row lease binding (OD-7: status only, never time).
    let Some(raw) = vault
        .store
        .sync_state
        .get(txn, &lease_key(parts.client_id))?
    else {
        return Err(Error::ReceiptLeaseUnknown {
            client_id: parts.client_id,
        });
    };
    let record = decode_lease_record(raw)?;
    if record.pubkey != parts.pubkey {
        return Err(Error::ReceiptAttestationInvalid { id: *id });
    }
    // Claimed-row status FIRST — preserves ReceiptLeaseRevoked precedence
    // when the att_client row is itself the revoked binding.
    if record.status == LeaseStatus::Revoked {
        return Err(Error::ReceiptLeaseRevoked {
            client_id: parts.client_id,
        });
    }

    // Step 5 — pubkey-bound revocation FLOOR (OD-8 amended, RULING C). The
    // kill switch binds to the Ed25519 PUBKEY, not the mintable att_client:
    // a revoked pubkey is terminal across ALL client_ids, so a device that
    // rotates client_id while reusing its key cannot recover (intended —
    // recovery requires a fresh KEYPAIR). Scan every ls: mirror row
    // (one-per-device, cheap) and reject if THIS signing pubkey appears in
    // ANY revoked binding, including the att_client==claimed path (catches a
    // self-rebind under a fresh id). Runs on BOTH accept arms reached here
    // (active AND expired): an attacker's fresh active row can be flipped to
    // expired by scan-at-connect. A malformed sibling ls: row is OUR mirror
    // corruption and propagates fail-closed (the `?`), failing the door
    // GLOBALLY — never a best-effort skip. Multi-user (vault, pubkey) scoping
    // is out of scope here (ONE-1161).
    for entry in vault.store.sync_state.prefix_iter(txn, LEASE_KEY_PREFIX)? {
        let (_key, sibling_raw) = entry?;
        let sibling = decode_lease_record(sibling_raw)?;
        if sibling.pubkey == parts.pubkey && sibling.status == LeaseStatus::Revoked {
            return Err(Error::ReceiptLeaseRevoked {
                client_id: parts.client_id,
            });
        }
    }
    Ok(())
}

/// Full-mirrors the root doc's `leases` map into local `ls:` rows inside
/// the CALLER's txn (OD-3; called in the same txn as the root persist).
///
/// Fail-closed per entry: a malformed key or value (server bug — the
/// server is the sole writer) quarantines an `x:` row (GDPR-inert
/// hash+len) and KEEPS any previous good `ls:` row — garbage is never
/// upserted, never silently dropped. N = device count (tiny).
pub(crate) fn mirror_leases_from_root_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root_doc: &LoroDoc,
) -> Result<()> {
    mirror_leases_impl(vault, wtxn, root_doc)
}

/// Own-txn wrapper around the lease mirror — the SERVER's half of OD-3
/// ("the server mirrors its own registry writes to its vault's `ls:` rows
/// in the same logical op").
pub fn mirror_leases_from_root(vault: &Vault, root_doc: &LoroDoc) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    mirror_leases_impl(vault, &mut wtxn, root_doc)?;
    wtxn.commit()?;
    Ok(())
}

fn mirror_leases_impl(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, root_doc: &LoroDoc) -> Result<()> {
    let leases = root_doc.get_map(ROOT_LEASES_MAP);
    let mut entries: Vec<(String, Option<Vec<u8>>)> = Vec::new();
    leases.for_each(|key, value| {
        let bytes = match value {
            loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob)) => Some(blob.to_vec()),
            _ => None,
        };
        entries.push((key.to_string(), bytes));
    });

    for (key, bytes) in entries {
        let valid_key = key.len() == 16
            && key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let valid = valid_key
            && bytes
                .as_deref()
                .is_some_and(|raw| decode_lease_record(raw).is_ok());
        if !valid {
            quarantine::quarantine_rejected_op_in_txn(
                vault,
                wtxn,
                LEASE_QUARANTINE_WINDOW,
                QuarantineContainer::Leases,
                &key,
                &Error::CorruptedIndex("lease registry entry"),
                bytes.as_deref().unwrap_or(&[]),
            )?;
            continue;
        }
        let row_key = format!("{LEASE_KEY_PREFIX}{key}");
        vault
            .store
            .sync_state
            .put(wtxn, &row_key, &bytes.expect("validated above"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OD-4 layout literals: 58 B, version 0x01, status byte at [1],
    /// pubkey at [2..34], three u64 LE timestamps — a transposed field or
    /// BE/LE flip fails here, not at a remote door.
    #[test]
    fn lease_record_layout_literals_round_trip() {
        let record = LeaseRecord {
            status: LeaseStatus::Active,
            pubkey: [0xAB; 32],
            granted_at: 0x0102030405060708,
            renewed_at: 0x1112131415161718,
            expires_at: 0x2122232425262728,
        };
        let encoded = encode_lease_record(&record);
        assert_eq!(encoded.len(), 58);
        assert_eq!(encoded[0], 0x01, "version byte");
        assert_eq!(encoded[1], 0x01, "active status byte");
        assert_eq!(&encoded[2..34], &[0xAB; 32]);
        assert_eq!(
            &encoded[34..42],
            &0x0102030405060708u64.to_le_bytes(),
            "granted_at u64 LE"
        );
        assert_eq!(&encoded[42..50], &0x1112131415161718u64.to_le_bytes());
        assert_eq!(&encoded[50..58], &0x2122232425262728u64.to_le_bytes());
        assert_eq!(decode_lease_record(&encoded).unwrap(), record);

        // Status wire bytes (OD-4): active=0x01, expired=0x02, revoked=0x03.
        for (status, byte) in [
            (LeaseStatus::Active, 0x01u8),
            (LeaseStatus::Expired, 0x02),
            (LeaseStatus::Revoked, 0x03),
        ] {
            assert_eq!(status as u8, byte);
            assert_eq!(LeaseStatus::from_wire_byte(byte), Some(status));
        }

        // Fail-closed decode: wrong length, unknown version, unknown status.
        assert!(decode_lease_record(&encoded[..57]).is_err());
        let mut bad_version = encoded;
        bad_version[0] = 0x02;
        assert!(decode_lease_record(&bad_version).is_err());
        let mut bad_status = encoded;
        bad_status[1] = 0x00;
        assert!(decode_lease_record(&bad_status).is_err());
    }

    /// OD-4 key grammar: `ls:` + `{client_id:016x}` (BE nibble order ⇒
    /// lexically sortable, 19 B total).
    #[test]
    fn lease_key_grammar_literal() {
        assert_eq!(client_id_hex(0x0123456789abcdef), "0123456789abcdef");
        assert_eq!(lease_key(0x0123456789abcdef), "ls:0123456789abcdef");
        assert_eq!(lease_key(7), "ls:0000000000000007");
        assert_eq!(lease_key(7).len(), 19);
    }

    /// OD-6 PoP transcript literal: domain || client_id BE || pubkey. A
    /// signature over a different client id must NOT verify (the transcript
    /// binds both, which is what makes the frame replay-safe).
    #[test]
    fn lease_pop_transcript_binds_client_id_and_key() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = key.verifying_key().to_bytes();

        let msg = lease_pop_transcript(0x0102030405060708, &pubkey);
        assert_eq!(&msg[..20], b"oneiron/lease-pop/v1");
        assert_eq!(&msg[20..28], &0x0102030405060708u64.to_be_bytes());
        assert_eq!(&msg[28..60], &pubkey);

        let sig = key.sign(&msg).to_bytes();
        assert!(verify_lease_pop(0x0102030405060708, &pubkey, &sig));
        assert!(
            !verify_lease_pop(0x0102030405060709, &pubkey, &sig),
            "a PoP signature must not transfer to a different client id"
        );
    }
}
