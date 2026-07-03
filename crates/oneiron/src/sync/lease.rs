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
//! value ≡ `ls:` row value, byte-identical, 66 B):
//!
//! ```text
//! [ver:1 = 0x02][status:1  0x01 active | 0x02 expired | 0x03 revoked]
//! [pubkey:32][granted_at:8 LE][renewed_at:8 LE][expires_at:8 LE]
//! [vault_id:8 BE]
//! ```
//!
//! Key surfaces:
//!
//! - LMDB mirror: `ls:` + vault_id_hex + `:` + client_id_hex (36 B).
//! - Root-doc `leases` map: vault_id_hex + `:` + client_id_hex (33 B).
//!
//! `vault_id_hex` = `{vault_id:016x}` and `client_id_hex` = `{client_id:016x}`
//! — 16 lowercase hex chars each, BE nibble order ⇒ lexically sortable
//! (convention: BE for sortable key material). Legacy root-doc entries keyed
//! only by `client_id_hex` are still accepted and mirrored using the
//! `vault_id` carried in the value, but all new server writes use the scoped
//! root key so hosted tenants cannot collide on a subscriber/client id.
//! Values carry the same `vault_id` and are mirrored byte-identically into
//! the `ls:` row value. Value timestamps LE (opaque-value convention,
//! `dt:` precedent).
//! The docs' baseline `ls:` = bare "u64 LE last-seen" is superseded: the
//! door needs pubkey + status, and `renewed_at` carries the last-seen
//! semantic (ARCH-0023b amendment queued per OD-4).
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
pub const LEASE_RECORD_LEN: usize = 66;
/// Lease-record version byte (OD-4).
pub const LEASE_RECORD_VERSION: u8 = 0x02;
/// 90-day lease: `expires_at = renewed_at + LEASE_DURATION_SECS` (OD-4).
pub const LEASE_DURATION_SECS: u64 = 7_776_000;
/// Current single-vault lease scope used by the existing server path.
pub(crate) const DEFAULT_LEASE_VAULT_ID: u64 = 0;
/// Proof-of-possession transcript domain separator (OD-6 literal):
/// `msg = LEASE_POP_DOMAIN || client_id:8 BE || pubkey:32`.
pub const LEASE_POP_DOMAIN: &[u8] = b"oneiron/lease-pop/v1";
/// Root-doc container holding the lease registry (OD-3).
pub const ROOT_LEASES_MAP: &str = "leases";
/// `QuarantineRecord.window_key` literal for root-doc lease quarantines
/// (the registry rides the ROOT doc, which has no YYYY-MM window).
pub const LEASE_QUARANTINE_WINDOW: &str = "root";
const LEASE_REGISTRY_KEY_ERROR: &str = "lease registry key";

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
    pub vault_id: u64,
    pub status: LeaseStatus,
    pub pubkey: [u8; 32],
    pub granted_at: u64,
    pub renewed_at: u64,
    pub expires_at: u64,
}

/// Decoded root-doc lease registry key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseRegistryKey {
    /// Tenant/shared-vault dimension. `None` means a legacy client-only root key.
    pub vault_id: Option<u64>,
    /// Subscriber/client dimension.
    pub client_id: u64,
}

impl LeaseRegistryKey {
    /// Returns the key's effective vault id and validates scoped keys against
    /// the record payload.
    pub fn effective_vault_id(self, record: &LeaseRecord) -> Result<u64> {
        match self.vault_id {
            Some(vault_id) if vault_id == record.vault_id => Ok(vault_id),
            Some(_) => Err(Error::CorruptedIndex("lease registry vault_id")),
            None => Ok(record.vault_id),
        }
    }
}

/// `{client_id:016x}` — the subscriber/client key component.
#[must_use]
pub fn client_id_hex(client_id: u64) -> String {
    format!("{client_id:016x}")
}

/// `{vault_id:016x}` — fixed-width BE-sortable vault id key component.
#[must_use]
pub fn vault_id_hex(vault_id: u64) -> String {
    format!("{vault_id:016x}")
}

/// `{vault_id_hex}:{client_id_hex}` — scoped root-doc registry key.
#[must_use]
pub fn lease_registry_key(vault_id: u64, client_id: u64) -> String {
    format!("{}:{}", vault_id_hex(vault_id), client_id_hex(client_id))
}

/// Decodes a root-doc lease registry key.
///
/// New keys are scoped as `{vault_id:016x}:{client_id:016x}`. Legacy
/// `{client_id:016x}` keys are accepted so existing single-vault roots can
/// be renewed or revoked and migrated by the next write.
pub fn decode_lease_registry_key(key: &str) -> Result<LeaseRegistryKey> {
    if key.len() == 16 {
        return Ok(LeaseRegistryKey {
            vault_id: None,
            client_id: parse_hex_component(key)?,
        });
    }

    let Some((vault, client)) = key.split_once(':') else {
        return Err(Error::CorruptedIndex(LEASE_REGISTRY_KEY_ERROR));
    };
    if key.split(':').count() != 2 {
        return Err(Error::CorruptedIndex(LEASE_REGISTRY_KEY_ERROR));
    }

    Ok(LeaseRegistryKey {
        vault_id: Some(parse_hex_component(vault)?),
        client_id: parse_hex_component(client)?,
    })
}

/// `ls:{vault_id_hex}:` — the LMDB mirror-row prefix for one vault.
#[must_use]
pub fn lease_key_prefix(vault_id: u64) -> String {
    format!("{LEASE_KEY_PREFIX}{}:", vault_id_hex(vault_id))
}

/// `ls:{vault_id_hex}:{client_id_hex}` — the LMDB mirror-row key (36 B).
#[must_use]
pub fn lease_key(vault_id: u64, client_id: u64) -> String {
    format!("{}{}", lease_key_prefix(vault_id), client_id_hex(client_id))
}

/// Encodes the pinned 66 B lease record (OD-4).
#[must_use]
pub fn encode_lease_record(record: &LeaseRecord) -> [u8; LEASE_RECORD_LEN] {
    let mut out = [0u8; LEASE_RECORD_LEN];
    out[0] = LEASE_RECORD_VERSION;
    out[1] = record.status as u8;
    out[2..34].copy_from_slice(&record.pubkey);
    out[34..42].copy_from_slice(&record.granted_at.to_le_bytes());
    out[42..50].copy_from_slice(&record.renewed_at.to_le_bytes());
    out[50..58].copy_from_slice(&record.expires_at.to_le_bytes());
    out[58..66].copy_from_slice(&record.vault_id.to_be_bytes());
    out
}

/// Decodes a pinned 66 B lease record. Fail-closed: exact length, known
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
    let granted_at = u64::from_le_bytes(
        raw[34..42]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("lease record length"))?,
    );
    let renewed_at = u64::from_le_bytes(
        raw[42..50]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("lease record length"))?,
    );
    let expires_at = u64::from_le_bytes(
        raw[50..58]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("lease record length"))?,
    );
    let vault_id = u64::from_be_bytes(
        raw[58..66]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("lease record length"))?,
    );
    Ok(LeaseRecord {
        vault_id,
        status,
        pubkey,
        granted_at,
        renewed_at,
        expires_at,
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

fn parse_hex_component(component: &str) -> Result<u64> {
    if component.len() != 16
        || !component
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::CorruptedIndex(LEASE_REGISTRY_KEY_ERROR));
    }
    u64::from_str_radix(component, 16).map_err(|_| Error::CorruptedIndex(LEASE_REGISTRY_KEY_ERROR))
}

/// The ONE-1140 origin predicate for a NEW receipt at a replay door
/// (door steps 3–5; steps 1–2 — structural validation and the
/// immutability/divergence gate — run in the caller, in that order):
///
/// 3. Ed25519-verify the attestation transcript against the embedded
///    `att_pk` → fail = [`Error::ReceiptAttestationInvalid`].
/// 4. Claimed-row lookup in the CALLER's txn over the v2
///    `ls:{vault_id_hex}:{att_client}` keyspace: row absent →
///    [`Error::ReceiptLeaseUnknown`]; decoded row `vault_id` ≠ caller's
///    trusted vault scope → local [`Error::CorruptedIndex`]; registry pubkey ≠
///    `att_pk` → [`Error::ReceiptAttestationInvalid`]; the CLAIMED row's
///    status revoked → [`Error::ReceiptLeaseRevoked`] (checked FIRST,
///    preserving its precedence); active | expired → fall through to step 5
///    (OD-7).
/// 5. Pubkey-bound revocation FLOOR (OD-8 amended, RULING C; ONE-1190). The
///    kill switch binds to the Ed25519 PUBKEY, not the mintable `att_client`:
///    scan every row under the caller's trusted `ls:{vault_id_hex}:` prefix
///    and reject with [`Error::ReceiptLeaseRevoked`] if this signing pubkey
///    appears in any same-vault revoked binding — so a revoked pubkey is
///    terminal across all client_ids in that vault, while an independently
///    leased identical key in another vault is not poisoned. Runs on BOTH
///    accept arms (active AND expired) and even on the `att_client`==claimed
///    path, catching a same-vault same-key rebind under a fresh id. Tenant
///    read/write routing remains out of scope for ONE-1192.
///
/// The four remote rejections (attestation-invalid, lease-unknown,
/// lease-revoked — claimed-row OR pubkey floor) classify as REMOTE via
/// `remote_rejection_reason` (quarantine-and-continue at the callers). A
/// malformed `ls:` row — the claimed point-read OR any sibling reached by
/// the floor scan — is LOCAL corruption (our own mirror wrote it) and
/// propagates fail-closed, failing this vault's door (wider blast radius
/// than the single receipt, but bounded to the vault and correct: never a
/// best-effort skip).
///
/// `blob` is the full stored envelope (25 B header + body): the transcript
/// binds the entity id and the EXACT header bytes, so a valid receipt
/// transplanted under another id or a shifted envelope fails step 3.
pub(crate) fn verify_new_receipt_origin_for_vault_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_id: u64,
    id: &EntityId,
    blob: &[u8],
) -> Result<[u8; 32]> {
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
    let Some(record) = claimed_lease_record_in_txn(vault, txn, vault_id, parts.client_id)? else {
        return Err(Error::ReceiptLeaseUnknown {
            client_id: parts.client_id,
        });
    };
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

    // Step 5 — pubkey-bound revocation FLOOR (OD-8 amended, RULING C;
    // ONE-1190). The
    // kill switch binds to the Ed25519 PUBKEY, not the mintable att_client:
    // a revoked pubkey is terminal across same-vault client_ids, so a device
    // that rotates client_id while reusing its key cannot recover inside that
    // vault (intended — recovery requires a fresh KEYPAIR). Scan every
    // same-vault ls: mirror row (one-per-device, cheap) and reject if THIS
    // signing pubkey appears in ANY revoked binding under the requesting
    // vault prefix, including the att_client==claimed path (catches a
    // self-rebind under a fresh id). Runs on BOTH accept arms reached here
    // (active AND expired): an attacker's fresh active row can be flipped to
    // expired by scan-at-connect. A malformed sibling ls: row inside this
    // vault prefix is OUR mirror corruption and propagates fail-closed (the
    // `?`), failing this vault's door — never a best-effort skip — without
    // reading other vaults. Tenant read/write scoping remains out of scope
    // for ONE-1192.
    let floor_prefix = lease_key_prefix(vault_id);
    for entry in vault.store.sync_state.prefix_iter(txn, &floor_prefix)? {
        let (_key, sibling_raw) = entry?;
        let sibling = decode_scoped_lease_record(sibling_raw, vault_id)?;
        if sibling.pubkey == parts.pubkey && sibling.status == LeaseStatus::Revoked {
            return Err(Error::ReceiptLeaseRevoked {
                client_id: parts.client_id,
            });
        }
    }
    Ok(parts.pubkey)
}

fn claimed_lease_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_id: u64,
    client_id: u64,
) -> Result<Option<LeaseRecord>> {
    let key = lease_key(vault_id, client_id);
    let Some(raw) = vault.store.sync_state.get(txn, &key)? else {
        return Ok(None);
    };
    Ok(Some(decode_scoped_lease_record(raw, vault_id)?))
}

fn decode_scoped_lease_record(raw: &[u8], vault_id: u64) -> Result<LeaseRecord> {
    let record = decode_lease_record(raw)?;
    if record.vault_id != vault_id {
        return Err(Error::CorruptedIndex("lease record vault_id"));
    }
    Ok(record)
}

/// Full-mirrors the root doc's `leases` map into local `ls:` rows inside
/// the CALLER's txn (OD-3; called in the same txn as the root persist).
///
/// Fail-closed per entry: a malformed key or value (server bug — the
/// server is the sole writer) quarantines an `x:` row (GDPR-inert
/// hash+len) and KEEPS any previous good `ls:` row — garbage is never
/// upserted, never silently dropped. N = device count (tiny).
///
/// MISUSE SURFACE (ONE-1140): callers MUST wrap this in the SAME write txn as
/// the `d:root` persist (`server_state::persist_root_snapshot_in_txn`) so the
/// root snapshot and its `ls:` mirror commit or roll back together. Using it
/// outside that atomic boundary re-opens the split-write bug. The cross-crate
/// caller is `oneiron-server`'s lease registrar.
#[doc(hidden)]
pub fn mirror_leases_from_root_in_txn(
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
    // Test-only fault injection (ONE-1140): force a mid-txn mirror failure so
    // the root-snapshot/`ls:`-mirror atomicity test can prove the `d:root`
    // put committed in the SAME write txn rolls back. No production effect.
    #[cfg(any(test, feature = "test-hooks"))]
    if test_hooks::take_mirror_failure() {
        return Err(Error::CorruptedIndex(
            "injected lease mirror failure (test hook)",
        ));
    }

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
        let Some(raw) = bytes.as_deref() else {
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
        };
        let Ok(registry_key) = decode_lease_registry_key(&key) else {
            quarantine::quarantine_rejected_op_in_txn(
                vault,
                wtxn,
                LEASE_QUARANTINE_WINDOW,
                QuarantineContainer::Leases,
                &key,
                &Error::CorruptedIndex("lease registry entry"),
                raw,
            )?;
            continue;
        };
        let Ok(record) = decode_lease_record(raw) else {
            quarantine::quarantine_rejected_op_in_txn(
                vault,
                wtxn,
                LEASE_QUARANTINE_WINDOW,
                QuarantineContainer::Leases,
                &key,
                &Error::CorruptedIndex("lease registry entry"),
                raw,
            )?;
            continue;
        };
        let Ok(vault_id) = registry_key.effective_vault_id(&record) else {
            quarantine::quarantine_rejected_op_in_txn(
                vault,
                wtxn,
                LEASE_QUARANTINE_WINDOW,
                QuarantineContainer::Leases,
                &key,
                &Error::CorruptedIndex("lease registry entry"),
                raw,
            )?;
            continue;
        };
        let client_id = registry_key.client_id;
        let row_key = lease_key(vault_id, client_id);
        delete_stale_v2_lease_rows_for_client(vault, wtxn, vault_id, client_id, &row_key)?;
        vault.store.sync_state.put(wtxn, &row_key, raw)?;
    }
    Ok(())
}

fn delete_stale_v2_lease_rows_for_client(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    vault_id: u64,
    client_id: u64,
    keep_key: &str,
) -> Result<()> {
    let prefix = lease_key_prefix(vault_id);
    let client_suffix = format!(":{}", client_id_hex(client_id));
    let mut stale_keys = Vec::new();
    for entry in vault.store.sync_state.prefix_iter(wtxn, &prefix)? {
        let (key, _raw) = entry?;
        if key != keep_key && key.ends_with(&client_suffix) {
            stale_keys.push(key.to_owned());
        }
    }
    for key in stale_keys {
        vault.store.sync_state.delete(wtxn, &key)?;
    }
    Ok(())
}

/// Cross-crate test-only fault-injection seam (ONE-1140). Lets the
/// `oneiron-server` lease-atomicity test force [`mirror_leases_from_root_in_txn`]
/// to fail mid-txn. Gated on `cfg(test)` (this crate's own tests) OR the
/// `test-hooks` feature (downstream dev-dependency builds); compiled out of
/// production entirely.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub mod test_hooks {
    use std::cell::Cell;

    thread_local! {
        // One-shot: armed by `arm_mirror_failure`, consumed by the next
        // `mirror_leases_impl` on this thread (Loro observer-free; the
        // registrar runs the mirror synchronously on the caller's thread).
        static MIRROR_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot mirror failure on the current thread.
    pub fn arm_mirror_failure() {
        MIRROR_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(crate) fn take_mirror_failure() -> bool {
        MIRROR_FAILURE.with(|c| c.replace(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VaultConfig;
    use ed25519_dalek::SigningKey;

    const TEST_RECEIPT_LEARNED_AT: u64 = 1_772_400_000;

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = VaultConfig::device();
        cfg.map_size = 16 * 1024 * 1024;
        cfg.embedding_model = None;
        let vault = Vault::open(dir.path(), cfg).unwrap();
        (dir, vault)
    }

    fn signed_receipt(seed: u8, client_id: u64) -> (EntityId, [u8; 32], Vec<u8>) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let receipt_id = EntityId::now();
        let subject = EntityId::now();
        let input = crate::deletion::RedactionReceiptInput {
            request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
            scope: crate::deletion::RedactionScope::entity(&subject),
            reason: crate::DeleteReason::GdprDelete,
            requested_at: 100,
            soft_complete_at: 101,
            hard_purge_complete_at: TEST_RECEIPT_LEARNED_AT,
            sweep_queued_at: Some(102),
        };
        let identity = crate::identity::DeviceIdentity {
            client_id,
            signing_key,
        };
        let body =
            crate::deletion::encode_redaction_audit_receipt(input, &receipt_id, &identity).unwrap();
        let mut blob = crate::deletion::receipt_envelope_header(TEST_RECEIPT_LEARNED_AT).to_vec();
        blob.extend_from_slice(&body);
        (receipt_id, pubkey, blob)
    }

    fn put_lease_row(
        vault: &Vault,
        vault_id: u64,
        client_id: u64,
        pubkey: [u8; 32],
        status: LeaseStatus,
    ) {
        let record = LeaseRecord {
            vault_id,
            status,
            pubkey,
            granted_at: 1,
            renewed_at: 2,
            expires_at: 3,
        };
        vault
            .sync_state_put(
                &lease_key(vault_id, client_id),
                &encode_lease_record(&record),
            )
            .unwrap();
    }

    fn verify_receipt_for_vault(
        vault: &Vault,
        vault_id: u64,
        id: &EntityId,
        blob: &[u8],
    ) -> Result<()> {
        let rtxn = vault.store.env.read_txn().unwrap();
        verify_new_receipt_origin_for_vault_in_txn(vault, &rtxn, vault_id, id, blob).map(|_| ())
    }

    /// OD-4 layout literals: 66 B, version 0x02, status byte at [1],
    /// pubkey at [2..34], three u64 LE timestamps, vault_id u64 BE — a
    /// transposed field or BE/LE flip fails here, not at a remote door.
    #[test]
    fn lease_record_layout_literals_round_trip() {
        let record = LeaseRecord {
            vault_id: 0x0102030405060708,
            status: LeaseStatus::Active,
            pubkey: [0xAB; 32],
            granted_at: 0x0102030405060708,
            renewed_at: 0x1112131415161718,
            expires_at: 0x2122232425262728,
        };
        let encoded = encode_lease_record(&record);
        assert_eq!(encoded.len(), LEASE_RECORD_LEN);
        assert_eq!(encoded.len(), 66);
        assert_eq!(encoded[0], 0x02, "version byte");
        assert_eq!(encoded[1], 0x01, "active status byte");
        assert_eq!(&encoded[2..34], &[0xAB; 32]);
        assert_eq!(
            &encoded[34..42],
            &0x0102030405060708u64.to_le_bytes(),
            "granted_at u64 LE"
        );
        assert_eq!(&encoded[42..50], &0x1112131415161718u64.to_le_bytes());
        assert_eq!(&encoded[50..58], &0x2122232425262728u64.to_le_bytes());
        assert_eq!(
            &encoded[58..66],
            &0x0102030405060708u64.to_be_bytes(),
            "vault_id u64 BE"
        );
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

        // Compat/fail-closed decode: the 58 B v1 layout and any wrong length
        // are refused; unknown status keeps its pinned error literal.
        let mut legacy_v1 = [0u8; 58];
        legacy_v1[0] = 0x01;
        legacy_v1[1] = 0x01;
        assert!(matches!(
            decode_lease_record(&legacy_v1),
            Err(Error::CorruptedIndex(_))
        ));
        assert!(matches!(
            decode_lease_record(&encoded[..65]),
            Err(Error::CorruptedIndex(_))
        ));
        let mut overlong = encoded.to_vec();
        overlong.push(0);
        assert!(matches!(
            decode_lease_record(&overlong),
            Err(Error::CorruptedIndex(_))
        ));
        let mut bad_version = encoded;
        bad_version[0] = 0x01;
        assert!(matches!(
            decode_lease_record(&bad_version),
            Err(Error::CorruptedIndex(_))
        ));
        let mut bad_status = encoded;
        bad_status[1] = 0x00;
        assert!(matches!(
            decode_lease_record(&bad_status),
            Err(Error::CorruptedIndex("lease record status"))
        ));
    }

    /// OD-4 key grammar: `ls:` + `{vault_id:016x}` + `:` +
    /// `{client_id:016x}` (BE nibble order ⇒ lexically sortable, 36 B total).
    #[test]
    fn lease_key_grammar_literal() {
        assert_eq!(client_id_hex(0x0123456789abcdef), "0123456789abcdef");
        assert_eq!(vault_id_hex(0x0102030405060708), "0102030405060708");
        let registry_key = lease_registry_key(0x0102030405060708, 0x0123456789abcdef);
        assert_eq!(registry_key, "0102030405060708:0123456789abcdef");
        assert_eq!(registry_key.len(), 33);
        assert_eq!(
            decode_lease_registry_key(&registry_key).unwrap(),
            LeaseRegistryKey {
                vault_id: Some(0x0102030405060708),
                client_id: 0x0123456789abcdef,
            }
        );
        assert_eq!(
            decode_lease_registry_key("0123456789abcdef").unwrap(),
            LeaseRegistryKey {
                vault_id: None,
                client_id: 0x0123456789abcdef,
            }
        );
        assert!(decode_lease_registry_key("0102030405060708:0123456789abcdeF").is_err());
        assert!(decode_lease_registry_key("0102030405060708:0123456789abcdef:00").is_err());
        assert_eq!(lease_key_prefix(0x0102030405060708), "ls:0102030405060708:");
        let key = lease_key(0x0102030405060708, 0x0123456789abcdef);
        assert_eq!(key, "ls:0102030405060708:0123456789abcdef");
        assert_eq!(key.len(), 36);
        assert_eq!(lease_key(7, 7), "ls:0000000000000007:0000000000000007");
    }

    #[test]
    fn lease_prefix_scan_isolates_vault_dimension() {
        let (_dir, vault) = test_vault();
        let vault_a = 0x0a0b0c0d0e0f1011;
        let vault_b = 0x11100f0e0d0c0b0a;
        let client = 0x0123456789abcdef;
        let record_a = LeaseRecord {
            vault_id: vault_a,
            status: LeaseStatus::Active,
            pubkey: [0xA1; 32],
            granted_at: 1,
            renewed_at: 2,
            expires_at: 3,
        };
        let record_b = LeaseRecord {
            vault_id: vault_b,
            pubkey: [0xB2; 32],
            ..record_a
        };
        let row_a = encode_lease_record(&record_a);
        let row_b = encode_lease_record(&record_b);
        vault
            .sync_state_put(&lease_key(vault_a, client), &row_a)
            .unwrap();
        vault
            .sync_state_put(&lease_key(vault_b, client), &row_b)
            .unwrap();

        let rtxn = vault.store.env.read_txn().unwrap();
        let scoped_prefix = lease_key_prefix(vault_a);
        assert_eq!(scoped_prefix, "ls:0a0b0c0d0e0f1011:");
        let rows = vault
            .store
            .sync_state
            .prefix_iter(&rtxn, &scoped_prefix)
            .unwrap()
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_string(), value.to_vec())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![(
                "ls:0a0b0c0d0e0f1011:0123456789abcdef".to_owned(),
                row_a.to_vec()
            )]
        );
    }

    #[test]
    fn receipt_door_uses_vault_scoped_claimed_lookup() {
        let (_dir, vault) = test_vault();
        let vault_a = 0x0a0b_0c0d_0e0f_1011;
        let vault_b = 0x1110_0f0e_0d0c_0b0a;
        let client = 0x0123_4567_89ab_cdef;
        let (receipt_id, pubkey, blob) = signed_receipt(0x21, client);

        put_lease_row(&vault, vault_a, client, pubkey, LeaseStatus::Active);

        let err = verify_receipt_for_vault(&vault, vault_b, &receipt_id, &blob).unwrap_err();
        assert!(
            matches!(err, Error::ReceiptLeaseUnknown { client_id } if client_id == client),
            "another vault's binding must not satisfy the claimed lookup: {err:?}"
        );
        assert!(
            verify_receipt_for_vault(&vault, vault_a, &receipt_id, &blob).is_ok(),
            "the same receipt must pass against the vault that owns the binding"
        );
    }

    #[test]
    fn receipt_door_scopes_pubkey_revocation_floor_to_vault_prefix() {
        let (_dir, vault) = test_vault();
        let vault_a = 0x0a0b_0c0d_0e0f_1011;
        let vault_b = 0x1110_0f0e_0d0c_0b0a;
        let revoked_client_a = 0xaaaa_aaaa_aaaa_aaaa;
        let active_client_b = 0xbbbb_bbbb_bbbb_bbbb;
        let revoked_client_b = 0xcccc_cccc_cccc_cccc;
        let (receipt_id, pubkey, blob) = signed_receipt(0x31, active_client_b);

        put_lease_row(
            &vault,
            vault_a,
            revoked_client_a,
            pubkey,
            LeaseStatus::Revoked,
        );
        put_lease_row(
            &vault,
            vault_b,
            active_client_b,
            pubkey,
            LeaseStatus::Active,
        );

        assert!(
            verify_receipt_for_vault(&vault, vault_b, &receipt_id, &blob).is_ok(),
            "a revoked pubkey in vault A must not bleed into vault B"
        );

        put_lease_row(
            &vault,
            vault_b,
            revoked_client_b,
            pubkey,
            LeaseStatus::Revoked,
        );
        let err = verify_receipt_for_vault(&vault, vault_b, &receipt_id, &blob).unwrap_err();
        assert!(
            matches!(err, Error::ReceiptLeaseRevoked { client_id } if client_id == active_client_b),
            "same-vault revoked pubkey must still reject: {err:?}"
        );
    }

    #[test]
    fn receipt_door_preserves_same_vault_expired_plus_revoked_floor() {
        let (_dir, vault) = test_vault();
        let vault_id = 0x0102_0304_0506_0708;
        let expired_client = 0x1111_1111_1111_1111;
        let revoked_client = 0x2222_2222_2222_2222;
        let (receipt_id, pubkey, blob) = signed_receipt(0x41, expired_client);

        put_lease_row(
            &vault,
            vault_id,
            expired_client,
            pubkey,
            LeaseStatus::Expired,
        );
        put_lease_row(
            &vault,
            vault_id,
            revoked_client,
            pubkey,
            LeaseStatus::Revoked,
        );

        let err = verify_receipt_for_vault(&vault, vault_id, &receipt_id, &blob).unwrap_err();
        assert!(
            matches!(err, Error::ReceiptLeaseRevoked { client_id } if client_id == expired_client),
            "expired claimed rows still accept OD-7, but same-vault revoked pubkey floor rejects"
        );
    }

    #[test]
    fn revoked_claimed_row_returns_claimed_client_id_before_scoped_floor_scan() {
        let (_dir, vault) = test_vault();
        let vault_id = 0x0102_0304_0506_0708;
        let claimed_client = 0x4545_4545_4545_4545u64;
        let corrupt_sibling_client = 0x4545_4545_4545_0001u64;
        let (receipt_id, pubkey, blob) = signed_receipt(0x45, claimed_client);

        put_lease_row(
            &vault,
            vault_id,
            claimed_client,
            pubkey,
            LeaseStatus::Revoked,
        );
        vault
            .sync_state_put(&lease_key(vault_id, corrupt_sibling_client), b"too-short")
            .unwrap();

        let err = verify_receipt_for_vault(&vault, vault_id, &receipt_id, &blob)
            .expect_err("revoked claimed row must reject before scanning corrupt siblings");
        assert!(
            matches!(err, Error::ReceiptLeaseRevoked { client_id } if client_id == claimed_client),
            "claimed-row revoked path must return the claimed client_id, got: {err:?}"
        );
    }

    #[test]
    fn mismatched_claimed_lease_key_vault_fails_closed_before_floor_scope() {
        let (_dir, vault) = test_vault();
        let trusted_vault_id = 0x0102_0304_0506_0708;
        let payload_vault_id = 0x0807_0605_0403_0201;
        let claimed_client = 0x4646_4646_4646_4646u64;
        let revoked_sibling_client = 0x4646_4646_4646_0001u64;
        let (receipt_id, pubkey, blob) = signed_receipt(0x46, claimed_client);
        let claimed_record = LeaseRecord {
            vault_id: payload_vault_id,
            status: LeaseStatus::Active,
            pubkey,
            granted_at: 10,
            renewed_at: 20,
            expires_at: 30,
        };
        vault
            .sync_state_put(
                &lease_key(trusted_vault_id, claimed_client),
                &encode_lease_record(&claimed_record),
            )
            .unwrap();
        put_lease_row(
            &vault,
            trusted_vault_id,
            revoked_sibling_client,
            pubkey,
            LeaseStatus::Revoked,
        );

        let err = verify_receipt_for_vault(&vault, trusted_vault_id, &receipt_id, &blob)
            .expect_err("key/payload vault mismatch must not scope the floor to payload vault");
        assert!(
            matches!(err, Error::CorruptedIndex("lease record vault_id")),
            "local lease key/value mismatch must fail closed, got: {err:?}"
        );
    }

    #[test]
    fn receipt_door_corrupt_sibling_row_is_vault_scoped() {
        let (_dir, vault) = test_vault();
        let vault_a = 0x0a0b_0c0d_0e0f_1011;
        let vault_b = 0x1110_0f0e_0d0c_0b0a;
        let client = 0x0123_4567_89ab_cdef;
        let (receipt_id, pubkey, blob) = signed_receipt(0x51, client);

        put_lease_row(&vault, vault_a, client, pubkey, LeaseStatus::Active);
        vault
            .sync_state_put(
                &lease_key(vault_b, 0xdead_beef_dead_beef),
                b"corrupt-outside-scope",
            )
            .unwrap();

        assert!(
            verify_receipt_for_vault(&vault, vault_a, &receipt_id, &blob).is_ok(),
            "a corrupt row under another vault prefix must not affect this vault"
        );

        vault
            .sync_state_put(
                &lease_key(vault_a, 0xfeed_face_feed_face),
                b"corrupt-inside-scope",
            )
            .unwrap();
        let err = verify_receipt_for_vault(&vault, vault_a, &receipt_id, &blob).unwrap_err();
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "a corrupt same-vault sibling row must fail closed: {err:?}"
        );
    }

    #[test]
    fn root_lease_mirror_keeps_foreign_vault_row_for_same_client() {
        let (_dir, vault) = test_vault();
        let doc = LoroDoc::new();
        let old_vault_id = 0x0101_0101_0101_0101;
        let new_vault_id = 0x0202_0202_0202_0202;
        let client_id = 0x0a0b_0c0d_0e0f_1011;

        let old_record = LeaseRecord {
            vault_id: old_vault_id,
            status: LeaseStatus::Active,
            pubkey: [0xA1; 32],
            granted_at: 10,
            renewed_at: 20,
            expires_at: 30,
        };
        let new_record = LeaseRecord {
            vault_id: new_vault_id,
            pubkey: [0xB2; 32],
            ..old_record
        };
        let old_key = lease_key(old_vault_id, client_id);
        let new_key = lease_key(new_vault_id, client_id);
        let old_bytes = encode_lease_record(&old_record);
        let new_bytes = encode_lease_record(&new_record);

        vault.sync_state_put(&old_key, &old_bytes).unwrap();
        doc.get_map(ROOT_LEASES_MAP)
            .insert(client_id_hex(client_id).as_str(), new_bytes.as_slice())
            .unwrap();
        doc.commit();

        mirror_leases_from_root(&vault, &doc).unwrap();
        assert_eq!(
            vault.sync_state_get(&old_key).unwrap().as_deref(),
            Some(old_bytes.as_slice()),
            "mirror cleanup must not delete a same-client row under another vault prefix"
        );
        assert_eq!(
            vault.sync_state_get(&new_key).unwrap().as_deref(),
            Some(new_bytes.as_slice())
        );
    }

    #[test]
    fn root_lease_mirror_isolates_tenants_for_same_subscriber() {
        let (_dir, vault) = test_vault();
        let doc = LoroDoc::new();
        let tenant_a = 0x0a0b_0c0d_0e0f_1011;
        let tenant_b = 0x1110_0f0e_0d0c_0b0a;
        let subscriber = 0x0123_4567_89ab_cdef;
        let record_a = LeaseRecord {
            vault_id: tenant_a,
            status: LeaseStatus::Revoked,
            pubkey: [0xA1; 32],
            granted_at: 10,
            renewed_at: 20,
            expires_at: 30,
        };
        let record_b = LeaseRecord {
            vault_id: tenant_b,
            status: LeaseStatus::Active,
            pubkey: [0xA1; 32],
            ..record_a
        };
        let bytes_a = encode_lease_record(&record_a);
        let bytes_b = encode_lease_record(&record_b);
        let leases = doc.get_map(ROOT_LEASES_MAP);
        leases
            .insert(
                lease_registry_key(tenant_a, subscriber).as_str(),
                bytes_a.as_slice(),
            )
            .unwrap();
        leases
            .insert(
                lease_registry_key(tenant_b, subscriber).as_str(),
                bytes_b.as_slice(),
            )
            .unwrap();
        doc.commit();

        mirror_leases_from_root(&vault, &doc).unwrap();

        assert_eq!(
            vault
                .sync_state_get(&lease_key(tenant_a, subscriber))
                .unwrap()
                .as_deref(),
            Some(bytes_a.as_slice()),
            "tenant A revoked replay-door row must stay under tenant A"
        );
        assert_eq!(
            vault
                .sync_state_get(&lease_key(tenant_b, subscriber))
                .unwrap()
                .as_deref(),
            Some(bytes_b.as_slice()),
            "tenant B active replay-door row must stay under tenant B"
        );
    }

    #[test]
    fn root_lease_map_value_matches_mirror_row_value() {
        let (_dir, vault) = test_vault();
        let doc = LoroDoc::new();
        let vault_id = 0x0102030405060708;
        let client_id = 0x0a0b0c0d0e0f1011;
        let record = LeaseRecord {
            vault_id,
            status: LeaseStatus::Expired,
            pubkey: [0x5A; 32],
            granted_at: 10,
            renewed_at: 20,
            expires_at: 30,
        };
        let bytes = encode_lease_record(&record);
        doc.get_map(ROOT_LEASES_MAP)
            .insert(
                lease_registry_key(vault_id, client_id).as_str(),
                bytes.as_slice(),
            )
            .unwrap();
        doc.commit();

        mirror_leases_from_root(&vault, &doc).unwrap();
        assert_eq!(
            vault
                .sync_state_get("ls:0102030405060708:0a0b0c0d0e0f1011")
                .unwrap()
                .as_deref(),
            Some(bytes.as_slice()),
            "root-doc leases value and ls: mirror value stay byte-identical"
        );
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
