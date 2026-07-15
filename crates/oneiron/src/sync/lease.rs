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
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::quarantine::{self, QuarantineContainer};

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
        let sibling = decode_scoped_lease_record(&sibling_raw, vault_id)?;
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
    Ok(Some(decode_scoped_lease_record(&raw, vault_id)?))
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
            stale_keys.push(key.into_owned());
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
mod tests;
