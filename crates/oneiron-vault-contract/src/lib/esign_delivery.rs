//! The e-sign delivery outbox's completion receipt (FIX 5306).
//!
//! A vault's e-sign delivery outbox (`--esign-delivery-outbox-dir`) hands
//! each authorized notice to the host's sender as an envelope,
//! `esign-delivery-<key>.json`, and the sender answers each one with an ack,
//! `esign-delivery-<key>.ack.json`; `key` is the lowercase-hex BLAKE3 of
//! `esign.delivery\0` and the notice's dedupe key ([`esign_delivery_stem`]).
//! When an ok ack completes a delivery attempt, the vault removes that
//! attempt's envelope, writes an [`EsignDeliveryCompleted`] receipt as
//! `esign-delivery-<key>.done.json` ([`EsignDeliveryCompleted::file_name`]),
//! and only then removes the ack. The sender takes the receipt to retire its
//! own record of that send, and removes the receipt last. While a receipt
//! stands, the vault writes no newer envelope under its key.
//!
//! A receipt means the delivery attempt completed: the sender acked it ok
//! and the vault committed that. It is not the document's own completion,
//! which is one kind of notice among others. The vault writes it whole, as
//! it writes an envelope: a private temporary sibling, synced, renamed, then
//! the directory synced.

use serde::{Deserialize, Serialize};

/// The receipt's schema version.
pub const ESIGN_DELIVERY_COMPLETED_SCHEMA_VERSION: u32 = 1;
/// The queue kind the vault keeps e-sign mail under, and every receipt's
/// `kind`.
pub const ESIGN_DELIVERY_KIND: &str = "esign.delivery";
/// Every receipt's `state`.
pub const ESIGN_DELIVERY_COMPLETED_STATE: &str = "completed";
/// The lease owner every outbox lease, and so every receipt, names.
pub const ESIGN_DELIVERY_LEASE_OWNER: &str = "esign-delivery-outbox";
/// The name prefix every outbox file of a notice shares.
pub const ESIGN_DELIVERY_FILE_PREFIX: &str = "esign-delivery-";
/// A receipt's name suffix, after its key.
pub const ESIGN_DELIVERY_DONE_SUFFIX: &str = ".done.json";

/// One delivery attempt the vault completed: the notice's dedupe key and the
/// exact lease the sender's ok ack answered. It names no recipient, body or
/// payload; the outbox it sits in names the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignDeliveryCompleted {
    /// [`ESIGN_DELIVERY_COMPLETED_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// [`ESIGN_DELIVERY_KIND`].
    pub kind: String,
    /// [`ESIGN_DELIVERY_COMPLETED_STATE`].
    pub state: String,
    /// The notice's dedupe key, exactly as its envelope carried it.
    pub dedupe_key: String,
    /// The completed try's id, 32 lowercase hex.
    pub attempt_id: String,
    /// [`ESIGN_DELIVERY_LEASE_OWNER`].
    pub lease_owner: String,
    /// The completed lease's generation within that try.
    pub attempt_count: u32,
    /// The envelope's `payload_sha256`, 64 lowercase hex.
    pub payload_sha256: String,
}

impl EsignDeliveryCompleted {
    /// Shape check of a receipt: the schema version, the literals and the
    /// hex shapes. A sender runs it on every receipt it reads, and checks
    /// the file's name against [`Self::file_name`].
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == ESIGN_DELIVERY_COMPLETED_SCHEMA_VERSION,
            "unknown receipt schema version"
        );
        anyhow::ensure!(self.kind == ESIGN_DELIVERY_KIND, "unknown receipt kind");
        anyhow::ensure!(
            self.state == ESIGN_DELIVERY_COMPLETED_STATE,
            "unknown receipt state"
        );
        anyhow::ensure!(
            self.lease_owner == ESIGN_DELIVERY_LEASE_OWNER,
            "unknown receipt lease owner"
        );
        anyhow::ensure!(
            lowercase_hex(&self.attempt_id, 32),
            "malformed receipt attempt_id"
        );
        anyhow::ensure!(
            lowercase_hex(&self.payload_sha256, 64),
            "malformed receipt payload_sha256"
        );
        Ok(())
    }

    /// The file this receipt is written as: `esign-delivery-<key>.done.json`.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!(
            "{}{ESIGN_DELIVERY_DONE_SUFFIX}",
            esign_delivery_stem(&self.dedupe_key)
        )
    }
}

/// The stem every outbox file of a notice is named by:
/// [`ESIGN_DELIVERY_FILE_PREFIX`] and the lowercase-hex BLAKE3 of
/// `esign.delivery\0` and its dedupe key.
#[must_use]
pub fn esign_delivery_stem(dedupe_key: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ESIGN_DELIVERY_KIND.as_bytes());
    hasher.update(&[0]);
    hasher.update(dedupe_key.as_bytes());
    format!("{ESIGN_DELIVERY_FILE_PREFIX}{}", hasher.finalize().to_hex())
}

/// Whether `value` is exactly `len` lowercase hex digits.
fn lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
