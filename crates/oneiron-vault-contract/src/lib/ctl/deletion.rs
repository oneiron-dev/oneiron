//! A managed vault's deletion (FIX 11710): what every `Ping` says once its
//! Owners deleted it, so the supervisor withdraws what served it.

use serde::{Deserialize, Deserializer, Serialize};

/// A vault its Owners deleted, as `Ping` reports it once the engine's
/// deletion marker is present (FIX 11710). From then on the vault answers
/// only what a deleted vault still serves (its holders' reads of the
/// deletion, their outcomes and receipts, leave notices, the operator's
/// door and the health probe), and runs no background pass but its backup
/// schedule and custody publication, which let its backups go at
/// `backup_retain_until`. The supervisor withdraws its relay room and routes
/// and stops the host's jobs for it; when is the supervisor's call. A
/// deletion is never undone, so a vault that reported one keeps reporting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingDeletion {
    /// When the delete-the-vault act ran, in Unix seconds on the vault's
    /// clock.
    pub deleted_at: u64,
    /// Until when the vault's backups are kept for disaster recovery, in
    /// Unix seconds on the vault's clock: the schedule lets them go at the
    /// first pass from then on, unless a legal hold defers it. `None` when
    /// the reply carried none a reader could read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_retain_until: Option<u64>,
}

/// `Ping`'s `deletion` as a supervisor reads it: absent or `null` is `None`,
/// the vault stands. A block whose `deleted_at` is not a whole number a u64
/// holds reads as `None` too, unknown, and never fails the `Ping` it rides;
/// so does such a `backup_retain_until` within a block that reads.
pub(super) fn observed<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PingDeletion>, D::Error> {
    let block = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(block.and_then(|block| {
        Some(PingDeletion {
            deleted_at: block.get("deleted_at")?.as_u64()?,
            backup_retain_until: block
                .get("backup_retain_until")
                .and_then(serde_json::Value::as_u64),
        })
    }))
}
