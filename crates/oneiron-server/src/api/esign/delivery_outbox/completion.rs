//! A completed delivery's hand-off (FIX 5306): the completion receipt the
//! sender takes to retire its own record of the send, and the slot that
//! receipt holds until the sender has taken it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use oneiron_vault_contract::esign_delivery::{
    ESIGN_DELIVERY_COMPLETED_SCHEMA_VERSION, ESIGN_DELIVERY_COMPLETED_STATE,
    ESIGN_DELIVERY_DONE_SUFFIX, EsignDeliveryCompleted,
};

use super::wire::{AckStatus, ack_binds, export, hex, parse_ack};
use super::{
    DELIVERY_KIND, LEASE_OWNER, Outbox, read_if_present, remove_if_unchanged, sync_dir,
    write_atomic,
};

impl Outbox {
    /// Hands the slot of `row`, a try its ok ack completed, to the sender, in
    /// an order a stop anywhere resumes from: the try's envelope goes and
    /// that is synced, its receipt is written whole, and its ack, until then
    /// the vault's only record that the completion still has to be handed
    /// over, goes last. A slot that holds another try's receipt keeps this
    /// ack until the sender takes that one. `Ok(true)` when the ack went.
    pub(super) fn hand_off(
        &self,
        stem: &str,
        row: &AttemptRecord,
        ack_path: &Path,
        ack_bytes: &[u8],
    ) -> anyhow::Result<bool> {
        let receipt =
            receipt(row).context("the completed try is not an e-sign notice with a dedupe key")?;
        // A receipt the sender would refuse is one this side must not write.
        receipt.validate()?;
        anyhow::ensure!(
            receipt.file_name() == format!("{stem}{ESIGN_DELIVERY_DONE_SUFFIX}"),
            "the receipt's key is not its slot's"
        );
        self.remove_envelope_of(stem, row)?;
        sync_dir(&self.dir).with_context(|| format!("sync {}", self.dir.display()))?;
        let bytes = serde_json::to_vec(&receipt)?;
        let path = self.done_path(stem);
        match read_if_present(&path)? {
            None => {
                write_atomic(&self.dir, &path, &bytes)
                    .with_context(|| format!("write {}", path.display()))?;
                tracing::info!(
                    attempt = %receipt.attempt_id,
                    %stem,
                    "esign delivery completed; its receipt is written for the sender"
                );
            }
            // The same receipt, written before a stop that left the ack.
            Some(held) if held == bytes => {}
            Some(_) => {
                tracing::info!(
                    %stem,
                    "esign delivery completion waits: its slot holds a receipt the sender has not taken"
                );
                return Ok(false);
            }
        }
        Ok(remove_if_unchanged(ack_path, ack_bytes)?)
    }

    /// Whether `stem`'s slot still holds a completion its sender has not
    /// taken: a receipt, or the ok ack of a completed try whose hand-off a
    /// failure stopped. No newer envelope replaces either, so a later lease
    /// never takes a completion from the sender.
    pub(super) fn holds_slot(&self, queue: &AttemptQueue<'_>, stem: &str) -> anyhow::Result<bool> {
        let done = self.done_path(stem);
        match fs::symlink_metadata(&done) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(anyhow::Error::new(error).context(format!("stat {}", done.display())));
            }
        }
        // An ack this tick could not read vouches for no completion; the
        // ack pass logged why.
        let Ok(Some(bytes)) = read_if_present(&self.ack_path(stem)) else {
            return Ok(false);
        };
        let Some((ack, id)) = parse_ack(&bytes) else {
            return Ok(false);
        };
        if ack.status != AckStatus::Ok {
            return Ok(false);
        }
        let Some(row) = queue.get(id)? else {
            return Ok(false);
        };
        Ok(row.kind == DELIVERY_KIND
            && row.state == AttemptState::Completed
            && ack_binds(&ack, &row, stem))
    }

    fn done_path(&self, stem: &str) -> PathBuf {
        self.dir.join(format!("{stem}{ESIGN_DELIVERY_DONE_SUFFIX}"))
    }
}

/// The receipt of `row`'s completed lease: its notice's dedupe key and the
/// exact fence its ok ack echoed.
fn receipt(row: &AttemptRecord) -> Option<EsignDeliveryCompleted> {
    let export = export(row)?;
    Some(EsignDeliveryCompleted {
        schema_version: ESIGN_DELIVERY_COMPLETED_SCHEMA_VERSION,
        kind: DELIVERY_KIND.to_owned(),
        state: ESIGN_DELIVERY_COMPLETED_STATE.to_owned(),
        dedupe_key: export.dedupe_key.to_owned(),
        attempt_id: hex(row.id.as_bytes()),
        lease_owner: LEASE_OWNER.to_owned(),
        attempt_count: row.attempt_count,
        payload_sha256: export.payload_sha256,
    })
}
