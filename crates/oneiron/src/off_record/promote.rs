//! Explicit promotion from an off-record session into the durable vault.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::lifecycle::{
    FloorWrites, live_session_entry, off_record_fence_key, session_entry_state,
    vet_off_record_session_ref,
};

const OFF_RECORD_PROMOTE_KEY_PREFIX: &[u8] = b"offrecord_promote:v0:";
const OFF_RECORD_PROMOTE_RECEIPT_VERSION: u8 = 0;

/// Durable, user-initiated receipt minted by promote. It carries opaque ids
/// only and survives the in-process session record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordPromoteReceipt {
    pub version: u8,
    pub session_ref: String,
    pub turn: [u8; 16],
    pub promoted_at: u64,
    /// Explicit-consent initiator class.
    pub initiator: String,
}

fn off_record_promote_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(OFF_RECORD_PROMOTE_KEY_PREFIX.len() + 16);
    key.extend_from_slice(OFF_RECORD_PROMOTE_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

fn encode_off_record_promote(receipt: &OffRecordPromoteReceipt) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(receipt)
        .map_err(|_| Error::InvariantViolation("off-record promote receipt encode failed"))
}

fn decode_off_record_promote(bytes: &[u8]) -> Result<OffRecordPromoteReceipt> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("off-record promote receipt"))
}

impl FloorWrites<'_> {
    /// Floor operation 3/3: commit one explicit promotion receipt while
    /// lifting the legacy fence for the promoted entity.
    pub(crate) fn commit_promote(
        &self,
        wtxn: &mut RwTxn<'_>,
        turn_id: &EntityId,
        receipt: &OffRecordPromoteReceipt,
    ) -> Result<()> {
        self.store
            .vault_meta
            .delete(wtxn, &off_record_fence_key(turn_id))?;
        self.store.vault_meta.put(
            wtxn,
            &off_record_promote_key(turn_id),
            &encode_off_record_promote(receipt)?,
        )?;
        Ok(())
    }
}

impl Vault {
    /// Promotes exactly one legacy-fenced turn under the session's
    /// per-session lock, so close and promote cannot race.
    pub fn promote_off_record_turn(
        &self,
        session_ref: &str,
        turn_id: &EntityId,
    ) -> Result<OffRecordPromoteReceipt> {
        vet_off_record_session_ref(session_ref)?;
        let entry = live_session_entry(&self.store, session_ref)?;
        let mut state = session_entry_state(&entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: session_ref.to_owned(),
            });
        }
        let mut next_record = state.record.clone();
        let position = next_record
            .fenced_turns
            .iter()
            .position(|bytes| bytes == turn_id.as_bytes())
            .ok_or_else(|| Error::OffRecordTurnNotFenced {
                session_ref: session_ref.to_owned(),
                turn_ref: turn_id.to_hex(),
            })?;
        next_record.fenced_turns.remove(position);
        next_record.promoted_turns.push(*turn_id.as_bytes());
        let receipt = OffRecordPromoteReceipt {
            version: OFF_RECORD_PROMOTE_RECEIPT_VERSION,
            session_ref: session_ref.to_owned(),
            turn: *turn_id.as_bytes(),
            promoted_at: crate::unix_seconds_now(),
            initiator: "user".to_owned(),
        };
        self.with_write_txn(|wtxn| {
            FloorWrites::new(&self.store).commit_promote(wtxn, turn_id, &receipt)
        })?;
        state.record = next_record;

        #[cfg(feature = "sync")]
        if let Err(error) = self.refresh_promoted_turn_in_live_window(turn_id) {
            tracing::warn!(
                turn = %turn_id.to_hex(),
                error = %error,
                "off-record promotion committed but live-window sync refresh deferred to recovery"
            );
        }

        Ok(receipt)
    }

    #[cfg(feature = "sync")]
    fn refresh_promoted_turn_in_live_window(&self, turn_id: &EntityId) -> Result<()> {
        use crate::sync::window::{replay_pending_mirrors, reverse_rematerialize};

        for window in self.live_windows() {
            let replayed = replay_pending_mirrors(self, &window.doc, &window.key)?;
            let mirrored = reverse_rematerialize(self, &window.doc, &window.key)?;
            tracing::debug!(
                turn = %turn_id.to_hex(),
                window = %window.key,
                replayed,
                mirrored,
                "off-record promotion refreshed live sync window"
            );
        }
        Ok(())
    }

    pub fn off_record_promote_receipt(
        &self,
        turn_id: &EntityId,
    ) -> Result<Option<OffRecordPromoteReceipt>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self
            .store
            .vault_meta
            .get(&rtxn, &off_record_promote_key(turn_id))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_off_record_promote(&bytes)?))
    }
}
