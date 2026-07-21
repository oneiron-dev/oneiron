//! Explicit promotion from an off-record session into the durable vault.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::lifecycle::{
    FloorWrites, OFF_RECORD_CLOSED_FENCE_VALUE, live_session_entry, off_record_fence_key,
    session_entry_state, vet_off_record_session_ref,
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

pub(super) fn off_record_promote_key(id: &EntityId) -> Vec<u8> {
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
        // CONSENT GATE: only LIFT the fence for a turn whose entity body
        // actually exists at promote time. Tag-before-write means a fenced turn
        // can sit in `fenced_turns` with no entity row yet; deleting its fence
        // would let a LATER ordinary `put_entity` for the same id sail past
        // `guard_off_record_entity_put` (which keys on the fence row) and enter
        // the durable vault UNFENCED — admitting an off-record body that was
        // never present at the time of user consent. For a body-less turn,
        // retain the sessionless closed-fence marker (empty value) instead of
        // deleting the row, so the entity write door stays shut for that id.
        if self.store.entities.get(wtxn, turn_id.as_bytes())?.is_some() {
            self.store
                .vault_meta
                .delete(wtxn, &off_record_fence_key(turn_id))?;
        } else {
            self.store.vault_meta.put(
                wtxn,
                &off_record_fence_key(turn_id),
                OFF_RECORD_CLOSED_FENCE_VALUE,
            )?;
        }
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
        // Hold the per-session state lock across the closing/gone check, the
        // durable promote commit, AND the in-process record update. This
        // serializes promote against close: close stamps `closing` under the
        // same lock, so it cannot freeze a stale `fenced_turns` snapshot in the
        // middle of a promote and then PolicyDelete a turn whose durable promote
        // receipt was just written (which would both lose user-consented data
        // and orphan a receipt for a deleted turn). Either promote fully commits
        // before close stamps closing (close then sees the turn already promoted
        // and keeps it), or promote observes closing first and bails BEFORE
        // committing. Deadlock-safe: nothing inside the write txn locks
        // `entry.state`.
        let (receipt, next_record) = {
            let mut state = session_entry_state(&entry)?;
            if state.record.closing || state.gone {
                return Err(Error::OffRecordSessionClosing {
                    session_ref: session_ref.to_owned(),
                });
            }
            let position = state
                .record
                .fenced_turns
                .iter()
                .position(|bytes| bytes == turn_id.as_bytes())
                .ok_or_else(|| Error::OffRecordTurnNotFenced {
                    session_ref: session_ref.to_owned(),
                    turn_ref: turn_id.to_hex(),
                })?;
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
            state.record.fenced_turns.remove(position);
            state.record.promoted_turns.push(*turn_id.as_bytes());
            entry.publish_state(&state);
            let next_record = state.record.clone();
            (receipt, next_record)
        };

        #[cfg(feature = "sync")]
        if let Err(error) = self.refresh_promoted_turn_in_live_window(turn_id) {
            tracing::warn!(
                turn = %turn_id.to_hex(),
                error = %error,
                "off-record promotion committed but live-window sync refresh deferred to recovery"
            );
        }
        #[cfg(feature = "sync")]
        {
            let state = session_entry_state(&entry)?;
            if state.record.closing || state.gone {
                return Err(Error::OffRecordSessionClosing {
                    session_ref: session_ref.to_owned(),
                });
            }
            if state.record != next_record {
                return Err(Error::InvariantViolation(
                    "off-record session record drifted during live-window promote refresh",
                ));
            }
        }
        #[cfg(not(feature = "sync"))]
        let _ = next_record;

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
