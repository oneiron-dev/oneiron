//! Durable owner policy; no token or partial content is stored here.
use super::*;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::support::verify_owner_actor_binding_in_txn;
use crate::side_table::{self, Named, SideTable};

/// Vault default message-streaming policy. Key: `()`.
const POLICY: SideTable<(), MessageStreamPolicy, Named> =
    SideTable::new(&side_table::MESSAGE_STREAM_POLICY);
impl MessageWriteMode {
    pub(super) fn validate(self) -> MessageStreamResult<()> {
        if matches!(
            self,
            Self::Streamed {
                cadence: StreamCadence::PerWindow { chars: 0 },
                ..
            }
        ) {
            return Err(MessageStreamError::InvalidRequest(
                "window must be positive",
            ));
        }
        Ok(())
    }
}
impl MessageStreamPolicy {
    fn validate(&self) -> MessageStreamResult<()> {
        if self.idle_timeout_ms == 0 {
            return Err(MessageStreamError::InvalidRequest(
                "idle timeout must be positive",
            ));
        }
        self.default_mode.validate()?;
        for mode in self.agent_overrides.values() {
            mode.validate()?;
        }
        Ok(())
    }
    pub(super) fn resolve(
        &self,
        actor: &EntityId,
        explicit: Option<MessageWriteMode>,
    ) -> MessageWriteMode {
        explicit
            .or_else(|| self.agent_overrides.get(actor).copied())
            .unwrap_or(self.default_mode)
    }
}
impl Vault {
    pub fn message_stream_policy(&self) -> MessageStreamResult<MessageStreamPolicy> {
        let txn = self.store.env.read_txn()?;
        policy_in_txn(self, &txn)
    }
}
pub(super) fn policy_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> MessageStreamResult<MessageStreamPolicy> {
    let policy = POLICY.get(&vault.store, txn, &())?.unwrap_or_default();
    MessageStreamPolicy::validate(&policy)?;
    Ok(policy)
}
impl Memory<'_> {
    /// Changes vault defaults only through the live human owner authority door.
    pub fn set_message_stream_policy(
        &self,
        policy: &MessageStreamPolicy,
    ) -> MessageStreamResult<()> {
        policy.validate()?;
        if self.actor_class != EdgeActorClass::Human {
            return Err(MessageStreamError::WrongActor);
        }
        POLICY.encode_value(policy)?;
        self.with_verified_actor_write_txn(|txn| {
            verify_owner_actor_binding_in_txn(self.vault, txn, self.actor)?;
            POLICY.put(&self.vault.store, txn, &(), policy)?;
            Ok(())
        })?;
        Ok(())
    }
}

impl Vault {
    /// Lands one archived `MESSAGE_STREAM_POLICY` envelope in `txn`: canonical decode and the
    /// credential predicate, then the setter's own validation. Agent override ids are dormant
    /// match keys, so they need no lookup; open sessions keep their snapped settings.
    ///
    /// # Errors
    /// Storage faults; validation stays in the returned outcome.
    pub(crate) fn land_archived_message_stream_policy_row_in_txn(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        permit: &OwnerArchiveRestorePermit,
        row: &ArchiveRetainedSideRow,
    ) -> Result<ArchivedSideRowOutcome> {
        let (key, value) = match decode_archived_row(&POLICY, row) {
            Ok(decoded) => decoded,
            Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
        };
        if value.validate().is_err() {
            return Ok(ArchivedSideRowOutcome::HeldBack(
                RetainedSideHeldBackReason::InvalidValue,
            ));
        }
        install_archived_row(&POLICY, vault, txn, permit, &key, row)
    }
}
