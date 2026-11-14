//! Durable owner policy; no token or partial content is stored here.
use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::support::verify_owner_actor_binding_in_txn;
use crate::side_table::{self, Named, SideTable};

/// Vault default message-streaming policy. Key: `()`.
const POLICY: SideTable<(), MessageStreamPolicy, Named> =
    SideTable::new(&side_table::MESSAGE_STREAM_POLICY);

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
