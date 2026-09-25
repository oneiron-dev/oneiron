//! Durable owner policy; no token or partial content is stored here.
use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::support::verify_owner_actor_binding_in_txn;
const POLICY: &[u8] = b"message_stream_policy:v1";
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
        if self.idle_timeout_ms == 0 || self.agent_overrides.len() > MAX_MESSAGE_STREAMS {
            return Err(MessageStreamError::InvalidRequest(
                "invalid idle timeout or override count",
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
    let policy = vault
        .store
        .vault_meta
        .get(txn, POLICY)?
        .map(|b| storage::decode(&b))
        .transpose()?
        .unwrap_or_default();
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
        let bytes = storage::encode(policy)?;
        self.with_verified_actor_write_txn(|txn| {
            verify_owner_actor_binding_in_txn(self.vault, txn, self.actor)?;
            self.vault.store.vault_meta.put(txn, POLICY, &bytes)?;
            Ok(())
        })?;
        Ok(())
    }
}
