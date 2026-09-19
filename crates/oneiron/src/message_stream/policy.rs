//! Actor-bound streaming policy persistence; overrides affect only future begins.
use super::*;
use crate::memory::MemoryResult;
const POLICY_KEY: &[u8] = b"message_stream_policy:v1";
fn validate_mode(mode: MessageWriteMode) -> Result<()> {
    if matches!(
        mode,
        MessageWriteMode::Streamed {
            cadence: StreamCadence::PerWindow { milliseconds: 0 },
            ..
        }
    ) {
        return Err(Error::InvalidConfig(
            "stream cadence must be nonzero".into(),
        ));
    }
    Ok(())
}
pub(super) fn validate_policy(policy: &MessageStreamPolicy) -> Result<()> {
    validate_mode(policy.default_mode)?;
    if policy.idle_timeout_ms == 0 {
        return Err(Error::InvalidConfig(
            "stream idle timeout must be nonzero".into(),
        ));
    }
    for (actor, mode) in &policy.agent_overrides {
        EntityId::from_hex(actor)?;
        validate_mode(*mode)?;
    }
    Ok(())
}
impl Vault {
    pub fn message_stream_policy(&self) -> Result<MessageStreamPolicy> {
        let txn = self.store.env.read_txn()?;
        let policy = match self.store.vault_meta.get(&txn, POLICY_KEY)? {
            Some(bytes) => rmp_serde::from_slice(&bytes)
                .map_err(|_| Error::CorruptedIndex("message stream policy"))?,
            None => MessageStreamPolicy::default(),
        };
        validate_policy(&policy)?;
        Ok(policy)
    }
    /// Only the bound owner can change the vault-wide defaults or another actor's override.
    pub fn set_message_stream_policy(
        &self,
        policy: &MessageStreamPolicy,
        actor: WriteActor,
    ) -> MemoryResult<()> {
        validate_policy(policy)?;
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                crate::memory::verify_owner_actor_binding_in_txn(self, txn, actor.entity_ref())?;
                let bytes = rmp_serde::to_vec_named(policy)
                    .map_err(|_| Error::InvariantViolation("stream policy encode"))?;
                self.store.vault_meta.put(txn, POLICY_KEY, &bytes)?;
                Ok(())
            })
    }
    /// A bound agent may set its own override; it cannot alter another actor.
    pub fn set_agent_message_stream_override(
        &self,
        mode: Option<MessageWriteMode>,
        actor: WriteActor,
    ) -> MemoryResult<()> {
        if let Some(mode) = mode {
            validate_mode(mode)?;
        }
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                let mut policy: MessageStreamPolicy =
                    match self.store.vault_meta.get(txn, POLICY_KEY)? {
                        Some(bytes) => rmp_serde::from_slice(&bytes)
                            .map_err(|_| Error::CorruptedIndex("message stream policy"))?,
                        None => Default::default(),
                    };
                if let Some(mode) = mode {
                    policy
                        .agent_overrides
                        .insert(actor.entity_ref().to_hex(), mode);
                } else {
                    policy.agent_overrides.remove(&actor.entity_ref().to_hex());
                }
                validate_policy(&policy)?;
                self.store.vault_meta.put(
                    txn,
                    POLICY_KEY,
                    &rmp_serde::to_vec_named(&policy)
                        .map_err(|_| Error::InvariantViolation("stream policy encode"))?,
                )?;
                Ok(())
            })
    }
}
