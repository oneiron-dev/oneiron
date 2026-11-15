//! The owner's message-stream policy, read from its Setting keys (DESIGN 15-setting-primitive,
//! stage 1); no token or partial content is stored here.
use super::*;
use crate::memory::setting_keys::{MESSAGE_STREAM_IDLE_TIMEOUT, MESSAGE_STREAM_MODE};
use crate::setting::SettingScope;

impl MessageStreamPolicy {
    /// The mode a call writes in: the one it names, else the policy's.
    pub(super) fn resolve(&self, explicit: Option<MessageWriteMode>) -> MessageWriteMode {
        explicit.unwrap_or(self.default_mode)
    }
}
impl Vault {
    /// The vault's message-stream policy: the vault's write mode and its idle timeout.
    pub fn message_stream_policy(&self) -> MessageStreamResult<MessageStreamPolicy> {
        policy_for(self, None)
    }
}
/// The policy in force for `actor`: its own write mode, else the vault's, and the vault's idle
/// timeout. `None` reads the vault's.
pub(super) fn policy_for(
    vault: &Vault,
    actor: Option<EntityId>,
) -> MessageStreamResult<MessageStreamPolicy> {
    let txn = vault.store.env.read_txn()?;
    let known: Vec<SettingScope> = actor.into_iter().map(SettingScope::Agent).collect();
    let default_mode = MESSAGE_STREAM_MODE
        .read_in_txn(vault, &txn, &known, None)?
        .value;
    let idle_timeout_ms = MESSAGE_STREAM_IDLE_TIMEOUT
        .read_in_txn(vault, &txn, &[], None)?
        .value
        .0;
    Ok(MessageStreamPolicy {
        default_mode,
        idle_timeout_ms,
    })
}
