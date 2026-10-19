//! The vault's "Learn from my conversations" setting (FIX 5502 owner
//! rulings, OF-420), and its wire codec.
//!
//! The owner's rulings (10-19, "my casa my rules"): one setting per vault,
//! set by its admin and off until the admin turns it on. While it is on,
//! everything in the vault counts, people, agents and guests alike; private
//! worlds never do. The admin may also let people opt out
//! (`allow_opt_out`, off unless turned on): then a person's own
//! [`ConversationTrainingSet`] leaves their messages out.
//!
//! The install that served the admin, a live machine of the vault in any
//! role, signs the setting with its install key; it carries their act
//! ([`OwnerAct`], kind `conversation_training`, `owner` the admin's PERSON,
//! target the vault: [`conversation_training_vault_target`]) and its `seen`
//! is the vault's live setting choices as the deciding surface showed them,
//! under [`CONVERSATION_TRAINING_VAULT_REVISION_CONTEXT`]. Who may set it
//! (the vault's live owner, or a shared vault's Owner or Admin holding the
//! workspace-settings power) is the writer's rule, judged in the writing
//! transaction. No Grant action names it, so an agent's act never makes it.
//! It is a main-log entry, so every machine the owner admits folds it.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_CONVERSATION_TRAINING_VAULT: &str = "conversation_training_vault";
const CONVERSATION_TRAINING_VAULT_KEYS: [&str; 5] =
    [OP_KEY_KIND, OP_KEY_ACT, "machine", "on", "allow_opt_out"];
/// The domain of a setting act's `seen`, beside a person's opt-out's
/// ([`CONVERSATION_TRAINING_REVISION_CONTEXT`]): BLAKE3 over it and the
/// vault's sorted live setting choice hashes, in the `PolicyRevision` shape.
pub const CONVERSATION_TRAINING_VAULT_REVISION_CONTEXT: &[u8] =
    b"oneiron/conversation-training-vault-revision/v1";

/// The target a setting act names: the vault itself, as the
/// content-addressed id of its genesis row, the checkpoint policy's target
/// ([`checkpoint_policy_target`]), so every install names the same one.
pub fn conversation_training_vault_target(vault_id: &AuthorityVaultId) -> Result<EntityId> {
    checkpoint_policy_target(vault_id)
}

/// One admin choice of the vault's training setting, signed by the install
/// key of `machine`, a live machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationTrainingVaultSet {
    /// The admin's act: who decided, from which surface, on which of the
    /// vault's setting revisions. Its kind is `conversation_training` and
    /// its target the vault ([`conversation_training_vault_target`]).
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the choice.
    pub machine: EntityId,
    /// Whether the vault's conversations count for training.
    pub on: bool,
    /// Whether a person's own opt-out counts.
    pub allow_opt_out: bool,
}

impl ConversationTrainingVaultSet {
    pub fn validate(&self) -> Result<()> {
        // The admin's own say-so: no Grant action names it, and no ask
        // answers it.
        if self.act.act != OwnerActKind::ConversationTraining
            || self.act.by != ActBy::Owner
            || self.act.answer.is_some()
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The act names the entry's own vault.
    pub fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        let vault_id = entry.vault_id.ok_or_else(invalid_authority)?;
        self.act.validate_carried(
            OwnerActKind::ConversationTraining,
            conversation_training_vault_target(&vault_id)?,
        )
    }
}

pub(super) fn conversation_training_vault_value(set: &ConversationTrainingVaultSet) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_CONVERSATION_TRAINING_VAULT),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&set.act),
        ),
        (Value::from("machine"), Value::from(set.machine.to_hex())),
        (Value::from("on"), Value::from(set.on)),
        (Value::from("allow_opt_out"), Value::from(set.allow_opt_out)),
    ])
}

/// Booleans `on` and `allow_opt_out`; nothing else.
pub(super) fn decode_conversation_training_vault(
    entries: &[(Value, Value)],
) -> Result<AuthorityOp> {
    validate_keys(entries, &CONVERSATION_TRAINING_VAULT_KEYS)?;
    let flag = |name: &str| {
        required(entries, name)?
            .as_bool()
            .ok_or_else(invalid_authority)
    };
    Ok(AuthorityOp::ConversationTrainingVaultSet(
        ConversationTrainingVaultSet {
            act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
            machine: decode_canonical_id(required(entries, "machine")?)?,
            on: flag("on")?,
            allow_opt_out: flag("allow_opt_out")?,
        },
    ))
}
