//! Operator-set conversations that stay out of Dreamer consolidation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::setting::{SettingChange, SettingValue};
use crate::{EntityId, Error, Result, Vault};

/// Conversations whose turns must not enter a Dreamer consolidation pass: the value of the
/// owner's setting `dreamer.excluded_conversations`. A queued branch that spans conversations is
/// refused whole if any part is excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerExcludedConversations {
    pub version: u8,
    pub conversations: BTreeSet<EntityId>,
}

impl Default for DreamerExcludedConversations {
    fn default() -> Self {
        Self::new([])
    }
}

impl SettingValue for DreamerExcludedConversations {
    fn check(self) -> Result<Self> {
        self.validate()?;
        Ok(self)
    }
}

impl DreamerExcludedConversations {
    pub fn new(conversations: impl IntoIterator<Item = EntityId>) -> Self {
        Self {
            version: 1,
            conversations: conversations.into_iter().collect(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::InvalidConfig(
                "invalid Dreamer excluded conversations".into(),
            ));
        }
        Ok(())
    }

    pub fn contains(&self, conversation: &EntityId) -> bool {
        self.conversations.contains(conversation)
    }

    /// Whether `turn` belongs to one of these conversations, resolved in
    /// `txn`. A TURN with no conversation edge is never excluded.
    pub(crate) fn contains_turn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        turn: &EntityId,
    ) -> Result<bool> {
        if self.is_empty() {
            return Ok(false);
        }
        Ok(super::redirty::conversation_in_txn(vault, txn, turn)?
            .is_some_and(|conversation| self.contains(&conversation)))
    }

    pub fn is_empty(&self) -> bool {
        self.conversations.is_empty()
    }
}

impl Vault {
    pub fn dreamer_excluded_conversations(&self) -> Result<DreamerExcludedConversations> {
        let txn = self.store.env.read_txn()?;
        self.dreamer_excluded_conversations_in_txn(&txn)
    }

    /// Whether `turn` sits in an operator-excluded conversation, for
    /// execution doors with no ambient transaction.
    pub(crate) fn dreamer_turn_excluded(&self, turn: &EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.dreamer_excluded_conversations_in_txn(&txn)?
            .contains_turn(self, &txn, turn)
    }

    pub(crate) fn dreamer_excluded_conversations_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<DreamerExcludedConversations> {
        let setting = super::setting_keys::EXCLUDED_CONVERSATIONS
            .read_in_txn(self, txn, &[], None)?
            .value;
        setting.validate()?;
        Ok(setting)
    }
}

/// The hook of `dreamer.excluded_conversations`: words framed before the change forget the newly
/// excluded conversations in the change's own commit (FIX 12551(a)). It reads the value in force
/// after the write, not the changed row: a cleared pin over the owner's value row leaves that
/// row's conversations excluded, and they forget too. The follower never frames a conversation
/// while it is excluded, so one excluded before the change has nothing left to forget. An
/// unreadable deciding row fails the change, as it fails every reader of the key. Turns a scope's
/// watermark already stepped past while excluded are not queued again when a conversation is
/// un-excluded.
pub(super) fn forget_newly_excluded(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    _change: &SettingChange,
) -> Result<()> {
    let in_force = vault.dreamer_excluded_conversations_in_txn(txn)?;
    #[cfg(oneiron_test_support)]
    FORGOTTEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(in_force.conversations.clone());
    crate::dreamer_wake::follower::exclude_in_txn(vault, txn, &in_force.conversations)
}

/// Each set the hook asked the follower to forget in this process, oldest first: the integration
/// tests' view of the hook (`test_doors::dreamer_exclusion_forgets`).
#[cfg(oneiron_test_support)]
static FORGOTTEN: std::sync::Mutex<Vec<BTreeSet<EntityId>>> = std::sync::Mutex::new(Vec::new());

/// Each set the hook asked the follower to forget in this process, oldest first.
#[cfg(oneiron_test_support)]
pub(crate) fn forgotten_sets() -> Vec<BTreeSet<EntityId>> {
    FORGOTTEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}
