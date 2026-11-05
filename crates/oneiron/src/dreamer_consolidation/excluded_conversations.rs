//! Operator-set conversations that stay out of Dreamer consolidation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Operator-set Dreamer conversation exclusions. Key: ().
const EXCLUDED_CONVERSATIONS: SideTable<(), DreamerExcludedConversations, Named> =
    SideTable::new(&side_table::DREAMER_EXCLUDED_CONVERSATIONS);

/// Conversations whose turns must not enter a Dreamer consolidation pass.
/// A queued branch that spans conversations is refused whole if any part is
/// excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Operator configuration seam, like the selection row. It is not an agent
    /// verb; the live server exposes it only through its owner Dreamer route,
    /// and the owner proof is revalidated inside the write transaction, so a
    /// credential revoked while the request queued for the writer cannot
    /// still replace or clear the row.
    /// Replace semantics: writing an empty set clears the row, and setting the
    /// same value again rewrites the same row. Readers load it per round/pass,
    /// so it may be set any time before the first wake or resume. Turns a
    /// scope's watermark already stepped past while excluded are not
    /// retroactively queued if the conversation is later un-excluded.
    pub fn set_dreamer_excluded_conversations(
        &self,
        owner: &AuthenticatedOwner,
        setting: &DreamerExcludedConversations,
    ) -> Result<()> {
        setting.validate()?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let previous = EXCLUDED_CONVERSATIONS
                .get(&self.store, txn, &())?
                .unwrap_or_default();
            EXCLUDED_CONVERSATIONS.put(&self.store, txn, &(), setting)?;
            // Words framed before this commit forget the newly excluded
            // conversations in the same commit (FIX 12551(a)).
            let newly: BTreeSet<EntityId> = setting
                .conversations
                .difference(&previous.conversations)
                .copied()
                .collect();
            crate::dreamer_wake::follower::exclude_in_txn(self, txn, &newly)
        })
    }

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
        let setting = EXCLUDED_CONVERSATIONS
            .get(&self.store, txn, &())?
            .unwrap_or_default();
        setting.validate()?;
        Ok(setting)
    }
}
