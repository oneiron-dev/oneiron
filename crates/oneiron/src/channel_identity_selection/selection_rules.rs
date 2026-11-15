//! Rule and rule-set types for channel-identity selection law.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::write_envelope::WriteActor;

use super::selection_resolution::{ChannelIdentitySelectionError, ChannelIdentitySelectionResult};
use super::selection_vocabulary::SelectionRuleWriterKind;

/// Canonical field order of the persisted rule-set map.
pub(super) const RULE_SET_KEYS: [&str; 3] = ["schema_version", "revision", "rows"];

/// Canonical field order of one persisted rule map.
pub(super) const RULE_KEYS: [&str; 11] = [
    "rule_id",
    "relationship",
    "scope",
    "face",
    "pinned_identity_ref",
    "priority",
    "enabled",
    "agent_amendable",
    "updated_at",
    "updated_by",
    "writer_kind",
];

#[doc(hidden)]
pub use oneiron_verb_wire::channel_identity_selection::selection_rules::{
    ChannelIdentitySelectionRule, ChannelIdentitySelectionRuleSet,
};

/// An authenticated writer of selection rules.
///
/// The owner's writer comes only from an [`AuthenticatedOwner`], and an
/// agent's from its [`WriteActor`]. A write actor's class is caller-asserted,
/// so it can name an agent but never mint the owner's writer. The write door
/// checks both again inside its transaction.
/// There is deliberately no way to mint a
/// [`SelectionRuleWriterKind::SystemDefault`] writer: compiled law is not
/// something a caller writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentitySelectionWriter {
    kind: SelectionRuleWriterKind,
    owner: Option<AuthenticatedOwner>,
    /// The agent's write actor, frontier included, rechecked against the
    /// authority fold at the write.
    agent: Option<WriteActor>,
}

impl ChannelIdentitySelectionWriter {
    /// The owner's writer, from the owner's authentication.
    #[must_use]
    pub fn owner(owner: &AuthenticatedOwner) -> Self {
        Self {
            kind: SelectionRuleWriterKind::Owner,
            owner: Some(owner.clone()),
            agent: None,
        }
    }

    /// Derives an agent's writer from its write actor.
    ///
    /// `Agent` writes as an agent. `Human` is refused: the owner writes through
    /// [`Self::owner`]. `System` is refused: an unattended process has no
    /// standing to rewrite the law that decides which face the vault wears.
    pub fn from_authenticated_write(actor: &WriteActor) -> ChannelIdentitySelectionResult<Self> {
        match actor.actor_class() {
            EdgeActorClass::Agent => Ok(Self {
                kind: SelectionRuleWriterKind::Agent,
                owner: None,
                agent: Some(*actor),
            }),
            EdgeActorClass::Human => Err(ChannelIdentitySelectionError::OwnerWriterNeedsOwnerProof),
            EdgeActorClass::System => Err(ChannelIdentitySelectionError::WriterClassNotAmendable),
        }
    }

    /// The writer still holds in the write's own transaction: the owner proof
    /// belongs to this vault, is live and names this vault's owner (a native
    /// proof of any other person is no owner's writer), and an agent writer
    /// names a live actor of this vault whose type can act as an agent and, in
    /// a rooted vault, whose authority binding is live. Returns the actor
    /// stamped into every row the write touches: the owner's from the proof's
    /// revalidation, never from the proof's fields.
    pub(super) fn revalidate_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> ChannelIdentitySelectionResult<EntityId> {
        if let Some(owner) = &self.owner {
            return Ok(owner.revalidate_as_vault_owner_in_txn(vault, txn)?);
        }
        let Some(agent) = &self.agent else {
            return Err(ChannelIdentitySelectionError::WriterNotInVault);
        };
        let actor_ref = agent.entity_ref();
        let live_type =
            crate::vault::live_entity_row_in_txn(&vault.store, txn, &actor_ref)?.live_type();
        if !live_type.is_some_and(|entity_type| {
            crate::provenance::validate_actor_class(entity_type, EdgeActorClass::Agent).is_ok()
        }) {
            return Err(ChannelIdentitySelectionError::WriterNotInVault);
        }
        vault.verify_write_actor_in_txn(txn, agent)?;
        Ok(actor_ref)
    }

    /// Derived provenance class.
    #[must_use]
    pub const fn kind(&self) -> SelectionRuleWriterKind {
        self.kind
    }
}
