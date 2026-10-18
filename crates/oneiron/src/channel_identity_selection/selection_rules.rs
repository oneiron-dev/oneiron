//! Rule and rule-set types for channel-identity selection law.

use std::cmp::Reverse;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::write_envelope::WriteActor;

use super::selection_resolution::{
    ChannelIdentitySelectionError, ChannelIdentitySelectionResult, SelectionRuleScope,
};
use super::selection_vocabulary::{
    CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION, ChannelIdentityFace, RelationshipContext,
    SelectionRuleWriterKind, is_valid_ref_token,
};

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

/// One selection row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentitySelectionRule {
    pub rule_id: String,
    pub relationship: RelationshipContext,
    pub scope: SelectionRuleScope,
    pub face: ChannelIdentityFace,
    /// Scoped override: an exact identity that must wear `face`.
    pub pinned_identity_ref: Option<EntityId>,
    pub priority: i32,
    /// A disabled row is inert: it never wins and never counts as a canonical
    /// winner, which is how an owner retires a builtin without deleting it.
    pub enabled: bool,
    pub agent_amendable: bool,
    pub updated_at: u64,
    /// `None` when `writer_kind` is [`SelectionRuleWriterKind::SystemDefault`],
    /// and on a written row once its writer was erased (FIX 3520).
    pub updated_by: Option<EntityId>,
    pub writer_kind: SelectionRuleWriterKind,
}

impl ChannelIdentitySelectionRule {
    pub(super) fn validate(&self) -> ChannelIdentitySelectionResult<()> {
        if !is_valid_ref_token(&self.rule_id) {
            return Err(ChannelIdentitySelectionError::InvalidRule(
                "rule_id must be a non-empty bounded ASCII token",
            ));
        }
        self.scope.validate()?;
        // An erased writer leaves a written row with no `updated_by`; the
        // codec keeps that apart from a row that lost its stamp.
        let system_default = self.writer_kind == SelectionRuleWriterKind::SystemDefault;
        if system_default && self.updated_by.is_some() {
            return Err(ChannelIdentitySelectionError::InvalidRule(
                "a system-default row names no updated_by",
            ));
        }
        Ok(())
    }

    /// Whether this row can win a query carrying `scopes`.
    pub(super) fn applies_to(
        &self,
        relationship: RelationshipContext,
        scopes: &[SelectionRuleScope],
    ) -> bool {
        self.enabled
            && self.relationship == relationship
            && (self.scope.is_vault_default() || scopes.contains(&self.scope))
    }

    /// Total precedence key: specificity, then priority, then recency, then
    /// the lexically smallest `rule_id`. Row ids are unique in a validated
    /// set, so the key is unique and the winner is order-independent.
    pub(super) fn precedence(&self) -> (u8, i32, u64, Reverse<&str>) {
        (
            self.scope.specificity(),
            self.priority,
            self.updated_at,
            Reverse(self.rule_id.as_str()),
        )
    }
}

/// The persisted overlay, or the compiled law. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentitySelectionRuleSet {
    pub schema_version: u16,
    pub revision: u64,
    pub rows: Vec<ChannelIdentitySelectionRule>,
}

impl ChannelIdentitySelectionRuleSet {
    /// Structural validation shared by the stored overlay and the compiled law.
    pub(super) fn validate(&self) -> ChannelIdentitySelectionResult<()> {
        if self.schema_version != CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION {
            return Err(ChannelIdentitySelectionError::SchemaVersionMismatch {
                expected: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
                stored: self.schema_version,
            });
        }
        for (index, row) in self.rows.iter().enumerate() {
            row.validate()?;
            if self.rows[..index]
                .iter()
                .any(|earlier| earlier.rule_id == row.rule_id)
            {
                return Err(ChannelIdentitySelectionError::DuplicateRuleId);
            }
        }
        self.validate_canonical_winners()
    }

    /// Exactly one enabled vault-default row may claim each relationship
    /// context. Exact-scope rows may stack; precedence orders them.
    fn validate_canonical_winners(&self) -> ChannelIdentitySelectionResult<()> {
        for context in RelationshipContext::ALL {
            let winners = self
                .rows
                .iter()
                .filter(|row| {
                    row.enabled && row.relationship == context && row.scope.is_vault_default()
                })
                .count();
            if winners > 1 {
                return Err(ChannelIdentitySelectionError::DuplicateCanonicalWinner);
            }
        }
        Ok(())
    }

    /// Validation for a record that claims to have been persisted.
    ///
    /// Revision `0` means "never amended" and is reserved for the compiled
    /// defaults, so a stored record at `0` has regressed below the baseline it
    /// was written above.
    pub(super) fn validate_stored(&self) -> ChannelIdentitySelectionResult<()> {
        if self.revision < FIRST_STORED_REVISION {
            return Err(ChannelIdentitySelectionError::RevisionRegressed {
                stored: self.revision,
                floor: FIRST_STORED_REVISION,
            });
        }
        self.validate()
    }
}

/// Revision of the first persisted overlay; the compiled defaults sit at `0`.
const FIRST_STORED_REVISION: u64 = 1;

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
