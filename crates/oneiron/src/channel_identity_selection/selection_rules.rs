//! Rule and rule-set types for channel-identity selection law.

use std::cmp::Reverse;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// `None` exactly when `writer_kind` is
    /// [`SelectionRuleWriterKind::SystemDefault`].
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
        let system_default = self.writer_kind == SelectionRuleWriterKind::SystemDefault;
        if system_default != self.updated_by.is_none() {
            return Err(ChannelIdentitySelectionError::InvalidRule(
                "only a system-default row may omit updated_by",
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
/// The only constructor is [`Self::from_authenticated_write`], so a writer kind
/// is always DERIVED from an authenticated [`WriteActor`] and can never arrive
/// as caller-supplied data. There is deliberately no way to mint a
/// [`SelectionRuleWriterKind::SystemDefault`] writer: compiled law is not
/// something a caller writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdentitySelectionWriter {
    actor_ref: EntityId,
    kind: SelectionRuleWriterKind,
}

impl ChannelIdentitySelectionWriter {
    /// Derives a writer from an authenticated write actor.
    ///
    /// `Human` writes as the owner, `Agent` writes as an agent, and `System`
    /// is refused: an unattended process has no standing to rewrite the law
    /// that decides which face the vault wears.
    pub fn from_authenticated_write(actor: &WriteActor) -> ChannelIdentitySelectionResult<Self> {
        let kind = match actor.actor_class() {
            EdgeActorClass::Human => SelectionRuleWriterKind::Owner,
            EdgeActorClass::Agent => SelectionRuleWriterKind::Agent,
            EdgeActorClass::System => {
                return Err(ChannelIdentitySelectionError::WriterClassNotAmendable);
            }
        };
        Ok(Self {
            actor_ref: actor.entity_ref(),
            kind,
        })
    }

    /// Entity stamped into every row this writer touches.
    #[must_use]
    pub const fn actor_ref(&self) -> EntityId {
        self.actor_ref
    }

    /// Derived provenance class.
    #[must_use]
    pub const fn kind(&self) -> SelectionRuleWriterKind {
        self.kind
    }
}
