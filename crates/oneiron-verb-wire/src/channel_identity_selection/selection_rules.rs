//! Moved from `crates/oneiron/src/channel_identity_selection/selection_rules.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::channel_identity_selection::selection_resolution::ChannelIdentitySelectionError;
use crate::channel_identity_selection::selection_resolution::ChannelIdentitySelectionResult;
use crate::channel_identity_selection::selection_resolution::SelectionRuleScope;
use oneiron_authority::channel_selection_vocabulary::CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION;
use oneiron_authority::channel_selection_vocabulary::ChannelIdentityFace;
use oneiron_authority::channel_selection_vocabulary::RelationshipContext;
use oneiron_authority::channel_selection_vocabulary::SelectionRuleWriterKind;
use oneiron_authority::channel_selection_vocabulary::is_valid_ref_token;
use oneiron_contracts::entity_id::EntityId;
use std::cmp::Reverse;

/// One selection row.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
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
    pub fn validate(&self) -> ChannelIdentitySelectionResult<()> {
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
    pub fn applies_to(
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
    pub fn precedence(&self) -> (u8, i32, u64, Reverse<&str>) {
        (
            self.scope.specificity(),
            self.priority,
            self.updated_at,
            Reverse(self.rule_id.as_str()),
        )
    }
}

/// The persisted overlay, or the compiled law. See the module docs.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentitySelectionRuleSet {
    pub schema_version: u16,
    pub revision: u64,
    pub rows: Vec<ChannelIdentitySelectionRule>,
}

impl ChannelIdentitySelectionRuleSet {
    /// Structural validation shared by the stored overlay and the compiled law.
    pub fn validate(&self) -> ChannelIdentitySelectionResult<()> {
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
    pub fn validate_stored(&self) -> ChannelIdentitySelectionResult<()> {
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
pub const FIRST_STORED_REVISION: u64 = 1;
