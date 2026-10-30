//! Channel identity selection: the selection rules, their updates and the identity pick.
//! `ChannelSelectionRuleInput` and `Memory::channel_identity_select` are its call surface.
//! Its request and view records are local definitions; `memory::channel_doors` re-exports them.

use serde::{Deserialize, Serialize};

use super::*;
use crate::channel_identity::ChannelIdentityState;
use crate::channel_identity_selection::{
    ChannelIdentityCandidate, ChannelIdentityFace, ChannelIdentitySelectionDecision,
    ChannelIdentitySelectionError, ChannelIdentitySelectionPatch, ChannelIdentitySelectionQuery,
    ChannelIdentitySelectionRule, ChannelIdentitySelectionRuleSet, ChannelIdentitySelectionWriter,
    RelationshipContext, SelectionRuleScope, SelectionRuleWriterKind,
    resolve_channel_identity_selection,
};
use crate::thread_passport::ThreadMask;

/// Authorship fields are deliberately absent. The authenticated writer and
/// engine clock stamp the persisted row.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSelectionRuleInput {
    pub rule_id: String,
    pub relationship: RelationshipContext,
    pub scope: SelectionRuleScope,
    pub face: ChannelIdentityFace,
    #[serde(default)]
    pub pinned_identity_ref: Option<EntityId>,
    pub priority: i32,
    pub enabled: bool,
    pub agent_amendable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChannelSelectionPatchInput {
    Upsert { rule: ChannelSelectionRuleInput },
    Remove { rule_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSelectionUpdateRequest {
    pub expected_revision: u64,
    pub patch: ChannelSelectionPatchInput,
}

/// Semantic face classification for a selection question, never send
/// authority. Shape and active state are read from live engine records.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSelectionCandidateInput {
    pub identity_ref: EntityId,
    pub face: ChannelIdentityFace,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSelectionRequest {
    pub relationship: RelationshipContext,
    #[serde(default)]
    pub applicable_scopes: Vec<SelectionRuleScope>,
    pub candidates: Vec<ChannelSelectionCandidateInput>,
    /// The server reads the passport pin; a caller cannot supply its mask.
    #[serde(default)]
    pub thread_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelSelectionView {
    pub revision: u64,
    pub decision: ChannelIdentitySelectionDecision,
    pub mask: ThreadMaskView,
}

fn selection_error(error: ChannelIdentitySelectionError) -> MemoryError {
    use ChannelIdentitySelectionError as E;
    let error = match error {
        E::Storage(error) => return error.into(),
        error => error,
    };
    let code = match &error {
        E::RevisionConflict { .. } | E::PinnedCandidateInactive | E::NoCandidateForFace => {
            super::super::MEMORY_CODE_INVALID_STATE
        }
        E::RuleNotAgentAmendable
        | E::AgentCannotLockRule
        | E::OwnerWriterNeedsOwnerProof
        | E::WriterClassNotAmendable
        | E::WriterNotInVault => super::super::MEMORY_CODE_FORBIDDEN,
        _ => super::super::MEMORY_CODE_BAD_REQUEST,
    };
    MemoryError::new(code, error.to_string(), &[])
}

impl Memory<'_> {
    pub fn channel_selection_rules(&self) -> MemoryResult<ChannelIdentitySelectionRuleSet> {
        super::super::support::verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        let rules = self
            .vault
            .channel_identity_selection_rules()
            .map_err(selection_error)?;
        for rule in &rules.rows {
            self.channel_selection_scope_readable(&rule.scope)?;
            if let Some(id) = rule.pinned_identity_ref {
                self.channel_readable(id)?;
            }
        }
        Ok(rules)
    }

    fn channel_selection_scope_readable(&self, scope: &SelectionRuleScope) -> MemoryResult<()> {
        match scope {
            SelectionRuleScope::World { world_ref } => self.channel_readable(*world_ref),
            SelectionRuleScope::Relationship { relationship_ref } => {
                self.channel_readable(*relationship_ref)
            }
            _ => Ok(()),
        }
    }

    /// The embedded path has an owner proof only on the constructor-owned
    /// handle. An authenticated agent remains an agent writer.
    pub fn channel_selection_update(
        &self,
        input: ChannelSelectionUpdateRequest,
    ) -> MemoryResult<ChannelIdentitySelectionRuleSet> {
        if self.actor_class == crate::EdgeActorClass::Human {
            let owner = self.embedded_owner("vault.channel_identities.selection.update")?;
            self.channel_selection_update_as(Some(&owner), input)
        } else {
            self.channel_selection_update_as(None, input)
        }
    }

    pub fn channel_selection_update_as(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: ChannelSelectionUpdateRequest,
    ) -> MemoryResult<ChannelIdentitySelectionRuleSet> {
        let writer = if let Some(owner) = owner {
            self.channel_owner(owner)?;
            ChannelIdentitySelectionWriter::owner(owner)
        } else {
            super::super::support::verify_actor_binding(self.vault, self.actor, self.actor_class)?;
            ChannelIdentitySelectionWriter::from_authenticated_write(&self.write_actor())
                .map_err(selection_error)?
        };
        let patch = match input.patch {
            ChannelSelectionPatchInput::Remove { rule_id } => {
                ChannelIdentitySelectionPatch::Remove { rule_id }
            }
            ChannelSelectionPatchInput::Upsert { rule } => {
                self.channel_selection_scope_readable(&rule.scope)?;
                if let Some(id) = rule.pinned_identity_ref {
                    self.channel_readable(id)?;
                }
                ChannelIdentitySelectionPatch::Upsert(ChannelIdentitySelectionRule {
                    rule_id: rule.rule_id,
                    relationship: rule.relationship,
                    scope: rule.scope,
                    face: rule.face,
                    pinned_identity_ref: rule.pinned_identity_ref,
                    priority: rule.priority,
                    enabled: rule.enabled,
                    agent_amendable: rule.agent_amendable,
                    updated_at: self.vault.now_recorded_at(),
                    updated_by: Some(self.actor),
                    writer_kind: SelectionRuleWriterKind::Agent,
                })
            }
        };
        self.vault
            .update_channel_identity_selection_rules(input.expected_revision, &writer, patch)
            .map_err(selection_error)
    }

    pub fn channel_identity_select(
        &self,
        input: ChannelSelectionRequest,
    ) -> MemoryResult<ChannelSelectionView> {
        let rules = self.channel_selection_rules()?;
        for scope in &input.applicable_scopes {
            self.channel_selection_scope_readable(scope)?;
        }
        let candidates = input
            .candidates
            .into_iter()
            .map(|candidate| {
                let identity = self.channel_identity_get(ChannelIdentityRequest {
                    identity_ref: candidate.identity_ref,
                    request_ref: None,
                })?;
                Ok(ChannelIdentityCandidate {
                    identity_ref: candidate.identity_ref,
                    face: candidate.face,
                    shape: identity.shape,
                    active: identity.state == ChannelIdentityState::Active,
                })
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        let pinned_mask = input
            .thread_ref
            .as_deref()
            .map(|thread| self.channel_thread_mask(thread))
            .transpose()?
            .flatten();
        let pin = match (input.thread_ref.as_deref(), pinned_mask) {
            (Some(thread), Some(mask)) => {
                Some(mask.thread_pin(self.vault.canonical_thread_ref(thread)?))
            }
            _ => None,
        };
        let decision = resolve_channel_identity_selection(
            &rules,
            ChannelIdentitySelectionQuery {
                relationship: input.relationship,
                applicable_scopes: &input.applicable_scopes,
                candidates: &candidates,
                thread_pin: pin.as_ref(),
            },
        )
        .map_err(selection_error)?;
        let mask = if let Some(mask) = pinned_mask {
            mask
        } else {
            let identity = self.channel_identity_get(ChannelIdentityRequest {
                identity_ref: decision.identity_ref,
                request_ref: None,
            })?;
            ThreadMask {
                identity_ref: decision.identity_ref,
                actor_ref: identity.binding.actor_ref().ok_or_else(|| {
                    MemoryError::bad_request("a thread mask requires an actor-bound identity")
                })?,
                facet_ref: identity.binding.facet_ref(),
            }
        };
        self.channel_mask_readable(mask)?;
        Ok(ChannelSelectionView {
            revision: rules.revision,
            decision,
            mask: mask.into(),
        })
    }
}
