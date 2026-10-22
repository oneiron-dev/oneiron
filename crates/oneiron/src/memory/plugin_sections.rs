//! Plugin Context Board sections (DOOR-112, e2e BOARD-07): the typed
//! `vault.packs.sections.*` doors over the engine's section-manifest seam.
//! A caller proposes one typed [`SectionManifestEnvelope`] for an existing
//! skill or a pinned hub package; the proposal lands as the existing
//! Generated/Proposed `plugin.section_install` claim and renders nothing.
//! The owner grants exactly the reviewed claim (the `vault.claims.review`
//! handle binds its content) and the post-consent executor admits the
//! section; the owner revokes by retracting that claim, after which no
//! rebuild renders the section or reaches its verbs. A caller-triggered
//! suggestion pass runs the Dreamer analyze-to-propose job over one pinned
//! hub: repetition nominates a pack, it never installs or consents, and the
//! owner's suggestion knob silences the pass before any catalog access.
use serde::{Deserialize, Serialize};

use super::{
    ClaimSettleDecision, ClaimSettleRequest, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    Memory, MemoryError, MemoryResult,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::consent::AuthenticatedOwner;
use crate::context_board::{
    EngineSectionBindings, PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload,
    PluginInstallOrigin, PluginInstallTarget, PluginSectionAdmission, PluginSectionError,
    PluginSectionRegistry, SectionManifestEnvelope, VaultPluginInstallExecutor,
    VaultPluginInstallSource, digest_to_hex, execute_approved_plugin_section_install,
    propose_plugin_section_install,
};
use crate::dreamer_plugin_suggest::{
    LocalSkillHubPackCatalog, PluginSuggestJob, PluginSuggestionDisposition, WorkflowPatternNotice,
    run_plugin_suggestion_job,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::skill_hub::pack_catalog::PackSection;
use crate::skill_hub::{HubRef, RefFetch, pinned_tracking};
use crate::write_envelope::{WriteActor, WriteProvenance};

mod pages;

/// The plugin seam's refusals as this surface's errors: a missing claim is
/// not found, an unapproved one is invalid state, a stored vault error keeps
/// its own mapping, and every other validation refusal is the caller's to fix.
fn plugin_error(error: PluginSectionError) -> MemoryError {
    match error {
        PluginSectionError::Vault(inner) => MemoryError::from(inner),
        PluginSectionError::ClaimNotFound => {
            MemoryError::not_found("no plugin section install claim has that ref")
        }
        PluginSectionError::ClaimNotApproved | PluginSectionError::MissingPendingConsent => {
            MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                error.to_string(),
                &["Grant the reviewed proposal first."],
            )
        }
        other => MemoryError::bad_request(other.to_string()),
    }
}

fn claim_id(claim_ref: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(claim_ref.trim()).map_err(|_| {
        MemoryError::bad_request_with(
            "claim_ref is the 32-hex ref a plugin section proposal returned",
            &["Pass the claim_ref of vault.packs.sections.propose or vault.packs.sections.list."],
        )
    })
}

/// Which exact skill bytes one manifest proposal is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PluginSectionTargetInput {
    /// An already-imported skill, Candidate or Active.
    ExistingSkill {
        /// The skill entity.
        skill_ref: EntityId,
    },
    /// An uninstalled pinned hub package; no byte is written before consent.
    HubPackage {
        /// The pinned hub ref the package is fetched at.
        hub_ref: HubRef,
        /// The preallocated ref the consented import lands at.
        target_skill_ref: EntityId,
    },
}

impl From<&PluginSectionTargetInput> for PluginInstallTarget {
    fn from(target: &PluginSectionTargetInput) -> Self {
        match target {
            PluginSectionTargetInput::ExistingSkill { skill_ref } => {
                PluginInstallTarget::ExistingSkill {
                    skill_ref: *skill_ref,
                }
            }
            PluginSectionTargetInput::HubPackage {
                hub_ref,
                target_skill_ref,
            } => PluginInstallTarget::HubPackage {
                hub_ref: hub_ref.clone(),
                target_skill_ref: *target_skill_ref,
            },
        }
    }
}

/// `vault.packs.sections.propose`'s input: one typed manifest, its exact
/// target, and the conversation turn that initiated the offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionProposeRequest {
    pub manifest: SectionManifestEnvelope,
    pub target: PluginSectionTargetInput,
    /// The initiating turn, as an opaque ref string.
    pub turn_ref: String,
}

/// One offered plugin section: the proposed install claim awaiting the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionProposal {
    /// The install claim (32 hex).
    pub claim_ref: String,
    /// Its pending-consent tray row (`gate:<hex>`).
    pub pending_ref: String,
    /// SHA-256 of the canonical manifest bytes, lowercase hex.
    pub manifest_digest: String,
    pub section_id: String,
    /// The validated manifest the owner is asked to grant.
    pub manifest: SectionManifestEnvelope,
}

/// `vault.packs.sections.list`'s input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionListRequest {
    /// Pending proposals on this page (default 256). A page size, not a cap:
    /// a larger request is served in full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// The `next_cursor` of the previous page; none starts at the oldest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// One install still awaiting owner consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionPendingRow {
    pub claim_ref: String,
    pub pack_id: String,
    pub section_id: String,
    pub label: String,
    /// `conversation` or `dreamer_suggestion`.
    pub origin: String,
    pub awaiting_owner_consent: bool,
}

/// One admitted plugin section and the exact manifest it was granted under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionAdmittedRow {
    pub claim_ref: String,
    pub section_id: String,
    pub manifest: SectionManifestEnvelope,
}

/// One pack-origin section projected from an Active pinned pack install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionPackRow {
    pub section_id: String,
    pub pack_name: String,
    pub source_id: String,
    pub content_hash: String,
    pub section: PackSection,
}

/// `vault.packs.sections.list`'s answer: one page of what waits, every
/// admitted section, what installed packs project, plus the pack section
/// names the renderer produces from that same registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionsView {
    /// This page of pending proposals, oldest consent first.
    pub pending: Vec<PluginSectionPendingRow>,
    /// Every pending proposal in this read snapshot, across pages.
    pub pending_total: u64,
    /// Pending proposals after this page.
    pub pending_remaining: u64,
    /// The cursor for the next page of pending proposals; none at the end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// True when this page holds the last pending proposal.
    pub end: bool,
    pub admitted: Vec<PluginSectionAdmittedRow>,
    pub pack_sections: Vec<PluginSectionPackRow>,
    pub rendered_pack_sections: Vec<String>,
}

/// `vault.packs.sections.grant`'s input. A still-proposed claim is settled
/// through its review handle; an already-approved one (settled through
/// `vault.claims.settle`) grants with no handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionGrantRequest {
    /// The install claim (32 hex).
    pub claim_ref: String,
    /// The handle `vault.claims.review` returned for exactly this claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_id: Option<String>,
}

/// What one grant concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginSectionGrantState {
    /// The section is admitted and renders.
    Admitted,
    /// The supplying skill is not Active yet; a later rebuild admits the
    /// section once the existing skill doors activate it.
    PendingActivation,
}

/// `vault.packs.sections.grant`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionGrant {
    pub claim_ref: String,
    pub state: PluginSectionGrantState,
    /// The section, when it was admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
    /// The supplying skill (32 hex).
    pub skill_ref: String,
    /// The Settlement receipt (`gate:<hex>`), when this grant settled the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_receipt_ref: Option<String>,
    /// The exact manifest that was granted.
    pub manifest: SectionManifestEnvelope,
}

/// `vault.packs.sections.revoke`'s input: one install claim, or every live
/// install claim of one section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionRevokeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
}

/// `vault.packs.sections.revoke`'s answer: the retracted install claims.
/// Their sections and advertised verbs vanish from the next rebuild; the
/// supplying skill itself stays installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
    pub claim_refs: Vec<String>,
    pub revoked: u32,
}

/// `vault.packs.sections.suggest`'s input: one typed workflow-pattern
/// notice, and the pinned hub ref whose catalog the pass reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionSuggestRequest {
    pub hub_ref: HubRef,
    /// The run that observed the pattern.
    pub run_id: String,
    /// The digest window the suggestion belongs to.
    pub digest_window: String,
    /// Stable typed pattern key (the state family a pack serves), never prose.
    pub pattern_key: String,
    /// Owner-facing narration of the observation; never parsed.
    pub summary: String,
    /// Entities the observation rests on; the claim's evidence.
    pub evidence_refs: Vec<EntityId>,
    pub observed_at: u64,
}

/// What one suggestion pass concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginSectionSuggestionState {
    /// The owner switched suggestions off; no catalog was consulted.
    Disabled,
    /// The catalog offered nothing for this pattern.
    NoMatch,
    /// This exact suggestion was already put to the owner.
    SuppressedDuplicate,
    /// One install claim now awaits owner consent.
    Proposed,
}

/// `vault.packs.sections.suggest`'s answer: an attributed proposal at most.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionSuggestion {
    pub state: PluginSectionSuggestionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// The owner's plugin-suggestion knob as `vault.packs.sections.suggestions.get`
/// and `.set` answer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSuggestionsView {
    pub enabled: bool,
}

/// `vault.packs.sections.suggestions.set`'s input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSuggestionsSetRequest {
    pub enabled: bool,
}

impl Memory<'_> {
    /// The proof's person must be this handle's own human actor, as the
    /// claim settlement doors require.
    fn plugin_section_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<EntityId> {
        let person = owner.revalidate(self.vault())?;
        if person != self.actor() || self.actor_class() != EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a plugin section grant is the vault owner's, on the owner's own handle",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(person)
    }

    /// Offers one typed section manifest on the caller's own credential:
    /// validates the exact candidate bytes and lands one Proposed install
    /// claim. Imports nothing, registers nothing, renders nothing.
    pub fn plugin_section_propose(
        &self,
        input: &PluginSectionProposeRequest,
    ) -> MemoryResult<PluginSectionProposal> {
        let vault = self.vault();
        let provenance = WriteProvenance::new(rmpv::Value::Map(vec![(
            rmpv::Value::from("surface"),
            rmpv::Value::from("vault.packs.sections.propose"),
        )]))
        .map_err(MemoryError::from)?;
        let proposal = propose_plugin_section_install(
            vault,
            WriteActor::new(self.actor(), self.actor_class()),
            provenance,
            PluginInstallTarget::from(&input.target),
            &input.manifest,
            PluginInstallOrigin::Conversation {
                turn_ref: input.turn_ref.clone(),
            },
            &VaultPluginInstallSource { vault },
            &EngineSectionBindings,
            vault.now_recorded_at(),
        )
        .map_err(plugin_error)?;
        self.produced_from([proposal.claim_id]);
        Ok(PluginSectionProposal {
            claim_ref: proposal.claim_id.to_hex(),
            pending_ref: format!("gate:{}", proposal.decision_id.to_hex()),
            manifest_digest: digest_to_hex(&proposal.manifest_digest),
            section_id: input.manifest.manifest.section_id.0.clone(),
            manifest: input.manifest.clone(),
        })
    }

    /// The owner's grant: settles exactly the reviewed install claim when it
    /// still waits, then runs the post-consent executor under that approved
    /// claim. One consent covers install plus section admission.
    pub fn plugin_section_grant_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &PluginSectionGrantRequest,
    ) -> MemoryResult<PluginSectionGrant> {
        self.plugin_section_owner(owner)?;
        let vault = self.vault();
        let id = claim_id(&input.claim_ref)?;
        let body = vault
            .get_claim(&id)?
            .ok_or_else(|| MemoryError::not_found("no claim has that ref"))?;
        if body.predicate != PREDICATE_PLUGIN_SECTION_INSTALL {
            return Err(MemoryError::bad_request(
                "the claim is no plugin section install",
            ));
        }
        let manifest = PluginInstallClaimPayload::from_value(&body.value)
            .and_then(|payload| payload.manifest())
            .map_err(plugin_error)?;
        let settlement_receipt_ref = if body.approval == ClaimApprovalStatus::Proposed
            && body.lifecycle == ClaimLifecycleStatus::Active
        {
            let review_id = input.review_id.as_deref().ok_or_else(|| {
                MemoryError::bad_request_with(
                    "a proposed install grants through its review_id",
                    &["Review the claim with vault.claims.review and pass its review_id."],
                )
            })?;
            let settlement = self.claim_settle_as_owner(
                owner,
                &ClaimSettleRequest {
                    claim_ref: input.claim_ref.clone(),
                    review_id: review_id.to_owned(),
                    decision: ClaimSettleDecision::Approve,
                },
            )?;
            Some(settlement.receipt_ref)
        } else if body.approval == ClaimApprovalStatus::Approved
            && body.lifecycle == ClaimLifecycleStatus::Active
            && !body.stale
        {
            None
        } else {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the install claim is no live proposal or approved grant",
                &["Offer the section again with vault.packs.sections.propose."],
            ));
        };
        let mut registry = PluginSectionRegistry::new();
        let admission = execute_approved_plugin_section_install(
            vault,
            &mut registry,
            id,
            &VaultPluginInstallExecutor { vault },
            &EngineSectionBindings,
            vault.now_recorded_at(),
        )
        .map_err(plugin_error)?;
        self.produced_from([id]);
        Ok(match admission {
            PluginSectionAdmission::Admitted {
                skill_ref,
                section_id,
            } => PluginSectionGrant {
                claim_ref: id.to_hex(),
                state: PluginSectionGrantState::Admitted,
                section_id: Some(section_id.0),
                skill_ref: skill_ref.to_hex(),
                settlement_receipt_ref,
                manifest,
            },
            PluginSectionAdmission::PendingActivation { skill_ref } => PluginSectionGrant {
                claim_ref: id.to_hex(),
                state: PluginSectionGrantState::PendingActivation,
                section_id: None,
                skill_ref: skill_ref.to_hex(),
                settlement_receipt_ref,
                manifest,
            },
        })
    }

    /// The owner's revoke: retracts the live install claim(s) in one writer,
    /// with the owner's proof and every guard rechecked inside that same
    /// transaction, so the section and its verbs leave the next rebuild.
    pub fn plugin_section_revoke_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &PluginSectionRevokeRequest,
    ) -> MemoryResult<PluginSectionRevoked> {
        let vault = self.vault();
        let mut section_id = input.section_id.clone();
        let ids: Vec<EntityId> = if let Some(claim_ref) = &input.claim_ref {
            vec![claim_id(claim_ref)?]
        } else if let Some(wanted) = &input.section_id {
            let rtxn = vault
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            vault
                .claims_with_predicate_in_txn(&rtxn, PREDICATE_PLUGIN_SECTION_INSTALL)?
                .into_iter()
                .filter(|(_, body)| body.lifecycle == ClaimLifecycleStatus::Active)
                .filter_map(|(id, body)| {
                    PluginInstallClaimPayload::from_value(&body.value)
                        .ok()
                        .filter(|payload| payload.section_id.0 == *wanted)
                        .map(|_| id)
                })
                .collect()
        } else {
            return Err(MemoryError::bad_request(
                "name a claim_ref or a section_id to revoke",
            ));
        };
        if ids.is_empty() {
            return Err(MemoryError::not_found(
                "no live plugin section install matches",
            ));
        }
        let now = vault.now_recorded_at();
        let revoked = vault.try_with_write_txn_grouped(|wtxn| -> MemoryResult<Vec<EntityId>> {
            let person = owner.revalidate_in_txn(vault, &*wtxn)?;
            if person != self.actor() || self.actor_class() != EdgeActorClass::Human {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "a plugin section grant is revoked by the vault's owner, on the owner's own handle",
                    &["Present the owner's own verified, unattenuated credential."],
                ));
            }
            let actor = WriteActor::new(person, EdgeActorClass::Human);
            let mut done = Vec::new();
            for id in &ids {
                let body = vault
                    .get_claim_in_txn(&*wtxn, id)?
                    .ok_or_else(|| MemoryError::not_found("no claim has that ref"))?;
                if body.predicate != PREDICATE_PLUGIN_SECTION_INSTALL
                    || body.lifecycle != ClaimLifecycleStatus::Active
                    || !matches!(
                        body.approval,
                        ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Approved
                    )
                {
                    return Err(MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        "the install claim is no live proposal or approved grant",
                        &["Read it again with vault.packs.sections.list."],
                    ));
                }
                if section_id.is_none()
                    && let Ok(payload) = PluginInstallClaimPayload::from_value(&body.value)
                {
                    section_id = Some(payload.section_id.0);
                }
                vault.retract_claim_in_txn_as(wtxn, id, now, Some(actor))?;
                done.push(*id);
            }
            Ok(done)
        })?;
        self.produced_from(revoked.iter().copied());
        Ok(PluginSectionRevoked {
            section_id,
            revoked: u32::try_from(revoked.len()).unwrap_or(u32::MAX),
            claim_refs: revoked.iter().map(EntityId::to_hex).collect(),
        })
    }

    /// One workflow suggestion pass on the caller's own credential: knob,
    /// catalog over the pinned hub, dedupe, and at most one attributed
    /// Proposed install claim. Installs and consents to nothing.
    pub fn plugin_section_suggest(
        &self,
        input: &PluginSectionSuggestRequest,
    ) -> MemoryResult<PluginSectionSuggestion> {
        let vault = self.vault();
        let job = PluginSuggestJob {
            run_id: input.run_id.clone(),
            digest_window: input.digest_window.clone(),
            notice: WorkflowPatternNotice {
                pattern_key: input.pattern_key.clone(),
                summary: input.summary.clone(),
                evidence_refs: input.evidence_refs.clone(),
                observed_at: input.observed_at,
            },
        };
        let actor = WriteActor::new(self.actor(), self.actor_class());
        let source = VaultPluginInstallSource { vault };
        let now = vault.now_recorded_at();
        let disposition =
            match vault.hub_ref_fetch(&pinned_tracking(input.hub_ref.clone())?, None)? {
                RefFetch::Git(adapter, _) => run_plugin_suggestion_job(
                    vault,
                    &LocalSkillHubPackCatalog { adapter: &adapter },
                    &source,
                    &job,
                    actor,
                    &EngineSectionBindings,
                    now,
                ),
                RefFetch::Http(adapter, _) => run_plugin_suggestion_job(
                    vault,
                    &LocalSkillHubPackCatalog { adapter: &adapter },
                    &source,
                    &job,
                    actor,
                    &EngineSectionBindings,
                    now,
                ),
            }
            .map_err(plugin_error)?;
        Ok(match disposition {
            PluginSuggestionDisposition::Disabled => PluginSectionSuggestion {
                state: PluginSectionSuggestionState::Disabled,
                suggestion_key: None,
                claim_ref: None,
                pack_id: None,
                section_id: None,
                label: None,
            },
            PluginSuggestionDisposition::NoMatch => PluginSectionSuggestion {
                state: PluginSectionSuggestionState::NoMatch,
                suggestion_key: None,
                claim_ref: None,
                pack_id: None,
                section_id: None,
                label: None,
            },
            PluginSuggestionDisposition::SuppressedDuplicate { suggestion_key } => {
                PluginSectionSuggestion {
                    state: PluginSectionSuggestionState::SuppressedDuplicate,
                    suggestion_key: Some(suggestion_key),
                    claim_ref: None,
                    pack_id: None,
                    section_id: None,
                    label: None,
                }
            }
            PluginSuggestionDisposition::Proposed {
                suggestion_key,
                install_claim_id,
                board_row,
            } => {
                self.produced_from([install_claim_id]);
                PluginSectionSuggestion {
                    state: PluginSectionSuggestionState::Proposed,
                    suggestion_key: Some(suggestion_key),
                    claim_ref: Some(install_claim_id.to_hex()),
                    pack_id: Some(board_row.pack_id),
                    section_id: Some(board_row.section_id.0),
                    label: Some(board_row.label),
                }
            }
        })
    }

    /// The owner's suggestion knob, read under the owner's proof.
    pub fn plugin_suggestions_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<PluginSuggestionsView> {
        self.plugin_section_owner(owner)?;
        Ok(PluginSuggestionsView {
            enabled: self.vault().plugin_suggestions_enabled()?,
        })
    }

    /// The owner's suggestion knob: off silences every later pass before any
    /// catalog access.
    pub fn plugin_suggestions_set_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &PluginSuggestionsSetRequest,
    ) -> MemoryResult<PluginSuggestionsView> {
        self.plugin_section_owner(owner)?;
        self.vault().set_plugin_suggestions_enabled(input.enabled)?;
        Ok(PluginSuggestionsView {
            enabled: input.enabled,
        })
    }
}
