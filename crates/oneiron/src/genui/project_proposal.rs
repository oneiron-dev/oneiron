//! Typed project proposal and owner-confirmed, write-free mint intent (OF-501).

use super::consent_eval::{
    ConsentActionKind, ConsentActionRequest, action_button_node, atom_id,
    ensure_authenticated_actor, ensure_component_request, ensure_declared_action, lens_text,
    meta_line, non_empty,
};
use super::protocol::Of336ActionDescriptor;
use crate::consent::AuthenticatedOwner;
use crate::lens::{
    CollectionAtom, GeneratedLens, GeneratedUiActionDeclaration, GeneratedUiActionTier,
    GeneratedUiCard, LensAtom, LensNode, LensRenderId, ReceiptAtom, SelfUiActionId,
};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const PROJECT_PROPOSAL_MINT_ACTION_ID: &str = "mint_project";

/// The agent supplies content and picks; the engine does not infer a project from text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalDraft {
    pub goal: String,
    pub why: String,
    pub axes: Vec<String>,
}

/// Agent-drafted roster, budget and skill choices; refs are resolved at the write gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectProposalPicks {
    pub leader_agent_def_ref: String,
    pub board_human_refs: Vec<String>,
    pub budget_share_bps: u16,
    pub starting_skill_refs: Vec<String>,
}

/// A proposal is not authority. Only the host-held card and an authenticated owner
/// may produce an intent; the project writer must still enforce its own gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProjectProposalCardWire", deny_unknown_fields)]
pub struct ProjectProposalCard {
    pub card_id: String,
    pub principal_ref: String,
    /// Message on which this card was shown; the eventual writer binds born_from.
    pub source_message_ref: String,
    pub goal: ProjectGoalDraft,
    pub leader_agent_def_ref: String,
    pub board_human_refs: Vec<String>,
    /// Share of the parent budget in basis points (0..=10_000).
    pub budget_share_bps: u16,
    /// Vault-base skill refs to fork into the new project at mint time.
    pub starting_skill_refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectProposalCardWire {
    card_id: String,
    principal_ref: String,
    source_message_ref: String,
    goal: ProjectGoalDraft,
    leader_agent_def_ref: String,
    board_human_refs: Vec<String>,
    budget_share_bps: u16,
    starting_skill_refs: Vec<String>,
}

impl TryFrom<ProjectProposalCardWire> for ProjectProposalCard {
    type Error = Error;

    fn try_from(wire: ProjectProposalCardWire) -> Result<Self> {
        let card = Self {
            card_id: wire.card_id,
            principal_ref: wire.principal_ref,
            source_message_ref: wire.source_message_ref,
            goal: wire.goal,
            leader_agent_def_ref: wire.leader_agent_def_ref,
            board_human_refs: wire.board_human_refs,
            budget_share_bps: wire.budget_share_bps,
            starting_skill_refs: wire.starting_skill_refs,
        };
        card.validate()?;
        Ok(card)
    }
}

/// A validated trigger, not a project row or permission to write one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectMintIntent {
    pub principal_ref: String,
    pub origin_component_id: String,
    pub origin_action_id: String,
    pub source_message_ref: String,
    pub goal: ProjectGoalDraft,
    pub leader_agent_def_ref: String,
    pub board_human_refs: Vec<String>,
    pub budget_share_bps: u16,
    pub starting_skill_refs: Vec<String>,
}

impl ProjectProposalCard {
    pub fn new(
        card_id: impl Into<String>,
        principal_ref: impl Into<String>,
        source_message_ref: impl Into<String>,
        goal: ProjectGoalDraft,
        picks: ProjectProposalPicks,
    ) -> Result<Self> {
        let card = Self {
            card_id: card_id.into(),
            principal_ref: principal_ref.into(),
            source_message_ref: source_message_ref.into(),
            goal,
            leader_agent_def_ref: picks.leader_agent_def_ref,
            board_human_refs: picks.board_human_refs,
            budget_share_bps: picks.budget_share_bps,
            starting_skill_refs: picks.starting_skill_refs,
        };
        card.validate()?;
        Ok(card)
    }

    /// Recheck before rendering or emitting an intent: public fields and decoded
    /// payloads must not bypass the constructor's constraints.
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("card_id", &self.card_id),
            ("principal_ref", &self.principal_ref),
            ("source_message_ref", &self.source_message_ref),
            ("goal", &self.goal.goal),
            ("why", &self.goal.why),
            ("leader_agent_def_ref", &self.leader_agent_def_ref),
        ] {
            non_empty(name, value.clone())?;
            lens_text(value.clone())?;
        }
        LensRenderId::new(self.card_id.clone())?;
        for (name, reference) in [
            ("card_id", &self.card_id),
            ("principal_ref", &self.principal_ref),
            ("source_message_ref", &self.source_message_ref),
            ("leader_agent_def_ref", &self.leader_agent_def_ref),
        ] {
            ensure_canonical_ref(name, reference)?;
        }
        if self.goal.axes.is_empty() || self.board_human_refs.is_empty() {
            return Err(Error::InvalidConfig(
                "project proposal requires goal axes and board humans".to_owned(),
            ));
        }
        if self.budget_share_bps > 10_000 {
            return Err(Error::InvalidConfig(
                "project proposal budget share exceeds its parent".to_owned(),
            ));
        }
        for (name, refs) in [
            ("goal axes", &self.goal.axes),
            ("board humans", &self.board_human_refs),
            ("starting skills", &self.starting_skill_refs),
        ] {
            if refs.len() > 128 {
                return Err(Error::InvalidConfig(format!(
                    "project proposal {name} exceeds its limit"
                )));
            }
            let mut unique = HashSet::new();
            for value in refs {
                non_empty(name, value.clone())?;
                lens_text(value.clone())?;
                if name != "goal axes" {
                    ensure_canonical_ref(name, value)?;
                }
                if !unique.insert(value) {
                    return Err(Error::InvalidConfig(format!(
                        "project proposal {name} contains duplicate entries"
                    )));
                }
            }
        }
        // Atom Kit combines entries into single bounded LensText values. Check
        // the combined text here so all three adapters accept the same card.
        for refs in [
            &self.goal.axes,
            &self.board_human_refs,
            &self.starting_skill_refs,
        ] {
            lens_text(refs.join(", "))?;
        }
        // Unsupported primitives compile from node fallbacks, not the outer
        // Of336RenderedComponent fallback. Keep that complete and bounded.
        lens_text(self.fallback_text())?;
        Ok(())
    }

    #[must_use]
    pub fn actions(&self) -> Vec<Of336ActionDescriptor> {
        vec![Of336ActionDescriptor {
            action_id: PROJECT_PROPOSAL_MINT_ACTION_ID.to_owned(),
            label: "Create project".to_owned(),
            action: ConsentActionKind::ProjectMint,
        }]
    }

    /// A tap only emits an intent. The caller must use the host-held card, not a
    /// client-supplied replacement, and route the intent through the project gate.
    pub fn evaluate_action(
        &self,
        request: &ConsentActionRequest,
        authenticated_owner: &AuthenticatedOwner,
    ) -> Result<ProjectMintIntent> {
        self.validate()?;
        ensure_component_request(&self.card_id, request)?;
        ensure_declared_action(&self.actions(), request)?;
        ensure_authenticated_actor(&self.principal_ref, request, authenticated_owner)?;
        Ok(ProjectMintIntent {
            principal_ref: self.principal_ref.clone(),
            origin_component_id: self.card_id.clone(),
            origin_action_id: request.action_id.clone(),
            source_message_ref: self.source_message_ref.clone(),
            goal: self.goal.clone(),
            leader_agent_def_ref: self.leader_agent_def_ref.clone(),
            board_human_refs: self.board_human_refs.clone(),
            budget_share_bps: self.budget_share_bps,
            starting_skill_refs: self.starting_skill_refs.clone(),
        })
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        format!(
            "{} — {}. Why: {}. Axes: {}. Leader: {}. Board: {}. Budget: {} bps. Starting skills: {}.",
            self.goal.goal,
            self.source_message_ref,
            self.goal.why,
            self.goal.axes.join(", "),
            self.leader_agent_def_ref,
            self.board_human_refs.join(", "),
            self.budget_share_bps,
            self.starting_skill_refs.join(", "),
        )
    }

    /// Expand the named proposal into the existing atom-kit envelope. No new
    /// project-specific primitive or foreign renderer is required.
    pub(super) fn generated_ui_card(&self) -> Result<GeneratedUiCard> {
        self.validate()?;
        let root = self.atom_kit_root()?;
        let button = root
            .children
            .last()
            .expect("proposal always has one action");
        let LensAtom::SelfUi(control) = &button.atom else {
            unreachable!("the proposal action is a self.ui button");
        };
        let declaration = GeneratedUiActionDeclaration {
            element_id: button.id.clone(),
            action_id: SelfUiActionId::new(PROJECT_PROPOSAL_MINT_ACTION_ID)?,
            tier: GeneratedUiActionTier::DeterministicTool,
            action: control.action().clone(),
        };
        GeneratedUiCard::interactive(
            LensRenderId::new(self.card_id.clone())?,
            GeneratedLens::new(root)?,
            vec![declaration],
            Default::default(),
        )
    }

    pub(super) fn atom_kit_root(&self) -> Result<LensNode> {
        let mut root = LensNode::new(
            atom_id("project-proposal-root")?,
            LensAtom::Sheet(CollectionAtom {
                title: lens_text(&self.goal.goal)?,
                rows: Vec::new(),
            }),
        );
        root.children.push(LensNode::with_fallback_text(
            atom_id("project-proposal-fields")?,
            LensAtom::Receipt(ReceiptAtom {
                title: lens_text(&self.goal.goal)?,
                lines: vec![
                    meta_line("why", &self.goal.why)?,
                    meta_line("axes", &self.goal.axes.join(", "))?,
                    meta_line("leader_agent_def_ref", &self.leader_agent_def_ref)?,
                    meta_line("board_human_refs", &self.board_human_refs.join(", "))?,
                    meta_line("budget_share_bps", &self.budget_share_bps.to_string())?,
                    meta_line("starting_skill_refs", &self.starting_skill_refs.join(", "))?,
                    meta_line("source_message_ref", &self.source_message_ref)?,
                ],
                seal: None,
            }),
            lens_text(self.fallback_text())?,
        ));
        root.children
            .push(action_button_node(self.actions().remove(0))?);
        Ok(root)
    }
}

/// A ref must agree byte-for-byte with the store-authenticated principal or
/// downstream ID resolver; prose is deliberately not normalized here.
fn ensure_canonical_ref(name: &str, reference: &str) -> Result<()> {
    if reference != reference.trim() {
        return Err(Error::InvalidConfig(format!(
            "project proposal {name} must not have surrounding whitespace"
        )));
    }
    Ok(())
}
