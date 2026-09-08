//! Consent-ask and bundle-approve cards with scope vocabularies.

use super::consent_eval::{
    ConsentActionDecision, ConsentActionEvaluation, ConsentActionKind, ConsentActionRequest,
    GrantMintIntent, GrantMintIntentScope, action_button_node, atom_id, consent_evaluation,
    ensure_authenticated_actor, ensure_component_request, ensure_declared_action,
    ensure_principal_ref, lens_text, meta_line, non_empty, noop_policy_rejection,
    required_scope_ref, widening_grant_surface_is_eligible,
};
use super::protocol::{Of336ActionDescriptor, Of336ComponentKind};
use crate::consent::AuthenticatedOwner;
use crate::lens::{CollectionAtom, LensAtom, LensNode, ReceiptAtom, SealAtom, SealLevel};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentAskCard {
    pub card_id: String,
    pub principal_ref: String,
    pub prompt: String,
    pub preview: String,
    pub verb_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_receipt_ref: Option<String>,
    pub scope_escalators: Vec<ConsentScopeEscalator>,
}

impl ConsentAskCard {
    pub fn new(
        card_id: impl Into<String>,
        principal_ref: impl Into<String>,
        prompt: impl Into<String>,
        preview: impl Into<String>,
        verb_class: impl Into<String>,
        scope_escalators: Vec<ConsentScopeEscalator>,
    ) -> Result<Self> {
        let scope_escalators = if scope_escalators.is_empty() {
            ConsentScopeEscalator::all().to_vec()
        } else {
            scope_escalators
        };
        Ok(Self {
            card_id: non_empty("consent ask card_id", card_id.into())?,
            principal_ref: non_empty("consent ask principal_ref", principal_ref.into())?,
            prompt: non_empty("consent ask prompt", prompt.into())?,
            preview: non_empty("consent ask preview", preview.into())?,
            verb_class: non_empty("consent ask verb_class", verb_class.into())?,
            counterparty_ref: None,
            channel: None,
            origin_receipt_ref: None,
            scope_escalators,
        })
    }

    #[must_use]
    pub fn with_counterparty_ref(mut self, counterparty_ref: impl Into<String>) -> Self {
        self.counterparty_ref = Some(counterparty_ref.into());
        self
    }

    #[must_use]
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    #[must_use]
    pub fn with_origin_receipt_ref(mut self, origin_receipt_ref: impl Into<String>) -> Self {
        self.origin_receipt_ref = Some(origin_receipt_ref.into());
        self
    }

    #[must_use]
    pub fn actions(&self) -> Vec<Of336ActionDescriptor> {
        let mut actions = vec![
            Of336ActionDescriptor {
                action_id: "approve_once".to_owned(),
                label: "Approve".to_owned(),
                action: ConsentActionKind::Approve,
            },
            Of336ActionDescriptor {
                action_id: "decline".to_owned(),
                label: "Decline".to_owned(),
                action: ConsentActionKind::Decline,
            },
        ];
        actions.extend(
            self.scope_escalators
                .iter()
                .map(|scope| Of336ActionDescriptor {
                    action_id: format!("escalate_{}", scope.as_str()),
                    label: scope.label().to_owned(),
                    action: ConsentActionKind::Escalate(*scope),
                }),
        );
        actions
    }

    pub fn evaluate_action(
        &self,
        request: &ConsentActionRequest,
        authenticated_owner: &AuthenticatedOwner,
    ) -> Result<ConsentActionEvaluation> {
        ensure_component_request(&self.card_id, request)?;
        ensure_principal_ref(&self.principal_ref)?;
        ensure_declared_action(&self.actions(), request)?;
        ensure_authenticated_actor(&self.principal_ref, request, authenticated_owner)?;

        let (decision, grant_mint_intent) = match request.action {
            ConsentActionKind::Approve => (ConsentActionDecision::ApprovedOnce, None),
            ConsentActionKind::Decline => (ConsentActionDecision::Declined, None),
            ConsentActionKind::Escalate(scope) => {
                if scope != ConsentScopeEscalator::JustOnce
                    && !widening_grant_surface_is_eligible(request.surface)
                {
                    return Ok(noop_policy_rejection(
                        Of336ComponentKind::ConsentAsk,
                        &self.card_id,
                        &self.principal_ref,
                        request,
                        ConsentActionDecision::NoopSurfaceIneligible,
                        "consent_surface:widening_ineligible",
                    ));
                }
                if scope != ConsentScopeEscalator::JustOnce
                    && self.counterparty_ref.as_deref() == Some(request.actor.actor_ref())
                {
                    return Ok(noop_policy_rejection(
                        Of336ComponentKind::ConsentAsk,
                        &self.card_id,
                        &self.principal_ref,
                        request,
                        ConsentActionDecision::NoopBeneficiaryConfirm,
                        "consent_beneficiary:self_grant",
                    ));
                }
                let grant_scope = self.grant_scope(scope)?;
                (
                    ConsentActionDecision::GrantMintIntent,
                    Some(GrantMintIntent {
                        principal_ref: self.principal_ref.clone(),
                        origin_component_id: self.card_id.clone(),
                        origin_action_id: request.action_id.clone(),
                        origin_receipt_ref: self.origin_receipt_ref.clone(),
                        scope: grant_scope,
                    }),
                )
            }
            ConsentActionKind::BundleApprove(_) => {
                return Err(Error::InvalidConfig(
                    "bundle approval action cannot target consent ask card".to_string(),
                ));
            }
        };
        Ok(consent_evaluation(
            Of336ComponentKind::ConsentAsk,
            &self.card_id,
            &self.principal_ref,
            request,
            decision,
            grant_mint_intent,
        ))
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        format!("{} {}", self.prompt, self.preview)
    }

    fn grant_scope(&self, scope: ConsentScopeEscalator) -> Result<GrantMintIntentScope> {
        match scope {
            ConsentScopeEscalator::JustOnce => Ok(GrantMintIntentScope::JustOnce {
                effect_ref: self.origin_receipt_ref.clone(),
            }),
            ConsentScopeEscalator::AlwaysThisContact => Ok(GrantMintIntentScope::Contact {
                contact_ref: required_scope_ref(
                    "always-this-contact",
                    self.counterparty_ref.as_deref(),
                )?
                .to_owned(),
            }),
            ConsentScopeEscalator::AlwaysThisVerbClass => Ok(GrantMintIntentScope::VerbClass {
                verb_class: self.verb_class.clone(),
            }),
            ConsentScopeEscalator::AlwaysThisChannel => Ok(GrantMintIntentScope::Channel {
                channel: required_scope_ref("always-this-channel", self.channel.as_deref())?
                    .to_owned(),
            }),
        }
    }

    pub(super) fn atom_kit_root(&self) -> Result<LensNode> {
        let mut root = LensNode::new(
            atom_id("consent-ask-root")?,
            LensAtom::Sheet(CollectionAtom {
                title: lens_text("Consent ask")?,
                rows: Vec::new(),
            }),
        );
        root.children.push(LensNode::new(
            atom_id("consent-ask-receipt")?,
            LensAtom::Receipt(ReceiptAtom {
                title: lens_text(&self.prompt)?,
                lines: vec![
                    meta_line("preview", &self.preview)?,
                    meta_line("principal_ref", &self.principal_ref)?,
                    meta_line("verb_class", &self.verb_class)?,
                ],
                seal: Some(SealAtom {
                    level: SealLevel::Actor,
                    label: lens_text("principal-auth")?,
                }),
            }),
        ));
        for action in self.actions() {
            root.children.push(action_button_node(action)?);
        }
        Ok(root)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleApproveCard {
    pub card_id: String,
    pub principal_ref: String,
    pub title: String,
    pub brief_ref: String,
    pub verb_class: String,
    pub items: Vec<BundleSendItem>,
    pub scope_choices: Vec<BundleApprovalScope>,
}

impl BundleApproveCard {
    pub fn new(
        card_id: impl Into<String>,
        principal_ref: impl Into<String>,
        title: impl Into<String>,
        brief_ref: impl Into<String>,
        verb_class: impl Into<String>,
        items: Vec<BundleSendItem>,
        scope_choices: Vec<BundleApprovalScope>,
    ) -> Result<Self> {
        if items.is_empty() {
            return Err(Error::InvalidConfig(
                "bundle approve card must include at least one send item".to_string(),
            ));
        }
        let scope_choices = if scope_choices.is_empty() {
            vec![
                BundleApprovalScope::ExactEnumeratedSends,
                BundleApprovalScope::BriefVerbClass,
            ]
        } else {
            scope_choices
        };
        Ok(Self {
            card_id: non_empty("bundle approve card_id", card_id.into())?,
            principal_ref: non_empty("bundle approve principal_ref", principal_ref.into())?,
            title: non_empty("bundle approve title", title.into())?,
            brief_ref: non_empty("bundle approve brief_ref", brief_ref.into())?,
            verb_class: non_empty("bundle approve verb_class", verb_class.into())?,
            items,
            scope_choices,
        })
    }

    #[must_use]
    pub fn item_labels(&self) -> Vec<String> {
        self.items.iter().map(BundleSendItem::label).collect()
    }

    #[must_use]
    pub fn actions(&self) -> Vec<Of336ActionDescriptor> {
        let mut actions = vec![Of336ActionDescriptor {
            action_id: "decline_bundle".to_owned(),
            label: "Decline".to_owned(),
            action: ConsentActionKind::Decline,
        }];
        actions.extend(
            self.scope_choices
                .iter()
                .map(|scope| Of336ActionDescriptor {
                    action_id: format!("approve_bundle_{}", scope.as_str()),
                    label: scope.label().to_owned(),
                    action: ConsentActionKind::BundleApprove(*scope),
                }),
        );
        actions
    }

    pub fn evaluate_action(
        &self,
        request: &ConsentActionRequest,
        authenticated_owner: &AuthenticatedOwner,
    ) -> Result<ConsentActionEvaluation> {
        ensure_component_request(&self.card_id, request)?;
        ensure_principal_ref(&self.principal_ref)?;
        ensure_declared_action(&self.actions(), request)?;
        if self.items.is_empty() {
            return Err(Error::InvalidConfig(
                "bundle approve card must include at least one send item".to_string(),
            ));
        }
        ensure_authenticated_actor(&self.principal_ref, request, authenticated_owner)?;

        let (decision, grant_mint_intent) = match request.action {
            ConsentActionKind::Decline => (ConsentActionDecision::Declined, None),
            ConsentActionKind::BundleApprove(scope) => {
                if scope == BundleApprovalScope::BriefVerbClass
                    && !widening_grant_surface_is_eligible(request.surface)
                {
                    return Ok(noop_policy_rejection(
                        Of336ComponentKind::BundleApprove,
                        &self.card_id,
                        &self.principal_ref,
                        request,
                        ConsentActionDecision::NoopSurfaceIneligible,
                        "consent_surface:widening_ineligible",
                    ));
                }
                if scope == BundleApprovalScope::BriefVerbClass
                    && self
                        .items
                        .iter()
                        .any(|item| item.counterparty_ref == request.actor.actor_ref())
                {
                    return Ok(noop_policy_rejection(
                        Of336ComponentKind::BundleApprove,
                        &self.card_id,
                        &self.principal_ref,
                        request,
                        ConsentActionDecision::NoopBeneficiaryConfirm,
                        "consent_beneficiary:self_grant",
                    ));
                }
                let grant_scope = match scope {
                    BundleApprovalScope::ExactEnumeratedSends => {
                        GrantMintIntentScope::BundleExactSends {
                            send_refs: self
                                .items
                                .iter()
                                .map(|item| item.send_ref.clone())
                                .collect(),
                        }
                    }
                    BundleApprovalScope::BriefVerbClass => GrantMintIntentScope::BriefVerbClass {
                        brief_ref: self.brief_ref.clone(),
                        verb_class: self.verb_class.clone(),
                    },
                };
                (
                    ConsentActionDecision::GrantMintIntent,
                    Some(GrantMintIntent {
                        principal_ref: self.principal_ref.clone(),
                        origin_component_id: self.card_id.clone(),
                        origin_action_id: request.action_id.clone(),
                        origin_receipt_ref: None,
                        scope: grant_scope,
                    }),
                )
            }
            ConsentActionKind::Approve | ConsentActionKind::Escalate(_) => {
                return Err(Error::InvalidConfig(
                    "ask-card action cannot target bundle approve card".to_string(),
                ));
            }
        };
        Ok(consent_evaluation(
            Of336ComponentKind::BundleApprove,
            &self.card_id,
            &self.principal_ref,
            request,
            decision,
            grant_mint_intent,
        ))
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        format!("{}: {}", self.title, self.item_labels().join("; "))
    }

    pub(super) fn atom_kit_root(&self) -> Result<LensNode> {
        let mut root = LensNode::new(
            atom_id("bundle-approve-root")?,
            LensAtom::Sheet(CollectionAtom {
                title: lens_text(&self.title)?,
                rows: Vec::new(),
            }),
        );
        root.children.push(LensNode::new(
            atom_id("bundle-approve-receipt")?,
            LensAtom::Receipt(ReceiptAtom {
                title: lens_text(&self.title)?,
                lines: vec![
                    meta_line("brief_ref", &self.brief_ref)?,
                    meta_line("verb_class", &self.verb_class)?,
                    meta_line("sends", &self.item_labels().join("; "))?,
                ],
                seal: Some(SealAtom {
                    level: SealLevel::Actor,
                    label: lens_text("bundle-approve")?,
                }),
            }),
        ));
        for action in self.actions() {
            root.children.push(action_button_node(action)?);
        }
        Ok(root)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSendItem {
    pub send_ref: String,
    pub counterparty_ref: String,
    pub channel: String,
    pub summary: String,
}

impl BundleSendItem {
    pub fn new(
        send_ref: impl Into<String>,
        counterparty_ref: impl Into<String>,
        channel: impl Into<String>,
        summary: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            send_ref: non_empty("bundle send_ref", send_ref.into())?,
            counterparty_ref: non_empty("bundle counterparty_ref", counterparty_ref.into())?,
            channel: non_empty("bundle channel", channel.into())?,
            summary: non_empty("bundle summary", summary.into())?,
        })
    }

    #[must_use]
    pub fn label(&self) -> String {
        format!(
            "{} via {}: {}",
            self.counterparty_ref, self.channel, self.summary
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentScopeEscalator {
    JustOnce,
    AlwaysThisContact,
    AlwaysThisVerbClass,
    AlwaysThisChannel,
}

impl ConsentScopeEscalator {
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::JustOnce,
            Self::AlwaysThisContact,
            Self::AlwaysThisVerbClass,
            Self::AlwaysThisChannel,
        ]
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JustOnce => "just_once",
            Self::AlwaysThisContact => "always_this_contact",
            Self::AlwaysThisVerbClass => "always_this_verb_class",
            Self::AlwaysThisChannel => "always_this_channel",
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::JustOnce => "Just this once",
            Self::AlwaysThisContact => "Always for this contact",
            Self::AlwaysThisVerbClass => "Always for this verb class",
            Self::AlwaysThisChannel => "Always on this channel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleApprovalScope {
    ExactEnumeratedSends,
    BriefVerbClass,
}

impl BundleApprovalScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactEnumeratedSends => "exact_enumerated_sends",
            Self::BriefVerbClass => "brief_verb_class",
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExactEnumeratedSends => "Approve these sends",
            Self::BriefVerbClass => "Approve this brief and verb class",
        }
    }
}
