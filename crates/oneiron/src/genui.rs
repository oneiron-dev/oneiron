//! OF-336 generated-UI component contract.
//!
//! This module owns the engine-resident payload shape and view-time deep-link
//! resolution, which reads the vault; grant storage and outbound execution
//! remain in later gates.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    Error, Result, Vault,
    attempt_queue::AttemptId,
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    booking::DisclosureRung,
    claim::ClaimLifecycleStatus,
    commitment::decode_commitment_claim,
    consent::AuthenticatedOwner,
    edge::EdgeKind,
    entity_id::EntityId,
    failure_ladder::{
        BlockedReportRef, FailureClass, HealerRepairRoute, RetryLineagePathology, failure_card_ref,
        failure_case_ref,
    },
    lens::{
        ButtonControl, CollectionAtom, GeneratedLens, LensAtom, LensAtomId, LensNode, LensText,
        MetaLineAtom, ReceiptAtom, SealAtom, SealLevel, SelfUiAction, SelfUiActionId,
        SelfUiControl, SelfUiControlId, SelfUiValue,
    },
    receipt::{COMMITMENT_TRIGGER_PREFIX, ReceiptKind, ReceiptRecord, commitment_trigger_ref},
    registry::ENTITY_TYPE_MESSAGE,
    run_tree::{RunTree, RunTreeFailureDiagram, mark_run_tree_failure},
};

pub const OF336_PROTOCOL_VERSION: u16 = 1;
pub const OF336_CARD_CATALOG_VERSION: &str = "eirispec.card.v1";
pub const OF336_MCP_UI_MIME: &str = "application/vnd.mcp-ui.remote-dom";

/// First-class surface adapters pinned by OF-367 RS7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Of336SurfaceAdapter {
    EiriSpecCareRegister,
    DashboardAtomKitAudit,
    McpUi,
}

impl Of336SurfaceAdapter {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EiriSpecCareRegister => "eirispec_care_register",
            Self::DashboardAtomKitAudit => "dashboard_atom_kit_audit",
            Self::McpUi => "mcp_ui",
        }
    }
}

/// RCPT-3 component set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Of336ComponentKind {
    ReceiptView,
    ConsentAsk,
    BundleApprove,
}

impl Of336ComponentKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptView => "receipt_view",
            Self::ConsentAsk => "consent_ask",
            Self::BundleApprove => "bundle_approve",
        }
    }
}

/// One rendered adapter payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Of336RenderedComponent {
    pub protocol_version: u16,
    pub adapter: Of336SurfaceAdapter,
    pub component_kind: Of336ComponentKind,
    pub component_id: String,
    pub fallback_text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Of336ActionDescriptor>,
    pub tree: Value,
}

/// One stable action advertised by an OF-336 card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Of336ActionDescriptor {
    pub action_id: String,
    pub label: String,
    pub action: ConsentActionKind,
}

/// The three RCPT-3 components as one engine contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "component", content = "payload", rename_all = "snake_case")]
pub enum Of336Component {
    ReceiptView(ReceiptViewComponent),
    ConsentAsk(ConsentAskCard),
    BundleApprove(BundleApproveCard),
}

impl Of336Component {
    #[must_use]
    pub fn component_id(&self) -> &str {
        match self {
            Self::ReceiptView(component) => &component.component_id,
            Self::ConsentAsk(component) => &component.card_id,
            Self::BundleApprove(component) => &component.card_id,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> Of336ComponentKind {
        match self {
            Self::ReceiptView(_) => Of336ComponentKind::ReceiptView,
            Self::ConsentAsk(_) => Of336ComponentKind::ConsentAsk,
            Self::BundleApprove(_) => Of336ComponentKind::BundleApprove,
        }
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        match self {
            Self::ReceiptView(component) => component.fallback_text(),
            Self::ConsentAsk(component) => component.fallback_text(),
            Self::BundleApprove(component) => component.fallback_text(),
        }
    }

    #[must_use]
    pub fn actions(&self) -> Vec<Of336ActionDescriptor> {
        match self {
            Self::ReceiptView(_) => Vec::new(),
            Self::ConsentAsk(component) => component.actions(),
            Self::BundleApprove(component) => component.actions(),
        }
    }

    pub fn render(&self, adapter: Of336SurfaceAdapter) -> Result<Of336RenderedComponent> {
        let tree = match adapter {
            Of336SurfaceAdapter::EiriSpecCareRegister => self.render_eirispec(),
            Of336SurfaceAdapter::DashboardAtomKitAudit => self.render_atom_kit()?,
            Of336SurfaceAdapter::McpUi => self.render_mcp_ui(),
        };
        Ok(Of336RenderedComponent {
            protocol_version: OF336_PROTOCOL_VERSION,
            adapter,
            component_kind: self.kind(),
            component_id: self.component_id().to_owned(),
            fallback_text: self.fallback_text(),
            actions: self.actions(),
            tree,
        })
    }

    fn render_eirispec(&self) -> Value {
        let card_id = self.component_id();
        let fallback_text = self.fallback_text();
        let mut elements = serde_json::Map::new();
        let mut root_children = Vec::new();

        match self {
            Self::ReceiptView(component) => {
                let receipt_id = "receipt";
                root_children.push(receipt_id.to_owned());
                elements.insert(
                    receipt_id.to_owned(),
                    json!({
                        "type": "eiriNote",
                        "props": {
                            "title": component.title(),
                            "body": component.receipt_lines(),
                            "register": "care"
                        },
                        "children": [],
                        "fallbackText": fallback_text
                    }),
                );
                for (index, link) in component.links.iter().enumerate() {
                    let id = format!("link-{index}");
                    root_children.push(id.clone());
                    elements.insert(
                        id,
                        json!({
                            "type": "button",
                            "props": {
                                "label": link.label,
                                "action": {
                                    "kind": "navigation",
                                    "target": link.target_ref,
                                    "resolution": link.resolution
                                }
                            },
                            "children": [],
                            "fallbackText": link.fallback_text()
                        }),
                    );
                }
            }
            Self::ConsentAsk(component) => {
                root_children.push("prompt".to_owned());
                elements.insert(
                    "prompt".to_owned(),
                    json!({
                        "type": "eiriNote",
                        "props": {
                            "title": "Consent ask",
                            "body": [component.prompt, component.preview],
                            "register": "care"
                        },
                        "children": [],
                        "fallbackText": fallback_text
                    }),
                );
                append_eirispec_actions(&mut elements, &mut root_children, &component.actions());
            }
            Self::BundleApprove(component) => {
                root_children.push("bundle".to_owned());
                elements.insert(
                    "bundle".to_owned(),
                    json!({
                        "type": "checklistItem",
                        "props": {
                            "label": component.title,
                            "items": component.item_labels()
                        },
                        "children": [],
                        "fallbackText": fallback_text
                    }),
                );
                append_eirispec_actions(&mut elements, &mut root_children, &component.actions());
            }
        }

        elements.insert(
            "root".to_owned(),
            json!({
                "type": "stack",
                "props": {},
                "children": root_children,
                "fallbackText": fallback_text
            }),
        );

        json!({
            "protocolVersion": OF336_PROTOCOL_VERSION,
            "catalogVersion": OF336_CARD_CATALOG_VERSION,
            "cardId": card_id,
            "root": "root",
            "elements": elements,
            "fallbackText": fallback_text
        })
    }

    fn render_atom_kit(&self) -> Result<Value> {
        let root = match self {
            Self::ReceiptView(component) => component.atom_kit_root()?,
            Self::ConsentAsk(component) => component.atom_kit_root()?,
            Self::BundleApprove(component) => component.atom_kit_root()?,
        };
        serde_json::to_value(GeneratedLens::new(root)?).map_err(|error| {
            Error::InvalidConfig(format!("OF-336 atom-kit render failed: {error}"))
        })
    }

    fn render_mcp_ui(&self) -> Value {
        json!({
            "mime_type": OF336_MCP_UI_MIME,
            "component": self.kind().as_str(),
            "component_id": self.component_id(),
            "fallback_text": self.fallback_text(),
            "actions": self.actions(),
            "props": match self {
                Self::ReceiptView(component) => json!(component),
                Self::ConsentAsk(component) => json!(component),
                Self::BundleApprove(component) => json!(component),
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptViewComponent {
    pub component_id: String,
    pub receipt: ReceiptRecord,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<ReceiptDeepLink>,
}

impl ReceiptViewComponent {
    pub fn new(
        component_id: impl Into<String>,
        receipt: ReceiptRecord,
        links: Vec<ReceiptDeepLink>,
    ) -> Result<Self> {
        let component_id = non_empty("receipt_view component_id", component_id.into())?;
        Ok(Self {
            component_id,
            receipt,
            links,
        })
    }

    #[must_use]
    pub fn title(&self) -> String {
        format!("{} receipt", self.receipt.receipt_kind.as_str())
    }

    #[must_use]
    pub fn receipt_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("outcome: {}", self.receipt.outcome),
            format!("occurred_at: {}", self.receipt.occurred_at),
        ];
        if let Some(actor) = self.receipt.actor.as_deref() {
            lines.push(format!("actor: {actor}"));
        }
        if let Some(on_behalf_of) = self.receipt.on_behalf_of.as_deref() {
            lines.push(format!("on_behalf_of: {on_behalf_of}"));
        }
        if let Some(trigger_ref) = self.receipt.trigger_ref.as_deref() {
            lines.push(format!("trigger_ref: {trigger_ref}"));
        }
        lines.extend(
            self.links
                .iter()
                .map(|link| format!("link: {}", link.fallback_text())),
        );
        lines
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        self.receipt_lines().join(" | ")
    }

    fn atom_kit_root(&self) -> Result<LensNode> {
        let mut lines = vec![
            meta_line("kind", self.receipt.receipt_kind.as_str())?,
            meta_line("outcome", &self.receipt.outcome)?,
            meta_line("occurred_at", &self.receipt.occurred_at.to_string())?,
        ];
        if let Some(trigger_ref) = self.receipt.trigger_ref.as_deref() {
            lines.push(meta_line("trigger_ref", trigger_ref)?);
        }
        for link in &self.links {
            lines.push(meta_line(&link.label, &link.fallback_text())?);
        }

        Ok(LensNode::new(
            atom_id("receipt-view-root")?,
            LensAtom::Receipt(ReceiptAtom {
                title: lens_text(self.title())?,
                lines,
                seal: Some(SealAtom {
                    level: SealLevel::Actor,
                    label: lens_text("receipt_view")?,
                }),
            }),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDeepLink {
    pub target_kind: ReceiptDeepLinkKind,
    pub target_ref: String,
    pub label: String,
    pub resolution: ViewTimeResolution,
}

impl ReceiptDeepLink {
    pub fn new(
        target_kind: ReceiptDeepLinkKind,
        target_ref: impl Into<String>,
        label: impl Into<String>,
        resolution: ViewTimeResolution,
    ) -> Result<Self> {
        Ok(Self {
            target_kind,
            target_ref: non_empty("receipt deep-link target_ref", target_ref.into())?,
            label: non_empty("receipt deep-link label", label.into())?,
            resolution,
        })
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        format!(
            "{} -> {} ({})",
            self.label,
            self.target_ref,
            self.resolution.as_str()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDeepLinkKind {
    Commitment,
    TranscriptMoment,
    Brief,
    Share,
    AccessGrant,
    Entity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTimeResolution {
    Active,
    Revoked,
    Unavailable,
}

impl ViewTimeResolution {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Resolves a commitment-sourced receipt into a view-time deep link.
///
/// `Ok(None)` means the receipt does not name a commitment at all — a
/// non-commitment `intent_source`, or a commitment-sourced receipt whose
/// trigger is absent or carries some other prefix. Once a receipt DOES name a
/// commitment, this either produces a link or fails typed; it never degrades a
/// real reference into silence.
///
/// Resolution is about READABILITY at view time, not about whether the
/// obligation is still open. A fulfilled, released, lapsed or superseded
/// commitment resolves [`ViewTimeResolution::Active`] because its history is
/// still there to be read — that is the whole point of a receipt deep link.
/// Only a RETRACTED claim head resolves [`ViewTimeResolution::Revoked`]:
/// retraction is the owner saying the belief should not have been recorded,
/// and the link must say so rather than quietly showing it.
///
/// # Errors
///
/// [`Error::InvalidKey`] for a malformed `commitment:` suffix,
/// [`Error::EntityNotFound`] when no claim head exists under the referenced
/// id, [`Error::InvalidClaimBody`] when that head is not a `commitment.record`
/// claim, and the [`ReceiptDeepLink::new`] validation errors for an empty
/// label.
pub fn resolve_commitment_receipt_link(
    vault: &Vault,
    receipt: &ReceiptRecord,
    label: impl Into<String>,
) -> Result<Option<ReceiptDeepLink>> {
    let Some(target_ref) = commitment_trigger_ref(receipt)? else {
        return Ok(None);
    };
    let id = EntityId::from_hex(
        target_ref
            .strip_prefix(COMMITMENT_TRIGGER_PREFIX)
            .unwrap_or(target_ref.as_str()),
    )?;

    // The ungated targeted read on purpose: this is the history door, and a
    // closed commitment must stay reachable from the receipt that cited it.
    let body = vault.get_claim(&id)?.ok_or(Error::EntityNotFound)?;
    decode_commitment_claim(&body)?.ok_or(Error::InvalidClaimBody(
        "claim predicate is not commitment.record",
    ))?;

    let resolution = match body.lifecycle {
        ClaimLifecycleStatus::Retracted => ViewTimeResolution::Revoked,
        ClaimLifecycleStatus::Active | ClaimLifecycleStatus::Superseded => {
            ViewTimeResolution::Active
        }
    };
    ReceiptDeepLink::new(
        ReceiptDeepLinkKind::Commitment,
        target_ref,
        label,
        resolution,
    )
    .map(Some)
}

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

    fn atom_kit_root(&self) -> Result<LensNode> {
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

    fn atom_kit_root(&self) -> Result<LensNode> {
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

// ---------------------------------------------------------------------------
// DEC-0006 invariant 9 arming — surface (a), the in-moment ask
// ---------------------------------------------------------------------------

/// Action id of the approve-once outcome — the DEFAULT of the confirm trio.
pub const CONSENT_ACTION_APPROVE_ONCE: &str = "approve_once";
/// Action id of the deny outcome.
pub const CONSENT_ACTION_DECLINE: &str = "decline";
/// Action id prefix of the approve-and-stop-asking outcome. The suffix names
/// WHICH bound the owner is stamping ([`ConsentScopeEscalator::as_str`]), so a
/// stop-asking tap is always bound to one row rather than a blanket "yes".
pub const CONSENT_ACTION_ESCALATE_PREFIX: &str = "escalate_";
/// Action id prefix of the BATCH form of the same ask — the ARCH-0072
/// admission slate. It is surface (a) in batch form, not a third surface.
pub const CONSENT_BUNDLE_ACTION_ID_PREFIX: &str = "approve_bundle_";
/// Action id of the batch decline.
pub const CONSENT_BUNDLE_ACTION_DECLINE: &str = "decline_bundle";

/// The three outcomes DEC-0006 invariant 2 pins for EVERY manual confirm,
/// including a scope-exceed escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentConfirmOutcome {
    /// Approve once — the default.
    ApproveOnce,
    /// Approve and stop asking: the in-moment path into
    /// `Vault::create_standing_grant`, bounded to one grant row under the same
    /// owner stamp.
    ApproveAndStopAsking,
    /// Deny.
    Deny,
}

impl ConsentConfirmOutcome {
    /// The trio, in offer order — approve once is first because it is the
    /// default. There is deliberately no fourth outcome and no duration
    /// option: the registry replaces expiry-guessing (invariant 9).
    #[must_use]
    pub const fn trio() -> [Self; 3] {
        [Self::ApproveOnce, Self::ApproveAndStopAsking, Self::Deny]
    }

    /// Which outcome an emitted ask action id maps to.
    ///
    /// The escalator ids are the approve-and-stop-asking outcome: each one
    /// stamps ONE bound (contact / verb-class / channel), which is what makes
    /// stop-asking an owner act on a row rather than an inference.
    /// `escalate_just_once` is the escalator vocabulary's own restatement of
    /// approve-once and maps there.
    #[must_use]
    pub fn from_action_id(action_id: &str) -> Option<Self> {
        match action_id {
            CONSENT_ACTION_APPROVE_ONCE => Some(Self::ApproveOnce),
            CONSENT_ACTION_DECLINE | CONSENT_BUNDLE_ACTION_DECLINE => Some(Self::Deny),
            _ => {
                if let Some(scope) = action_id.strip_prefix(CONSENT_ACTION_ESCALATE_PREFIX) {
                    return Some(if scope == ConsentScopeEscalator::JustOnce.as_str() {
                        Self::ApproveOnce
                    } else {
                        Self::ApproveAndStopAsking
                    });
                }
                // A bundle approve is the batch form of approve-and-stop-asking:
                // one tap accepts the slate's drafted rows.
                action_id
                    .starts_with(CONSENT_BUNDLE_ACTION_ID_PREFIX)
                    .then_some(Self::ApproveAndStopAsking)
            }
        }
    }
}

/// Whether an emitted ask action id offers a duration/expiry choice.
///
/// Invariant 9 kills duration pickers everywhere the owner answers an ask; the
/// one named exception is a mint-time field on the ARCH-0071 delegation
/// record, which is not an ask option and never reaches this vocabulary.
#[must_use]
pub fn consent_action_id_offers_duration(action_id: &str) -> bool {
    const DURATION_TOKENS: [&str; 6] = ["duration", "expire", "expiry", "ttl", "until", "days"];
    DURATION_TOKENS
        .iter()
        .any(|token| action_id.contains(token))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentSurface {
    EiriConversation,
    Dashboard,
    SharedSlack,
    McpUi,
    Voice,
}

impl ConsentSurface {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EiriConversation => "eiri_conversation",
            Self::Dashboard => "dashboard",
            Self::SharedSlack => "shared_slack",
            Self::McpUi => "mcp_ui",
            Self::Voice => "voice",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "identity", rename_all = "snake_case")]
pub enum ConsentActorIdentity {
    SurfaceActor {
        actor_ref: String,
    },
    VoicePath {
        speaker_ref: String,
        owner_voice_print_verified: bool,
    },
}

impl ConsentActorIdentity {
    #[must_use]
    pub fn actor_ref(&self) -> &str {
        match self {
            Self::SurfaceActor { actor_ref } => actor_ref,
            Self::VoicePath { speaker_ref, .. } => speaker_ref,
        }
    }

    #[must_use]
    pub fn authenticates_principal(&self, principal_ref: &str) -> bool {
        if principal_ref.trim().is_empty() || self.actor_ref().trim().is_empty() {
            return false;
        }
        match self {
            Self::SurfaceActor { actor_ref } => actor_ref == principal_ref,
            Self::VoicePath {
                speaker_ref,
                owner_voice_print_verified,
            } => *owner_voice_print_verified && speaker_ref == principal_ref,
        }
    }

    /// Whether this claimed actor matches a store-authenticated owner handle.
    ///
    /// Consent action evaluation uses this door: neither actor text nor the
    /// caller-deserialized voice boolean is authority. The handle can only come
    /// from [`crate::Vault::authenticate_owner`].
    #[must_use]
    pub fn authenticates_owner(
        &self,
        principal_ref: &str,
        authenticated_owner: &AuthenticatedOwner,
    ) -> bool {
        !principal_ref.trim().is_empty()
            && !self.actor_ref().trim().is_empty()
            && authenticated_owner.principal_ref() == principal_ref
            && self.actor_ref() == principal_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentActionRequest {
    pub component_id: String,
    pub action_id: String,
    pub action: ConsentActionKind,
    pub actor: ConsentActorIdentity,
    pub surface: ConsentSurface,
    pub occurred_at: u64,
}

impl ConsentActionRequest {
    pub fn new(
        component_id: impl Into<String>,
        action_id: impl Into<String>,
        action: ConsentActionKind,
        actor: ConsentActorIdentity,
        surface: ConsentSurface,
        occurred_at: u64,
    ) -> Result<Self> {
        Ok(Self {
            component_id: non_empty("consent action component_id", component_id.into())?,
            action_id: non_empty("consent action action_id", action_id.into())?,
            action,
            actor,
            surface,
            occurred_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentActionKind {
    Approve,
    Decline,
    Escalate(ConsentScopeEscalator),
    BundleApprove(BundleApprovalScope),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentActionDecision {
    ApprovedOnce,
    Declined,
    GrantMintIntent,
    NoopNonPrincipal,
    NoopSurfaceIneligible,
    NoopBeneficiaryConfirm,
}

impl ConsentActionDecision {
    #[must_use]
    pub const fn outcome(self) -> &'static str {
        match self {
            Self::ApprovedOnce => "approved",
            Self::Declined => "declined",
            Self::GrantMintIntent => "grant_mint_intent",
            Self::NoopNonPrincipal => "no_op_non_principal",
            Self::NoopSurfaceIneligible => "no_op_surface_ineligible",
            Self::NoopBeneficiaryConfirm => "no_op_beneficiary_confirm",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentActionEvaluation {
    pub decision: ConsentActionDecision,
    pub receipt: ReceiptRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_mint_intent: Option<GrantMintIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantMintIntent {
    pub principal_ref: String,
    pub origin_component_id: String,
    pub origin_action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_receipt_ref: Option<String>,
    pub scope: GrantMintIntentScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum GrantMintIntentScope {
    JustOnce {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        effect_ref: Option<String>,
    },
    Contact {
        contact_ref: String,
    },
    VerbClass {
        verb_class: String,
    },
    Channel {
        channel: String,
    },
    BundleExactSends {
        send_refs: Vec<String>,
    },
    BriefVerbClass {
        brief_ref: String,
        verb_class: String,
    },
    /// One calendar shared at one rung with the intent's `principal_ref`.
    Calendar {
        calendar_ref: String,
        rung: DisclosureRung,
    },
}

/// Converts one bounded calendar-sharing sentence into exactly one
/// [`GrantMintIntent`].
///
/// The agent-facing input is a sentence — "share my work calendar fully with
/// Yura" — already resolved upstream to typed refs and a rung. This seam turns
/// that into a single `(calendar_ref, audience, rung)` grant intent, where the
/// audience is the intent's `principal_ref`. It never fans the sentence out
/// into a settings matrix: one sentence mints one scope, or it errors.
pub fn calendar_grant_mint_intent(
    principal_ref: &str,
    origin_component_id: &str,
    origin_action_id: &str,
    origin_receipt_ref: Option<&str>,
    calendar_ref: &str,
    rung: DisclosureRung,
) -> Result<GrantMintIntent> {
    Ok(GrantMintIntent {
        principal_ref: non_empty("calendar grant principal_ref", principal_ref.to_owned())?,
        origin_component_id: non_empty(
            "calendar grant origin_component_id",
            origin_component_id.to_owned(),
        )?,
        origin_action_id: non_empty(
            "calendar grant origin_action_id",
            origin_action_id.to_owned(),
        )?,
        origin_receipt_ref: origin_receipt_ref.map(str::to_owned),
        scope: GrantMintIntentScope::Calendar {
            calendar_ref: non_empty("calendar grant calendar_ref", calendar_ref.to_owned())?,
            rung,
        },
    })
}

fn append_eirispec_actions(
    elements: &mut serde_json::Map<String, Value>,
    root_children: &mut Vec<String>,
    actions: &[Of336ActionDescriptor],
) {
    for action in actions {
        let id = action.action_id.clone();
        root_children.push(id.clone());
        elements.insert(
            id,
            json!({
                "type": "button",
                "props": {
                    "label": action.label,
                    "action": {
                        "kind": "agentCallback",
                        "name": action.action_id,
                        "typedAction": action.action
                    }
                },
                "children": [],
                "fallbackText": action.label
            }),
        );
    }
}

fn action_button_node(action: Of336ActionDescriptor) -> Result<LensNode> {
    Ok(LensNode::new(
        atom_id(format!("action-{}", action.action_id))?,
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: control_id(&action.action_id)?,
            label: lens_text(action.label)?,
            action: SelfUiAction {
                command: action_id(action_command(&action.action))?,
                args: vec![SelfUiValue::Text(lens_text(action.action_id)?)],
            },
        })),
    ))
}

fn action_command(action: &ConsentActionKind) -> &'static str {
    match action {
        ConsentActionKind::Approve => "consent_approve",
        ConsentActionKind::Decline => "consent_decline",
        ConsentActionKind::Escalate(_) => "consent_grant_mint",
        ConsentActionKind::BundleApprove(_) => "bundle_grant_mint",
    }
}

fn consent_evaluation(
    component_kind: Of336ComponentKind,
    component_id: &str,
    principal_ref: &str,
    request: &ConsentActionRequest,
    decision: ConsentActionDecision,
    grant_mint_intent: Option<GrantMintIntent>,
) -> ConsentActionEvaluation {
    ConsentActionEvaluation {
        decision,
        receipt: consent_receipt(
            component_kind,
            component_id,
            principal_ref,
            request,
            decision,
            None,
        ),
        grant_mint_intent,
    }
}

fn ensure_authenticated_actor(
    principal_ref: &str,
    request: &ConsentActionRequest,
    authenticated_owner: &AuthenticatedOwner,
) -> Result<()> {
    if request
        .actor
        .authenticates_owner(principal_ref, authenticated_owner)
    {
        return Ok(());
    }
    Err(Error::ConsentUnauthenticatedActor(
        "the action actor is not bound to the card's store-authenticated principal",
    ))
}

fn noop_policy_rejection(
    component_kind: Of336ComponentKind,
    component_id: &str,
    principal_ref: &str,
    request: &ConsentActionRequest,
    decision: ConsentActionDecision,
    reason: &str,
) -> ConsentActionEvaluation {
    ConsentActionEvaluation {
        decision,
        receipt: consent_receipt(
            component_kind,
            component_id,
            principal_ref,
            request,
            decision,
            Some(reason),
        ),
        grant_mint_intent: None,
    }
}

const fn widening_grant_surface_is_eligible(surface: ConsentSurface) -> bool {
    matches!(
        surface,
        ConsentSurface::EiriConversation | ConsentSurface::Dashboard | ConsentSurface::McpUi
    )
}

fn consent_receipt(
    component_kind: Of336ComponentKind,
    component_id: &str,
    principal_ref: &str,
    request: &ConsentActionRequest,
    decision: ConsentActionDecision,
    reason: Option<&str>,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert(
        "component_kind".to_owned(),
        component_kind.as_str().to_owned(),
    );
    fields.insert("component_id".to_owned(), component_id.to_owned());
    fields.insert("action_id".to_owned(), request.action_id.clone());
    fields.insert("surface".to_owned(), request.surface.as_str().to_owned());
    fields.insert(
        "expected_principal_ref".to_owned(),
        principal_ref.to_owned(),
    );
    if let Some(reason) = reason {
        fields.insert("reason".to_owned(), reason.to_owned());
    }

    ReceiptRecord {
        receipt_id: format!(
            "consent:{}:{}:{}",
            component_id, request.action_id, request.occurred_at
        ),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: request.occurred_at,
        actor: Some(request.actor.actor_ref().to_owned()),
        on_behalf_of: Some(principal_ref.to_owned()),
        outcome: decision.outcome().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("of336:{component_id}")),
        policy_trace: reason.map_or_else(
            || vec!["principal_auth:principal_bound".to_owned()],
            |reason| vec![reason.to_owned()],
        ),
        fields,
    }
}

fn ensure_component_request(card_id: &str, request: &ConsentActionRequest) -> Result<()> {
    if request.component_id == card_id {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "consent action targets component {:?}, expected {:?}",
        request.component_id, card_id
    )))
}

fn ensure_principal_ref(principal_ref: &str) -> Result<()> {
    if principal_ref.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "consent principal_ref must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn ensure_declared_action(
    actions: &[Of336ActionDescriptor],
    request: &ConsentActionRequest,
) -> Result<()> {
    let Some(action) = actions
        .iter()
        .find(|action| action.action_id == request.action_id)
    else {
        return Err(Error::InvalidConfig(format!(
            "consent action {:?} was not declared by component {:?}",
            request.action_id, request.component_id
        )));
    };
    if action.action == request.action {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "consent action {:?} payload does not match declared typed action",
        request.action_id
    )))
}

fn required_scope_ref<'a>(scope: &str, value: Option<&'a str>) -> Result<&'a str> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::InvalidConfig(format!("{scope} requires a bound scope ref")))
}

fn non_empty(context: &str, value: String) -> Result<String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(Error::InvalidConfig(format!("{context} must not be empty")));
    }
    Ok(value)
}

fn lens_text(value: impl Into<String>) -> Result<LensText> {
    LensText::new(value)
}

fn atom_id(value: impl Into<String>) -> Result<LensAtomId> {
    LensAtomId::new(value)
}

fn control_id(value: &str) -> Result<SelfUiControlId> {
    SelfUiControlId::new(value)
}

fn action_id(value: &str) -> Result<SelfUiActionId> {
    SelfUiActionId::new(value)
}

fn meta_line(label: &str, value: &str) -> Result<MetaLineAtom> {
    Ok(MetaLineAtom {
        label: lens_text(label)?,
        value: lens_text(value)?,
    })
}

// ── ONE-1887 surfaced-failure card data contract ────────────────────────────
//
// Consumer-neutral ENGINE data only. The renderer/surface lane decides how to
// draw the loom-style diagram; this contract identifies the failing node and
// exposes the references an interactive Q&A needs. There are deliberately no
// pixels, no layout, no localized copy, and no downstream product names here.

/// The only schema constant this card carries.
pub const SURFACED_FAILURE_CARD_SCHEMA_VERSION: u16 = 1;

/// Edges one Q&A validation step reads before it stops looking.
const HEALER_QA_EDGE_SCAN_LIMIT: usize = 64;

/// Where the healer's diagnosis stands when the card is emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureDiagnosisState {
    /// A configured healer has the case but has not answered yet.
    NotRun,
    /// The scope's healer slot is explicitly reserved. This is a first-class
    /// state, never a generic failure string and never [`Self::NotRun`].
    ReservedHealerSlot,
    Diagnosed(HealerRepairRoute),
}

/// One referenced Q&A message. The body stays in the MESSAGE record; the card
/// never inlines a replacement transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealerQaEntryRef {
    /// Lowercase-hex MESSAGE EntityId spelling.
    pub message_ref: String,
    /// Lowercase-hex witnessed author EntityId spelling.
    pub actor_ref: String,
    pub occurred_at: u64,
}

/// The reference-backed healer/human Q&A feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealerQaFeed {
    /// Lowercase-hex thread EntityId spelling.
    pub thread_ref: String,
    #[serde(default)]
    pub entries: Vec<HealerQaEntryRef>,
}

/// The typed human surface for one terminalized failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfacedFailureCard {
    pub schema_version: u16,
    /// Lowercase-hex deterministic failure-card correlation key.
    pub card_ref: String,
    /// Lowercase-hex deterministic failure-case correlation key.
    pub case_ref: String,
    pub failure_class: FailureClass,
    /// Always 0 for permanent/ambiguous by policy; never computed from lineage
    /// for those classes.
    pub consecutive_transients: u16,
    #[serde(default)]
    pub pathology: Option<RetryLineagePathology>,
    pub diagram: RunTreeFailureDiagram,
    pub diagnosis: FailureDiagnosisState,
    #[serde(default)]
    pub blocked_reports: Vec<BlockedReportRef>,
    pub qa: HealerQaFeed,
}

/// Caller input for [`surfaced_failure_card`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfacedFailureCardInput {
    pub failure_class: FailureClass,
    pub consecutive_transients: u16,
    pub pathology: Option<RetryLineagePathology>,
    pub tree: RunTree,
    pub failing_attempt_id: AttemptId,
    pub diagnosis: FailureDiagnosisState,
    pub blocked_reports: Vec<BlockedReportRef>,
    pub qa: HealerQaFeed,
}

/// Composes the typed surfaced-failure card.
///
/// `card_ref`/`case_ref` are MINTED here from `failing_attempt_id` through the
/// pinned domain-separated derivation — never accepted as free caller strings.
/// The pathology carrier is copied through unchanged: it is `Some` only for an
/// immediate pathology surface and never enters a `HealerCase`.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the marker does not name exactly one rendered
/// node, when a ref is not hex, when a `message_ref` does not resolve to a live
/// MESSAGE, when membership or authorship does not hold, when `occurred_at`
/// disagrees with the message's `occurred_start`, when a permanent/ambiguous
/// failure carries a nonzero transient count, or when a diagnosed repair does
/// not name the failing attempt's dispatched agent.
pub fn surfaced_failure_card(
    vault: &Vault,
    input: SurfacedFailureCardInput,
) -> Result<SurfacedFailureCard> {
    if matches!(
        input.failure_class,
        FailureClass::Permanent | FailureClass::Ambiguous
    ) && input.consecutive_transients != 0
    {
        return Err(Error::InvalidConfig(
            "permanent/ambiguous failure cards require zero consecutive_transients".to_owned(),
        ));
    }
    if let FailureDiagnosisState::Diagnosed(route) = &input.diagnosis {
        require_diagnosed_agent(vault, input.failing_attempt_id, route)?;
    }
    let diagram = mark_run_tree_failure(input.tree, input.failing_attempt_id)?;
    let qa = validated_qa_feed(vault, input.qa)?;
    let blocked_reports =
        crate::failure_ladder::verified_blocked_reports(vault, &input.blocked_reports)?;
    Ok(SurfacedFailureCard {
        schema_version: SURFACED_FAILURE_CARD_SCHEMA_VERSION,
        card_ref: failure_card_ref(input.failing_attempt_id),
        case_ref: failure_case_ref(input.failing_attempt_id),
        failure_class: input.failure_class,
        consecutive_transients: input.consecutive_transients,
        pathology: input.pathology,
        diagram,
        diagnosis: input.diagnosis,
        blocked_reports,
        qa,
    })
}

/// A selected repair must target the agent dispatched by the failing row.
/// Initial cards without a diagnosis do not require this additional read.
fn require_diagnosed_agent(
    vault: &Vault,
    failing_attempt_id: AttemptId,
    route: &HealerRepairRoute,
) -> Result<()> {
    let agent_ref = match route {
        HealerRepairRoute::SkillEdit { agent_ref, .. }
        | HealerRepairRoute::PromptInjectAndForkResume { agent_ref, .. }
        | HealerRepairRoute::Environment { agent_ref, .. }
        | HealerRepairRoute::EscalateWithDiagnosis { agent_ref, .. } => agent_ref,
    };
    let expected = parse_card_ref("healer diagnosis agent_ref", agent_ref)?;
    let record = crate::AttemptQueue::new(vault)
        .get(failing_attempt_id)?
        .ok_or_else(|| {
            Error::InvalidConfig("healer diagnosis requires a stored failing attempt".to_owned())
        })?;
    if crate::failure_ladder::dispatched_target_ref(&record) != Some(expected) {
        return Err(Error::InvalidConfig(
            "healer diagnosis agent must match the failing attempt's dispatched agent".to_owned(),
        ));
    }
    Ok(())
}

/// Validates every Q&A entry against the vault, then orders the survivors
/// deterministically by `(occurred_at, message_ref)`.
fn validated_qa_feed(vault: &Vault, feed: HealerQaFeed) -> Result<HealerQaFeed> {
    let thread_ref = parse_card_ref("healer qa thread_ref", &feed.thread_ref)?;
    let mut entries = Vec::with_capacity(feed.entries.len());
    for entry in feed.entries {
        entries.push(validated_qa_entry(vault, thread_ref, entry)?);
    }
    entries.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then_with(|| left.message_ref.cmp(&right.message_ref))
    });
    Ok(HealerQaFeed {
        thread_ref: feed.thread_ref,
        entries,
    })
}

fn validated_qa_entry(
    vault: &Vault,
    thread_ref: EntityId,
    entry: HealerQaEntryRef,
) -> Result<HealerQaEntryRef> {
    let message_ref = parse_card_ref("healer qa message_ref", &entry.message_ref)?;
    let actor_ref = parse_card_ref("healer qa actor_ref", &entry.actor_ref)?;
    let occurred_start = message_occurred_start(vault, message_ref)?;
    if occurred_start != entry.occurred_at {
        return Err(Error::InvalidConfig(
            "healer qa occurred_at must equal the message's occurred_start".to_owned(),
        ));
    }
    require_thread_membership(vault, message_ref, thread_ref)?;
    require_witnessed_author(vault, message_ref, actor_ref)?;
    Ok(entry)
}

/// Resolves `message_ref` for kind MESSAGE only and returns its
/// `occurred_start`. A header-only row is the soft-delete shell, not a
/// referenceable message.
fn message_occurred_start(vault: &Vault, message_ref: EntityId) -> Result<u64> {
    let Some(raw) = vault.get_raw(&message_ref)? else {
        return Err(Error::InvalidConfig(
            "healer qa message_ref must resolve to a stored MESSAGE".to_owned(),
        ));
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_MESSAGE || raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Err(Error::InvalidConfig(
            "healer qa message_ref must resolve to a live MESSAGE entity".to_owned(),
        ));
    }
    Ok(header.occurred_start)
}

/// Membership is an EDGE fact read through the vault's existing bounded
/// neighbor surface. Direct membership uses `PartOf` or `BelongsTo`; canonical
/// MESSAGE→TURN→CONVERSATION membership uses `PartOf` then `ChildOf`. The walk
/// stops at two hops, and `thread_ref` may name either container.
fn require_thread_membership(
    vault: &Vault,
    message_ref: EntityId,
    thread_ref: EntityId,
) -> Result<()> {
    let containers = vault.neighbor_edges_bounded(
        &message_ref,
        true,
        Some(EdgeKind::PartOf),
        None,
        HEALER_QA_EDGE_SCAN_LIMIT,
    )?;
    if containers.iter().any(|edge| edge.target == thread_ref) {
        return Ok(());
    }
    let conversations = vault.neighbor_edges_bounded(
        &message_ref,
        true,
        Some(EdgeKind::BelongsTo),
        None,
        HEALER_QA_EDGE_SCAN_LIMIT,
    )?;
    if conversations.iter().any(|edge| edge.target == thread_ref) {
        return Ok(());
    }
    for edge in &containers {
        let outer = vault.neighbor_edges_bounded(
            &edge.target,
            true,
            Some(EdgeKind::ChildOf),
            None,
            HEALER_QA_EDGE_SCAN_LIMIT,
        )?;
        if outer.iter().any(|hop| hop.target == thread_ref) {
            return Ok(());
        }
    }
    Err(Error::InvalidConfig(
        "healer qa message_ref is not part of the named thread".to_owned(),
    ))
}

/// Authorship is likewise an edge fact. A MESSAGE with NO `AuthoredBy` edge —
/// System-authored rows carry none by design — fails validation; surface
/// system/tool output by referencing the containing witnessed exchange instead.
fn require_witnessed_author(
    vault: &Vault,
    message_ref: EntityId,
    actor_ref: EntityId,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let author = crate::memory::sole_edge_target(
        &vault.store,
        &txn,
        &message_ref,
        EdgeKind::AuthoredBy,
        "message",
    )
    .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    if author.is_none() {
        return Err(Error::InvalidConfig(
            "healer qa message_ref carries no AuthoredBy witness".to_owned(),
        ));
    }
    if author == Some(actor_ref) {
        return Ok(());
    }
    Err(Error::InvalidConfig(
        "healer qa actor_ref is not the message's witnessed author".to_owned(),
    ))
}

fn parse_card_ref(context: &str, value: &str) -> Result<EntityId> {
    EntityId::from_hex(value).map_err(|_| {
        Error::InvalidConfig(format!("{context} must be a hex-encoded EntityId string"))
    })
}

#[cfg(test)]
mod tests;
