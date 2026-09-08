//! OF-336 envelope, adapters, component enum and render dispatch.

use super::consent_cards::{BundleApproveCard, ConsentAskCard};
use super::consent_eval::{ConsentActionKind, append_eirispec_actions};
use super::receipt_view::ReceiptViewComponent;
use crate::lens::GeneratedLens;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
