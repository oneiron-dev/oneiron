//! Typed document, recipient, field and event vocabulary for ARCH-0064.
use crate::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    Document,
    Template,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentStatus {
    Draft,
    Pending,
    Completed,
    Rejected,
    Voided,
    Expired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientRole {
    Signer,
    Approver,
    Viewer,
    Cc,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Unsent,
    Sent,
    Viewed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningStatus {
    Waiting,
    Ready,
    Completed,
    Rejected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessStatus {
    Unverified,
    Verified,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignItem {
    pub artifact_ref: String,
    pub original_version: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignRecipient {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: RecipientRole,
    pub order: u32,
    pub expires_at: u64,
    /// Subject/principal identity, not a compiled persona.
    pub principal_ref: Option<String>,
    pub automated: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldGeometry {
    pub page: u32,
    pub x_percent: f64,
    pub y_percent: f64,
    pub width_percent: f64,
    pub height_percent: f64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldMeta {
    Signature,
    Initials,
    Name,
    Email,
    Date,
    Text { max_bytes: u32 },
    Checkbox,
    Select { options: Vec<String> },
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignField {
    pub id: String,
    pub item: u32,
    pub recipient: String,
    pub required: bool,
    pub geometry: FieldGeometry,
    pub meta: FieldMeta,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignDocument {
    pub schema_version: u8,
    pub kind: DocumentKind,
    pub title: String,
    pub sequential: bool,
    pub expires_at: u64,
    pub items: Vec<EsignItem>,
    pub recipients: Vec<EsignRecipient>,
    pub fields: Vec<EsignField>,
    pub full_trail_appendix: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignAuditActor {
    pub actor: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum FieldValue {
    Text(String),
    Checked(bool),
    Signature { image_ref: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureRow {
    pub field: String,
    pub recipient: String,
    pub value: FieldValue,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientState {
    pub delivery: DeliveryStatus,
    pub signing: SigningStatus,
    pub access: AccessStatus,
    pub expires_at: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum EsignEvent {
    Drafted {
        document: EsignDocument,
    },
    Sent,
    Viewed {
        recipient: String,
    },
    FieldSaved {
        signature: SignatureRow,
    },
    Signed {
        recipient: String,
        next: Option<String>,
    },
    Declined {
        recipient: String,
        reason: String,
    },
    Voided {
        reason: String,
    },
    Expired,
    /// Authored only after native verification succeeds for every sealed item.
    Sealed {
        rejected: bool,
        item_sha256: Vec<[u8; 32]>,
    },
    ResealRequested {
        owner: String,
        authorization: String,
    },
}
impl EsignEvent {
    pub(super) fn predicate(&self) -> &'static str {
        match self {
            Self::Drafted { .. } => "esign.draft",
            Self::Sent => "esign.sent",
            Self::Viewed { .. } => "esign.viewed",
            Self::FieldSaved { .. } => "esign.field",
            Self::Signed { .. } => "esign.signed",
            Self::Declined { .. } => "esign.declined",
            Self::Voided { .. } => "esign.voided",
            Self::Expired => "esign.expired",
            Self::Sealed {
                rejected: false, ..
            } => "esign.completed",
            Self::Sealed { rejected: true, .. } => "esign.rejected",
            Self::ResealRequested { .. } => "esign.reseal_requested",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignEventRow {
    pub sequence: u64,
    pub previous_sha256: [u8; 32],
    pub event: EsignEvent,
    pub actor: EsignAuditActor,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq)]
pub struct EsignState {
    pub document: EsignDocument,
    pub status: DocumentStatus,
    pub recipients: BTreeMap<String, RecipientState>,
    /// One current signature/value per field, never a duplicate signature row.
    pub signatures: BTreeMap<String, SignatureRow>,
    pub rejection: Option<String>,
    pub sealed_sha256: Vec<[u8; 32]>,
    pub reseal_pending: bool,
}

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("esign: {reason}"))
}
pub(super) fn reference(value: &str) -> Result<()> {
    if EntityId::from_hex(value)?.to_hex() == value {
        Ok(())
    } else {
        Err(invalid("noncanonical reference"))
    }
}
pub(super) fn validate_document(doc: &EsignDocument, now: u64) -> Result<()> {
    if doc.schema_version != 1
        || doc.title.is_empty()
        || doc.title.len() > 4096
        || doc.items.is_empty()
        || doc.items.len() > 100
        || doc.recipients.len() > 1000
        || doc.fields.len() > 10000
        || doc.expires_at <= now
    {
        return Err(invalid("invalid document bounds"));
    }
    let mut items = BTreeSet::new();
    for item in &doc.items {
        reference(&item.artifact_ref)?;
        if item.original_version == 0 || !items.insert(&item.artifact_ref) {
            return Err(invalid("invalid item"));
        }
    }
    let mut recipients = BTreeSet::new();
    for r in &doc.recipients {
        reference(&r.id)?;
        if let Some(principal) = &r.principal_ref {
            reference(principal)?;
        }
        if !recipients.insert(&r.id)
            || r.email.len() > 320
            || !r.email.contains('@')
            || r.email.contains(['\r', '\n'])
            || r.name.len() > 4096
            || r.expires_at <= now
            || r.expires_at > doc.expires_at
        {
            return Err(invalid("invalid recipient"));
        }
    }
    let mut fields = BTreeSet::new();
    for f in &doc.fields {
        reference(&f.id)?;
        let g = &f.geometry;
        if !fields.insert(&f.id)
            || !recipients.contains(&f.recipient)
            || !doc.recipients.iter().any(|r| {
                r.id == f.recipient
                    && matches!(r.role, RecipientRole::Signer | RecipientRole::Approver)
            })
            || f.item as usize >= doc.items.len()
            || g.page == 0
            || [g.x_percent, g.y_percent, g.width_percent, g.height_percent]
                .iter()
                .any(|v| !v.is_finite() || *v < 0.0 || *v > 100.0)
            || g.width_percent == 0.0
            || g.height_percent == 0.0
            || g.x_percent + g.width_percent > 100.0
            || g.y_percent + g.height_percent > 100.0
        {
            return Err(invalid("invalid field geometry or owner"));
        }
        match &f.meta {
            FieldMeta::Text { max_bytes } if *max_bytes == 0 || *max_bytes > 65536 => {
                return Err(invalid("invalid text field"));
            }
            FieldMeta::Select { options }
                if options.is_empty()
                    || options.len() > 256
                    || options.iter().any(|v| v.is_empty() || v.len() > 4096)
                    || options.iter().collect::<BTreeSet<_>>().len() != options.len() =>
            {
                return Err(invalid("invalid choices"));
            }
            _ => {}
        }
    }
    Ok(())
}
