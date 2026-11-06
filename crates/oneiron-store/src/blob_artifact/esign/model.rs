//! Typed document, recipient, field and event vocabulary for ARCH-0064.
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    Document,
    Template,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocumentStatus {
    Draft,
    Pending,
    Completed,
    Rejected,
    Voided,
    Expired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignItem {
    pub artifact_ref: String,
    pub original_version: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The law that keeps this recipient's signature with a natural person,
    /// when one does (ARCH-0076 #roles-everywhere). Such a recipient is never
    /// automated, so no dial, rung or escalated role signs for them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub natural_person: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldGeometry {
    pub page: u32,
    pub x_percent: f64,
    pub y_percent: f64,
    pub width_percent: f64,
    pub height_percent: f64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignField {
    pub id: String,
    pub item: u32,
    pub recipient: String,
    pub required: bool,
    pub geometry: FieldGeometry,
    pub meta: FieldMeta,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignAuditActor {
    pub actor: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum FieldValue {
    Text(String),
    Checked(bool),
    Signature { image_ref: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsignAuthenticationMethod {
    Bearer,
    Person,
    Agent,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsignSigningIntent {
    Direct,
    HeldAllow,
}
/// The accepted act's evidence, kept apart from the platform's seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningEvidence {
    pub authentication_method: EsignAuthenticationMethod,
    /// No disclosure artifact exists yet; absence is recorded, not invented.
    pub disclosure_version: Option<String>,
    pub consent: bool,
    pub intent: EsignSigningIntent,
}
/// The predicate of the claim that opens a signing document's ledger.
pub const DRAFT_PREDICATE: &str = "esign.draft";

pub fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("esign: {reason}"))
}
pub fn reference(value: &str) -> Result<()> {
    if EntityId::from_hex(value)?.to_hex() == value {
        Ok(())
    } else {
        Err(invalid("noncanonical reference"))
    }
}
/// The longest address an SMTP path carries: a 64-octet local part, `@` and a
/// 255-octet domain (RFC 5321 section 4.5.3.1). A recipient is mailed, so this
/// is a format bound, not a cap.
pub const EMAIL_MAX_BYTES: usize = 64 + 1 + 255;
