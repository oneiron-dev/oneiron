//! MCP connector actor registry.
//!
//! The registry is deliberately not an authority carrier. It resolves an
//! external connector credential to the actor identity and scope that the MCP
//! gateway should attach to the existing vault write path. Approval authority
//! remains in Gate `actor_ceilings` policy rows.

use std::{collections::BTreeMap, fmt};

use oneiron::{
    EdgeActorClass, EntityId, WriteActor,
    context_pack::{MCP_CONTEXT_PACK_REF_SCHEMA_VERSION, McpContextPackRef},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub const MCP_TOOL_ARGS_SCHEMA_VERSION: &str = "mcp_tool_args.v1";
const MCP_SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const ENTITY_ID_PATTERN: &str = "^[0-9a-f]{32}$";
const SHORT_REF_PATTERN: &str = "^[a-z]{2}[0-9]+:[0-9A-Fa-f]{2}$";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpToolName {
    Nav,
    Read,
    Edit,
    Ask,
    RoutedAsk,
}

impl McpToolName {
    const ALL: [Self; 5] = [
        Self::Nav,
        Self::Read,
        Self::Edit,
        Self::Ask,
        Self::RoutedAsk,
    ];

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &Self::ALL
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nav => "oneiron.nav",
            Self::Read => "oneiron.read",
            Self::Edit => "oneiron.edit",
            Self::Ask => "oneiron.ask",
            Self::RoutedAsk => "oneiron.ask_routed",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "oneiron.nav" => Some(Self::Nav),
            "oneiron.read" => Some(Self::Read),
            "oneiron.edit" => Some(Self::Edit),
            "oneiron.ask" => Some(Self::Ask),
            "oneiron.ask_routed" => Some(Self::RoutedAsk),
            _ => None,
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Nav => "Navigate the Oneiron plain verb surface without mutating the vault.",
            Self::Read => "Read one resolved Oneiron entity, short ref, or context-pack reference.",
            Self::Edit => "Validate a named Oneiron memory edit verb before any vault mutation.",
            Self::Ask => {
                "Ask over a supplied context pack while preserving actor and consent metadata."
            }
            Self::RoutedAsk => {
                "Ask over a supplied context pack with explicit foreign-client routing metadata."
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct McpToolSchema {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[must_use]
pub fn mcp_tool_schemas() -> Vec<McpToolSchema> {
    McpToolName::all()
        .iter()
        .copied()
        .map(mcp_tool_schema)
        .collect()
}

#[must_use]
pub fn mcp_tool_schema(tool: McpToolName) -> McpToolSchema {
    let input_schema = match tool {
        McpToolName::Nav => nav_tool_schema(),
        McpToolName::Read => read_tool_schema(),
        McpToolName::Edit => edit_tool_schema(),
        McpToolName::Ask => ask_tool_schema(),
        McpToolName::RoutedAsk => routed_ask_tool_schema(),
    };

    McpToolSchema {
        name: tool.as_str(),
        description: tool.description(),
        input_schema,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "tool", content = "args", rename_all = "snake_case")]
pub enum McpValidatedToolArgs {
    Nav(McpNavToolArgs),
    Read(McpReadToolArgs),
    Edit(McpEditToolArgs),
    Ask(McpAskToolArgs),
    RoutedAsk(McpRoutedAskToolArgs),
}

pub fn validate_mcp_tool_args(
    tool: McpToolName,
    args: Value,
) -> Result<McpValidatedToolArgs, McpToolValidationError> {
    match tool {
        McpToolName::Nav => {
            decode_tool_args::<McpNavToolArgs>(tool, args).map(McpValidatedToolArgs::Nav)
        }
        McpToolName::Read => {
            decode_tool_args::<McpReadToolArgs>(tool, args).map(McpValidatedToolArgs::Read)
        }
        McpToolName::Edit => {
            decode_tool_args::<McpEditToolArgs>(tool, args).map(McpValidatedToolArgs::Edit)
        }
        McpToolName::Ask => {
            decode_tool_args::<McpAskToolArgs>(tool, args).map(McpValidatedToolArgs::Ask)
        }
        McpToolName::RoutedAsk => decode_tool_args::<McpRoutedAskToolArgs>(tool, args)
            .map(McpValidatedToolArgs::RoutedAsk),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpToolValidationError {
    #[error("{tool} args are not valid for the tool schema: {message}")]
    Decode { tool: &'static str, message: String },
    #[error("{tool}.{field}: {message}")]
    Field {
        tool: &'static str,
        field: &'static str,
        message: String,
    },
}

impl McpToolValidationError {
    fn field(tool: McpToolName, field: &'static str, message: impl Into<String>) -> Self {
        Self::Field {
            tool: tool.as_str(),
            field,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpNavToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub mode: McpNavMode,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub context_pack: Option<McpContextPackRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpNavMode {
    Search,
    Timeline,
    List,
    Hydrate,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpReadToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub target: McpReadTarget,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpReadTarget {
    #[serde(default)]
    pub entity_ref: Option<String>,
    #[serde(default)]
    pub short_ref: Option<String>,
    #[serde(default)]
    pub context_pack: Option<McpContextPackRef>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpEditToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub verb: McpEditVerb,
    pub idempotency_key: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub entity: Option<McpEditEntityInput>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub new_id: Option<String>,
    #[serde(default)]
    pub old_id: Option<String>,
    #[serde(default)]
    pub at: Option<u64>,
    #[serde(default)]
    pub reason: Option<McpDeleteReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpEditVerb {
    Remember,
    Supersede,
    Retract,
    Delete,
    HardDelete,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpEditEntityInput {
    #[serde(default)]
    pub id: Option<String>,
    pub entity_type: u8,
    #[serde(default)]
    pub occurred_start: Option<u64>,
    #[serde(default)]
    pub occurred_end: Option<u64>,
    #[serde(default)]
    pub learned_at: Option<u64>,
    pub body: Value,
    #[serde(default)]
    pub text: Vec<McpTextField>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpTextField {
    pub field: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpDeleteReason {
    #[serde(rename = "user_delete")]
    User,
    #[serde(rename = "user_hard_delete")]
    UserHard,
    #[serde(rename = "gdpr_delete")]
    Gdpr,
    #[serde(rename = "policy_delete")]
    Policy,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpAskToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub context_pack: McpContextPackRef,
    pub consent: McpConsentMetadata,
    pub query: String,
    #[serde(default)]
    pub effort: Option<McpAskEffort>,
    #[serde(default)]
    pub citation_mode: Option<McpCitationMode>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpRoutedAskToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub context_pack: McpContextPackRef,
    pub consent: McpConsentMetadata,
    pub query: String,
    pub route: McpAskRoute,
    #[serde(default)]
    pub effort: Option<McpAskEffort>,
    #[serde(default)]
    pub citation_mode: Option<McpCitationMode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpAskEffort {
    Minimal,
    Standard,
    Deep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpCitationMode {
    ClaimRefs,
    ClaimRefsAndSpans,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpAskRoute {
    pub model_tier: String,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub substrate_ref: Option<String>,
    #[serde(default)]
    pub reasoning_effort: Option<McpAskEffort>,
    #[serde(default)]
    pub max_latency_ms: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpActorMetadata {
    pub actor_ref: String,
    pub actor_class: McpActorClass,
    pub gate_actor_class: McpActorClass,
    pub gate_actor_ref: String,
    pub scope: McpToolScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpActorClass {
    Human,
    Agent,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolScope {
    #[serde(default)]
    pub world_ref: Option<String>,
    #[serde(default)]
    pub facet_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpConsentMetadata {
    pub policy_ref: String,
    pub purpose: String,
    #[serde(default)]
    pub approval_ref: Option<String>,
    #[serde(default)]
    pub consent_receipt_ref: Option<String>,
    #[serde(default)]
    pub require_human_approval: bool,
}

trait ValidateMcpArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError>;
}

impl ValidateMcpArgs for McpNavToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        validate_optional_nonblank(tool, "query", self.query.as_deref())?;
        validate_optional_nonblank(tool, "cursor", self.cursor.as_deref())?;
        if self.limit == Some(0) {
            return Err(McpToolValidationError::field(
                tool,
                "limit",
                "must be greater than zero",
            ));
        }
        validate_optional_context_pack(tool, self.context_pack.as_ref())
    }
}

impl ValidateMcpArgs for McpReadToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        self.target.validate(tool)
    }
}

impl ValidateMcpArgs for McpEditToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "idempotency_key", &self.idempotency_key)?;

        match self.verb {
            McpEditVerb::Remember => {
                let entity = self.entity.as_ref().ok_or_else(|| {
                    McpToolValidationError::field(tool, "entity", "is required for remember")
                })?;
                entity.validate(tool)?;
                validate_absent(tool, "id", self.id.is_some())?;
                validate_absent(tool, "new_id", self.new_id.is_some())?;
                validate_absent(tool, "old_id", self.old_id.is_some())?;
                validate_absent(tool, "at", self.at.is_some())?;
                validate_absent(tool, "reason", self.reason.is_some())
            }
            McpEditVerb::Supersede => {
                validate_absent(tool, "entity", self.entity.is_some())?;
                validate_absent(tool, "id", self.id.is_some())?;
                validate_absent(tool, "reason", self.reason.is_some())?;
                validate_required_entity_ref(tool, "new_id", self.new_id.as_deref())?;
                validate_required_entity_ref(tool, "old_id", self.old_id.as_deref())
            }
            McpEditVerb::Retract => {
                validate_absent(tool, "entity", self.entity.is_some())?;
                validate_absent(tool, "new_id", self.new_id.is_some())?;
                validate_absent(tool, "old_id", self.old_id.is_some())?;
                validate_absent(tool, "reason", self.reason.is_some())?;
                validate_required_entity_ref(tool, "id", self.id.as_deref())
            }
            McpEditVerb::Delete => {
                self.validate_delete_family(tool)?;
                let reason = self.reason.ok_or_else(|| {
                    McpToolValidationError::field(tool, "reason", "is required for delete")
                })?;
                if reason != McpDeleteReason::User {
                    return Err(McpToolValidationError::field(
                        tool,
                        "reason",
                        "delete only accepts user_delete",
                    ));
                }
                Ok(())
            }
            McpEditVerb::HardDelete => {
                self.validate_delete_family(tool)?;
                let reason = self.reason.ok_or_else(|| {
                    McpToolValidationError::field(tool, "reason", "is required for hard_delete")
                })?;
                if reason == McpDeleteReason::User {
                    return Err(McpToolValidationError::field(
                        tool,
                        "reason",
                        "hard_delete requires user_hard_delete, gdpr_delete, or policy_delete",
                    ));
                }
                Ok(())
            }
        }
    }
}

impl McpEditToolArgs {
    fn validate_delete_family(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_absent(tool, "entity", self.entity.is_some())?;
        validate_absent(tool, "new_id", self.new_id.is_some())?;
        validate_absent(tool, "old_id", self.old_id.is_some())?;
        validate_absent(tool, "at", self.at.is_some())?;
        validate_required_entity_ref(tool, "id", self.id.as_deref())
    }
}

impl ValidateMcpArgs for McpAskToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        validate_context_pack(tool, &self.context_pack)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "query", &self.query)
    }
}

impl ValidateMcpArgs for McpRoutedAskToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        validate_context_pack(tool, &self.context_pack)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "query", &self.query)?;
        self.route.validate(tool)
    }
}

impl McpReadTarget {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        match (
            self.entity_ref.as_deref(),
            self.short_ref.as_deref(),
            self.context_pack.as_ref(),
        ) {
            (Some(entity_ref), None, None) => {
                validate_entity_ref(tool, "target.entity_ref", entity_ref)
            }
            (None, Some(short_ref), None) => {
                validate_short_ref(tool, "target.short_ref", short_ref)
            }
            (None, None, Some(context_pack)) => {
                validate_context_pack_field(tool, "target.context_pack", context_pack)
            }
            _ => Err(McpToolValidationError::field(
                tool,
                "target",
                "must include exactly one of entity_ref, short_ref, or context_pack",
            )),
        }
    }
}

impl McpEditEntityInput {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_optional_entity_ref(tool, "entity.id", self.id.as_deref())?;
        if let (Some(start), Some(end)) = (self.occurred_start, self.occurred_end)
            && start > end
        {
            return Err(McpToolValidationError::field(
                tool,
                "entity.occurred_start",
                "must be less than or equal to entity.occurred_end",
            ));
        }
        for text in &self.text {
            text.validate(tool)?;
        }
        Ok(())
    }
}

impl McpTextField {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_nonblank(tool, "entity.text.field", &self.field)?;
        validate_nonblank(tool, "entity.text.value", &self.value)
    }
}

impl McpAskRoute {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_nonblank(tool, "route.model_tier", &self.model_tier)?;
        validate_optional_nonblank(tool, "route.model_id", self.model_id.as_deref())?;
        validate_optional_nonblank(tool, "route.substrate_ref", self.substrate_ref.as_deref())?;
        if self.max_latency_ms == Some(0) {
            return Err(McpToolValidationError::field(
                tool,
                "route.max_latency_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl McpActorMetadata {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_entity_ref(tool, "actor.actor_ref", &self.actor_ref)?;
        validate_entity_ref(tool, "actor.gate_actor_ref", &self.gate_actor_ref)?;
        if self.actor_class != self.gate_actor_class {
            return Err(McpToolValidationError::field(
                tool,
                "actor.gate_actor_class",
                "must match actor_class for foreign MCP clients",
            ));
        }
        self.scope.validate(tool)
    }
}

impl McpToolScope {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_optional_entity_ref(tool, "actor.scope.world_ref", self.world_ref.as_deref())?;
        validate_optional_entity_ref(tool, "actor.scope.facet_ref", self.facet_ref.as_deref())
    }
}

impl McpConsentMetadata {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_nonblank(tool, "consent.policy_ref", &self.policy_ref)?;
        validate_nonblank(tool, "consent.purpose", &self.purpose)?;
        validate_optional_nonblank(tool, "consent.approval_ref", self.approval_ref.as_deref())?;
        validate_optional_nonblank(
            tool,
            "consent.consent_receipt_ref",
            self.consent_receipt_ref.as_deref(),
        )
    }
}

fn decode_tool_args<T>(tool: McpToolName, args: Value) -> Result<T, McpToolValidationError>
where
    T: DeserializeOwned + ValidateMcpArgs,
{
    let parsed =
        serde_json::from_value::<T>(args).map_err(|error| McpToolValidationError::Decode {
            tool: tool.as_str(),
            message: error.to_string(),
        })?;
    parsed.validate(tool)?;
    Ok(parsed)
}

fn validate_schema_version(tool: McpToolName, version: &str) -> Result<(), McpToolValidationError> {
    if version == MCP_TOOL_ARGS_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(McpToolValidationError::field(
            tool,
            "schema_version",
            format!("must be {MCP_TOOL_ARGS_SCHEMA_VERSION}"),
        ))
    }
}

fn validate_context_pack(
    tool: McpToolName,
    context_pack: &McpContextPackRef,
) -> Result<(), McpToolValidationError> {
    validate_context_pack_field(tool, "context_pack", context_pack)
}

fn validate_context_pack_field(
    tool: McpToolName,
    field: &'static str,
    context_pack: &McpContextPackRef,
) -> Result<(), McpToolValidationError> {
    context_pack
        .validate()
        .map_err(|error| McpToolValidationError::field(tool, field, error.to_string()))
}

fn validate_optional_context_pack(
    tool: McpToolName,
    context_pack: Option<&McpContextPackRef>,
) -> Result<(), McpToolValidationError> {
    match context_pack {
        Some(context_pack) => validate_context_pack(tool, context_pack),
        None => Ok(()),
    }
}

fn validate_nonblank(
    tool: McpToolName,
    field: &'static str,
    value: &str,
) -> Result<(), McpToolValidationError> {
    if value.trim().is_empty() {
        Err(McpToolValidationError::field(
            tool,
            field,
            "must not be blank",
        ))
    } else {
        Ok(())
    }
}

fn validate_short_ref(
    tool: McpToolName,
    field: &'static str,
    reference: &str,
) -> Result<(), McpToolValidationError> {
    validate_nonblank(tool, field, reference)?;
    let Some((short_id, content_hash)) = reference.split_once(':') else {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "must be in shortId:contentHashHex form",
        ));
    };
    validate_short_ref_parts(tool, field, short_id, content_hash)
}

fn validate_short_ref_parts(
    tool: McpToolName,
    field: &'static str,
    short_id: &str,
    content_hash: &str,
) -> Result<(), McpToolValidationError> {
    let short_id_bytes = short_id.as_bytes();
    if short_id_bytes.len() < 3
        || !short_id_bytes[0].is_ascii_lowercase()
        || !short_id_bytes[1].is_ascii_lowercase()
        || !short_id_bytes[2..].iter().all(|byte| byte.is_ascii_digit())
    {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "short id must be two lowercase letters followed by decimal digits",
        ));
    }
    if content_hash.len() != 2 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "content hash must be exactly two hex digits",
        ));
    }
    u8::from_str_radix(content_hash, 16)
        .map_err(|_| McpToolValidationError::field(tool, field, "content hash must be hex"))?;
    Ok(())
}

fn validate_optional_nonblank(
    tool: McpToolName,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    match value {
        Some(value) => validate_nonblank(tool, field, value),
        None => Ok(()),
    }
}

fn validate_required_entity_ref(
    tool: McpToolName,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    let value = value
        .ok_or_else(|| McpToolValidationError::field(tool, field, "is required for this verb"))?;
    validate_entity_ref(tool, field, value)
}

fn validate_optional_entity_ref(
    tool: McpToolName,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    match value {
        Some(value) => validate_entity_ref(tool, field, value),
        None => Ok(()),
    }
}

fn validate_entity_ref(
    tool: McpToolName,
    field: &'static str,
    value: &str,
) -> Result<(), McpToolValidationError> {
    let parsed = EntityId::from_hex(value).map_err(|_| {
        McpToolValidationError::field(tool, field, "must be a canonical 32-character entity id")
    })?;
    if parsed.to_hex() == value {
        Ok(())
    } else {
        Err(McpToolValidationError::field(
            tool,
            field,
            "must be a canonical 32-character entity id",
        ))
    }
}

fn validate_absent(
    tool: McpToolName,
    field: &'static str,
    present: bool,
) -> Result<(), McpToolValidationError> {
    if present {
        Err(McpToolValidationError::field(
            tool,
            field,
            "is not valid for this verb",
        ))
    } else {
        Ok(())
    }
}

fn nav_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/nav.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "mode": { "type": "string", "enum": ["search", "timeline", "list", "hydrate"] },
            "query": nonblank_string_schema(),
            "limit": { "type": "integer", "minimum": 1 },
            "cursor": nonblank_string_schema(),
            "context_pack": context_pack_ref_schema(),
        }),
        &["schema_version", "actor", "consent", "mode"],
    )
}

fn read_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/read.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "target": read_target_schema(),
        }),
        &["schema_version", "actor", "consent", "target"],
    )
}

fn edit_tool_schema() -> Value {
    let mut schema = tool_schema_root(
        "https://oneiron.local/schemas/mcp/edit.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "verb": { "type": "string", "enum": ["remember", "supersede", "retract", "delete", "hard_delete"] },
            "idempotency_key": nonblank_string_schema(),
            "dry_run": { "type": "boolean" },
            "entity": edit_entity_schema(),
            "id": entity_id_schema(),
            "new_id": entity_id_schema(),
            "old_id": entity_id_schema(),
            "at": { "type": "integer", "minimum": 0 },
            "reason": { "type": "string", "enum": ["user_delete", "user_hard_delete", "gdpr_delete", "policy_delete"] },
        }),
        &[
            "schema_version",
            "actor",
            "consent",
            "verb",
            "idempotency_key",
        ],
    );
    schema
        .as_object_mut()
        .expect("tool schema root is an object")
        .insert(
            "allOf".to_owned(),
            json!([
                {
                    "if": {
                        "properties": { "verb": { "const": "remember" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["entity"],
                        "not": forbidden_properties_schema(&["id", "new_id", "old_id", "at", "reason"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "supersede" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["new_id", "old_id"],
                        "not": forbidden_properties_schema(&["entity", "id", "reason"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "retract" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["id"],
                        "not": forbidden_properties_schema(&["entity", "new_id", "old_id", "reason"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "delete" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["id", "reason"],
                        "properties": { "reason": { "const": "user_delete" } },
                        "not": forbidden_properties_schema(&["entity", "new_id", "old_id", "at"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "hard_delete" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["id", "reason"],
                        "properties": {
                            "reason": {
                                "enum": ["user_hard_delete", "gdpr_delete", "policy_delete"],
                            },
                        },
                        "not": forbidden_properties_schema(&["entity", "new_id", "old_id", "at"]),
                    },
                },
            ]),
        );
    schema
}

fn ask_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/ask.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "context_pack": context_pack_ref_schema(),
            "consent": consent_schema(),
            "query": nonblank_string_schema(),
            "effort": ask_effort_schema(),
            "citation_mode": citation_mode_schema(),
        }),
        &[
            "schema_version",
            "actor",
            "context_pack",
            "consent",
            "query",
        ],
    )
}

fn routed_ask_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/ask_routed.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "context_pack": context_pack_ref_schema(),
            "consent": consent_schema(),
            "query": nonblank_string_schema(),
            "route": ask_route_schema(),
            "effort": ask_effort_schema(),
            "citation_mode": citation_mode_schema(),
        }),
        &[
            "schema_version",
            "actor",
            "context_pack",
            "consent",
            "query",
            "route",
        ],
    )
}

fn tool_schema_root(id: &'static str, properties: Value, required: &[&'static str]) -> Value {
    json!({
        "$schema": MCP_SCHEMA_DRAFT,
        "$id": id,
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

fn forbidden_properties_schema(properties: &[&'static str]) -> Value {
    let disallowed = properties
        .iter()
        .map(|field| json!({ "required": [field] }))
        .collect::<Vec<_>>();
    json!({ "anyOf": disallowed })
}

fn schema_version_property() -> Value {
    json!({
        "type": "string",
        "const": MCP_TOOL_ARGS_SCHEMA_VERSION,
    })
}

fn entity_id_schema() -> Value {
    json!({
        "type": "string",
        "pattern": ENTITY_ID_PATTERN,
    })
}

fn short_ref_schema() -> Value {
    json!({
        "type": "string",
        "pattern": SHORT_REF_PATTERN,
    })
}

fn nonblank_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "\\S",
    })
}

fn actor_class_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["human", "agent"],
    })
}

fn actor_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["actor_ref", "actor_class", "gate_actor_class", "gate_actor_ref", "scope"],
        "oneOf": [
            {
                "properties": {
                    "actor_class": { "const": "human" },
                    "gate_actor_class": { "const": "human" },
                },
            },
            {
                "properties": {
                    "actor_class": { "const": "agent" },
                    "gate_actor_class": { "const": "agent" },
                },
            },
        ],
        "properties": {
            "actor_ref": entity_id_schema(),
            "actor_class": actor_class_schema(),
            "gate_actor_class": actor_class_schema(),
            "gate_actor_ref": entity_id_schema(),
            "scope": scope_schema(),
        },
    })
}

fn scope_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "world_ref": entity_id_schema(),
            "facet_ref": entity_id_schema(),
        },
    })
}

fn consent_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["policy_ref", "purpose"],
        "properties": {
            "policy_ref": nonblank_string_schema(),
            "purpose": nonblank_string_schema(),
            "approval_ref": nonblank_string_schema(),
            "consent_receipt_ref": nonblank_string_schema(),
            "require_human_approval": { "type": "boolean" },
        },
    })
}

fn context_pack_ref_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version"],
        "anyOf": [
            { "required": ["pack_ref"] },
            { "required": ["retrieval_run_id"] },
            {
                "required": ["result_ids"],
                "properties": {
                    "result_ids": { "minItems": 1 },
                },
            },
        ],
        "properties": {
            "schema_version": {
                "type": "string",
                "const": MCP_CONTEXT_PACK_REF_SCHEMA_VERSION,
            },
            "context_version": nonblank_string_schema(),
            "pack_ref": nonblank_string_schema(),
            "retrieval_run_id": nonblank_string_schema(),
            "result_ids": {
                "type": "array",
                "items": entity_id_schema(),
            },
            "budget_ref": nonblank_string_schema(),
        },
    })
}

fn read_target_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "oneOf": [
            { "required": ["entity_ref"] },
            { "required": ["short_ref"] },
            { "required": ["context_pack"] },
        ],
        "properties": {
            "entity_ref": entity_id_schema(),
            "short_ref": short_ref_schema(),
            "context_pack": context_pack_ref_schema(),
        },
    })
}

fn edit_entity_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["entity_type", "body"],
        "properties": {
            "id": entity_id_schema(),
            "entity_type": { "type": "integer", "minimum": 0, "maximum": 255 },
            "occurred_start": { "type": "integer", "minimum": 0 },
            "occurred_end": { "type": "integer", "minimum": 0 },
            "learned_at": { "type": "integer", "minimum": 0 },
            "body": {},
            "text": {
                "type": "array",
                "items": text_field_schema(),
            },
        },
    })
}

fn text_field_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["field", "value"],
        "properties": {
            "field": nonblank_string_schema(),
            "value": nonblank_string_schema(),
        },
    })
}

fn ask_effort_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["minimal", "standard", "deep"],
    })
}

fn citation_mode_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["claim_refs", "claim_refs_and_spans"],
    })
}

fn ask_route_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["model_tier"],
        "properties": {
            "model_tier": nonblank_string_schema(),
            "model_id": nonblank_string_schema(),
            "substrate_ref": nonblank_string_schema(),
            "reasoning_effort": ask_effort_schema(),
            "max_latency_ms": { "type": "integer", "minimum": 1 },
        },
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct McpCredentialHashKey([u8; 32]);

impl McpCredentialHashKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for McpCredentialHashKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpCredentialHashKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct McpCredentialFingerprint([u8; 32]);

impl fmt::Debug for McpCredentialFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpCredentialFingerprint(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpConnectorScope {
    pub world_ref: Option<EntityId>,
    pub facet_ref: Option<EntityId>,
}

impl McpConnectorScope {
    #[must_use]
    pub const fn vault_wide() -> Self {
        Self {
            world_ref: None,
            facet_ref: None,
        }
    }

    #[must_use]
    pub const fn scoped(world_ref: Option<EntityId>, facet_ref: Option<EntityId>) -> Self {
        Self {
            world_ref,
            facet_ref,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpConnectorActorRecord {
    actor_ref: EntityId,
    actor_class: EdgeActorClass,
    scope: McpConnectorScope,
    expires_at: Option<u64>,
    revoked_at: Option<u64>,
}

impl McpConnectorActorRecord {
    #[must_use]
    pub const fn new(
        actor_ref: EntityId,
        actor_class: EdgeActorClass,
        scope: McpConnectorScope,
    ) -> Self {
        Self {
            actor_ref,
            actor_class,
            scope,
            expires_at: None,
            revoked_at: None,
        }
    }

    #[must_use]
    pub const fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    #[must_use]
    pub const fn with_revoked_at(mut self, revoked_at: u64) -> Self {
        self.revoked_at = Some(revoked_at);
        self
    }

    #[must_use]
    pub const fn gate_actor_class(&self) -> &'static str {
        self.actor_class.gate_actor_class()
    }

    #[must_use]
    pub fn gate_actor_ref(&self) -> String {
        self.actor_ref.to_hex()
    }

    #[must_use]
    pub const fn write_actor(&self) -> WriteActor {
        WriteActor::new(self.actor_ref, self.actor_class)
    }

    const fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }

    fn is_stale(&self, now: u64) -> bool {
        self.revoked_at.is_some_and(|revoked_at| now >= revoked_at) || self.is_expired(now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpResolvedActor {
    pub actor_ref: EntityId,
    pub actor_class: EdgeActorClass,
    pub gate_actor_class: &'static str,
    pub gate_actor_ref: String,
    pub scope: McpConnectorScope,
}

impl McpResolvedActor {
    #[must_use]
    pub const fn write_actor(&self) -> WriteActor {
        WriteActor::new(self.actor_ref, self.actor_class)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpConnectorActorRegistrationError {
    #[error("credential must not be blank")]
    EmptyCredential,
    #[error("credential is already registered")]
    DuplicateCredential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpConnectorActorResolutionError {
    #[error("credential not found")]
    UnknownCredential,
    #[error("credential has expired")]
    ExpiredCredential,
    #[error("credential has been revoked")]
    RevokedCredential,
    #[error("actor ceiling row not found")]
    MissingActorCeiling,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpConnectorActorRevokeStatus {
    Revoked,
    AlreadyRevoked { revoked_at: u64 },
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpConnectorActorRegistry {
    credential_hash_key: McpCredentialHashKey,
    records: BTreeMap<McpCredentialFingerprint, McpConnectorActorRecord>,
}

impl fmt::Debug for McpConnectorActorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpConnectorActorRegistry")
            .field("credential_hash_key", &"<redacted>")
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl McpConnectorActorRegistry {
    #[must_use]
    pub const fn new(credential_hash_key: McpCredentialHashKey) -> Self {
        Self {
            credential_hash_key,
            records: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        credential: impl Into<String>,
        record: McpConnectorActorRecord,
    ) -> Result<(), McpConnectorActorRegistrationError> {
        let credential = credential.into();
        let Some(credential) = normalize_credential(&credential) else {
            return Err(McpConnectorActorRegistrationError::EmptyCredential);
        };
        let fingerprint = self.fingerprint_credential(credential);
        if self.records.contains_key(&fingerprint) {
            return Err(McpConnectorActorRegistrationError::DuplicateCredential);
        }
        self.records.insert(fingerprint, record);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        credential: &str,
        revoked_at: u64,
    ) -> Result<McpConnectorActorRevokeStatus, McpConnectorActorResolutionError> {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return Err(McpConnectorActorResolutionError::UnknownCredential);
        };
        let record = self
            .records
            .get_mut(&fingerprint)
            .ok_or(McpConnectorActorResolutionError::UnknownCredential)?;

        if let Some(existing_revoked_at) = record.revoked_at {
            return Ok(McpConnectorActorRevokeStatus::AlreadyRevoked {
                revoked_at: existing_revoked_at,
            });
        }

        record.revoked_at = Some(revoked_at);
        Ok(McpConnectorActorRevokeStatus::Revoked)
    }

    pub fn resolve(
        &self,
        credential: &str,
        now: u64,
        actor_ceiling_exists: impl FnOnce(&str, &str) -> bool,
    ) -> Result<McpResolvedActor, McpConnectorActorResolutionError> {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return Err(McpConnectorActorResolutionError::UnknownCredential);
        };
        let record = self
            .records
            .get(&fingerprint)
            .ok_or(McpConnectorActorResolutionError::UnknownCredential)?;

        if record.is_revoked() {
            return Err(McpConnectorActorResolutionError::RevokedCredential);
        }
        if record.is_expired(now) {
            return Err(McpConnectorActorResolutionError::ExpiredCredential);
        }

        let gate_actor_class = record.gate_actor_class();
        let gate_actor_ref = record.gate_actor_ref();
        if !actor_ceiling_exists(gate_actor_class, &gate_actor_ref) {
            return Err(McpConnectorActorResolutionError::MissingActorCeiling);
        }

        Ok(McpResolvedActor {
            actor_ref: record.actor_ref,
            actor_class: record.actor_class,
            gate_actor_class,
            gate_actor_ref,
            scope: record.scope.clone(),
        })
    }

    pub fn unregister(&mut self, credential: &str) -> bool {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return false;
        };
        self.records.remove(&fingerprint).is_some()
    }

    pub fn prune_revoked_or_expired(&mut self, now: u64) -> usize {
        let before = self.records.len();
        self.records.retain(|_, record| !record.is_stale(now));
        before - self.records.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn fingerprint_lookup_credential(&self, credential: &str) -> Option<McpCredentialFingerprint> {
        normalize_credential(credential).map(|credential| self.fingerprint_credential(credential))
    }

    fn fingerprint_credential(&self, credential: &str) -> McpCredentialFingerprint {
        McpCredentialFingerprint(
            *blake3::keyed_hash(&self.credential_hash_key.0, credential.as_bytes()).as_bytes(),
        )
    }
}

fn normalize_credential(credential: &str) -> Option<&str> {
    let credential = credential.trim();
    (!credential.is_empty()).then_some(credential)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const ACTOR_ID: &str = "11111111111111111111111111111111";
    const RESULT_ID: &str = "77777777777777777777777777777777";

    #[derive(Debug, Deserialize)]
    struct McpToolValidationFixture {
        cases: Vec<McpToolValidationFixtureCase>,
    }

    #[derive(Debug, Deserialize)]
    struct McpToolValidationFixtureCase {
        name: String,
        tool: String,
        valid: bool,
        args: Value,
    }

    fn id(seed: u128) -> EntityId {
        EntityId::from_bytes(seed.to_be_bytes()).expect("test id should be nonzero")
    }

    fn registry() -> McpConnectorActorRegistry {
        McpConnectorActorRegistry::new(McpCredentialHashKey::from_bytes([42; 32]))
    }

    fn actor_ceiling_for(
        actor_class: EdgeActorClass,
        actor_ref: EntityId,
    ) -> impl FnOnce(&str, &str) -> bool {
        let expected_actor_ref = actor_ref.to_hex();
        move |gate_actor_class, gate_actor_ref| {
            gate_actor_class == actor_class.gate_actor_class()
                && gate_actor_ref == expected_actor_ref
        }
    }

    fn actor_json() -> Value {
        json!({
            "actor_ref": ACTOR_ID,
            "actor_class": "agent",
            "gate_actor_class": "agent",
            "gate_actor_ref": ACTOR_ID,
            "scope": {},
        })
    }

    fn consent_json(purpose: &str) -> Value {
        json!({
            "policy_ref": "policy:foreign-mcp",
            "purpose": purpose,
        })
    }

    fn unexpected_actor_ceiling_lookup(_: &str, _: &str) -> bool {
        panic!("actor ceiling lookup should not run after credential failure")
    }

    #[test]
    fn mcp_tool_schema_serializes_protocol_input_schema_field() {
        let schema =
            serde_json::to_value(mcp_tool_schema(McpToolName::Read)).expect("schema serializes");

        assert!(schema.get("inputSchema").is_some());
        assert!(schema.get("input_schema").is_none());
    }

    #[test]
    fn mcp_tool_schemas_are_closed_and_versioned() {
        let schemas = mcp_tool_schemas();
        assert_eq!(schemas.len(), McpToolName::all().len());

        for schema in schemas {
            let root = &schema.input_schema;
            assert_eq!(root["$schema"], MCP_SCHEMA_DRAFT);
            assert_eq!(root["type"], "object");
            assert_eq!(root["additionalProperties"], false);
            assert_eq!(
                root["properties"]["schema_version"]["const"],
                MCP_TOOL_ARGS_SCHEMA_VERSION
            );
            assert!(
                root["required"]
                    .as_array()
                    .expect("required is an array")
                    .contains(&Value::String("schema_version".to_owned())),
                "{} must require schema_version",
                schema.name
            );
            assert_closed_object_schemas(root, schema.name);
        }
    }

    #[test]
    fn mcp_tool_validation_fixtures_gate_args_before_execution() {
        let fixture: McpToolValidationFixture = serde_json::from_str(include_str!(
            "../tests/fixtures/mcp_tool_args.validation.json"
        ))
        .expect("fixture should parse");

        for case in fixture.cases {
            let tool = McpToolName::from_name(&case.tool)
                .unwrap_or_else(|| panic!("{} names a known tool", case.name));
            let result = validate_mcp_tool_args(tool, case.args);
            if case.valid {
                let validated = result.unwrap_or_else(|error| {
                    panic!("{} should validate but failed: {error}", case.name)
                });
                assert_fixture_preserved_metadata(&case.name, &validated);
            } else {
                assert!(result.is_err(), "{} should fail validation", case.name);
            }
        }
    }

    #[test]
    fn mcp_tool_schemas_express_preflight_shape_invariants() {
        let actor = actor_schema();
        assert_eq!(actor["oneOf"].as_array().expect("actor oneOf").len(), 2);

        let context_pack = context_pack_ref_schema();
        assert_eq!(
            context_pack["anyOf"]
                .as_array()
                .expect("context-pack handle anyOf")
                .len(),
            3
        );
        assert_eq!(
            context_pack["properties"]["pack_ref"]["pattern"],
            Value::String("\\S".to_owned())
        );

        let read_target = read_target_schema();
        assert_eq!(
            read_target["oneOf"]
                .as_array()
                .expect("read target selector oneOf")
                .len(),
            3
        );
        assert_eq!(
            read_target["properties"]["short_ref"]["pattern"],
            Value::String(SHORT_REF_PATTERN.to_owned())
        );

        let edit = edit_tool_schema();
        let edit_verbs = edit["allOf"]
            .as_array()
            .expect("edit verb-specific constraints")
            .iter()
            .map(|branch| {
                branch["if"]["properties"]["verb"]["const"]
                    .as_str()
                    .expect("verb const")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            edit_verbs,
            vec!["remember", "supersede", "retract", "delete", "hard_delete"]
        );
    }

    #[test]
    fn read_target_context_pack_errors_use_nested_field() {
        let error = validate_mcp_tool_args(
            McpToolName::Read,
            json!({
                "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": {
                    "actor_ref": ACTOR_ID,
                    "actor_class": "agent",
                    "gate_actor_class": "agent",
                    "gate_actor_ref": ACTOR_ID,
                    "scope": {},
                },
                "consent": {
                    "policy_ref": "policy:foreign-mcp",
                    "purpose": "read_context",
                },
                "target": {
                    "context_pack": {
                        "schema_version": "context_pack_ref.v2",
                        "pack_ref": "context-pack:one-1215",
                    },
                },
            }),
        )
        .expect_err("invalid nested context-pack version should fail");

        assert!(
            error
                .to_string()
                .starts_with("oneiron.read.target.context_pack:"),
            "{error}"
        );
    }

    #[test]
    fn read_target_short_ref_uses_hydrate_parser_shape() {
        let error = validate_mcp_tool_args(
            McpToolName::Read,
            json!({
                "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": actor_json(),
                "consent": consent_json("read_context"),
                "target": {
                    "short_ref": "not-a-ref",
                },
            }),
        )
        .expect_err("invalid short ref should fail before hydrate");

        assert!(
            error.to_string().contains("shortId:contentHashHex"),
            "{error}"
        );

        validate_mcp_tool_args(
            McpToolName::Read,
            json!({
                "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": actor_json(),
                "consent": consent_json("read_context"),
                "target": {
                    "short_ref": "ab123:4f",
                },
            }),
        )
        .expect("hydrate-shaped short ref should validate");
    }

    #[test]
    fn remember_rejects_impossible_occurrence_range() {
        let error = validate_mcp_tool_args(
            McpToolName::Edit,
            json!({
                "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": actor_json(),
                "consent": consent_json("write_memory"),
                "verb": "remember",
                "idempotency_key": "mcp-test-impossible-range",
                "entity": {
                    "entity_type": 1,
                    "occurred_start": 20,
                    "occurred_end": 10,
                    "body": {
                        "txt": "Impossible range"
                    },
                },
            }),
        )
        .expect_err("start greater than end should fail");

        assert!(
            error
                .to_string()
                .contains("entity.occurred_start: must be less than or equal"),
            "{error}"
        );
    }

    #[test]
    fn decode_errors_describe_schema_shape_not_json_syntax() {
        let error = validate_mcp_tool_args(
            McpToolName::Ask,
            json!({ "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION }),
        )
        .expect_err("missing required fields should fail decode");

        let message = error.to_string();
        assert!(message.contains("not valid for the tool schema"));
        assert!(!message.contains("not valid JSON"));
    }

    fn assert_closed_object_schemas(value: &Value, path: &str) {
        match value {
            Value::Object(map) => {
                if matches!(map.get("type"), Some(Value::String(kind)) if kind == "object") {
                    assert_eq!(
                        map.get("additionalProperties"),
                        Some(&Value::Bool(false)),
                        "object schema at {path} must be closed"
                    );
                }

                for (key, child) in map {
                    assert_closed_object_schemas(child, &format!("{path}.{key}"));
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_closed_object_schemas(item, &format!("{path}[{index}]"));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    fn assert_fixture_preserved_metadata(name: &str, validated: &McpValidatedToolArgs) {
        match validated {
            McpValidatedToolArgs::Ask(args) => {
                assert_eq!(args.actor.actor_ref, ACTOR_ID, "{name} actor_ref");
                assert_eq!(
                    args.context_pack.result_ids,
                    vec![RESULT_ID.to_owned()],
                    "{name} results"
                );
                assert_eq!(
                    args.consent.approval_ref.as_deref(),
                    Some("approval:one-1215"),
                    "{name} approval"
                );
                assert_eq!(
                    args.consent.consent_receipt_ref.as_deref(),
                    Some("consent:one-1215"),
                    "{name} consent receipt"
                );
            }
            McpValidatedToolArgs::RoutedAsk(args) => {
                assert_eq!(args.actor.actor_ref, ACTOR_ID, "{name} actor_ref");
                assert_eq!(
                    args.context_pack.result_ids,
                    vec![RESULT_ID.to_owned()],
                    "{name} results"
                );
                assert_eq!(
                    args.consent.approval_ref.as_deref(),
                    Some("approval:one-1215"),
                    "{name} approval"
                );
                assert_eq!(
                    args.consent.consent_receipt_ref.as_deref(),
                    Some("consent:one-1215"),
                    "{name} consent receipt"
                );
                assert_eq!(args.route.model_tier, "routed-small", "{name} route");
            }
            McpValidatedToolArgs::Nav(_)
            | McpValidatedToolArgs::Read(_)
            | McpValidatedToolArgs::Edit(_) => {}
        }
    }

    #[test]
    fn owner_key_resolves_to_human_gate_actor_identity() {
        let owner = id(0xA001);
        let mut registry = registry();
        registry
            .register(
                "owner-key",
                McpConnectorActorRecord::new(
                    owner,
                    EdgeActorClass::Human,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("owner key registration succeeds");

        let resolved = registry
            .resolve(
                "owner-key",
                10,
                actor_ceiling_for(EdgeActorClass::Human, owner),
            )
            .expect("owner resolves");

        assert_eq!(resolved.actor_ref, owner);
        assert_eq!(resolved.actor_class, EdgeActorClass::Human);
        assert_eq!(resolved.gate_actor_class, "human");
        assert_eq!(resolved.gate_actor_ref, owner.to_hex());
        assert_eq!(resolved.scope, McpConnectorScope::vault_wide());
        assert_eq!(
            resolved.write_actor(),
            WriteActor::new(owner, EdgeActorClass::Human)
        );
    }

    #[test]
    fn connector_key_resolves_to_agent_identity_and_scope() {
        let connector = id(0xB001);
        let world = id(0xB002);
        let facet = id(0xB003);
        let mut registry = registry();
        registry
            .register(
                "connector-key",
                McpConnectorActorRecord::new(
                    connector,
                    EdgeActorClass::Agent,
                    McpConnectorScope::scoped(Some(world), Some(facet)),
                )
                .with_expiry(20),
            )
            .expect("connector key registration succeeds");

        let resolved = registry
            .resolve(
                "connector-key",
                19,
                actor_ceiling_for(EdgeActorClass::Agent, connector),
            )
            .expect("connector resolves before expiry");

        assert_eq!(resolved.actor_ref, connector);
        assert_eq!(resolved.gate_actor_class, "agent");
        assert_eq!(resolved.gate_actor_ref, connector.to_hex());
        assert_eq!(
            resolved.scope,
            McpConnectorScope::scoped(Some(world), Some(facet))
        );
    }

    #[test]
    fn unknown_and_expired_connector_keys_fail_closed() {
        let mut registry = registry();
        registry
            .register(
                "expired-key",
                McpConnectorActorRecord::new(
                    id(0xC001),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                )
                .with_expiry(20),
            )
            .expect("expired key registration succeeds");

        assert_eq!(
            registry.resolve("missing-key", 19, unexpected_actor_ceiling_lookup),
            Err(McpConnectorActorResolutionError::UnknownCredential)
        );
        assert_eq!(
            registry.resolve("expired-key", 20, unexpected_actor_ceiling_lookup),
            Err(McpConnectorActorResolutionError::ExpiredCredential)
        );
    }

    #[test]
    fn revoked_connector_key_fails_closed() {
        let mut registry = registry();
        registry
            .register(
                "revoked-key",
                McpConnectorActorRecord::new(
                    id(0xD001),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("revoked key registration succeeds");

        assert_eq!(
            registry.revoke("revoked-key", 12),
            Ok(McpConnectorActorRevokeStatus::Revoked)
        );

        assert_eq!(
            registry.resolve("revoked-key", 13, unexpected_actor_ceiling_lookup),
            Err(McpConnectorActorResolutionError::RevokedCredential)
        );
    }

    #[test]
    fn blank_and_duplicate_connector_keys_fail_closed() {
        let mut registry = registry();
        let record = McpConnectorActorRecord::new(
            id(0xE001),
            EdgeActorClass::Agent,
            McpConnectorScope::vault_wide(),
        );

        assert_eq!(
            registry.register("  ", record.clone()),
            Err(McpConnectorActorRegistrationError::EmptyCredential)
        );

        registry
            .register("connector-key", record.clone())
            .expect("first registration succeeds");
        assert_eq!(
            registry.register("connector-key", record),
            Err(McpConnectorActorRegistrationError::DuplicateCredential)
        );
    }

    #[test]
    fn credential_whitespace_is_canonicalized_for_all_lookups() {
        let actor = id(0xF001);
        let mut registry = registry();
        let record = McpConnectorActorRecord::new(
            actor,
            EdgeActorClass::Agent,
            McpConnectorScope::vault_wide(),
        );

        registry
            .register(" connector-key ", record.clone())
            .expect("registration trims credential");
        assert_eq!(
            registry.register("connector-key", record),
            Err(McpConnectorActorRegistrationError::DuplicateCredential)
        );

        assert_eq!(
            registry
                .resolve(
                    "\tconnector-key\n",
                    10,
                    actor_ceiling_for(EdgeActorClass::Agent, actor),
                )
                .expect("trimmed lookup resolves")
                .actor_ref,
            actor
        );
        assert_eq!(
            registry.revoke(" connector-key ", 11),
            Ok(McpConnectorActorRevokeStatus::Revoked)
        );
        assert_eq!(
            registry.resolve("connector-key", 12, unexpected_actor_ceiling_lookup),
            Err(McpConnectorActorResolutionError::RevokedCredential)
        );
    }

    #[test]
    fn registry_debug_does_not_print_credentials_or_hash_key() {
        let mut registry = registry();
        registry
            .register(
                "very-secret-connector-key",
                McpConnectorActorRecord::new(
                    id(0xF101),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");

        let debug = format!("{registry:?}");
        assert!(debug.contains("record_count"));
        assert!(!debug.contains("very-secret-connector-key"));
        assert!(!debug.contains("42"));
    }

    #[test]
    fn double_revoke_preserves_original_timestamp() {
        let mut registry = registry();
        registry
            .register(
                "connector-key",
                McpConnectorActorRecord::new(
                    id(0xF201),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");

        assert_eq!(
            registry.revoke("connector-key", 12),
            Ok(McpConnectorActorRevokeStatus::Revoked)
        );
        assert_eq!(
            registry.revoke("connector-key", 99),
            Ok(McpConnectorActorRevokeStatus::AlreadyRevoked { revoked_at: 12 })
        );
    }

    #[test]
    fn prune_and_unregister_remove_stale_credentials() {
        let mut registry = registry();
        registry
            .register(
                "expired-key",
                McpConnectorActorRecord::new(
                    id(0xF301),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                )
                .with_expiry(10),
            )
            .expect("expired key registration succeeds");
        registry
            .register(
                "revoked-key",
                McpConnectorActorRecord::new(
                    id(0xF302),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                )
                .with_revoked_at(11),
            )
            .expect("revoked key registration succeeds");
        registry
            .register(
                "active-key",
                McpConnectorActorRecord::new(
                    id(0xF303),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("active key registration succeeds");

        assert_eq!(registry.prune_revoked_or_expired(11), 2);
        assert_eq!(registry.len(), 1);
        assert!(registry.unregister(" active-key "));
        assert!(registry.is_empty());
    }

    #[test]
    fn resolved_actor_exposes_only_gate_actor_identity_not_authority() {
        let actor = id(0xF401);
        let mut registry = registry();
        registry
            .register(
                "connector-key",
                McpConnectorActorRecord::new(
                    actor,
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");

        let resolved = registry
            .resolve(
                "connector-key",
                10,
                actor_ceiling_for(EdgeActorClass::Agent, actor),
            )
            .expect("connector resolves");

        assert_eq!(resolved.gate_actor_class, "agent");
        assert_eq!(resolved.gate_actor_ref, actor.to_hex());
        assert_eq!(
            resolved.write_actor(),
            WriteActor::new(actor, EdgeActorClass::Agent)
        );
    }

    #[test]
    fn missing_actor_ceiling_fails_closed_after_credential_resolves() {
        let actor = id(0xF501);
        let mut registry = registry();
        registry
            .register(
                "connector-key",
                McpConnectorActorRecord::new(
                    actor,
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");

        assert_eq!(
            registry.resolve("connector-key", 10, |_, _| false),
            Err(McpConnectorActorResolutionError::MissingActorCeiling)
        );
    }
}
