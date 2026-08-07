//! AGENT_DEF (`AgentDefinition`) entity — AGENT-1 (ONE-1443, OF-334).
//!
//! A saved, host-agnostic composition record: a set of skills, connectors,
//! code-mode MCPs, an optional model tier, a run scope, and an optional custom
//! prompt, carried alongside the shared `SkillRecord` lifecycle block. The body
//! is a hand-written pinned-key MessagePack map following the SKILL codec
//! discipline (strict: trailing bytes, non-string keys, unknown keys, and
//! duplicate keys are all rejected), so a host can never smuggle presentation
//! fields into the record. A stored definition is inert at rest: it references
//! skills/connectors/MCPs by id and grants nothing until a later dispatch layer
//! (AGENT-3) resolves and authorizes them.

use std::collections::HashSet;

use rmpv::Value;

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::ModelTierRef;
use crate::pipeline::WorldScope;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::skill::{SKILL_DEPENDENCY_KEYS, SkillDependency};
use crate::temporal::TimeRange;

/// The pinned on-disk body keys for an `AgentDefinition`, in encode order.
///
/// `instructions`, `modelTier`, `world`, `ceiling`, `forkedFrom`, `logicalId`,
/// and `displayName` are optional and elided from the encoded map when absent
/// or default-valued (the elide-the-default pattern); every other key is
/// required. Decode rejects any key outside this set, so the schema is a
/// review-visible contract and hosts cannot add fields. A body with
/// `ceiling = proposed` (the default) and no fork lineage encodes
/// byte-identically to the pre-AGENT-2 17-key codec.
///
/// `enabled` is the SOLE always-encode exception (ONE-1890): a decode default
/// alone would let a seeded `enabled: true` row encode differently across
/// vaults, breaking byte-identical cross-vault seeding.
pub const AGENT_DEF_BODY_KEYS: [&str; 22] = [
    "agentId",
    "desc",
    "version",
    "instructions",
    "skills",
    "connectors",
    "codeModeMcps",
    "modelTier",
    "scope",
    "world",
    "ceiling",
    "forkedFrom",
    "approvalStatus",
    "lifecycleStatus",
    "source",
    "confidence",
    "generated",
    "humanAuthored",
    "provenance",
    "logicalId",
    "enabled",
    "displayName",
];

/// The pinned key pair for an [`McpRef`] sub-map.
pub const MCP_REF_KEYS: [&str; 2] = ["key", "minVersion"];

/// Maximum byte length of an `agent_id`.
pub const AGENT_ID_MAX_BYTES: usize = 256;
/// Maximum byte length of a `desc`.
pub const AGENT_DESC_MAX_BYTES: usize = 4096;
/// Maximum byte length of a `version` string (also reused for ref `min_version`).
pub const AGENT_VERSION_MAX_BYTES: usize = 128;
/// Maximum byte length of the optional `instructions` custom prompt.
pub const AGENT_INSTRUCTIONS_MAX_BYTES: usize = 16_384;
/// Maximum byte length of the optional `model_tier` reference string.
pub const AGENT_MODEL_TIER_MAX_BYTES: usize = 256;
/// Maximum byte length of a skill/connector/MCP reference id or key.
pub const AGENT_REF_KEY_MAX_BYTES: usize = 256;
/// Maximum number of entries in each composition list.
pub const AGENT_MAX_LIST_ENTRIES: usize = 64;

const KEY_AGENT_ID: &str = AGENT_DEF_BODY_KEYS[0];
const KEY_DESC: &str = AGENT_DEF_BODY_KEYS[1];
const KEY_VERSION: &str = AGENT_DEF_BODY_KEYS[2];
const KEY_INSTRUCTIONS: &str = AGENT_DEF_BODY_KEYS[3];
const KEY_SKILLS: &str = AGENT_DEF_BODY_KEYS[4];
const KEY_CONNECTORS: &str = AGENT_DEF_BODY_KEYS[5];
const KEY_CODE_MODE_MCPS: &str = AGENT_DEF_BODY_KEYS[6];
const KEY_MODEL_TIER: &str = AGENT_DEF_BODY_KEYS[7];
const KEY_SCOPE: &str = AGENT_DEF_BODY_KEYS[8];
const KEY_WORLD: &str = AGENT_DEF_BODY_KEYS[9];
const KEY_CEILING: &str = AGENT_DEF_BODY_KEYS[10];
const KEY_FORKED_FROM: &str = AGENT_DEF_BODY_KEYS[11];
const KEY_APPROVAL_STATUS: &str = AGENT_DEF_BODY_KEYS[12];
const KEY_LIFECYCLE_STATUS: &str = AGENT_DEF_BODY_KEYS[13];
const KEY_SOURCE: &str = AGENT_DEF_BODY_KEYS[14];
const KEY_CONFIDENCE: &str = AGENT_DEF_BODY_KEYS[15];
const KEY_GENERATED: &str = AGENT_DEF_BODY_KEYS[16];
const KEY_HUMAN_AUTHORED: &str = AGENT_DEF_BODY_KEYS[17];
const KEY_PROVENANCE: &str = AGENT_DEF_BODY_KEYS[18];
const KEY_LOGICAL_ID: &str = AGENT_DEF_BODY_KEYS[19];
const KEY_ENABLED: &str = AGENT_DEF_BODY_KEYS[20];
const KEY_DISPLAY_NAME: &str = AGENT_DEF_BODY_KEYS[21];

/// Reserved logical-id prefix for seeded system rows. Enforced at the
/// AGENT_DEF put-decode chokepoint (`batch.rs::apply_put`), which is the only
/// place that holds both the body and the row id it is being stored at.
pub(crate) const SYSTEM_LOGICAL_ID_PREFIX: &str = "sys.";

/// Maximum byte length of a `logical_id`.
const AGENT_LOGICAL_ID_MAX_BYTES: usize = 256;
/// Maximum byte length of the runtime-editable `display_name`.
const AGENT_DISPLAY_NAME_MAX_BYTES: usize = 256;

const KEY_DEP_SKILL_ID: &str = SKILL_DEPENDENCY_KEYS[0];
const KEY_DEP_MIN_VERSION: &str = SKILL_DEPENDENCY_KEYS[1];

const KEY_MCP_KEY: &str = MCP_REF_KEYS[0];
const KEY_MCP_MIN_VERSION: &str = MCP_REF_KEYS[1];

const SCOPE_ALL: &str = "all";
const SCOPE_BASE: &str = "base";
const SCOPE_WORLD: &str = "world";

/// A versioned reference to a code-mode MCP, patterned on [`SkillDependency`].
///
/// `min_version` is the cheap forward hook for the OF-215 trajectory where MCPs
/// become versioned entities; today it is stored verbatim and never
/// existence-checked at write time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct McpRef {
    pub key: String,
    pub min_version: Option<String>,
}

impl McpRef {
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            min_version: None,
        }
    }

    #[must_use]
    pub fn with_min_version(key: impl Into<String>, min_version: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            min_version: Some(min_version.into()),
        }
    }
}

/// The run scope persisted with an `AgentDefinition`.
///
/// A new persisted descriptor rather than an embedded [`WorldScope`], which is
/// a runtime-only type that does not implement `Serialize`. `World` carries the
/// world's [`EntityId`], hex-encoded into the body. `WorldSet` is deliberately
/// not modelled here — it is a repo-clamp key with no day-1 caller, and a later
/// additive variant per the `#[non_exhaustive]` marker.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentScope {
    /// Span every world (the constructor default; matches `PipelineBuilder`).
    All,
    /// Base-reality only.
    Base,
    /// This world plus base reality.
    World(EntityId),
}

impl AgentScope {
    /// Maps to the runtime [`WorldScope`] a dispatch layer (AGENT-3) reconstitutes.
    #[must_use]
    pub fn to_world_scope(&self) -> WorldScope {
        match self {
            Self::All => WorldScope::All,
            Self::Base => WorldScope::Base,
            Self::World(world) => WorldScope::World(*world),
        }
    }

    fn discriminant(&self) -> &'static str {
        match self {
            Self::All => SCOPE_ALL,
            Self::Base => SCOPE_BASE,
            Self::World(_) => SCOPE_WORLD,
        }
    }
}

/// The authored approval-ceiling bound persisted on an `AgentDefinition`
/// (OF-074: binary — the third trust tier is compositional, not a variant).
///
/// This is the agent's *self-limit*, not the owner's grant: effective
/// authority at every gate evaluation is `definition ceiling ∧ preset bound ∧
/// manifest actor_ceilings projection` (the meet across all three), so a
/// stored `Auto` never bypasses the owner-signed manifest. A persisted-
/// descriptor mirror of the gate's `PolicyApprovalCeiling` (which stays
/// `pub(crate)`); the conversion lives gate-side so this module never imports
/// gate types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCeiling {
    Auto,
    Proposed,
}

impl AgentCeiling {
    /// The pinned wire string, matching `PolicyApprovalCeiling` vocabulary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Proposed => "proposed",
        }
    }

    /// Parses the pinned wire vocabulary (`"auto"` / `"proposed"`).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "proposed" => Some(Self::Proposed),
            _ => None,
        }
    }

    /// True iff `self` requests wider authority than `bound` — the only
    /// ordering the no-widen rule ever needs.
    #[must_use]
    pub const fn widens_beyond(self, bound: Self) -> bool {
        matches!((self, bound), (Self::Auto, Self::Proposed))
    }
}

/// The canonical seeded system-agent roster (OF-334 / ONE-1890): data, not a
/// compiled enum. Every baseline row is an ordinary byte-17 `AGENT_DEF` entity
/// with a pinned row id, a pinned actor id equal to it, and a stable `sys.*`
/// logical id. ONE-1709 appends `sys.team_lead` to this same file.
const SYSTEM_AGENT_DEFINITIONS_V1_JSON: &str =
    include_str!("data/system_agent_definitions.v1.json");

/// Seam shim (SEAM-GATE-PRESET-NEUTRALIZATION): gate.rs resolves a fork parent
/// through ONE call. Post-ONE-1890 `forked_from` already IS the parent row id,
/// so the shim is identity over `EntityId` — kept so gate.rs never re-spells
/// the lineage seam.
pub(crate) fn forked_from_row_ref(forked_from: &EntityId) -> EntityId {
    *forked_from
}

/// A saved, host-agnostic agent composition record.
///
/// The lifecycle block (`approval_status` … `provenance`) is the shared
/// `SkillRecord` machinery, field-for-field. `generated`/`human_authored` are a
/// mutually-exclusive authorship pair and `generated` tracks
/// `source == ClaimSource::Generated`; both invariants are frozen on update.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AgentDefinition {
    pub agent_id: String,
    pub desc: String,
    pub version: String,
    pub instructions: Option<String>,
    pub skills: Vec<SkillDependency>,
    pub connectors: Vec<String>,
    pub code_mode_mcps: Vec<McpRef>,
    pub model_tier: Option<ModelTierRef>,
    pub scope: AgentScope,
    pub ceiling: AgentCeiling,
    /// The fork parent's stored row id. Frozen on update.
    pub forked_from: Option<EntityId>,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: ClaimLifecycleStatus,
    pub source: ClaimSource,
    pub confidence: f32,
    pub generated: bool,
    pub human_authored: bool,
    pub provenance: Value,
    /// Stable lookup key for a seeded row (`sys.*`). User-created definitions
    /// carry `None`; once `Some`, it is frozen on update.
    pub logical_id: Option<String>,
    /// Whether this definition may be dispatched. Row state, not absence —
    /// reseeding never resurrects a user's "off".
    pub enabled: bool,
    /// Runtime-editable display name; deliberately NOT in the freeze-set.
    pub display_name: Option<String>,
}

impl AgentDefinition {
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor mirrors the pinned AGENT_DEF record fields"
    )]
    #[must_use]
    pub fn new(
        agent_id: impl Into<String>,
        desc: impl Into<String>,
        version: impl Into<String>,
        instructions: Option<String>,
        skills: Vec<SkillDependency>,
        connectors: Vec<String>,
        code_mode_mcps: Vec<McpRef>,
        model_tier: Option<ModelTierRef>,
        scope: AgentScope,
        ceiling: AgentCeiling,
        forked_from: Option<EntityId>,
        approval_status: ClaimApprovalStatus,
        lifecycle_status: ClaimLifecycleStatus,
        source: ClaimSource,
        confidence: f32,
        generated: bool,
        human_authored: bool,
        provenance: Value,
        logical_id: Option<String>,
        enabled: bool,
        display_name: Option<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            desc: desc.into(),
            version: version.into(),
            instructions,
            skills,
            connectors,
            code_mode_mcps,
            model_tier,
            scope,
            ceiling,
            forked_from,
            approval_status,
            lifecycle_status,
            source,
            confidence,
            generated,
            human_authored,
            provenance,
            logical_id,
            enabled,
            display_name,
        }
    }
}

/// Encodes a validated `AgentDefinition` into its pinned-key MessagePack body.
pub fn encode_agent_definition(def: &AgentDefinition) -> Result<Vec<u8>> {
    validate_agent_definition(def)?;
    let mut entries = vec![
        (
            Value::from(KEY_AGENT_ID),
            Value::from(def.agent_id.as_str()),
        ),
        (Value::from(KEY_DESC), Value::from(def.desc.as_str())),
        (Value::from(KEY_VERSION), Value::from(def.version.as_str())),
    ];
    if let Some(instructions) = &def.instructions {
        entries.push((
            Value::from(KEY_INSTRUCTIONS),
            Value::from(instructions.as_str()),
        ));
    }
    entries.push((
        Value::from(KEY_SKILLS),
        Value::Array(def.skills.iter().map(encode_skill_dependency).collect()),
    ));
    entries.push((
        Value::from(KEY_CONNECTORS),
        Value::Array(
            def.connectors
                .iter()
                .map(|connector| Value::from(connector.as_str()))
                .collect(),
        ),
    ));
    entries.push((
        Value::from(KEY_CODE_MODE_MCPS),
        Value::Array(def.code_mode_mcps.iter().map(encode_mcp_ref).collect()),
    ));
    if let Some(model_tier) = &def.model_tier {
        entries.push((
            Value::from(KEY_MODEL_TIER),
            Value::from(model_tier.as_str()),
        ));
    }
    entries.push((
        Value::from(KEY_SCOPE),
        Value::from(def.scope.discriminant()),
    ));
    if let AgentScope::World(world) = &def.scope {
        entries.push((Value::from(KEY_WORLD), Value::from(world.to_hex())));
    }
    if def.ceiling == AgentCeiling::Auto {
        entries.push((Value::from(KEY_CEILING), Value::from(def.ceiling.as_str())));
    }
    if let Some(parent) = &def.forked_from {
        entries.push((Value::from(KEY_FORKED_FROM), Value::from(parent.to_hex())));
    }
    entries.push((
        Value::from(KEY_APPROVAL_STATUS),
        Value::from(def.approval_status.as_str()),
    ));
    entries.push((
        Value::from(KEY_LIFECYCLE_STATUS),
        Value::from(def.lifecycle_status.as_str()),
    ));
    entries.push((Value::from(KEY_SOURCE), Value::from(def.source.as_str())));
    entries.push((Value::from(KEY_CONFIDENCE), Value::F32(def.confidence)));
    entries.push((Value::from(KEY_GENERATED), Value::Boolean(def.generated)));
    entries.push((
        Value::from(KEY_HUMAN_AUTHORED),
        Value::Boolean(def.human_authored),
    ));
    entries.push((Value::from(KEY_PROVENANCE), def.provenance.clone()));
    if let Some(logical_id) = &def.logical_id {
        entries.push((
            Value::from(KEY_LOGICAL_ID),
            Value::from(logical_id.as_str()),
        ));
    }
    // The one always-encode key: a decode-default-only `enabled` would make a
    // seeded `enabled: true` row encode differently across vaults.
    entries.push((Value::from(KEY_ENABLED), Value::Boolean(def.enabled)));
    if let Some(display_name) = &def.display_name {
        entries.push((
            Value::from(KEY_DISPLAY_NAME),
            Value::from(display_name.as_str()),
        ));
    }

    let value = Value::Map(entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("AGENT_DEF body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes a pinned-key MessagePack body into an `AgentDefinition`.
pub fn decode_agent_definition(bytes: &[u8]) -> Result<AgentDefinition> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidAgentDefBody("body is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidAgentDefBody("trailing bytes after body map"));
    }
    decode_agent_definition_value(&value)
}

/// Body-only structural validation for the public raw-put seam.
///
/// The authoring-side no-widen arm that used to live here is GONE with the
/// preset table (ONE-1890): a body alone cannot answer "what is my parent's
/// ceiling?" now that lineage is a row id. It relocated to the `batch.rs`
/// AGENT_DEF create arm, which loads the parent ROW, and the gate's live clamp
/// resolves the same bound at evaluation time (GATE-HALF).
pub(crate) fn validate_agent_definition_bytes(bytes: &[u8]) -> Result<()> {
    decode_agent_definition(bytes).map(|_| ())
}

pub(crate) fn validate_agent_definition_update(
    prior: &AgentDefinition,
    updated: &AgentDefinition,
) -> Result<()> {
    validate_agent_definition(updated)?;
    if prior == updated {
        return Ok(());
    }
    if prior.agent_id != updated.agent_id {
        return Err(Error::InvalidAgentDefBody(
            "agentId cannot change on update",
        ));
    }
    if prior.forked_from != updated.forked_from {
        return Err(Error::InvalidAgentDefBody(
            "forkedFrom cannot change on update",
        ));
    }
    if prior.logical_id != updated.logical_id {
        return Err(Error::InvalidAgentDefBody(
            "logicalId cannot change on update",
        ));
    }
    if prior.generated != updated.generated || prior.human_authored != updated.human_authored {
        return Err(Error::InvalidAgentDefBody(
            "authorship flags cannot change on update",
        ));
    }
    if prior.source != updated.source {
        return Err(Error::InvalidAgentDefBody("source cannot change on update"));
    }
    if prior.version == updated.version {
        return Err(Error::InvalidAgentDefBody(
            "version must change when updating agent definition body",
        ));
    }
    Ok(())
}

fn decode_agent_definition_value(value: &Value) -> Result<AgentDefinition> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidAgentDefBody("body must be a MessagePack map"));
    };

    let mut agent_id = None;
    let mut desc = None;
    let mut version = None;
    let mut instructions = None;
    let mut skills = None;
    let mut connectors = None;
    let mut code_mode_mcps = None;
    let mut model_tier = None;
    let mut scope_discriminant = None;
    let mut world = None;
    let mut ceiling = None;
    let mut forked_from = None;
    let mut approval_status = None;
    let mut lifecycle_status = None;
    let mut source = None;
    let mut confidence = None;
    let mut generated = None;
    let mut human_authored = None;
    let mut provenance = None;
    let mut logical_id = None;
    let mut enabled = None;
    let mut display_name = None;
    let mut seen = [false; AGENT_DEF_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidAgentDefBody("body keys must be strings"));
        };
        let Some(index) = AGENT_DEF_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidAgentDefBody(
                "body key is not in the pinned AGENT_DEF_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidAgentDefBody("duplicate body key"));
        }
        seen[index] = true;

        match AGENT_DEF_BODY_KEYS[index] {
            KEY_AGENT_ID => {
                agent_id = Some(text_value(
                    value,
                    AGENT_ID_MAX_BYTES,
                    "agentId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_DESC => {
                desc = Some(text_value(
                    value,
                    AGENT_DESC_MAX_BYTES,
                    "desc must be a non-empty UTF-8 string at most 4096 bytes",
                )?);
            }
            KEY_VERSION => {
                version = Some(text_value(
                    value,
                    AGENT_VERSION_MAX_BYTES,
                    "version must be a non-empty UTF-8 string at most 128 bytes",
                )?);
            }
            KEY_INSTRUCTIONS => {
                instructions = Some(text_value(
                    value,
                    AGENT_INSTRUCTIONS_MAX_BYTES,
                    "instructions must be a non-empty UTF-8 string at most 16384 bytes",
                )?);
            }
            KEY_SKILLS => skills = Some(decode_skill_dependencies(value)?),
            KEY_CONNECTORS => connectors = Some(decode_connectors(value)?),
            KEY_CODE_MODE_MCPS => code_mode_mcps = Some(decode_mcp_refs(value)?),
            KEY_MODEL_TIER => {
                let tier = text_value(
                    value,
                    AGENT_MODEL_TIER_MAX_BYTES,
                    "modelTier must be a non-empty UTF-8 string at most 256 bytes",
                )?;
                model_tier = Some(ModelTierRef(tier));
            }
            KEY_SCOPE => {
                scope_discriminant = Some(
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(Error::InvalidAgentDefBody("scope must be a string"))?,
                );
            }
            KEY_WORLD => {
                let hex = value.as_str().ok_or(Error::InvalidAgentDefBody(
                    "world must be a hex-encoded EntityId string",
                ))?;
                world = Some(EntityId::from_hex(hex).map_err(|_| {
                    Error::InvalidAgentDefBody("world must be a hex-encoded EntityId string")
                })?);
            }
            KEY_CEILING => {
                ceiling = Some(value.as_str().and_then(AgentCeiling::parse).ok_or(
                    Error::InvalidAgentDefBody("ceiling must be one of auto|proposed"),
                )?);
            }
            KEY_FORKED_FROM => {
                let text = value.as_str().ok_or(Error::InvalidAgentDefBody(
                    "forkedFrom must be a hex-encoded EntityId string",
                ))?;
                forked_from = Some(decode_forked_from(text)?);
            }
            KEY_APPROVAL_STATUS => {
                approval_status = Some(value.as_str().and_then(ClaimApprovalStatus::parse).ok_or(
                    Error::InvalidAgentDefBody(
                        "approvalStatus must be one of auto|proposed|approved|rejected",
                    ),
                )?);
            }
            KEY_LIFECYCLE_STATUS => {
                lifecycle_status =
                    Some(value.as_str().and_then(ClaimLifecycleStatus::parse).ok_or(
                        Error::InvalidAgentDefBody(
                            "lifecycleStatus must be one of active|superseded|retracted",
                        ),
                    )?);
            }
            KEY_SOURCE => {
                source =
                    Some(
                        value.as_str().and_then(ClaimSource::parse).ok_or(
                            Error::InvalidAgentDefBody(
                                "source must be one of user_stated|observed|inferred|imported|tool_output|generated",
                            ),
                        )?,
                    );
            }
            KEY_CONFIDENCE => {
                confidence = Some(crate::claim::unit_interval_f32(value).ok_or(
                    Error::InvalidAgentDefBody("confidence must be finite in the unit interval"),
                )?);
            }
            KEY_GENERATED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidAgentDefBody("generated must be a boolean"));
                };
                generated = Some(*flag);
            }
            KEY_HUMAN_AUTHORED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidAgentDefBody(
                        "humanAuthored must be a boolean",
                    ));
                };
                human_authored = Some(*flag);
            }
            KEY_PROVENANCE => provenance = Some(value.clone()),
            KEY_LOGICAL_ID => {
                logical_id = Some(text_value(
                    value,
                    AGENT_LOGICAL_ID_MAX_BYTES,
                    "logicalId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_ENABLED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidAgentDefBody("enabled must be a boolean"));
                };
                enabled = Some(*flag);
            }
            KEY_DISPLAY_NAME => {
                display_name = Some(text_value(
                    value,
                    AGENT_DISPLAY_NAME_MAX_BYTES,
                    "displayName must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            _ => unreachable!("index resolved from AGENT_DEF_BODY_KEYS"),
        }
    }

    let scope = resolve_scope(scope_discriminant.as_deref(), world)?;

    let definition = AgentDefinition {
        agent_id: agent_id.ok_or(Error::InvalidAgentDefBody("missing required key agentId"))?,
        desc: desc.ok_or(Error::InvalidAgentDefBody("missing required key desc"))?,
        version: version.ok_or(Error::InvalidAgentDefBody("missing required key version"))?,
        instructions,
        skills: skills.ok_or(Error::InvalidAgentDefBody("missing required key skills"))?,
        connectors: connectors.ok_or(Error::InvalidAgentDefBody(
            "missing required key connectors",
        ))?,
        code_mode_mcps: code_mode_mcps.ok_or(Error::InvalidAgentDefBody(
            "missing required key codeModeMcps",
        ))?,
        model_tier,
        scope,
        ceiling: ceiling.unwrap_or(AgentCeiling::Proposed),
        forked_from,
        approval_status: approval_status.ok_or(Error::InvalidAgentDefBody(
            "missing required key approvalStatus",
        ))?,
        lifecycle_status: lifecycle_status.ok_or(Error::InvalidAgentDefBody(
            "missing required key lifecycleStatus",
        ))?,
        source: source.ok_or(Error::InvalidAgentDefBody("missing required key source"))?,
        confidence: confidence.ok_or(Error::InvalidAgentDefBody(
            "missing required key confidence",
        ))?,
        generated: generated.ok_or(Error::InvalidAgentDefBody("missing required key generated"))?,
        human_authored: human_authored.ok_or(Error::InvalidAgentDefBody(
            "missing required key humanAuthored",
        ))?,
        provenance: provenance.ok_or(Error::InvalidAgentDefBody(
            "missing required key provenance",
        ))?,
        logical_id,
        // Missing decodes as enabled: pre-1890 bodies carried no key and were
        // dispatchable.
        enabled: enabled.unwrap_or(true),
        display_name,
    };
    validate_agent_definition(&definition)?;
    Ok(definition)
}

/// Decodes the `forkedFrom` wire string: always 32 lower-case hex on encode,
/// plus a compat-only arm for the six legacy `sys.*` preset strings persisted
/// before ONE-1890 (crash-recovery carve-out: one mapping, zero machinery).
/// Unknown strings stay typed decode errors.
fn decode_forked_from(text: &str) -> Result<EntityId> {
    if let Ok(id) = EntityId::from_hex(text) {
        return Ok(id);
    }
    legacy_logical_id_row(text)?.ok_or(Error::InvalidAgentDefBody(
        "forkedFrom must be a hex-encoded EntityId string",
    ))
}

/// The pinned row id a legacy `sys.*` wire string maps to, or `None` when the
/// string names no seeded row. The ONE map both legacy decoders share.
pub(crate) fn legacy_logical_id_row(logical_id: &str) -> Result<Option<EntityId>> {
    Ok(system_agent_manifest()?
        .definitions
        .iter()
        .find(|seed| seed.logical_id == logical_id)
        .map(|seed| seed.entity_id.0))
}

/// Resolves the `scope`/`world` two-key cross-field invariant: the `world` key
/// is present iff the discriminant is `world`. Unknown-key rejection cannot
/// catch this case because `world` is itself a pinned key, so it needs its own
/// arm.
fn resolve_scope(discriminant: Option<&str>, world: Option<EntityId>) -> Result<AgentScope> {
    let discriminant =
        discriminant.ok_or(Error::InvalidAgentDefBody("missing required key scope"))?;
    match discriminant {
        SCOPE_ALL => {
            if world.is_some() {
                return Err(Error::InvalidAgentDefBody(
                    "world key is only valid when scope is world",
                ));
            }
            Ok(AgentScope::All)
        }
        SCOPE_BASE => {
            if world.is_some() {
                return Err(Error::InvalidAgentDefBody(
                    "world key is only valid when scope is world",
                ));
            }
            Ok(AgentScope::Base)
        }
        SCOPE_WORLD => {
            let world = world.ok_or(Error::InvalidAgentDefBody(
                "scope world requires a world key",
            ))?;
            Ok(AgentScope::World(world))
        }
        _ => Err(Error::InvalidAgentDefBody(
            "scope must be one of all|base|world",
        )),
    }
}

fn encode_skill_dependency(dependency: &SkillDependency) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_DEP_SKILL_ID),
            Value::from(dependency.skill_id.as_str()),
        ),
        (
            Value::from(KEY_DEP_MIN_VERSION),
            dependency
                .min_version
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
    ])
}

fn encode_mcp_ref(mcp: &McpRef) -> Value {
    Value::Map(vec![
        (Value::from(KEY_MCP_KEY), Value::from(mcp.key.as_str())),
        (
            Value::from(KEY_MCP_MIN_VERSION),
            mcp.min_version.as_deref().map_or(Value::Nil, Value::from),
        ),
    ])
}

fn decode_skill_dependencies(value: &Value) -> Result<Vec<SkillDependency>> {
    let Value::Array(values) = value else {
        return Err(Error::InvalidAgentDefBody(
            "skills must be a MessagePack array",
        ));
    };
    if values.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::InvalidAgentDefBody(
            "skills must contain at most 64 entries",
        ));
    }
    values.iter().map(decode_skill_dependency).collect()
}

fn decode_skill_dependency(value: &Value) -> Result<SkillDependency> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidAgentDefBody(
            "skill dependency must be a MessagePack map",
        ));
    };

    let mut skill_id = None;
    let mut min_version = None;
    let mut seen = [false; SKILL_DEPENDENCY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidAgentDefBody(
                "skill dependency keys must be strings",
            ));
        };
        let Some(index) = SKILL_DEPENDENCY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidAgentDefBody(
                "skill dependency key must be skillId|minVersion",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidAgentDefBody("duplicate skill dependency key"));
        }
        seen[index] = true;
        match SKILL_DEPENDENCY_KEYS[index] {
            KEY_DEP_SKILL_ID => {
                skill_id = Some(text_value(
                    value,
                    AGENT_REF_KEY_MAX_BYTES,
                    "skill dependency skillId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_DEP_MIN_VERSION => {
                min_version = Some(match value {
                    Value::Nil => None,
                    _ => Some(text_value(
                        value,
                        AGENT_VERSION_MAX_BYTES,
                        "skill dependency minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
                    )?),
                });
            }
            _ => unreachable!("index resolved from SKILL_DEPENDENCY_KEYS"),
        }
    }

    Ok(SkillDependency {
        skill_id: skill_id.ok_or(Error::InvalidAgentDefBody(
            "missing required skill dependency key skillId",
        ))?,
        min_version: min_version.ok_or(Error::InvalidAgentDefBody(
            "missing required skill dependency key minVersion",
        ))?,
    })
}

fn decode_connectors(value: &Value) -> Result<Vec<String>> {
    let Value::Array(values) = value else {
        return Err(Error::InvalidAgentDefBody(
            "connectors must be a MessagePack array",
        ));
    };
    if values.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::InvalidAgentDefBody(
            "connectors must contain at most 64 entries",
        ));
    }
    values
        .iter()
        .map(|value| {
            text_value(
                value,
                AGENT_REF_KEY_MAX_BYTES,
                "connector key must be a non-empty UTF-8 string at most 256 bytes",
            )
        })
        .collect()
}

fn decode_mcp_refs(value: &Value) -> Result<Vec<McpRef>> {
    let Value::Array(values) = value else {
        return Err(Error::InvalidAgentDefBody(
            "codeModeMcps must be a MessagePack array",
        ));
    };
    if values.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::InvalidAgentDefBody(
            "codeModeMcps must contain at most 64 entries",
        ));
    }
    values.iter().map(decode_mcp_ref).collect()
}

fn decode_mcp_ref(value: &Value) -> Result<McpRef> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidAgentDefBody(
            "MCP ref must be a MessagePack map",
        ));
    };

    let mut key = None;
    let mut min_version = None;
    let mut seen = [false; MCP_REF_KEYS.len()];

    for (entry_key, value) in entries {
        let Some(entry_key) = entry_key.as_str() else {
            return Err(Error::InvalidAgentDefBody("MCP ref keys must be strings"));
        };
        let Some(index) = MCP_REF_KEYS.iter().position(|known| *known == entry_key) else {
            return Err(Error::InvalidAgentDefBody(
                "MCP ref key must be key|minVersion",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidAgentDefBody("duplicate MCP ref key"));
        }
        seen[index] = true;
        match MCP_REF_KEYS[index] {
            KEY_MCP_KEY => {
                key = Some(text_value(
                    value,
                    AGENT_REF_KEY_MAX_BYTES,
                    "MCP ref key must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_MCP_MIN_VERSION => {
                min_version = Some(match value {
                    Value::Nil => None,
                    _ => Some(text_value(
                        value,
                        AGENT_VERSION_MAX_BYTES,
                        "MCP ref minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
                    )?),
                });
            }
            _ => unreachable!("index resolved from MCP_REF_KEYS"),
        }
    }

    Ok(McpRef {
        key: key.ok_or(Error::InvalidAgentDefBody(
            "missing required MCP ref key key",
        ))?,
        min_version: min_version.ok_or(Error::InvalidAgentDefBody(
            "missing required MCP ref key minVersion",
        ))?,
    })
}

fn validate_agent_definition(def: &AgentDefinition) -> Result<()> {
    validate_text_field(
        &def.agent_id,
        AGENT_ID_MAX_BYTES,
        "agentId must be a non-empty UTF-8 string at most 256 bytes",
    )?;
    validate_text_field(
        &def.desc,
        AGENT_DESC_MAX_BYTES,
        "desc must be a non-empty UTF-8 string at most 4096 bytes",
    )?;
    validate_text_field(
        &def.version,
        AGENT_VERSION_MAX_BYTES,
        "version must be a non-empty UTF-8 string at most 128 bytes",
    )?;
    if let Some(instructions) = &def.instructions {
        validate_text_field(
            instructions,
            AGENT_INSTRUCTIONS_MAX_BYTES,
            "instructions must be a non-empty UTF-8 string at most 16384 bytes",
        )?;
    }
    if let Some(model_tier) = &def.model_tier {
        validate_text_field(
            model_tier.as_str(),
            AGENT_MODEL_TIER_MAX_BYTES,
            "modelTier must be a non-empty UTF-8 string at most 256 bytes",
        )?;
    }
    if let Some(logical_id) = &def.logical_id {
        validate_text_field(
            logical_id,
            AGENT_LOGICAL_ID_MAX_BYTES,
            "logicalId must be a non-empty UTF-8 string at most 256 bytes",
        )?;
    }
    if let Some(display_name) = &def.display_name {
        validate_text_field(
            display_name,
            AGENT_DISPLAY_NAME_MAX_BYTES,
            "displayName must be a non-empty UTF-8 string at most 256 bytes",
        )?;
    }
    if !def.confidence.is_finite() || !(0.0..=1.0).contains(&def.confidence) {
        return Err(Error::InvalidAgentDefBody(
            "confidence must be finite in the unit interval",
        ));
    }
    if def.generated == def.human_authored {
        return Err(Error::InvalidAgentDefBody(
            "exactly one of generated or humanAuthored must be true",
        ));
    }
    if def.generated != (def.source == ClaimSource::Generated) {
        return Err(Error::InvalidAgentDefBody(
            "generated flag must match generated source",
        ));
    }
    validate_provenance(&def.provenance)?;
    validate_skill_dependencies(&def.skills)?;
    validate_connectors(&def.connectors)?;
    validate_mcp_refs(&def.code_mode_mcps)?;
    Ok(())
}

fn validate_provenance(provenance: &Value) -> Result<()> {
    let Value::Map(entries) = provenance else {
        return Err(Error::InvalidAgentDefBody(
            "provenance must be a non-empty MessagePack map",
        ));
    };
    if entries.is_empty() {
        return Err(Error::InvalidAgentDefBody(
            "provenance must be a non-empty MessagePack map",
        ));
    }
    let mut seen = HashSet::new();
    for (key, _) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidAgentDefBody(
                "provenance keys must be strings",
            ));
        };
        if key.trim().is_empty() {
            return Err(Error::InvalidAgentDefBody(
                "provenance keys must be non-empty strings",
            ));
        }
        if !seen.insert(key) {
            return Err(Error::InvalidAgentDefBody("duplicate provenance key"));
        }
    }
    Ok(())
}

fn validate_skill_dependencies(skills: &[SkillDependency]) -> Result<()> {
    if skills.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::InvalidAgentDefBody(
            "skills must contain at most 64 entries",
        ));
    }
    let mut seen = HashSet::new();
    for dependency in skills {
        validate_text_field(
            &dependency.skill_id,
            AGENT_REF_KEY_MAX_BYTES,
            "skill dependency skillId must be a non-empty UTF-8 string at most 256 bytes",
        )?;
        if !seen.insert(dependency.skill_id.as_str()) {
            return Err(Error::InvalidAgentDefBody("duplicate skill dependency"));
        }
        if let Some(min_version) = &dependency.min_version {
            validate_text_field(
                min_version,
                AGENT_VERSION_MAX_BYTES,
                "skill dependency minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
            )?;
        }
    }
    Ok(())
}

fn validate_connectors(connectors: &[String]) -> Result<()> {
    if connectors.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::InvalidAgentDefBody(
            "connectors must contain at most 64 entries",
        ));
    }
    let mut seen = HashSet::new();
    for connector in connectors {
        validate_text_field(
            connector,
            AGENT_REF_KEY_MAX_BYTES,
            "connector key must be a non-empty UTF-8 string at most 256 bytes",
        )?;
        if !seen.insert(connector.as_str()) {
            return Err(Error::InvalidAgentDefBody("duplicate connector"));
        }
    }
    Ok(())
}

fn validate_mcp_refs(mcps: &[McpRef]) -> Result<()> {
    if mcps.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(Error::InvalidAgentDefBody(
            "codeModeMcps must contain at most 64 entries",
        ));
    }
    let mut seen = HashSet::new();
    for mcp in mcps {
        validate_text_field(
            &mcp.key,
            AGENT_REF_KEY_MAX_BYTES,
            "MCP ref key must be a non-empty UTF-8 string at most 256 bytes",
        )?;
        if !seen.insert(mcp.key.as_str()) {
            return Err(Error::InvalidAgentDefBody("duplicate MCP ref"));
        }
        if let Some(min_version) = &mcp.min_version {
            validate_text_field(
                min_version,
                AGENT_VERSION_MAX_BYTES,
                "MCP ref minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
            )?;
        }
    }
    Ok(())
}

fn text_value(value: &Value, max_bytes: usize, context: &'static str) -> Result<String> {
    let text = value.as_str().ok_or(Error::InvalidAgentDefBody(context))?;
    validate_text_field(text, max_bytes, context)?;
    Ok(text.to_owned())
}

fn validate_text_field(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidAgentDefBody(context));
    }
    Ok(())
}

/// Legacy per-vault system-agent toggle key prefix in `vault_meta` (full key =
/// prefix + logical-id bytes). Pre-ONE-1890 state, consumed ONCE into the
/// seeded row's `enabled` field and deleted in the same transaction; the
/// literal survives only here, in the seeder's legacy-consumption path.
const LEGACY_SYSTEM_AGENT_TOGGLE_KEY_PREFIX: &[u8] = b"agent_def:system_toggle:v1:";

/// The two pre-1890 reserved-actor census rows in `vault_meta`, deleted with
/// the census they served — both readers died with the compiled roster. Like
/// the toggle prefix above, these literals survive only here, in the seeder's
/// legacy-consumption path.
const PRE_1890_ACTOR_CENSUS_KEYS: [&[u8]; 2] = [
    b"agent_def:reserved_actor_census:v2",
    b"agent_def:default_reserved_actor_census:v1",
];

/// `occurred`/`learned_at` for every seeded row, pinned so the six baseline
/// rows are byte-identical across vaults (idiom: `DEFAULT_POLICY_MANIFEST_TIMESTAMP`).
const SEEDED_AGENT_DEFINITION_TIMESTAMP: u64 = 0;

/// A 32-character lower-case hex `EntityId`, the manifest's only id spelling.
#[derive(Debug)]
struct HexEntityId(EntityId);

impl<'de> serde::Deserialize<'de> for HexEntityId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = <&str as serde::Deserialize>::deserialize(deserializer)?;
        if text.len() != 32
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom(
                "entity id must be 32 lower-case hex characters",
            ));
        }
        EntityId::from_hex(text)
            .map(HexEntityId)
            .map_err(|_| serde::de::Error::custom("entity id must be a valid EntityId"))
    }
}

/// The canonical seeded-roster manifest. Private: the parsed form never
/// escapes this module, and `AgentDefinition` stays the only public model.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemAgentDefinitionManifest {
    version: u8,
    definitions: Vec<SystemAgentDefinitionSeed>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemAgentDefinitionSeed {
    entity_id: HexEntityId,
    logical_id: String,
    actor_entity_id: HexEntityId,
    display_name: String,
    enabled: bool,
    /// Field-for-field JSON adapter for the remaining `AgentDefinition` body
    /// keys. Nothing is derived from `logical_id` or `display_name`.
    definition: AgentDefinitionManifestFields,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDefinitionManifestFields {
    agent_id: String,
    desc: String,
    version: String,
    instructions: Option<String>,
    skills: Vec<ManifestSkillDependency>,
    connectors: Vec<String>,
    code_mode_mcps: Vec<ManifestMcpRef>,
    model_tier: Option<String>,
    scope: ManifestScope,
    ceiling: String,
    forked_from: Option<HexEntityId>,
    approval_status: String,
    lifecycle_status: String,
    source: String,
    confidence: f32,
    generated: bool,
    human_authored: bool,
    provenance: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSkillDependency {
    skill_id: String,
    min_version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestMcpRef {
    key: String,
    min_version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum ManifestScope {
    All,
    Base,
    World { world: HexEntityId },
}

impl AgentDefinitionManifestFields {
    fn to_definition(
        &self,
        logical_id: String,
        enabled: bool,
        display_name: String,
    ) -> Result<AgentDefinition> {
        let ceiling = AgentCeiling::parse(&self.ceiling).ok_or(Error::InvalidAgentDefBody(
            "manifest ceiling must be one of auto|proposed",
        ))?;
        let approval_status =
            ClaimApprovalStatus::parse(&self.approval_status).ok_or(Error::InvalidAgentDefBody(
                "manifest approvalStatus must be a known claim approval status",
            ))?;
        let lifecycle_status = ClaimLifecycleStatus::parse(&self.lifecycle_status).ok_or(
            Error::InvalidAgentDefBody("manifest lifecycleStatus must be a known claim lifecycle"),
        )?;
        let source = ClaimSource::parse(&self.source).ok_or(Error::InvalidAgentDefBody(
            "manifest source must be a known claim source",
        ))?;
        Ok(AgentDefinition::new(
            self.agent_id.clone(),
            self.desc.clone(),
            self.version.clone(),
            self.instructions.clone(),
            self.skills
                .iter()
                .map(|dependency| SkillDependency {
                    skill_id: dependency.skill_id.clone(),
                    min_version: dependency.min_version.clone(),
                })
                .collect(),
            self.connectors.clone(),
            self.code_mode_mcps
                .iter()
                .map(|mcp| McpRef {
                    key: mcp.key.clone(),
                    min_version: mcp.min_version.clone(),
                })
                .collect(),
            self.model_tier.clone().map(ModelTierRef),
            match &self.scope {
                ManifestScope::All => AgentScope::All,
                ManifestScope::Base => AgentScope::Base,
                ManifestScope::World { world } => AgentScope::World(world.0),
            },
            ceiling,
            self.forked_from.as_ref().map(|parent| parent.0),
            approval_status,
            lifecycle_status,
            source,
            self.confidence,
            self.generated,
            self.human_authored,
            json_object_to_msgpack(&self.provenance),
            Some(logical_id),
            enabled,
            Some(display_name),
        ))
    }
}

fn json_object_to_msgpack(object: &serde_json::Map<String, serde_json::Value>) -> Value {
    Value::Map(
        object
            .iter()
            .map(|(key, value)| (Value::from(key.as_str()), json_to_msgpack(value)))
            .collect(),
    )
}

fn json_to_msgpack(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(flag) => Value::Boolean(*flag),
        serde_json::Value::Number(number) => number
            .as_i64()
            .map(Value::from)
            .or_else(|| number.as_u64().map(Value::from))
            .or_else(|| number.as_f64().map(Value::from))
            .unwrap_or(Value::Nil),
        serde_json::Value::String(text) => Value::from(text.as_str()),
        serde_json::Value::Array(values) => {
            Value::Array(values.iter().map(json_to_msgpack).collect())
        }
        serde_json::Value::Object(object) => json_object_to_msgpack(object),
    }
}

/// Parses and fully validates a seeded-roster manifest. MALFORMED IS NOT
/// MISSING: every rejection here aborts open before any row is staged.
pub(crate) fn parse_system_agent_definition_manifest(
    json: &str,
) -> Result<SystemAgentDefinitionManifest> {
    let manifest: SystemAgentDefinitionManifest = serde_json::from_str(json).map_err(|_| {
        Error::InvalidAgentDefBody("system agent manifest is not valid schema-v1 JSON")
    })?;
    if manifest.version != 1 {
        return Err(Error::InvalidAgentDefBody(
            "system agent manifest schema version must be 1",
        ));
    }
    let mut logical_ids = HashSet::new();
    let mut row_ids = HashSet::new();
    let mut actor_ids = HashSet::new();
    for seed in &manifest.definitions {
        validate_text_field(
            &seed.logical_id,
            AGENT_LOGICAL_ID_MAX_BYTES,
            "manifest logical id must be a non-empty string at most 256 bytes",
        )?;
        if !seed.logical_id.starts_with(SYSTEM_LOGICAL_ID_PREFIX) {
            return Err(Error::InvalidAgentDefBody(
                "manifest logical id must use the reserved sys. prefix",
            ));
        }
        validate_text_field(
            &seed.display_name,
            AGENT_DISPLAY_NAME_MAX_BYTES,
            "manifest display name must be a non-empty string at most 256 bytes",
        )?;
        // Schema v1: the gate classifier derives authority by reading the
        // entity stored AT the actor id, so a divergent actor id could never
        // resolve to the seeded definition.
        if seed.actor_entity_id.0 != seed.entity_id.0 {
            return Err(Error::InvalidAgentDefBody(
                "manifest schema v1 requires actor_entity_id to equal entity_id",
            ));
        }
        if !logical_ids.insert(seed.logical_id.as_str()) {
            return Err(Error::InvalidAgentDefBody(
                "manifest logical ids must be unique",
            ));
        }
        if !row_ids.insert(seed.entity_id.0) {
            return Err(Error::InvalidAgentDefBody(
                "manifest row ids must be unique",
            ));
        }
        if !actor_ids.insert(seed.actor_entity_id.0) {
            return Err(Error::InvalidAgentDefBody(
                "manifest actor ids must be unique",
            ));
        }
    }
    Ok(manifest)
}

/// The parsed embedded manifest. Parsed once: decode-path consumers (the
/// legacy `forkedFrom` and dispatch-target compat arms) must not re-parse JSON
/// per row.
fn system_agent_manifest() -> Result<&'static SystemAgentDefinitionManifest> {
    static MANIFEST: std::sync::OnceLock<Option<SystemAgentDefinitionManifest>> =
        std::sync::OnceLock::new();
    MANIFEST
        .get_or_init(|| {
            parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON).ok()
        })
        .as_ref()
        .ok_or(Error::InvalidAgentDefBody(
            "embedded system agent manifest is malformed",
        ))
}

/// The `sys.*` logical-id reservation, enforced at the AGENT_DEF put-decode
/// chokepoint where both the body and its destination row id are in hand: a
/// `sys.`-prefixed logical id is admissible only at its own pinned row id.
pub(crate) fn validate_reserved_logical_id(id: &EntityId, def: &AgentDefinition) -> Result<()> {
    let Some(logical_id) = def.logical_id.as_deref() else {
        return Ok(());
    };
    if !logical_id.starts_with(SYSTEM_LOGICAL_ID_PREFIX) {
        return Ok(());
    }
    if legacy_logical_id_row(logical_id)? == Some(*id) {
        return Ok(());
    }
    Err(Error::InvalidAgentDefBody(
        "sys.* logical ids are reserved for seeded rows",
    ))
}

/// Seeds/reconciles the canonical roster inside the caller's write
/// transaction. Takes the open-path input quartet rather than a `&Vault`,
/// because it runs before any handle exists.
pub(crate) fn seed_system_agent_definitions(
    store: &crate::store::Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut heed::RwTxn<'_>,
    text_index_trusted: bool,
) -> Result<()> {
    let manifest = parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON)?;
    reconcile_system_agent_definitions_in(
        store,
        config,
        analyzer,
        wtxn,
        text_index_trusted,
        &manifest,
    )
}

/// Convergent reconciliation over the stored rows: create what is missing,
/// never overwrite what exists, fail closed on a foreign occupant. LMDB write
/// serialization plus deterministic ids makes concurrent opens converge — the
/// later writer observes the first writer's committed row and writes nothing.
pub(crate) fn reconcile_system_agent_definitions_in(
    store: &crate::store::Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut heed::RwTxn<'_>,
    text_index_trusted: bool,
    manifest: &SystemAgentDefinitionManifest,
) -> Result<()> {
    for seed in &manifest.definitions {
        let id = seed.entity_id.0;
        let legacy_enabled = take_legacy_system_agent_toggle(store, wtxn, &seed.logical_id)?;
        match store.entities.get(wtxn, id.as_bytes())? {
            Some(raw) => {
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::SeededAgentDefinitionConflict { id })?;
                if header.entity_type != ENTITY_TYPE_AGENT_DEF {
                    return Err(Error::SeededAgentDefinitionConflict { id });
                }
                let stored = decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..])
                    .map_err(|_| Error::SeededAgentDefinitionConflict { id })?;
                // A valid occupant whose logical id is missing or different is
                // a legacy foreign row: conflict, never adoption, never
                // overwrite. A match leaves every stored byte alone —
                // including user edits, `display_name`, and `enabled = false`.
                if stored.logical_id.as_deref() != Some(seed.logical_id.as_str()) {
                    return Err(Error::SeededAgentDefinitionConflict { id });
                }
            }
            None => {
                let definition = seed.definition_row(legacy_enabled)?;
                let data = encode_agent_definition(&definition)?;
                apply_ops(
                    store,
                    config,
                    analyzer,
                    wtxn,
                    vec![BatchOp::Put {
                        id,
                        entity_type: ENTITY_TYPE_AGENT_DEF,
                        occurred: TimeRange {
                            start: SEEDED_AGENT_DEFINITION_TIMESTAMP,
                            end: SEEDED_AGENT_DEFINITION_TIMESTAMP,
                        },
                        learned_at: SEEDED_AGENT_DEFINITION_TIMESTAMP,
                        data,
                        allow_maintenance: false,
                        allow_reserved_predicate: false,
                        hub_sync_imported: false,
                    }],
                    text_index_trusted,
                    false,
                    true,
                )?;
            }
        }
    }
    for key in PRE_1890_ACTOR_CENSUS_KEYS {
        store.vault_meta.delete(wtxn, key)?;
    }
    Ok(())
}

/// Reads and DELETES the pre-1890 per-vault toggle for `logical_id`, in the
/// caller's transaction. `Some(false)`/`Some(true)` initialize a newly created
/// row's `enabled`; an absent or unreadable byte leaves the manifest default.
fn take_legacy_system_agent_toggle(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    logical_id: &str,
) -> Result<Option<bool>> {
    let mut key = LEGACY_SYSTEM_AGENT_TOGGLE_KEY_PREFIX.to_vec();
    key.extend_from_slice(logical_id.as_bytes());
    let stored = match store.vault_meta.get(wtxn, key.as_slice())? {
        Some(raw) if *raw == [0x01] => Some(true),
        Some(raw) if *raw == [0x00] => Some(false),
        Some(_) | None => None,
    };
    store.vault_meta.delete(wtxn, key.as_slice())?;
    Ok(stored)
}

impl SystemAgentDefinitionSeed {
    /// The row this seed materializes, with `enabled` initialized from the
    /// one-time legacy toggle when one was present.
    fn definition_row(&self, legacy_enabled: Option<bool>) -> Result<AgentDefinition> {
        self.definition.to_definition(
            self.logical_id.clone(),
            legacy_enabled.unwrap_or(self.enabled),
            self.display_name.clone(),
        )
    }
}

impl Vault {
    /// Encodes (validating) and writes an `AgentDefinition` through the generic
    /// entity door.
    pub fn put_agent_definition(
        &self,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_agent_definition(def)?;
        self.put_entity(id, ENTITY_TYPE_AGENT_DEF, occurred, learned_at, &data)
    }

    /// Discoverability alias for `put_agent_definition` so the registry verb
    /// name `define_agent` greps to the vault surface. The house
    /// `put_/get_/update_` naming stays canonical.
    #[inline]
    pub fn define_agent(
        &self,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.put_agent_definition(id, def, occurred, learned_at)
    }

    /// Reads the prior record, enforces the immutability gate, and writes the
    /// new body in a single write transaction.
    pub fn update_agent_definition(
        &self,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_agent_definition(def)?;
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_agent_definition_in_txn(&wtxn, id)?;
        validate_agent_definition_update(&existing, def)?;
        self.apply_agent_definition_body(&mut wtxn, id, occurred, learned_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Returns the decoded `AgentDefinition` for `id`, or `None` if absent.
    pub fn get_agent_definition(&self, id: &EntityId) -> Result<Option<AgentDefinition>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AGENT_DEF {
            return Err(Error::InvalidAgentDefBody(
                "entity is not a type-17 AGENT_DEF",
            ));
        }
        decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Resolves a seeded row by its stable `sys.*` logical id: the canonical
    /// manifest pins the id, the live STORED row supplies the data. User
    /// edits, the runtime-editable `display_name`, and `enabled` therefore
    /// stay authoritative. An unknown logical id or an absent row is
    /// `Ok(None)`; a stored-row decode failure propagates.
    pub fn get_seeded_agent_definition_by_logical_id(
        &self,
        logical_id: &str,
    ) -> Result<Option<(EntityId, AgentDefinition)>> {
        let Some(id) = legacy_logical_id_row(logical_id)? else {
            return Ok(None);
        };
        Ok(self
            .get_agent_definition(&id)?
            .map(|definition| (id, definition)))
    }

    fn read_agent_definition_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<AgentDefinition> {
        let raw = self
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AGENT_DEF {
            return Err(Error::InvalidAgentDefBody(
                "entity is not a type-17 AGENT_DEF",
            ));
        }
        decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..])
    }

    fn apply_agent_definition_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_AGENT_DEF,
                occurred,
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}

#[cfg(test)]
mod one_1698_tests {
    use crate::edge::EdgeActorClass;
    use crate::gate::PolicyApprovalCeiling;
    use crate::{VaultConfig, WriteActor};

    /// The `sys.default` row id, pinned by the canonical manifest. Constructed
    /// explicitly (with intent) because `test_util::entity` refuses
    /// production-pinned seed bytes.
    fn default_base_row_id() -> crate::EntityId {
        crate::EntityId::from_bytes([0xA6; 16]).expect("pinned seeded row id is non-reserved")
    }

    #[test]
    fn seeded_default_base_row_carries_its_own_ceiling() -> crate::Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let (id, definition) = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")?
            .expect("default base row is seeded");
        assert_eq!(id, default_base_row_id());
        assert_eq!(definition.agent_id, "sys.default");

        let rtxn = vault.store.env.read_txn()?;
        let ceiling = crate::gate::agent_definition_ceiling_for_actor(
            &vault.store,
            &rtxn,
            WriteActor::new(id, EdgeActorClass::Agent),
        );
        assert_eq!(ceiling, Some(PolicyApprovalCeiling::Auto));
        Ok(())
    }

    #[test]
    fn deleted_seeded_row_resolves_proposed() -> crate::Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let id = default_base_row_id();
        vault.with_write_txn(|wtxn| {
            vault.store.entities.delete(wtxn, id.as_bytes())?;
            Ok(())
        })?;

        let rtxn = vault.store.env.read_txn()?;
        let ceiling = crate::gate::agent_definition_ceiling_for_actor(
            &vault.store,
            &rtxn,
            WriteActor::new(id, EdgeActorClass::Agent),
        );
        assert_eq!(ceiling, Some(PolicyApprovalCeiling::Proposed));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
