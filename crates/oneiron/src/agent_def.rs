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
/// `instructions`, `modelTier`, `world`, `ceiling`, and `forkedFrom` are
/// optional and elided from the encoded map when absent or default-valued
/// (the elide-the-default pattern); every other key is required. Decode
/// rejects any key outside this set, so the schema is a review-visible
/// contract and hosts cannot add fields. A body with `ceiling = proposed`
/// (the default) and no fork lineage encodes byte-identically to the
/// pre-AGENT-2 17-key codec.
pub const AGENT_DEF_BODY_KEYS: [&str; 19] = [
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

/// Version stamped into preset templates and fork provenance. Bumping it does
/// not migrate anything: presets are compiled-in and never persisted; existing
/// forks are snapshots that keep the version they forked from.
pub const SYSTEM_AGENT_PRESET_VERSION: &str = "1";

/// The code-shipped system-agent presets (OF-334 / EF-155).
///
/// Presets are compiled-in templates, never stored as vault entities —
/// "editing a system agent" is impossible by construction; the only mutation
/// path is [`Vault::fork_system_agent`]. At the gate they are keyed by the
/// pinned actor entity ids (`[0xA1; 16]`..`[0xA6; 16]`), never by labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemAgentPreset {
    Scout,
    Keeper,
    Creative,
    Herald,
    Guide,
    Default,
}

impl SystemAgentPreset {
    /// The pinned preset id (also the template's `agent_id` and the
    /// `forkedFrom` wire string).
    #[must_use]
    pub const fn preset_id(self) -> &'static str {
        match self {
            Self::Scout => "sys.scout",
            Self::Keeper => "sys.keeper",
            Self::Creative => "sys.creative",
            Self::Herald => "sys.herald",
            Self::Guide => "sys.guide",
            Self::Default => "sys.default",
        }
    }

    /// Parses a pinned preset id.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        if id == Self::Default.preset_id() {
            return Some(Self::Default);
        }
        Self::all()
            .into_iter()
            .find(|preset| preset.preset_id() == id)
    }

    /// Deterministic domain-preset roster order (declaration order).
    ///
    /// The default base stays outside this domain roster and its five-bit
    /// census; its reserved id has a separate additive census.
    #[must_use]
    pub const fn all() -> [SystemAgentPreset; 5] {
        [
            Self::Scout,
            Self::Keeper,
            Self::Creative,
            Self::Herald,
            Self::Guide,
        ]
    }

    /// The always-available generic base used by zero-configuration dispatch.
    #[must_use]
    pub const fn default_base() -> SystemAgentPreset {
        SystemAgentPreset::Default
    }

    /// The preset's compiled ceiling bound. Herald (external effector: email)
    /// and Guide (policy/consent surfaces) self-limit to Proposed — no fork of
    /// either can ever re-widen to Auto; the inward-facing memory workers do
    /// not self-limit (their writes stay bounded by the manifest projection
    /// and the gate's source-trust/criticality axes).
    #[must_use]
    pub const fn ceiling(self) -> AgentCeiling {
        match self {
            Self::Scout | Self::Keeper | Self::Creative | Self::Default => AgentCeiling::Auto,
            Self::Herald | Self::Guide => AgentCeiling::Proposed,
        }
    }

    const fn actor_id_byte(self) -> u8 {
        match self {
            Self::Scout => 0xA1,
            Self::Keeper => 0xA2,
            Self::Creative => 0xA3,
            Self::Herald => 0xA4,
            Self::Guide => 0xA5,
            Self::Default => 0xA6,
        }
    }

    /// The pinned actor-provenance identity (precedent: the `[0xE1; 16]`
    /// first-party connector actor id). Write-door-reserved in
    /// `batch.rs::apply_put` so no entity can squat on a system identity, but
    /// deliberately NOT added to the `EntityId::from_bytes` reserved sentinels
    /// — the ids must stay constructible as actor identities.
    #[must_use]
    pub fn actor_entity_id(self) -> EntityId {
        EntityId::from_bytes([self.actor_id_byte(); 16])
            .expect("pinned system agent actor id is non-reserved")
    }

    /// Reverse lookup for the pinned actor ids.
    #[must_use]
    pub fn from_actor_entity_id(id: &EntityId) -> Option<Self> {
        if id.as_bytes() == &[Self::Default.actor_id_byte(); 16] {
            return Some(Self::Default);
        }
        Self::all()
            .into_iter()
            .find(|preset| id.as_bytes() == &[preset.actor_id_byte(); 16])
    }

    /// Materializes the preset's in-memory `AgentDefinition` template (valid
    /// under authoring validation, encodable for dispatch snapshots).
    /// Prompts are host-layer (`instructions: None`); skill registries are
    /// vault-populated, so presets ship reference-free; connector/MCP keys
    /// are inert references, never existence-checked at write time.
    #[must_use]
    pub fn template(self) -> AgentDefinition {
        let (desc, connectors, code_mode_mcps) = match self {
            Self::Scout => (
                "System scout: outbound research and retrieval runs.",
                vec!["web.search".to_owned()],
                Vec::new(),
            ),
            Self::Keeper => (
                "System keeper: memory hygiene and consolidation follow-ups.",
                Vec::new(),
                Vec::new(),
            ),
            Self::Creative => (
                "System creative: drafting and ideation runs.",
                Vec::new(),
                Vec::new(),
            ),
            Self::Herald => (
                "System herald: outbound correspondence via connected email.",
                Vec::new(),
                vec![McpRef::new("email")],
            ),
            Self::Guide => (
                "System guide: onboarding, policy and consent explanation.",
                Vec::new(),
                Vec::new(),
            ),
            Self::Default => ("default", Vec::new(), Vec::new()),
        };
        AgentDefinition::new(
            self.preset_id(),
            desc,
            SYSTEM_AGENT_PRESET_VERSION,
            None,
            Vec::new(),
            connectors,
            code_mode_mcps,
            None,
            AgentScope::All,
            self.ceiling(),
            None,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
            ClaimSource::Imported,
            1.0,
            false,
            true,
            Value::Map(vec![
                (Value::from("system"), Value::from(self.preset_id())),
                (
                    Value::from("presetVersion"),
                    Value::from(SYSTEM_AGENT_PRESET_VERSION),
                ),
            ]),
        )
    }
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
    pub forked_from: Option<SystemAgentPreset>,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: ClaimLifecycleStatus,
    pub source: ClaimSource,
    pub confidence: f32,
    pub generated: bool,
    pub human_authored: bool,
    pub provenance: Value,
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
        forked_from: Option<SystemAgentPreset>,
        approval_status: ClaimApprovalStatus,
        lifecycle_status: ClaimLifecycleStatus,
        source: ClaimSource,
        confidence: f32,
        generated: bool,
        human_authored: bool,
        provenance: Value,
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
    if let Some(preset) = def.forked_from {
        entries.push((
            Value::from(KEY_FORKED_FROM),
            Value::from(preset.preset_id()),
        ));
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

pub(crate) fn validate_agent_definition_bytes(bytes: &[u8]) -> Result<()> {
    let def = decode_agent_definition(bytes)?;
    validate_agent_definition_no_widen(&def)
}

/// The authoring-side no-widen arm, deliberately SPLIT from the structural
/// validation that decode runs (M1 resolution 2026-07-10): reads, snapshots,
/// and the gate resolver must keep decoding stored forks even if the compiled
/// preset ceiling table is later narrowed — such forks stay readable,
/// live-clamped at gate time, and force-narrowed on their next update. Runs
/// at every write door: the public raw-put seam
/// ([`validate_agent_definition_bytes`]), the update gate, and fork/put
/// (which ride the raw-put seam).
fn validate_agent_definition_no_widen(def: &AgentDefinition) -> Result<()> {
    if let Some(preset) = def.forked_from
        && def.ceiling.widens_beyond(preset.ceiling())
    {
        return Err(Error::InvalidAgentDefBody(
            "forked agent ceiling cannot widen beyond its parent preset ceiling",
        ));
    }
    Ok(())
}

pub(crate) fn validate_agent_definition_update(
    prior: &AgentDefinition,
    updated: &AgentDefinition,
) -> Result<()> {
    validate_agent_definition(updated)?;
    validate_agent_definition_no_widen(updated)?;
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
                forked_from = Some(value.as_str().and_then(SystemAgentPreset::parse).ok_or(
                    Error::InvalidAgentDefBody("forkedFrom must name a known system agent preset"),
                )?);
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
    };
    validate_agent_definition(&definition)?;
    Ok(definition)
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

/// Per-vault system-agent toggle key prefix in `vault_meta` (full key =
/// prefix + `preset_id()` bytes). Private runner-state style, precedent
/// `dreamer:home_node_macro:v1` — deliberately per-device and non-synced:
/// the toggle is a local scheduling/product preference, NOT a security
/// control (authority enforcement is the replicated ceiling ∧ manifest gate
/// lattice, which is fail-closed).
const SYSTEM_AGENT_TOGGLE_KEY_PREFIX: &[u8] = b"agent_def:system_toggle:v1:";

fn system_agent_toggle_key(preset: SystemAgentPreset) -> Vec<u8> {
    let mut key = SYSTEM_AGENT_TOGGLE_KEY_PREFIX.to_vec();
    key.extend_from_slice(preset.preset_id().as_bytes());
    key
}

/// The durable five-domain-preset occupancy census (`vault_meta`, one byte).
///
/// The value is a bitmask over [`SystemAgentPreset::all`] declaration order:
/// bit `i` is set iff preset `i`'s pinned actor id was occupied by a stored
/// entity when the census ran. The KEY's PRESENCE means the census completed.
///
/// Default uses a separate additive one-byte completion/occupancy key. The
/// resolver requires both keys and combines them only in memory.
const SYSTEM_AGENT_RESERVED_CENSUS_KEY: &[u8] = b"agent_def:reserved_actor_census:v2";
const SYSTEM_AGENT_DEFAULT_RESERVED_CENSUS_KEY: &[u8] =
    b"agent_def:default_reserved_actor_census:v1";
const SYSTEM_AGENT_DEFAULT_RESERVED_CENSUS_OCCUPIED: u8 = 0x01;
const SYSTEM_AGENT_DEFAULT_RESERVED_CENSUS_SENTINEL: u8 = 1 << 5;

const fn reserved_preset_bit(preset: SystemAgentPreset) -> u8 {
    match preset {
        SystemAgentPreset::Scout => 1 << 0,
        SystemAgentPreset::Keeper => 1 << 1,
        SystemAgentPreset::Creative => 1 << 2,
        SystemAgentPreset::Herald => 1 << 3,
        SystemAgentPreset::Guide => 1 << 4,
        SystemAgentPreset::Default => 0,
    }
}

/// The combined in-memory census, or `None` unless both durable censuses are
/// valid and complete. The stored five-bit v2 byte is never changed.
pub(crate) fn reserved_actor_census(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Option<u8> {
    let mut census = match store.vault_meta.get(txn, SYSTEM_AGENT_RESERVED_CENSUS_KEY) {
        Ok(Some(raw)) if raw.len() == 1 => raw[0],
        Ok(Some(_)) | Ok(None) => return None,
        Err(error) => {
            tracing::warn!(
                %error,
                "reserved system agent census read failed; failing closed",
            );
            return None;
        }
    };
    let default_census = match store
        .vault_meta
        .get(txn, SYSTEM_AGENT_DEFAULT_RESERVED_CENSUS_KEY)
    {
        Ok(Some(raw)) if *raw == [0x00] || *raw == [0x01] => raw[0],
        Ok(Some(_)) | Ok(None) => return None,
        Err(error) => {
            tracing::warn!(
                %error,
                "default system agent census read failed; failing closed",
            );
            return None;
        }
    };
    if default_census == SYSTEM_AGENT_DEFAULT_RESERVED_CENSUS_OCCUPIED {
        census |= SYSTEM_AGENT_DEFAULT_RESERVED_CENSUS_SENTINEL;
    }
    Some(census)
}

/// True when the completed census recorded this reserved id as occupied
/// (now or at census time). `census` is the mask from [`reserved_actor_census`].
#[must_use]
pub(crate) fn reserved_actor_id_was_occupied(census: u8, preset: SystemAgentPreset) -> bool {
    if preset == SystemAgentPreset::Default {
        census & SYSTEM_AGENT_DEFAULT_RESERVED_CENSUS_SENTINEL != 0
    } else {
        census & reserved_preset_bit(preset) != 0
    }
}

/// One-time census of the five domain ids and separate Default reserved id.
///
/// Runs during `Vault::open` and from `batch.rs::apply_put`; the gate stays
/// read-only. Open observes legacy occupants before returning a vault handle,
/// while `apply_put` reserves the ids. Both census writes share one transaction.
pub(crate) fn scan_reserved_actor_ids_once(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let domain_completed = store
        .vault_meta
        .get(wtxn, SYSTEM_AGENT_RESERVED_CENSUS_KEY)?
        .is_some();
    let default_completed = store
        .vault_meta
        .get(wtxn, SYSTEM_AGENT_DEFAULT_RESERVED_CENSUS_KEY)?
        .is_some();
    if domain_completed && default_completed {
        return Ok(());
    }
    if !domain_completed {
        let mut mask = 0_u8;
        for preset in SystemAgentPreset::all() {
            let id = preset.actor_entity_id();
            if store.entities.get(wtxn, id.as_bytes())?.is_some() {
                tracing::warn!(
                    actor_entity_id = %id.to_hex(),
                    preset = preset.preset_id(),
                    "reserved system agent actor id is occupied by a legacy entity; \
                     recording durable occupancy in the census",
                );
                mask |= reserved_preset_bit(preset);
            }
        }
        store
            .vault_meta
            .put(wtxn, SYSTEM_AGENT_RESERVED_CENSUS_KEY, &[mask])?;
    }
    if !default_completed {
        let preset = SystemAgentPreset::Default;
        let id = preset.actor_entity_id();
        let occupied = store.entities.get(wtxn, id.as_bytes())?.is_some();
        if occupied {
            tracing::warn!(
                actor_entity_id = %id.to_hex(),
                preset = preset.preset_id(),
                "reserved system agent actor id is occupied by a legacy entity; \
                 recording durable occupancy in the census",
            );
        }
        store.vault_meta.put(
            wtxn,
            SYSTEM_AGENT_DEFAULT_RESERVED_CENSUS_KEY,
            &[u8::from(occupied)],
        )?;
    }
    Ok(())
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

    /// Writes a per-vault preset toggle. Default ignores toggle requests.
    pub fn set_system_agent_enabled(&self, preset: SystemAgentPreset, enabled: bool) -> Result<()> {
        if preset == SystemAgentPreset::Default {
            return Ok(());
        }
        let key = system_agent_toggle_key(preset);
        let mut wtxn = self.store.env.write_txn()?;
        self.store
            .vault_meta
            .put(&mut wtxn, key.as_slice(), &[u8::from(enabled)])?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads a preset toggle. Default is unconditional; other absent keys are
    /// enabled, and malformed stored bytes are invariant violations.
    pub fn system_agent_enabled(&self, preset: SystemAgentPreset) -> Result<bool> {
        if preset == SystemAgentPreset::Default {
            return Ok(true);
        }
        let key = system_agent_toggle_key(preset);
        let rtxn = self.store.env.read_txn()?;
        match self.store.vault_meta.get(&rtxn, key.as_slice())? {
            None => Ok(true),
            Some(raw) if *raw == [0x01] => Ok(true),
            Some(raw) if *raw == [0x00] => Ok(false),
            Some(_) => Err(Error::InvariantViolation("system agent toggle byte")),
        }
    }

    /// Forks an enabled system-agent preset into a new custom definition —
    /// the ONLY mutation path off a preset (OF-334/EF-155: edit-a-system-agent
    /// = fork-to-custom). The fork inherits the preset's composition and
    /// ceiling (`forked_from` pins the no-widen bound; narrowing happens via
    /// later updates) and is stamped as an explicit user act
    /// (`source = UserStated`). Rides the existing type-17 put door.
    pub fn fork_system_agent(
        &self,
        id: &EntityId,
        preset: SystemAgentPreset,
        agent_id: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AgentDefinition> {
        if !self.system_agent_enabled(preset)? {
            return Err(Error::SystemAgentDisabled(
                "fork requires an enabled system agent preset",
            ));
        }
        let mut def = preset.template();
        def.agent_id = agent_id.to_owned();
        def.version = "1".to_owned();
        def.forked_from = Some(preset);
        def.ceiling = preset.ceiling();
        def.approval_status = ClaimApprovalStatus::Approved;
        def.source = ClaimSource::UserStated;
        def.confidence = 1.0;
        def.generated = false;
        def.human_authored = true;
        def.provenance = Value::Map(vec![
            (Value::from("forkOf"), Value::from(preset.preset_id())),
            (
                Value::from("presetVersion"),
                Value::from(SYSTEM_AGENT_PRESET_VERSION),
            ),
        ]);
        self.put_agent_definition(id, &def, occurred, learned_at)?;
        Ok(def)
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
    use super::{SystemAgentPreset, scan_reserved_actor_ids_once};
    use crate::edge::EdgeActorClass;
    use crate::gate::PolicyApprovalCeiling;
    use crate::{VaultConfig, WriteActor};

    #[test]
    fn default_base_preset_round_trips_without_joining_domain_census() {
        let preset = SystemAgentPreset::default_base();
        assert_eq!(preset.preset_id(), "sys.default");
        assert_eq!(SystemAgentPreset::parse("sys.default"), Some(preset));
        assert_eq!(preset.actor_entity_id().as_bytes(), &[0xA6; 16]);
        assert_eq!(
            SystemAgentPreset::from_actor_entity_id(&preset.actor_entity_id()),
            Some(preset)
        );
        assert_eq!(SystemAgentPreset::all().len(), 5);
    }

    #[test]
    fn recorded_default_id_occupancy_resolves_proposed_after_delete() -> crate::Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let preset = SystemAgentPreset::Default;
        let id = preset.actor_entity_id();
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .delete(wtxn, b"agent_def:default_reserved_actor_census:v1")?;
            vault.store.entities.put(wtxn, id.as_bytes(), &[0x01])?;
            scan_reserved_actor_ids_once(&vault.store, wtxn)?;
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

    #[test]
    fn default_toggle_is_ignored() -> crate::Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        vault.set_system_agent_enabled(SystemAgentPreset::Default, false)?;
        assert!(vault.system_agent_enabled(SystemAgentPreset::Default)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
