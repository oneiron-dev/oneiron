//! The AgentPack a sharer sends to another party (OF-491, FIX 2040): a
//! reference-free projection of an agent definition. The pack's instructions
//! and skill bodies always travel, because they are the pack. Born-with text
//! travels only as the sharer's [`super::TravelChoice`] says, and by default
//! none does. Refs never travel: no entity id, world id, fork parent,
//! provenance, lifecycle verdict or `sys.*` logical id leaves in it.
//!
//! Owner backup and restore keep the native facets
//! (`agent_def::agent_pack_files_in`), which hold entity ids so a restore
//! comes back whole. Only a sharing door builds this projection.
//!
//! Layout ([`AgentPackTravelProjection::files`]):
//! - `PACK.md`: frontmatter with name, description, version, `kind: agent`
//!   and the facet paths;
//! - `identity.md`: the instructions;
//! - `policy.md`: JSON with the schema tag, the policy, the display name and
//!   the born-with text that travelled;
//! - `skills.json`: each skill dependency, pinned by content hash;
//! - `skills/<content_hash>/<path>`: each skill's files;
//! - `knowledge/selected.json`: the selected knowledge, as text.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use super::BornWith;
use crate::agent_def::{
    AgentCeiling, AgentDefinition, AgentScope, AgentWakeCadence, CompactionOwnership,
    ContextBudgetSplit, DreamingMode, McpRef, MemoryProfile, OptionalMemory, OptionalMemoryProfile,
    RefusalDial, RefusalLevel, encode_agent_definition,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::compaction::output::OutputDecayPolicy;
use crate::context_pack::FieldProfile;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::ModelTierRef;
use crate::skill::{SkillDependency, canonical_skill_tree_hash};
use crate::skill_hub::{HubFile, HubPackage};

/// The schema tag `policy.md` carries.
pub const AGENT_PACK_TRAVEL_SCHEMA: &str = "oneiron.agent-pack-travel.v1";

const PACK_MANIFEST: &str = "PACK.md";
const IDENTITY: &str = "identity.md";
const POLICY: &str = "policy.md";
const SKILLS: &str = "skills.json";
const SKILLS_DIR: &str = "skills/";
const KNOWLEDGE: &str = "knowledge/selected.json";

/// The provenance a destination stamps on the definition it mints.
const PROVENANCE_SOURCE: &str = "agent-pack-travel";

/// A unit enum mirrored on the wire, converted both ways.
macro_rules! mirror {
    ($wire:ident <=> $native:ident { $($variant:ident),+ $(,)? }) => {
        impl From<$native> for $wire {
            fn from(value: $native) -> Self {
                match value {
                    $($native::$variant => Self::$variant),+
                }
            }
        }

        impl From<$wire> for $native {
            fn from(value: $wire) -> Self {
                match value {
                    $($wire::$variant => Self::$variant),+
                }
            }
        }
    };
}

/// The run scope, with a world named rather than referenced. The destination
/// binds a local world by that name or refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPackScope {
    All,
    Base,
    World { name: String },
}

/// The agent's own approval ceiling: a self-limit, never a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackCeiling {
    Auto,
    Proposed,
}

mirror!(AgentPackCeiling <=> AgentCeiling { Auto, Proposed });

/// A code-mode MCP the agent asks for, by key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackMcp {
    pub key: String,
    pub min_version: Option<String>,
}

impl From<&McpRef> for AgentPackMcp {
    fn from(value: &McpRef) -> Self {
        Self {
            key: value.key.clone(),
            min_version: value.min_version.clone(),
        }
    }
}

impl From<AgentPackMcp> for McpRef {
    fn from(value: AgentPackMcp) -> Self {
        Self {
            key: value.key,
            min_version: value.min_version,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackCompaction {
    Engine,
    Byoa,
}

mirror!(AgentPackCompaction <=> CompactionOwnership { Engine, Byoa });

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackBudgetSplit {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

impl From<ContextBudgetSplit> for AgentPackBudgetSplit {
    fn from(value: ContextBudgetSplit) -> Self {
        Self {
            claims: value.claims,
            turns: value.turns,
            summaries: value.summaries,
            other: value.other,
        }
    }
}

impl From<AgentPackBudgetSplit> for ContextBudgetSplit {
    fn from(value: AgentPackBudgetSplit) -> Self {
        Self::new(value.claims, value.turns, value.summaries, value.other)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackOutputDecay {
    pub overview_after_turns: u64,
    pub stub_after_turns: u64,
}

impl From<OutputDecayPolicy> for AgentPackOutputDecay {
    fn from(value: OutputDecayPolicy) -> Self {
        Self {
            overview_after_turns: value.overview_after_turns,
            stub_after_turns: value.stub_after_turns,
        }
    }
}

impl From<AgentPackOutputDecay> for OutputDecayPolicy {
    fn from(value: AgentPackOutputDecay) -> Self {
        Self {
            overview_after_turns: value.overview_after_turns,
            stub_after_turns: value.stub_after_turns,
        }
    }
}

/// The detail an optional recall reads at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackView {
    Minimal,
    Standard,
    Full,
}

mirror!(AgentPackView <=> FieldProfile { Minimal, Standard, Full });

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPackOptionalMemory {
    None,
    Budget {
        tokens: NonZeroU64,
        view: AgentPackView,
    },
}

impl From<OptionalMemory> for AgentPackOptionalMemory {
    fn from(value: OptionalMemory) -> Self {
        match value {
            OptionalMemory::None => Self::None,
            OptionalMemory::Budget { tokens, view } => Self::Budget {
                tokens,
                view: view.into(),
            },
        }
    }
}

impl From<AgentPackOptionalMemory> for OptionalMemory {
    fn from(value: AgentPackOptionalMemory) -> Self {
        match value {
            AgentPackOptionalMemory::None => Self::None,
            AgentPackOptionalMemory::Budget { tokens, view } => Self::Budget {
                tokens,
                view: view.into(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackOptionalMemoryProfile {
    pub default: AgentPackOptionalMemory,
    pub families: BTreeMap<String, AgentPackOptionalMemory>,
}

impl From<&OptionalMemoryProfile> for AgentPackOptionalMemoryProfile {
    fn from(value: &OptionalMemoryProfile) -> Self {
        Self {
            default: value.default.into(),
            families: value
                .families
                .iter()
                .map(|(family, memory)| (family.clone(), (*memory).into()))
                .collect(),
        }
    }
}

impl From<AgentPackOptionalMemoryProfile> for OptionalMemoryProfile {
    fn from(value: AgentPackOptionalMemoryProfile) -> Self {
        Self {
            default: value.default.into(),
            families: value
                .families
                .into_iter()
                .map(|(family, memory)| (family, memory.into()))
                .collect(),
        }
    }
}

/// The agent's context-window memory profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackMemoryProfile {
    pub window_token_budget: u64,
    pub budget_split: Option<AgentPackBudgetSplit>,
    /// A compaction backend key the destination resolves in its own registry.
    pub compaction_backend: String,
    pub compaction: AgentPackCompaction,
    pub hot_steps: Option<u64>,
    pub output_decay: Option<AgentPackOutputDecay>,
    pub verbatim_pins: Vec<String>,
    pub optional_memory: Option<AgentPackOptionalMemoryProfile>,
}

impl From<&MemoryProfile> for AgentPackMemoryProfile {
    fn from(value: &MemoryProfile) -> Self {
        Self {
            window_token_budget: value.window_token_budget,
            budget_split: value.budget_split.map(Into::into),
            compaction_backend: value.compaction_backend.0.clone(),
            compaction: value.compaction.into(),
            hot_steps: value.hot_steps,
            output_decay: value.output_decay.map(Into::into),
            verbatim_pins: value.verbatim_pins.clone(),
            optional_memory: value.optional_memory.as_ref().map(Into::into),
        }
    }
}

impl From<AgentPackMemoryProfile> for MemoryProfile {
    fn from(value: AgentPackMemoryProfile) -> Self {
        Self {
            window_token_budget: value.window_token_budget,
            budget_split: value.budget_split.map(Into::into),
            compaction_backend: ModelTierRef(value.compaction_backend),
            compaction: value.compaction.into(),
            hot_steps: value.hot_steps,
            output_decay: value.output_decay.map(Into::into),
            verbatim_pins: value.verbatim_pins,
            optional_memory: value.optional_memory.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackDreaming {
    Own,
    Inherit,
    Off,
}

mirror!(AgentPackDreaming <=> DreamingMode { Own, Inherit, Off });

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPackWakeCadence {
    Companion { every_turns: Option<u64> },
    Leader { every_turns: Option<u64> },
    Worker,
}

impl From<AgentWakeCadence> for AgentPackWakeCadence {
    fn from(value: AgentWakeCadence) -> Self {
        match value {
            AgentWakeCadence::Companion { every_turns } => Self::Companion { every_turns },
            AgentWakeCadence::Leader { every_turns } => Self::Leader { every_turns },
            AgentWakeCadence::Worker => Self::Worker,
        }
    }
}

impl From<AgentPackWakeCadence> for AgentWakeCadence {
    fn from(value: AgentPackWakeCadence) -> Self {
        match value {
            AgentPackWakeCadence::Companion { every_turns } => Self::Companion { every_turns },
            AgentPackWakeCadence::Leader { every_turns } => Self::Leader { every_turns },
            AgentPackWakeCadence::Worker => Self::Worker,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackRefusalLevel {
    None,
    Voice,
    Veto,
    Full,
}

mirror!(AgentPackRefusalLevel <=> RefusalLevel { None, Voice, Veto, Full });

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackRefusal {
    pub bond: Option<AgentPackRefusalLevel>,
    pub logistics: Option<AgentPackRefusalLevel>,
}

impl From<RefusalDial> for AgentPackRefusal {
    fn from(value: RefusalDial) -> Self {
        Self {
            bond: value.bond.map(Into::into),
            logistics: value.logistics.map(Into::into),
        }
    }
}

impl From<AgentPackRefusal> for RefusalDial {
    fn from(value: AgentPackRefusal) -> Self {
        Self {
            bond: value.bond.map(Into::into),
            logistics: value.logistics.map(Into::into),
        }
    }
}

/// The configuration the agent asks for. Every field is a request the
/// destination meets against its own grants; none confers authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackPolicy {
    pub scope: AgentPackScope,
    pub ceiling: AgentPackCeiling,
    /// Connector names; the destination resolves its own.
    pub connectors: Vec<String>,
    pub code_mode_mcps: Vec<AgentPackMcp>,
    pub model_tier: Option<String>,
    pub memory_profile: Option<AgentPackMemoryProfile>,
    pub dreaming: Option<AgentPackDreaming>,
    pub dreaming_model: Option<String>,
    pub wake_cadence: Option<AgentPackWakeCadence>,
    pub refusal: Option<AgentPackRefusal>,
}

/// One `skills.json` row: a skill dependency pinned by its content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackSkillRef {
    pub skill_id: String,
    pub version: String,
    pub min_version: Option<String>,
    /// `canonical_skill_tree_hash` over the skill's files, lowercase hex.
    pub content_hash: String,
}

/// One skill the agent depends on, with its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPackSkill {
    pub skill_id: String,
    pub version: String,
    /// The dependency's floor, as the definition names it.
    pub min_version: Option<String>,
    pub content_hash: String,
    /// The skill's files, path-sorted, relative to its folder.
    pub files: Vec<HubFile>,
}

impl AgentPackSkill {
    /// A skill from its files; the content hash is computed here.
    pub fn new(
        skill_id: impl Into<String>,
        version: impl Into<String>,
        min_version: Option<String>,
        mut files: Vec<HubFile>,
    ) -> Result<Self> {
        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let content_hash = tree_hash(&files)?;
        let skill = Self {
            skill_id: skill_id.into(),
            version: version.into(),
            min_version,
            content_hash,
            files,
        };
        skill.validate()?;
        Ok(skill)
    }

    /// The skill `dependency` names, from its stored package.
    pub fn from_package(dependency: &SkillDependency, package: &HubPackage) -> Result<Self> {
        if package.record.skill_id != dependency.skill_id {
            return Err(invalid("a skill package does not match its dependency"));
        }
        let hash = package.content_hash()?;
        if package
            .record
            .content_hash
            .is_some_and(|stored| stored != hash)
        {
            return Err(invalid("a skill package does not match its stored hash"));
        }
        Self::new(
            dependency.skill_id.clone(),
            package.record.version.clone(),
            dependency.min_version.clone(),
            package.export_files()?,
        )
    }

    /// Its `skills.json` row.
    #[must_use]
    pub fn reference(&self) -> AgentPackSkillRef {
        AgentPackSkillRef {
            skill_id: self.skill_id.clone(),
            version: self.version.clone(),
            min_version: self.min_version.clone(),
            content_hash: self.content_hash.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.skill_id.trim().is_empty()
            || self.version.trim().is_empty()
            || self
                .min_version
                .as_deref()
                .is_some_and(|v| v.trim().is_empty())
        {
            return Err(invalid("a skill needs an id and a version"));
        }
        if tree_hash(&self.files)? != self.content_hash {
            return Err(invalid("a skill's files do not match its content hash"));
        }
        Ok(())
    }
}

/// One selected piece of knowledge about the agent, as text. The destination
/// mints it as a local claim with this agent as the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackKnowledge {
    pub predicate: String,
    pub text: String,
}

/// `policy.md`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFacet {
    schema: String,
    display_name: Option<String>,
    policy: AgentPackPolicy,
    born_with: BornWith,
}

/// The AgentPack as it travels.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentPackTravelProjection {
    /// The definition's `agent_id`.
    pub name: String,
    pub description: String,
    pub version: String,
    /// The pack's own instructions: they always travel.
    pub instructions: Option<String>,
    pub display_name: Option<String>,
    pub policy: AgentPackPolicy,
    /// One per skill dependency, in the definition's order; bodies always travel.
    pub skills: Vec<AgentPackSkill>,
    pub knowledge: Vec<AgentPackKnowledge>,
    /// The born-with text the sharer let travel.
    pub born_with: BornWith,
}

impl AgentPackTravelProjection {
    /// Project `def` for another party. `world_name` names the world a World
    /// scope runs in (its id stays home), `skills` carries one body per
    /// dependency in order, and `born_with` is the sharer's projected choice.
    pub fn from_definition(
        def: &AgentDefinition,
        world_name: Option<&str>,
        skills: Vec<AgentPackSkill>,
        knowledge: Vec<AgentPackKnowledge>,
        born_with: BornWith,
    ) -> Result<Self> {
        let scope = match &def.scope {
            AgentScope::All => AgentPackScope::All,
            AgentScope::Base => AgentPackScope::Base,
            AgentScope::World(_) => AgentPackScope::World {
                name: world_name
                    .filter(|name| !name.trim().is_empty())
                    .ok_or_else(|| invalid("a world scope travels by the world's name"))?
                    .to_owned(),
            },
        };
        if skills.len() != def.skills.len()
            || skills.iter().zip(&def.skills).any(|(skill, dependency)| {
                skill.skill_id != dependency.skill_id || skill.min_version != dependency.min_version
            })
        {
            return Err(invalid(
                "every skill dependency travels with its body, in order",
            ));
        }
        let projection = Self {
            name: def.agent_id.clone(),
            description: def.desc.clone(),
            version: def.version.clone(),
            instructions: def.instructions.clone().filter(|text| !text.is_empty()),
            display_name: def.display_name.clone(),
            policy: AgentPackPolicy {
                scope,
                ceiling: def.ceiling.into(),
                connectors: def.connectors.clone(),
                code_mode_mcps: def.code_mode_mcps.iter().map(Into::into).collect(),
                model_tier: def.model_tier.as_ref().map(|tier| tier.0.clone()),
                memory_profile: def.memory_profile.as_ref().map(Into::into),
                dreaming: def.dreaming.map(Into::into),
                dreaming_model: def.dreaming_model.as_ref().map(|tier| tier.0.clone()),
                wake_cadence: def.wake_cadence.map(Into::into),
                refusal: def.refusal.map(Into::into),
            },
            skills,
            knowledge,
            born_with,
        };
        projection.validate()?;
        Ok(projection)
    }

    /// Refuses a pack the native rules would refuse, a nameless world, a skill
    /// whose files miss its hash, a repeated skill and empty knowledge.
    pub fn validate(&self) -> Result<()> {
        if let AgentPackScope::World { name } = &self.policy.scope
            && name.trim().is_empty()
        {
            return Err(invalid("a world scope needs the world's name"));
        }
        let mut ids = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        for skill in &self.skills {
            skill.validate()?;
            if !ids.insert(skill.skill_id.as_str()) || !hashes.insert(skill.content_hash.as_str()) {
                return Err(invalid("a skill travels once"));
            }
        }
        if self
            .knowledge
            .iter()
            .any(|row| row.predicate.trim().is_empty() || row.text.trim().is_empty())
        {
            return Err(invalid("knowledge needs a predicate and text"));
        }
        encode_agent_definition(&self.native(AgentScope::Base))?;
        Ok(())
    }

    /// The definition a destination admits: inert like any imported agent
    /// (disabled, proposed, ceiling at Proposed until its owner raises it),
    /// with no fork parent, provenance of its own or logical id. `world` is
    /// the local world the destination bound the scope's name to.
    pub fn to_definition(&self, world: Option<EntityId>) -> Result<AgentDefinition> {
        let scope = match (&self.policy.scope, world) {
            (AgentPackScope::All, _) => AgentScope::All,
            (AgentPackScope::Base, _) => AgentScope::Base,
            (AgentPackScope::World { .. }, Some(world)) => AgentScope::World(world),
            (AgentPackScope::World { .. }, None) => {
                return Err(invalid("a world scope needs a local world"));
            }
        };
        let def = self.native(scope);
        encode_agent_definition(&def)?;
        Ok(def)
    }

    fn native(&self, scope: AgentScope) -> AgentDefinition {
        let policy = &self.policy;
        let mut def = AgentDefinition::new(
            self.name.clone(),
            self.description.clone(),
            self.version.clone(),
            self.instructions.clone(),
            self.skills
                .iter()
                .map(|skill| SkillDependency {
                    skill_id: skill.skill_id.clone(),
                    min_version: skill.min_version.clone(),
                })
                .collect(),
            policy.connectors.clone(),
            policy
                .code_mode_mcps
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
            policy.model_tier.clone().map(ModelTierRef),
            scope,
            AgentCeiling::Proposed,
            None,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
            ClaimSource::Imported,
            0.5,
            false,
            true,
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from(PROVENANCE_SOURCE),
            )]),
            None,
            false,
            self.display_name.clone(),
        )
        .with_memory_profile(policy.memory_profile.clone().map(Into::into))
        .with_dreaming(
            policy.dreaming.map(Into::into),
            policy.dreaming_model.clone().map(ModelTierRef),
        )
        .with_refusal(policy.refusal.map(Into::into));
        def.wake_cadence = policy.wake_cadence.map(Into::into);
        def
    }

    /// The pack's folder, path-sorted.
    pub fn files(&self) -> Result<Vec<HubFile>> {
        self.validate()?;
        let policy = PolicyFacet {
            schema: AGENT_PACK_TRAVEL_SCHEMA.to_owned(),
            display_name: self.display_name.clone(),
            policy: self.policy.clone(),
            born_with: self.born_with.clone(),
        };
        let skills = self
            .skills
            .iter()
            .map(AgentPackSkill::reference)
            .collect::<Vec<_>>();
        let mut files = vec![
            HubFile::new(
                PACK_MANIFEST,
                manifest(&self.name, &self.description, &self.version)?,
            ),
            HubFile::new(IDENTITY, self.instructions.as_deref().unwrap_or("")),
            HubFile::new(POLICY, json(&policy)?),
            HubFile::new(SKILLS, json(&skills)?),
            HubFile::new(KNOWLEDGE, json(&self.knowledge)?),
        ];
        for skill in &self.skills {
            for file in &skill.files {
                files.push(HubFile::new(
                    format!("{SKILLS_DIR}{}/{}", skill.content_hash, file.path),
                    file.content.clone(),
                ));
            }
        }
        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        tree_hash(&files)?;
        Ok(files)
    }

    /// Reads a folder [`Self::files`] wrote. Refuses a missing or unknown file,
    /// another schema, a skill whose files miss its hash, a repeated skill and
    /// a folder not in the canonical form `files` writes.
    pub fn from_files(files: &[HubFile]) -> Result<Self> {
        tree_hash(files)?;
        let mut by_path = files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice()))
            .collect::<BTreeMap<_, _>>();
        let manifest_text = utf8(take(&mut by_path, PACK_MANIFEST)?)?;
        let instructions = utf8(take(&mut by_path, IDENTITY)?)?;
        let policy: PolicyFacet = parse(take(&mut by_path, POLICY)?)?;
        if policy.schema != AGENT_PACK_TRAVEL_SCHEMA {
            return Err(invalid("policy.md names another schema"));
        }
        let references: Vec<AgentPackSkillRef> = parse(take(&mut by_path, SKILLS)?)?;
        let knowledge: Vec<AgentPackKnowledge> = parse(take(&mut by_path, KNOWLEDGE)?)?;
        let mut skills = Vec::with_capacity(references.len());
        for reference in references {
            let folder = format!("{SKILLS_DIR}{}/", reference.content_hash);
            let paths = by_path
                .keys()
                .filter(|path| path.starts_with(&folder))
                .copied()
                .collect::<Vec<_>>();
            let mut skill_files = Vec::with_capacity(paths.len());
            for path in paths {
                let content = take(&mut by_path, path)?;
                skill_files.push(HubFile::new(&path[folder.len()..], content));
            }
            if skill_files.is_empty() {
                return Err(invalid("a skill travels with its files"));
            }
            let skill = AgentPackSkill::new(
                reference.skill_id,
                reference.version,
                reference.min_version,
                skill_files,
            )?;
            if skill.content_hash != reference.content_hash {
                return Err(invalid("a skill's files do not match its content hash"));
            }
            skills.push(skill);
        }
        if !by_path.is_empty() {
            return Err(invalid("the folder holds a file the pack does not name"));
        }
        let (name, description, version) = manifest_scalars(manifest_text)?;
        let projection = Self {
            name,
            description,
            version,
            instructions: (!instructions.is_empty()).then(|| instructions.to_owned()),
            display_name: policy.display_name,
            policy: policy.policy,
            skills,
            knowledge,
            born_with: policy.born_with,
        };
        let mut sorted = files.to_vec();
        sorted.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        if projection.files()? != sorted {
            return Err(invalid("the folder is not in canonical form"));
        }
        Ok(projection)
    }
}

/// `PACK.md`, in the native facets' frontmatter form.
fn manifest(name: &str, description: &str, version: &str) -> Result<String> {
    let facets = BTreeMap::from([
        ("identity", IDENTITY),
        ("policy", POLICY),
        ("skills", SKILLS),
        ("knowledge", KNOWLEDGE),
    ]);
    let scalar = |text: &str| serde_json::to_string(text).map_err(|_| invalid("PACK.md"));
    Ok(format!(
        "---\nname: {}\ndescription: {}\nversion: {}\nkind: agent\nfacets: {}\n---\n",
        scalar(name)?,
        scalar(description)?,
        scalar(version)?,
        serde_json::to_string(&facets).map_err(|_| invalid("PACK.md"))?,
    ))
}

/// Name, description and version from `PACK.md`; the rest of it is checked
/// by writing the folder again.
fn manifest_scalars(text: &str) -> Result<(String, String, String)> {
    let refused = || invalid("PACK.md frontmatter is not canonical");
    let mut lines = text.strip_prefix("---\n").ok_or_else(refused)?.lines();
    let mut scalar = |key: &str| -> Result<String> {
        let value = lines
            .next()
            .and_then(|line| line.strip_prefix(key))
            .and_then(|line| line.strip_prefix(": "))
            .ok_or_else(refused)?;
        serde_json::from_str(value).map_err(|_| refused())
    };
    Ok((scalar("name")?, scalar("description")?, scalar("version")?))
}

fn take<'a>(by_path: &mut BTreeMap<&str, &'a [u8]>, path: &str) -> Result<&'a [u8]> {
    by_path
        .remove(path)
        .ok_or_else(|| invalid("the folder is missing a pack file"))
}

fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| invalid("a pack text file is not UTF-8"))
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|error| {
        Error::InvalidConfig(format!(
            "agent pack travel: a facet does not parse: {error}"
        ))
    })
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid("a facet does not encode"))
}

fn tree_hash(files: &[HubFile]) -> Result<String> {
    Ok(canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?
    .to_hex())
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("agent pack travel: {reason}"))
}
