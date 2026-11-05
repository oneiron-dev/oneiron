//! Core half of `store::agent_definition_codec::keys`: its store-layer items live in `oneiron_store::agent_definition_codec::keys` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::agent_definition_codec::keys::*;

use crate::store::agent_record::{
    AGENT_DEF_BODY_KEYS, AGENT_MODEL_KEYS, CONTEXT_BUDGET_SPLIT_KEYS, MCP_REF_KEYS,
    MEMORY_PROFILE_KEYS,
};
use oneiron_store::write_envelope::skill_record::SKILL_DEPENDENCY_KEYS;

pub(crate) const KEY_AGENT_ID: &str = AGENT_DEF_BODY_KEYS[0];

pub(crate) const KEY_DESC: &str = AGENT_DEF_BODY_KEYS[1];

pub(crate) const KEY_VERSION: &str = AGENT_DEF_BODY_KEYS[2];

pub(crate) const KEY_INSTRUCTIONS: &str = AGENT_DEF_BODY_KEYS[3];

pub(crate) const KEY_SKILLS: &str = AGENT_DEF_BODY_KEYS[4];

pub(crate) const KEY_CONNECTORS: &str = AGENT_DEF_BODY_KEYS[5];

pub(crate) const KEY_CODE_MODE_MCPS: &str = AGENT_DEF_BODY_KEYS[6];

pub(crate) const KEY_MODEL_TIER: &str = AGENT_DEF_BODY_KEYS[7];

pub(crate) const KEY_SCOPE: &str = AGENT_DEF_BODY_KEYS[8];

pub(crate) const KEY_WORLD: &str = AGENT_DEF_BODY_KEYS[9];

pub(crate) const KEY_CEILING: &str = AGENT_DEF_BODY_KEYS[10];

pub(crate) const KEY_FORKED_FROM: &str = AGENT_DEF_BODY_KEYS[11];

pub(crate) const KEY_APPROVAL_STATUS: &str = AGENT_DEF_BODY_KEYS[12];

pub(crate) const KEY_LIFECYCLE_STATUS: &str = AGENT_DEF_BODY_KEYS[13];

pub(crate) const KEY_SOURCE: &str = AGENT_DEF_BODY_KEYS[14];

pub(crate) const KEY_CONFIDENCE: &str = AGENT_DEF_BODY_KEYS[15];

pub(crate) const KEY_GENERATED: &str = AGENT_DEF_BODY_KEYS[16];

pub(crate) const KEY_HUMAN_AUTHORED: &str = AGENT_DEF_BODY_KEYS[17];

pub(crate) const KEY_PROVENANCE: &str = AGENT_DEF_BODY_KEYS[18];

pub(crate) const KEY_LOGICAL_ID: &str = AGENT_DEF_BODY_KEYS[19];

pub(crate) const KEY_ENABLED: &str = AGENT_DEF_BODY_KEYS[20];

pub(crate) const KEY_DISPLAY_NAME: &str = AGENT_DEF_BODY_KEYS[21];

pub(crate) const KEY_MEMORY_PROFILE: &str = AGENT_DEF_BODY_KEYS[22];

pub(crate) const KEY_DREAMING: &str = AGENT_DEF_BODY_KEYS[23];

pub(crate) const KEY_DREAMING_MODEL: &str = AGENT_DEF_BODY_KEYS[24];

pub(crate) const KEY_WAKE_CADENCE: &str = AGENT_DEF_BODY_KEYS[25];

pub(crate) const KEY_REFUSAL: &str = AGENT_DEF_BODY_KEYS[26];

pub(crate) const KEY_MODELS: &str = AGENT_DEF_BODY_KEYS[27];

pub(crate) const KEY_COMPACTION_MODEL: &str = AGENT_DEF_BODY_KEYS[28];

pub(crate) const KEY_MODEL_REF: &str = AGENT_MODEL_KEYS[0];

pub(crate) const KEY_MODEL_WHEN: &str = AGENT_MODEL_KEYS[1];

pub(crate) const KEY_PROFILE_WINDOW_TOKEN_BUDGET: &str = MEMORY_PROFILE_KEYS[0];

pub(crate) const KEY_PROFILE_BUDGET_SPLIT: &str = MEMORY_PROFILE_KEYS[1];

pub(crate) const KEY_PROFILE_COMPACTION_BACKEND: &str = MEMORY_PROFILE_KEYS[2];

pub(crate) const KEY_PROFILE_COMPACTION: &str = MEMORY_PROFILE_KEYS[3];

pub(crate) const KEY_PROFILE_HOT_STEPS: &str = MEMORY_PROFILE_KEYS[4];

pub(crate) const KEY_PROFILE_OUTPUT_DECAY: &str = MEMORY_PROFILE_KEYS[5];

pub(crate) const KEY_PROFILE_VERBATIM_PINS: &str = MEMORY_PROFILE_KEYS[6];

pub(crate) const KEY_PROFILE_OPTIONAL_MEMORY: &str = MEMORY_PROFILE_KEYS[7];

pub(crate) const KEY_SPLIT_CLAIMS: &str = CONTEXT_BUDGET_SPLIT_KEYS[0];

pub(crate) const KEY_SPLIT_TURNS: &str = CONTEXT_BUDGET_SPLIT_KEYS[1];

pub(crate) const KEY_SPLIT_SUMMARIES: &str = CONTEXT_BUDGET_SPLIT_KEYS[2];

pub(crate) const KEY_SPLIT_OTHER: &str = CONTEXT_BUDGET_SPLIT_KEYS[3];

pub(crate) const KEY_MCP_KEY: &str = MCP_REF_KEYS[0];

pub(crate) const KEY_MCP_MIN_VERSION: &str = MCP_REF_KEYS[1];
