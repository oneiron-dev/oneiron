//! The bytes one definition's put reads (FIX 10542). Every text field is
//! kept, however long (rule 5): past its row (the length it once refused
//! past) a field family raises one check per family and definition id, its
//! longest entry counted, and the put goes on. A birth source's encoded
//! bytes are counted the same way at its carrier's put. The pure codecs
//! count nothing: these run where a put already holds its transaction.

use crate::entity_id::EntityId;
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::Store;

use super::types::{
    AGENT_DESC_MAX_BYTES, AGENT_DISPLAY_NAME_MAX_BYTES, AGENT_ID_MAX_BYTES,
    AGENT_INSTRUCTIONS_MAX_BYTES, AGENT_LOGICAL_ID_MAX_BYTES, AGENT_MODEL_TIER_MAX_BYTES,
    AGENT_REF_KEY_MAX_BYTES, AGENT_VERSION_MAX_BYTES, AgentDefinition,
    MAX_MEMORY_PROFILE_VERBATIM_PIN_BYTES,
};

/// A birth source's encoded bytes past which its put asks when the row
/// does not read: the size it once refused past.
const AGENT_BIRTH_SOURCE_CHECK_BYTES: usize = 32 * 1024 * 1024;

/// Counts the longest entry of each of `def`'s text field families against
/// its row, scoped to the family and `id`. Evidence only: it never refuses
/// and never fails the put that reads it; a row that does not read asks at
/// the old length. An absent or empty family reads no row.
pub(super) fn observe_definition_bytes(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    def: &AgentDefinition,
) {
    use EngineScan::{
        AgentDefinitionDescriptionBytes as Description, AgentDefinitionIdentityBytes as Identity,
        AgentDefinitionInstructionBytes as Instruction, AgentDefinitionReferenceBytes as Reference,
        AgentDefinitionVerbatimPinBytes as VerbatimPin, AgentDefinitionVersionBytes as Version,
    };
    let profile = def.memory_profile.as_ref();
    let text = |text: Option<&str>| text.map_or(0, str::len);
    let families: [(EngineScan, &[u8], usize, usize); 19] = [
        (Identity, b"agentId", AGENT_ID_MAX_BYTES, def.agent_id.len()),
        (
            Identity,
            b"logicalId",
            AGENT_LOGICAL_ID_MAX_BYTES,
            text(def.logical_id.as_deref()),
        ),
        (
            Identity,
            b"displayName",
            AGENT_DISPLAY_NAME_MAX_BYTES,
            text(def.display_name.as_deref()),
        ),
        (Description, b"desc", AGENT_DESC_MAX_BYTES, def.desc.len()),
        (
            Description,
            b"models.when",
            AGENT_DESC_MAX_BYTES,
            longest(def.models.iter().map(|model| model.when.len())),
        ),
        (
            Version,
            b"version",
            AGENT_VERSION_MAX_BYTES,
            def.version.len(),
        ),
        (
            Version,
            b"skills.minVersion",
            AGENT_VERSION_MAX_BYTES,
            longest(
                def.skills
                    .iter()
                    .map(|skill| text(skill.min_version.as_deref())),
            ),
        ),
        (
            Version,
            b"codeModeMcps.minVersion",
            AGENT_VERSION_MAX_BYTES,
            longest(
                def.code_mode_mcps
                    .iter()
                    .map(|mcp| text(mcp.min_version.as_deref())),
            ),
        ),
        (
            Instruction,
            b"instructions",
            AGENT_INSTRUCTIONS_MAX_BYTES,
            text(def.instructions.as_deref()),
        ),
        (
            Reference,
            b"modelTier",
            AGENT_MODEL_TIER_MAX_BYTES,
            def.model_tier
                .as_ref()
                .map_or(0, |tier| tier.as_str().len()),
        ),
        (
            Reference,
            b"dreamingModel",
            AGENT_MODEL_TIER_MAX_BYTES,
            def.dreaming_model
                .as_ref()
                .map_or(0, |model| model.as_str().len()),
        ),
        (
            Reference,
            b"compaction_model",
            AGENT_MODEL_TIER_MAX_BYTES,
            def.compaction_model
                .as_ref()
                .map_or(0, |model| model.as_str().len()),
        ),
        (
            Reference,
            b"models.model_ref",
            AGENT_MODEL_TIER_MAX_BYTES,
            longest(
                def.models
                    .iter()
                    .map(|model| model.model_ref.as_str().len()),
            ),
        ),
        (
            Reference,
            b"compaction_backend",
            AGENT_MODEL_TIER_MAX_BYTES,
            profile.map_or(0, |profile| profile.compaction_backend.as_str().len()),
        ),
        (
            Reference,
            b"skills.skillId",
            AGENT_REF_KEY_MAX_BYTES,
            longest(def.skills.iter().map(|skill| skill.skill_id.len())),
        ),
        (
            Reference,
            b"connectors",
            AGENT_REF_KEY_MAX_BYTES,
            longest(def.connectors.iter().map(String::len)),
        ),
        (
            Reference,
            b"codeModeMcps.key",
            AGENT_REF_KEY_MAX_BYTES,
            longest(def.code_mode_mcps.iter().map(|mcp| mcp.key.len())),
        ),
        (
            Reference,
            b"optional_memory.families",
            AGENT_REF_KEY_MAX_BYTES,
            longest(
                profile
                    .and_then(|profile| profile.optional_memory.as_ref())
                    .into_iter()
                    .flat_map(|optional| optional.families.keys())
                    .map(String::len),
            ),
        ),
        (
            VerbatimPin,
            b"verbatim_pins",
            MAX_MEMORY_PROFILE_VERBATIM_PIN_BYTES,
            longest(
                profile
                    .into_iter()
                    .flat_map(|profile| profile.verbatim_pins.iter())
                    .map(String::len),
            ),
        ),
    ];
    for (scan, family, old_bytes, bytes) in families {
        if bytes == 0 {
            continue;
        }
        let scope = [family, id.as_bytes()].concat();
        observe(store, txn, scan, &scope, old_bytes, bytes);
    }
}

/// Counts a birth source's encoded `bytes` at its carrier `id`'s put,
/// against its row. Evidence only, as [`observe_definition_bytes`].
pub(super) fn observe_birth_source_bytes(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    bytes: &[u8],
) {
    observe(
        store,
        txn,
        EngineScan::AgentBirthSourceBytes,
        id.as_bytes(),
        AGENT_BIRTH_SOURCE_CHECK_BYTES,
        bytes.len(),
    );
}

/// The longest of `lengths`, or 0 for none.
fn longest(lengths: impl Iterator<Item = usize>) -> usize {
    lengths.max().unwrap_or(0)
}

/// Counts `bytes` of `scan` for `scope`; a threshold row that does not read
/// asks at `old_bytes`.
fn observe(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scan: EngineScan,
    scope: &[u8],
    old_bytes: usize,
    bytes: usize,
) {
    let mut count = ScanCount::start(store, txn, scan, scope).unwrap_or_else(|_| {
        ScanCount::start_at(scan, scope, u64::try_from(old_bytes).unwrap_or(u64::MAX))
    });
    count.rows(bytes);
    count.defer(store);
}
