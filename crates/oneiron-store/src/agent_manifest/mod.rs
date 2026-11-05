//! The embedded seeded-roster manifest (OF-334 / ONE-1890): its parsed form,
//! the one cached parse, and the lookups the AGENT_DEF codec and put path
//! read it through (the legacy `sys.*` row map and the `sys.*` logical-id
//! reservation). Seeding and reconciliation stay in `agent_def`.

use std::collections::HashSet;

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// Reserved logical-id prefix for seeded system rows. Enforced at the
/// AGENT_DEF put-decode chokepoint (`batch.rs::apply_put`), which is the only
/// place that holds both the body and the row id it is being stored at.
pub const SYSTEM_LOGICAL_ID_PREFIX: &str = "sys.";

/// Bytes of a `logical_id` past which a put asks; any length is kept.
pub const AGENT_LOGICAL_ID_MAX_BYTES: usize = 256;

/// Bytes of the runtime-editable `display_name` past which a put asks.
pub const AGENT_DISPLAY_NAME_MAX_BYTES: usize = 256;

/// The canonical seeded system-agent roster (OF-334 / ONE-1890): data, not a
/// compiled enum. Every baseline row is an ordinary byte-17 `AGENT_DEF` entity
/// with a pinned row id, a pinned actor id equal to it, and a stable `sys.*`
/// logical id. ONE-1709 appends `sys.team_lead` to this same file.
pub const SYSTEM_AGENT_DEFINITIONS_V1_JSON: &str =
    include_str!("data/system_agent_definitions.v1.json");

/// A 32-character lower-case hex `EntityId`, the manifest's only id spelling.
#[derive(Debug)]
pub struct HexEntityId(pub EntityId);

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

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSkillDependency {
    pub skill_id: String,
    pub min_version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestMcpRef {
    pub key: String,
    pub min_version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ManifestScope {
    All,
    Base,
    World { world: HexEntityId },
}

/// A text field is non-blank. Its length refuses nothing (rule 5, FIX
/// 10542): `_old_max_bytes`, the length it once refused past, is now the
/// default a definition's put observes it against
/// (`super::byte_observation`).
pub fn validate_text_field(text: &str, _old_max_bytes: usize, context: &'static str) -> Result<()> {
    if text.trim().is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(context)));
    }
    Ok(())
}
