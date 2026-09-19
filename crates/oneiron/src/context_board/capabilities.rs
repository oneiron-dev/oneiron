//! Turn-local capability hits and session-long loaded skill bodies.

use super::{
    AgentLane, AgentRow, AgentsSection, BoardFrameError, BoardSection, SectionPolicy,
    SessionReadSet, ShedRank, one_line_token,
};
use crate::{
    EntityId,
    registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_SKILL},
};

/// A hit from the capability channel. Other entity types are ignored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityHit {
    #[serde(
        serialize_with = "serialize_capability_id",
        deserialize_with = "deserialize_capability_id"
    )]
    pub id: EntityId,
    pub entity_type: u8,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillsSection {
    pub found: Vec<String>,
    pub loaded: String,
}

impl SkillsSection {
    pub fn project(hits: &[CapabilityHit], session: &SessionReadSet) -> Self {
        let found = hits
            .iter()
            .filter(|hit| hit.entity_type == ENTITY_TYPE_SKILL)
            .map(|hit| format!("{} found {}", hit.id.to_hex(), one_line_token(&hit.label)))
            .collect();
        let loaded: Vec<_> = session
            .loaded_skills()
            .map(|(id, version)| format!("{}@{}", one_line_token(id), one_line_token(version)))
            .collect();
        Self {
            found,
            loaded: format!("loaded: {}", loaded.join(",")),
        }
    }

    pub fn board_section(&self) -> Result<BoardSection, BoardFrameError> {
        BoardSection::new(
            "SKILLS",
            vec![self.loaded.clone()],
            self.found.clone(),
            Vec::new(),
            SectionPolicy {
                pinned: false,
                shed_rank: Some(ShedRank::CapabilityDiscovery),
            },
        )
    }
}

impl AgentsSection {
    /// Replace this turn's candidate lane without changing child/peer presence.
    pub fn with_candidates(mut self, hits: &[CapabilityHit]) -> Self {
        self.rows.retain(|row| row.lane != AgentLane::Cand);
        self.rows.extend(
            hits.iter()
                .filter(|hit| hit.entity_type == ENTITY_TYPE_AGENT_DEF)
                .map(|hit| AgentRow {
                    id: hit.id.to_hex(),
                    lane: AgentLane::Cand,
                    line: format!("{} cand {}", hit.id.to_hex(), one_line_token(&hit.label)),
                    harness_label: None,
                }),
        );
        self
    }
}

fn serialize_capability_id<S: serde::Serializer>(
    id: &EntityId,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
}

fn deserialize_capability_id<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<EntityId, D::Error> {
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    EntityId::from_hex(&value).map_err(serde::de::Error::custom)
}
