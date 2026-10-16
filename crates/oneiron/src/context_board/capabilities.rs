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

    /// [`Self::project`] with the learning view on each found row: the
    /// skill's reliability posterior mean as `rel=` and, for a caller with an
    /// entity principal, its newest fit estimate for that actor as `fit=`,
    /// both to two places. A value the vault does not hold adds no token.
    pub fn project_with_learning(
        hits: &[CapabilityHit],
        session: &SessionReadSet,
        vault: &crate::Vault,
        actor: Option<EntityId>,
    ) -> crate::Result<Self> {
        let mut section = Self::project(hits, session);
        let skills = hits
            .iter()
            .filter(|hit| hit.entity_type == ENTITY_TYPE_SKILL);
        for (row, hit) in section.found.iter_mut().zip(skills) {
            if let Some(posterior) =
                crate::skill_reliability::skill_reliability_posterior(vault, &hit.id)?
            {
                row.push_str(&format!(" rel={:.2}", posterior.mean()));
            }
            if let Some(actor) = actor
                && let Some(fit) = crate::actor_claims::skill_fit_for(vault, &actor, &hit.id)?
            {
                row.push_str(&format!(" fit={fit:.2}"));
            }
        }
        Ok(section)
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
