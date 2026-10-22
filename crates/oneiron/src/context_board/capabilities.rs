//! Turn-local capability hits and session-long loaded skill bodies.

use super::{
    BoardFrameError, BoardSection, SectionPolicy, SessionReadSet, ShedRank, one_line_token,
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
    /// Skills and agent definitions the capability channel found, each one
    /// `found` row led by its vault short handle (`sk<n>`, `ag<n>`) (FIX
    /// 7984); a definition's row says `agent` (PEOPLE, ARCH-0067: the AGENTS
    /// section is gone, and its candidates found here). A hit the vault holds
    /// no handle for keeps its row under its hex id.
    pub fn project(
        hits: &[CapabilityHit],
        session: &SessionReadSet,
        vault: &crate::Vault,
    ) -> crate::Result<Self> {
        let found = found_rows(hits, vault)?
            .into_iter()
            .map(|(_, row)| row)
            .collect();
        Ok(Self::with_found(found, session))
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
        let mut found = Vec::new();
        for (hit, mut row) in found_rows(hits, vault)? {
            if hit.entity_type == ENTITY_TYPE_SKILL {
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
            found.push(row);
        }
        Ok(Self::with_found(found, session))
    }

    /// The section over its `found` rows, with the session's loaded line.
    fn with_found(found: Vec<String>, session: &SessionReadSet) -> Self {
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

/// The hits SKILLS lists as found, in hit order: skills and agent
/// definitions.
fn found_hits(hits: &[CapabilityHit]) -> impl Iterator<Item = &CapabilityHit> {
    hits.iter()
        .filter(|hit| matches!(hit.entity_type, ENTITY_TYPE_SKILL | ENTITY_TYPE_AGENT_DEF))
}

/// Each found hit with its `found` row, led by the short handle the vault's
/// short-id mapping holds for its id, else by its hex id.
fn found_rows<'a>(
    hits: &'a [CapabilityHit],
    vault: &crate::Vault,
) -> crate::Result<Vec<(&'a CapabilityHit, String)>> {
    let txn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for hit in found_hits(hits) {
        let handle =
            crate::ports::ShortIdStoreRead::port_short_id_reference(&vault.store, &txn, &hit.id)?
                .map_or_else(|| hit.id.to_hex(), |(handle, _)| handle);
        let kind = if hit.entity_type == ENTITY_TYPE_AGENT_DEF {
            "agent "
        } else {
            ""
        };
        rows.push((
            hit,
            format!("{handle} found {kind}{}", one_line_token(&hit.label)),
        ));
    }
    Ok(rows)
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
