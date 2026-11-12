//! Engine-seed identities: the narrow import-equivalence sets and the row
//! census, recomputed from the embedded sources by one builder.

use std::collections::BTreeSet;

use super::embedded_owner_actor_id;
use crate::EntityId;
use crate::error::Result;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR, ENTITY_TYPE_FACET, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SKILL, ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
    ENTITY_TYPE_SKILL_HUB,
};

/// The live rows a seeded open writes before any person or agent writes:
/// the empty-vault join guard's census.
#[derive(Debug)]
pub(crate) struct EngineSeedCensus {
    /// Every seeded (entity type, id) row: policy, machines, owner and
    /// substrate, system agents with their model people, substrates and
    /// subject claims, bootstrap and pack skills with their content anchors,
    /// whole-pack sources, hub and descriptors.
    pub rows: BTreeSet<(u8, EntityId)>,
    /// Every seeded SKILL id, so a minted provenance claim is known by its
    /// subject and predicate.
    pub skills: BTreeSet<EntityId>,
    /// Every seeded content-anchor id, so a minted scan verdict is known by
    /// its subject and predicate.
    pub anchors: BTreeSet<EntityId>,
}

impl EngineSeedCensus {
    /// Whether `(entity_type, id)` is a seeded row. The AGENT_DEF manifest
    /// match is the caller's: an edited seeded definition keeps its id but
    /// is no longer the seed.
    pub(crate) fn contains(&self, entity_type: u8, id: &EntityId) -> bool {
        self.rows.contains(&(entity_type, *id))
    }
}

/// The narrow engine-seed identity sets import equivalence is allowed to
/// know: pack skills and their source carriers as rows, system-agent subject
/// claims and pack-carrier facets as edges. Owns the [`EngineSeedCensus`]
/// from the same enumeration, so equivalence and census never drift.
#[derive(Debug)]
pub(crate) struct EngineSeedIdentities {
    /// The nine pack SKILL ids (8 connector `setup` + weave `weave-report`)
    /// from `builtin_pack_seed_ids`.
    pub pack_skills: BTreeSet<EntityId>,
    /// Their per-SKILL source-carrier ASSET ids. A carrier exists only for
    /// a clean tree, so presence is always checked at use, never assumed.
    pub pack_carriers: BTreeSet<EntityId>,
    /// The 14 system-agent subject `ClaimOf` edges as (claim, subject): each
    /// agent's `person.substrate` claim over its model PERSON and its
    /// `actor.subject_ref` claim over the agent itself.
    pub subject_claim_edges: BTreeSet<(EntityId, EntityId)>,
    /// The pack-carrier `FacetOf` edges as (carrier, facet). The facet is
    /// the owner's `substrate` FACET, the vault default on a fresh vault.
    pub carrier_facet_edges: BTreeSet<(EntityId, EntityId)>,
    /// The row census, from the same enumeration.
    pub census: EngineSeedCensus,
}

impl EngineSeedIdentities {
    /// Recomputes every set from the embedded sources in one enumeration.
    /// No transaction: all ids derive from pinned domains and embedded bytes.
    pub(crate) fn load() -> Result<Self> {
        let mut rows: BTreeSet<(u8, EntityId)> = BTreeSet::new();
        let mut skills: BTreeSet<EntityId> = BTreeSet::new();
        let mut anchors: BTreeSet<EntityId> = BTreeSet::new();
        rows.insert((
            ENTITY_TYPE_POLICY_MANIFEST,
            crate::gate::default_policy_manifest_id()?,
        ));
        rows.insert((
            ENTITY_TYPE_MACHINE,
            crate::dreamer_runner::authority::dreamer_actor_id()?,
        ));
        rows.insert((
            ENTITY_TYPE_MACHINE,
            crate::dreamer_runner::authority::coach_actor_id()?,
        ));
        let owner = embedded_owner_actor_id()?;
        rows.insert((ENTITY_TYPE_PERSON, owner));
        let owner_substrate = crate::claim::substrate_facet_id(owner)?;
        rows.insert((ENTITY_TYPE_FACET, owner_substrate));
        let mut subject_claim_edges: BTreeSet<(EntityId, EntityId)> = BTreeSet::new();
        for agent in crate::agent_def::seeded_system_agent_ids()? {
            rows.insert((ENTITY_TYPE_AGENT_DEF, agent));
            let (person, substrate, anchor) = crate::context_board::seeded_agent_person_ids(agent)?;
            rows.insert((ENTITY_TYPE_PERSON, person));
            rows.insert((ENTITY_TYPE_FACET, crate::claim::substrate_facet_id(person)?));
            rows.insert((ENTITY_TYPE_CLAIM, substrate));
            rows.insert((ENTITY_TYPE_CLAIM, anchor));
            // The substrate fact names the model PERSON, the anchor fact
            // names the agent.
            subject_claim_edges.insert((substrate, person));
            subject_claim_edges.insert((anchor, agent));
        }
        for (id, hash) in crate::skill_hub::bootstrap_skill_ids_and_hashes()? {
            seed_skill(&mut rows, &mut skills, &mut anchors, id, hash)?;
        }
        let mut pack_skills: BTreeSet<EntityId> = BTreeSet::new();
        let mut pack_carriers: BTreeSet<EntityId> = BTreeSet::new();
        for (source, pack) in crate::skill_hub::pack_catalog::builtin_pack_seed_ids()? {
            rows.insert((ENTITY_TYPE_ASSET, source));
            for (id, hash) in pack {
                pack_carriers.insert(crate::store::skill_source_carrier::source_carrier_id(
                    &id, &hash,
                )?);
                seed_skill(&mut rows, &mut skills, &mut anchors, id, hash)?;
                pack_skills.insert(id);
            }
        }
        rows.insert((
            ENTITY_TYPE_SKILL_HUB,
            crate::skill_hub::default_skill_hub_id()?,
        ));
        for row in crate::comm::claim_class_descriptors() {
            rows.insert((
                ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR,
                crate::comm::claim_class_descriptor_id(row.predicate)?,
            ));
        }
        let carrier_facet_edges = pack_carriers
            .iter()
            .map(|carrier| (*carrier, owner_substrate))
            .collect();
        Ok(Self {
            pack_skills,
            pack_carriers,
            subject_claim_edges,
            carrier_facet_edges,
            census: EngineSeedCensus {
                rows,
                skills,
                anchors,
            },
        })
    }

    /// Whether `(entity_type, id)` is a pack seed row: a pack SKILL or a
    /// pack source carrier. Bootstrap skills and whole-pack sources are not
    /// pack seeds; they stamp 0 and compare strictly.
    pub(crate) fn is_pack_seed(&self, entity_type: u8, id: &EntityId) -> bool {
        (entity_type == ENTITY_TYPE_SKILL && self.pack_skills.contains(id))
            || (entity_type == ENTITY_TYPE_ASSET && self.pack_carriers.contains(id))
    }

    /// Whether `(claim, subject)` is a seeded system-agent subject edge.
    pub(crate) fn is_subject_claim_edge(&self, claim: &EntityId, subject: &EntityId) -> bool {
        self.subject_claim_edges.contains(&(*claim, *subject))
    }

    /// Whether `(carrier, facet)` is a seeded pack-carrier facet edge.
    pub(crate) fn is_carrier_facet_edge(&self, carrier: &EntityId, facet: &EntityId) -> bool {
        self.carrier_facet_edges.contains(&(*carrier, *facet))
    }
}

/// One seeded skill's rows: the SKILL, its content anchor, and the
/// structural sets its random-id claims are known by.
fn seed_skill(
    seed: &mut BTreeSet<(u8, EntityId)>,
    skills: &mut BTreeSet<EntityId>,
    anchors: &mut BTreeSet<EntityId>,
    id: EntityId,
    hash: crate::skill::SkillContentHash,
) -> Result<()> {
    seed.insert((ENTITY_TYPE_SKILL, id));
    skills.insert(id);
    let anchor = crate::skill_hub::skill_content_anchor_entity_id(hash)?;
    seed.insert((ENTITY_TYPE_SKILL_CONTENT_ANCHOR, anchor));
    anchors.insert(anchor);
    Ok(())
}
