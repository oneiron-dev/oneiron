//! The empty-vault join guard's row census: which live rows a seeded
//! open writes before any person or agent writes, so a rootless vault
//! holding anything else can refuse to be set aside by `device enrol`.

use std::collections::BTreeSet;

use super::embedded_owner_actor_id;
use crate::EntityId;
use crate::claim::ClaimSubject;
use crate::error::Result;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR, ENTITY_TYPE_FACET, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SKILL, ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
    ENTITY_TYPE_SKILL_HUB,
};
use crate::vault::{LiveEntityRow, Vault, live_entity_row_in_txn};

/// Whether a CLAIM body is a seed import's bookkeeping: provenance on a
/// seeded skill, or a scan verdict on a seeded content anchor. Their ids
/// are minted at import, so only subject and predicate can know them.
fn seeded_claim(body: &[u8], skills: &BTreeSet<EntityId>, anchors: &BTreeSet<EntityId>) -> bool {
    let Ok(claim) = crate::claim::decode_claim_body(body, true) else {
        return false;
    };
    let ClaimSubject::Entity(subject) = claim.subject else {
        return false;
    };
    (claim.predicate == crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE
        && skills.contains(&subject))
        || (claim.predicate == crate::skill_hub::PREDICATE_SKILL_SCAN_VERDICT
            && anchors.contains(&subject))
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

impl Vault {
    /// The first live row this vault holds that its own seeded open did
    /// not write, as (entity type, id); `None` when every live row is one
    /// open seeds. Seeds whose ids are minted at import (skill provenance
    /// and scan claims, the root project) are recognized by subject and
    /// predicate or by the root pointer, never by stamp: the pack seeds
    /// stamp wall-clock. Deleted shells are not live rows.
    pub fn first_non_bootstrap_row(&self) -> Result<Option<(u8, EntityId)>> {
        let mut seed: BTreeSet<(u8, EntityId)> = BTreeSet::new();
        seed.insert((
            ENTITY_TYPE_POLICY_MANIFEST,
            crate::gate::default_policy_manifest_id()?,
        ));
        seed.insert((
            ENTITY_TYPE_MACHINE,
            crate::dreamer_runner::authority::dreamer_actor_id()?,
        ));
        seed.insert((
            ENTITY_TYPE_MACHINE,
            crate::dreamer_runner::authority::coach_actor_id()?,
        ));
        let owner = embedded_owner_actor_id()?;
        seed.insert((ENTITY_TYPE_PERSON, owner));
        seed.insert((ENTITY_TYPE_FACET, crate::claim::substrate_facet_id(owner)?));
        for agent in crate::agent_def::seeded_system_agent_ids()? {
            seed.insert((ENTITY_TYPE_AGENT_DEF, agent));
            let (person, substrate, anchor) = crate::context_board::seeded_agent_person_ids(agent)?;
            seed.insert((ENTITY_TYPE_PERSON, person));
            seed.insert((ENTITY_TYPE_FACET, crate::claim::substrate_facet_id(person)?));
            seed.insert((ENTITY_TYPE_CLAIM, substrate));
            seed.insert((ENTITY_TYPE_CLAIM, anchor));
        }
        let mut skills: BTreeSet<EntityId> = BTreeSet::new();
        let mut anchors: BTreeSet<EntityId> = BTreeSet::new();
        for (id, hash) in crate::skill_hub::bootstrap_skill_ids_and_hashes()? {
            seed_skill(&mut seed, &mut skills, &mut anchors, id, hash)?;
        }
        for (source, pack_skills) in crate::skill_hub::pack_catalog::builtin_pack_seed_ids()? {
            seed.insert((ENTITY_TYPE_ASSET, source));
            for (id, hash) in pack_skills {
                seed_skill(&mut seed, &mut skills, &mut anchors, id, hash)?;
            }
        }
        seed.insert((
            ENTITY_TYPE_SKILL_HUB,
            crate::skill_hub::default_skill_hub_id()?,
        ));
        for row in crate::comm::claim_class_descriptors() {
            seed.insert((
                ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR,
                crate::comm::claim_class_descriptor_id(row.predicate)?,
            ));
        }
        let root = match (self.project_type_byte(), self.root_project()) {
            (Ok(byte), Ok(id)) => Some((byte, id)),
            _ => None,
        };
        const PAGE: usize = 1024;
        let txn = self.store.env.read_txn()?;
        for byte in 0..=u8::MAX {
            let mut after: Option<EntityId> = None;
            loop {
                let page = self.entities_by_type_page(byte, after.as_ref(), PAGE)?;
                let full = page.len() == PAGE;
                after = page.last().copied();
                for id in page {
                    let LiveEntityRow::Live { entity_type, body } =
                        live_entity_row_in_txn(&self.store, &txn, &id)?
                    else {
                        continue;
                    };
                    let seeded = seed.contains(&(entity_type, id))
                        && (entity_type != ENTITY_TYPE_AGENT_DEF
                            || crate::agent_def::seeded_row_matches_manifest(&id, &body));
                    if seeded || root == Some((entity_type, id)) {
                        continue;
                    }
                    if entity_type == ENTITY_TYPE_CLAIM && seeded_claim(&body, &skills, &anchors) {
                        continue;
                    }
                    return Ok(Some((entity_type, id)));
                }
                if !full {
                    break;
                }
            }
        }
        Ok(None)
    }
}
