//! The empty-vault join guard's row census: which live rows a seeded
//! open writes before any person or agent writes, so a rootless vault
//! holding anything else can refuse to be set aside by `device enrol`.

use std::collections::BTreeSet;

use super::engine_seed_identities::EngineSeedIdentities;
use crate::EntityId;
use crate::claim::ClaimSubject;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM};
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

impl Vault {
    /// The first live row this vault holds that its own seeded open did
    /// not write, as (entity type, id); `None` when every live row is one
    /// open seeds. Seeds whose ids are minted at import (skill provenance
    /// and scan claims, the root project) are recognized by subject and
    /// predicate or by the root pointer, never by stamp: the pack seeds
    /// stamp wall-clock. Deleted shells are not live rows.
    pub fn first_non_bootstrap_row(&self) -> Result<Option<(u8, EntityId)>> {
        let census = EngineSeedIdentities::load()?.census;
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
                    let seeded = census.contains(entity_type, &id)
                        && (entity_type != ENTITY_TYPE_AGENT_DEF
                            || crate::agent_def::seeded_row_matches_manifest(&id, &body));
                    if seeded || root == Some((entity_type, id)) {
                        continue;
                    }
                    if entity_type == ENTITY_TYPE_CLAIM
                        && seeded_claim(&body, &census.skills, &census.anchors)
                    {
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
