//! Status-only history reads for already-served session rows, without weakening body reads.

use super::*;
use crate::context_board::ServedLifecycle;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_SKILL};

impl ScopedRead<'_> {
    pub(crate) fn read_set_lifecycle(&self, id: &EntityId) -> Result<Option<ServedLifecycle>> {
        let txn = self.vault.store.env.read_txn()?;
        let Some(raw) = self.entities().get(&txn, id.as_bytes())? else {
            return Ok(None);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(None);
        };
        if raw.len() == ENTITY_METADATA_HEADER_LEN
            || self.vault.archive_tombstone_in_txn(&txn, id)?.is_some()
        {
            return Ok(None);
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let policy = self.policy_manifest_in(&txn)?;
        let state = match header.entity_type {
            ENTITY_TYPE_CLAIM => {
                let claim = decode_claim_body(body, true)?;
                // Keyed memory has no generic discovery/history projection.
                if !crate::claim::claim_generic_readable(&claim)
                    || !matches!(
                        claim.approval,
                        crate::claim::ClaimApprovalStatus::Auto
                            | crate::claim::ClaimApprovalStatus::Approved
                    )
                {
                    return Ok(None);
                }
                let facets = self.claim_facet_refs_in(&txn, id)?;
                if !crate::gate::scoped_read_claim_allowed(
                    &policy,
                    &self.actor_key,
                    &claim,
                    &facets,
                ) {
                    return Ok(None);
                }
                claim.lifecycle
            }
            ENTITY_TYPE_SKILL => {
                let Ok(skill) = crate::skill::decode_skill_record(body) else {
                    return Ok(None);
                };
                match skill.lifecycle_status {
                    crate::skill::SkillLifecycle::Active => ClaimLifecycleStatus::Active,
                    crate::skill::SkillLifecycle::Superseded => ClaimLifecycleStatus::Superseded,
                    _ => return Ok(None),
                }
            }
            ENTITY_TYPE_AGENT_DEF => {
                crate::agent_def::decode_agent_definition(body)?.lifecycle_status
            }
            _ => return Ok(None),
        };
        if state == ClaimLifecycleStatus::Active {
            return Ok(Some(ServedLifecycle::Active));
        }
        if state == ClaimLifecycleStatus::Retracted {
            return Ok(Some(ServedLifecycle::Retracted));
        }
        let mut successor = None;
        for row in self.vault.store.edges_in.prefix_iter(&txn, id.as_bytes())? {
            let (key, bytes) = row?;
            let edge = crate::vault::parse_edge_record(&key, &bytes)?;
            if edge.kind != crate::EdgeKind::Supersedes {
                continue;
            }
            if successor.replace(edge.target).is_some() {
                return Ok(None);
            }
        }
        let Some(next) = successor else {
            return Ok(None);
        };
        if !self.is_entity_readable_with_policy_in(&txn, &policy, &next)? {
            return Ok(None);
        }
        let Some(raw) = self.entities().get(&txn, next.as_bytes())? else {
            return Ok(None);
        };
        let same_kind = EntityMetadataHeader::parse(&raw)
            .is_some_and(|next_header| next_header.entity_type == header.entity_type);
        Ok(same_kind.then(|| ServedLifecycle::Superseded(next.to_hex())))
    }
}
