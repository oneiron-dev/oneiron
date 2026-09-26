//! One durable proactivity digest per vault cadence, with intent-bound urgent wakes.
use super::invalid;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Owner-set cadence dial for the proactivity digest.
const CADENCE: SideTable<(), ProactivityCadence, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_CADENCE);
/// Rolling proactivity-digest emission state (last_emitted timestamp, seen revisions).
const STATE: SideTable<(), DigestState, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_STATE);
/// One emitted proactivity digest, keyed by its content-derived id.
const DIGEST: SideTable<[u8; 32], ProactivityDigest, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_DIGEST);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactivityCadence {
    pub period_secs: u64,
    pub group_by_facet: bool,
    pub urgent_breakthrough: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrgentDigestWake {
    pub intent_ref: EntityId,
    pub needed_before: u64,
    pub waiting_harms_intent: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestProposal {
    #[serde(with = "crate::serialize::entity_ref")]
    pub claim_ref: EntityId,
    pub revision: [u8; 32],
    pub summary: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactivityDigest {
    pub id: [u8; 32],
    pub created_at: u64,
    pub urgent: bool,
    pub groups: BTreeMap<String, Vec<DigestProposal>>,
    pub rendered: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestState {
    last_emitted: Option<u64>,
    seen: BTreeMap<String, [u8; 32]>,
}
impl Vault {
    pub fn set_proactivity_cadence(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        row: &ProactivityCadence,
    ) -> Result<()> {
        if row.period_secs == 0 {
            return Err(invalid());
        }
        self.with_write_txn(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            CADENCE.put(&self.store, txn, &(), row)?;
            Ok(())
        })
    }
    /// Builds a display projection only. Pending decisions remain pending.
    /// The urgent assessment comes from the host, but must name a live,
    /// approved intent whose deadline is before the next cadence boundary.
    pub fn proactivity_digest(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        now: u64,
        urgent: Option<&UrgentDigestWake>,
    ) -> Result<Option<ProactivityDigest>> {
        let authority = self.dreamer_authority()?.entity_ref();
        self.with_write_txn(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            let cadence: ProactivityCadence = match CADENCE.get(&self.store, &*txn, &())? {
                Some(row) => row,
                None => serde_json::from_str(include_str!("digest_defaults.json"))
                    .map_err(|_| invalid())?,
            };
            if cadence.period_secs == 0 {
                return Err(invalid());
            }
            let mut state: DigestState = STATE.get(&self.store, &*txn, &())?.unwrap_or_default();
            let next = state
                .last_emitted
                .map(|last| last.saturating_add(cadence.period_secs));
            let due = next.is_none_or(|next| now >= next);
            let breakthrough = if let (Some(wake), Some(next)) = (urgent, next) {
                if cadence.urgent_breakthrough
                    && wake.waiting_harms_intent
                    && wake.needed_before < next
                {
                    self.get_claim_in_txn(&*txn, &wake.intent_ref)?
                        .is_some_and(|body| {
                            body.predicate == "profile.intent"
                                && body.subject == crate::ClaimSubject::Entity(owner.actor())
                                && body.source == Some(ClaimSource::UserStated)
                                && body
                                    .value
                                    .as_str()
                                    .is_some_and(|text| !text.trim().is_empty())
                                && body.approval == ClaimApprovalStatus::Approved
                                && body.lifecycle == ClaimLifecycleStatus::Active
                                && !body.stale
                        })
                } else {
                    false
                }
            } else {
                false
            };
            if !due && !breakthrough {
                return Ok(None);
            }
            let mut groups: BTreeMap<String, Vec<DigestProposal>> = BTreeMap::new();
            for id in
                crate::claim::pending_claim_ids_for_producer_in_txn(&self.store, txn, authority)?
            {
                let Some(bytes) = self.store.entities.get(txn, id.as_bytes())? else {
                    continue;
                };
                let header = EntityMetadataHeader::parse(&bytes).ok_or_else(invalid)?;
                if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                    || bytes.len() == ENTITY_METADATA_HEADER_LEN
                {
                    continue;
                }
                let body =
                    crate::claim::decode_claim_body(&bytes[ENTITY_METADATA_HEADER_LEN..], true)?;
                if body.approval != ClaimApprovalStatus::Proposed
                    || body.lifecycle != ClaimLifecycleStatus::Active
                    || body.source != Some(ClaimSource::Generated)
                    || body.stale
                    || crate::claim::session_claim_producer(&body) != Some(authority)
                {
                    continue;
                }
                let revision = *blake3::hash(&bytes[ENTITY_METADATA_HEADER_LEN..]).as_bytes();
                if state.seen.get(&id.to_hex()) == Some(&revision) {
                    continue;
                }
                let group = if cadence.group_by_facet {
                    body.predicate
                        .split('.')
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(".")
                } else {
                    "proposals".into()
                };
                groups.entry(group).or_default().push(DigestProposal {
                    claim_ref: id,
                    revision,
                    summary: format!("{}: {}", body.predicate, body.value),
                });
            }
            if groups.is_empty() {
                return Ok(None);
            }
            let mut rendered = String::new();
            for (group, proposals) in &mut groups {
                proposals.sort_by_key(|p| p.claim_ref);
                rendered.push_str(&format!("{group}\n"));
                for proposal in proposals {
                    rendered.push_str(&format!(
                        "- {} [{}]\n",
                        proposal.summary,
                        proposal.claim_ref.to_hex()
                    ));
                    state
                        .seen
                        .insert(proposal.claim_ref.to_hex(), proposal.revision);
                }
            }
            let is_urgent = !due && breakthrough;
            let identity =
                serde_json::to_vec(&(now, &groups, is_urgent, &rendered)).map_err(|_| invalid())?;
            let digest = ProactivityDigest {
                id: *blake3::hash(&identity).as_bytes(),
                created_at: now,
                urgent: is_urgent,
                groups,
                rendered,
            };
            DIGEST.put(&self.store, txn, &digest.id, &digest)?;
            state.last_emitted = Some(now);
            STATE.put(&self.store, txn, &(), &state)?;
            Ok(Some(digest))
        })
    }
    pub fn read_proactivity_digest(&self, id: [u8; 32]) -> Result<Option<ProactivityDigest>> {
        let txn = self.store.env.read_txn()?;
        DIGEST
            .get(&self.store, &txn, &id)?
            .map(|digest| {
                let identity = serde_json::to_vec(&(
                    digest.created_at,
                    &digest.groups,
                    digest.urgent,
                    &digest.rendered,
                ))
                .map_err(|_| invalid())?;
                if digest.id != id || blake3::hash(&identity).as_bytes() != &id {
                    return Err(invalid());
                }
                Ok(digest)
            })
            .transpose()
    }
}
#[cfg(test)]
mod tests;
