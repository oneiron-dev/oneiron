//! The accepted PersonThreshold row (Q3). The Coach files each tune as a
//! Proposed `coach.person_threshold.proposal` in the owner's run tray; the
//! owner's Approve accepts it, and the host installs the newest accepted
//! revision on its bands.
use super::coach::COACH_PERSON_THRESHOLD_PROPOSAL_PREDICATE;
use crate::llm::decision::PersonThreshold;
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Result, Vault,
};

/// Proposal ids read per page of the predicate's posting list.
const PAGE: usize = 256;

impl Vault {
    /// The accepted person-threshold revision with the highest version, a tie
    /// going to the later-learned proposal: an owner-approved, active, fresh
    /// Coach proposal whose value parses. `None` when the owner accepted none.
    pub fn latest_accepted_person_threshold(&self) -> Result<Option<(EntityId, PersonThreshold)>> {
        let coach = crate::dreamer_runner::authority::coach_actor_id()?;
        let txn = self.store.env.read_txn()?;
        let mut best: Option<((u32, u64, EntityId), PersonThreshold)> = None;
        let mut after = None;
        loop {
            let page = crate::claim::claim_ids_for_predicate_page_in_txn(
                &self.store,
                &txn,
                COACH_PERSON_THRESHOLD_PROPOSAL_PREDICATE,
                after,
                PAGE,
            )?;
            let full = page.len() == PAGE;
            after = page.last().copied();
            for id in page {
                let Some(body) = self.get_claim_for_effect_in_txn(&txn, &id)? else {
                    continue;
                };
                let Some(row) = accepted_row(&body, coach) else {
                    continue;
                };
                let learned = self
                    .entity_header_in_txn(&txn, &id)?
                    .map_or(0, |header| header.learned_at);
                let key = (row.version, learned, id);
                if best.as_ref().is_none_or(|(held, _)| key > *held) {
                    best = Some((key, row));
                }
            }
            if !full {
                break;
            }
        }
        Ok(best.map(|((_, _, id), row)| (id, row)))
    }
}

/// The proposed row of an accepted Coach proposal, or `None` for any other
/// claim under the predicate.
fn accepted_row(body: &ClaimBody, coach: EntityId) -> Option<PersonThreshold> {
    if body.predicate != COACH_PERSON_THRESHOLD_PROPOSAL_PREDICATE
        || body.subject != ClaimSubject::Entity(coach)
        || body.approval != ClaimApprovalStatus::Approved
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
        || body.source != Some(ClaimSource::Generated)
        || crate::claim::session_claim_producer(body) != Some(coach)
    {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(body.value.as_str()?).ok()?;
    let proposed = value.get("proposed")?;
    let threshold = proposed.get("threshold")?.as_f64()?;
    let version = u32::try_from(proposed.get("version")?.as_u64()?).ok()?;
    (threshold > 0.0 && threshold <= 1.0 && version > 0)
        .then_some(PersonThreshold { threshold, version })
}
