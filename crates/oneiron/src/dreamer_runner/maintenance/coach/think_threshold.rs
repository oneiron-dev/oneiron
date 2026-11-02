//! Q2 tuning as the Coach (ARCH-0076 #ask, FIX 2437): the ThinkThreshold row
//! learns from quick picks that later proved wrong, as the person row learns
//! from answers a person changed. A quick pick is an answer the ladder gave on
//! a read that took the "needs more thinking?" reading and did not think more;
//! it proved wrong when a person changed it. Each such case is kept beside
//! the person-changed record it comes from, read once, and the host's policy
//! is asked once over all of them for a threshold, filed as a Proposed row in
//! the owner's run tray. The owner's Approve accepts it, and the host
//! installs the newest accepted revision on its bands. A batch is never
//! refused for its size; the page is how far one read snapshot reaches.
use std::ops::Bound;

use super::super::proposals;
use super::{COACH_THINK_THRESHOLD_FACET, COACH_THINK_THRESHOLD_PROPOSAL_PREDICATE};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::llm::decision::{PersonChangedAnswer, ThinkThreshold};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Error, Result, Vault,
};

/// Quick picks the Coach has not read yet. Key: the source the host bound
/// the person's answer to (its ask or receipt).
const THINK_MISSED: SideTable<EntityId, PersonChangedAnswer, Named> =
    SideTable::new(&side_table::COACH_THINK_MISSED);
/// Sources a think-threshold run has read, with the time it read them, so a
/// replayed record never counts twice. Key: as above.
const THINK_MISSED_READ: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::COACH_THINK_MISSED_READ);

/// Records one read snapshot takes: a page of the read, never a cap on the
/// batch.
const PAGE: usize = 1024;

/// Proposal ids read per page of the predicate's posting list.
const PROPOSAL_PAGE: usize = 256;

/// The rule that turns quick picks that proved wrong into a think threshold.
/// The number is the host's policy, never the engine's.
pub trait ThinkThresholdPolicy {
    /// The threshold to propose from the current row and the unread quick
    /// picks, or `None` to leave the row as it is.
    fn revise(
        &self,
        current: Option<ThinkThreshold>,
        missed: &[PersonChangedAnswer],
    ) -> Result<Option<f64>>;
}

/// Keeps `record`, a person-changed answer bound to `source`, for the think
/// tune when its prior read took the "needs more thinking?" reading: a quick
/// pick that proved wrong. A replay of the same source is a no-op; a
/// different record under it is refused.
pub(super) fn keep_quick_pick_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: EntityId,
    record: &PersonChangedAnswer,
) -> Result<()> {
    if record.prior_paired.is_none() || THINK_MISSED_READ.contains(&vault.store, &*txn, &source)? {
        return Ok(());
    }
    match THINK_MISSED.get(&vault.store, &*txn, &source)? {
        Some(held) if held == *record => Ok(()),
        Some(_) => Err(Error::InvalidConfig(
            "another quick-pick record already names this source".into(),
        )),
        None => THINK_MISSED.put(&vault.store, txn, &source, record),
    }
}

impl Vault {
    /// Q2 tuning as the Coach, under a leased `coach.think_threshold`
    /// attempt: reads up to `limit` unread quick picks once, in pages of
    /// 1,024 (a `limit` of 0 reads nothing and proposes nothing), asks
    /// `policy` once over all of them for a threshold and files it as a
    /// Proposed row, with every record it read marked read in the same
    /// write. Records past `limit` stay unread for a later run; a policy or
    /// storage failure marks none read. The Coach never sets the live row;
    /// an accepted proposal does. Returns the proposal, if the policy made
    /// one.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, a threshold the
    /// policy returns outside `(0, 1]`, the policy's own errors, or storage
    /// errors.
    pub fn run_coach_think_threshold(
        &self,
        attempt: &DreamerAdmittedAttempt,
        current: Option<ThinkThreshold>,
        policy: &dyn ThinkThresholdPolicy,
        limit: usize,
        now: u64,
    ) -> Result<Option<EntityId>> {
        self.require_coach_attempt(attempt, COACH_THINK_THRESHOLD_FACET)?;
        let unread = unread_records(self, limit)?;
        if unread.is_empty() {
            return Ok(None);
        }
        let records: Vec<PersonChangedAnswer> =
            unread.iter().map(|(_, record)| record.clone()).collect();
        let value = match policy.revise(current, &records)? {
            Some(threshold) if threshold.is_finite() && threshold > 0.0 && threshold <= 1.0 => {
                Some(serde_json::json!({
                    "previous": current.map(|row| serde_json::json!({
                        "threshold": row.threshold,
                        "version": row.version,
                    })),
                    "proposed": {
                        "threshold": threshold,
                        "version": current.map_or(1, |row| row.version.saturating_add(1)),
                    },
                    "missed": records.len(),
                    "sources": unread.iter().map(|(source, _)| source.to_hex()).collect::<Vec<_>>(),
                }))
            }
            Some(_) => {
                return Err(Error::InvalidConfig(
                    "the think threshold policy returned an invalid threshold".into(),
                ));
            }
            None => None,
        };
        // The run tray's keys, so the owner's run review can accept it.
        let envelope = proposals::run_tray_envelope(
            self,
            COACH_THINK_THRESHOLD_FACET,
            attempt.status.attempt.id,
        )?;
        let subject = envelope.actor().entity_ref();
        self.with_write_txn_grouped(|txn| {
            // A second run that read the same records first has already
            // proposed from them.
            for (source, _) in &unread {
                if THINK_MISSED_READ.contains(&self.store, &*txn, source)? {
                    return Ok(None);
                }
            }
            let proposal = value
                .as_ref()
                .map(|value| {
                    proposals::emit_in_txn(
                        self,
                        txn,
                        subject,
                        COACH_THINK_THRESHOLD_PROPOSAL_PREDICATE,
                        value,
                        &unread.iter().map(|(source, _)| *source).collect::<Vec<_>>(),
                        &envelope,
                        now,
                    )
                })
                .transpose()?;
            for (source, _) in &unread {
                THINK_MISSED.delete(&self.store, txn, source)?;
                THINK_MISSED_READ.put(&self.store, txn, source, &now)?;
            }
            Ok(proposal)
        })
    }

    /// The accepted think-threshold revision with the highest version, a tie
    /// going to the later-learned proposal: an owner-approved, active, fresh
    /// Coach proposal whose value parses. `None` when the owner accepted none.
    pub fn latest_accepted_think_threshold(&self) -> Result<Option<(EntityId, ThinkThreshold)>> {
        let coach = crate::dreamer_runner::authority::coach_actor_id()?;
        let txn = self.store.env.read_txn()?;
        let mut best: Option<((u32, u64, EntityId), ThinkThreshold)> = None;
        let mut after = None;
        loop {
            let page = crate::claim::claim_ids_for_predicate_page_in_txn(
                &self.store,
                &txn,
                COACH_THINK_THRESHOLD_PROPOSAL_PREDICATE,
                after,
                PROPOSAL_PAGE,
            )?;
            let full = page.len() == PROPOSAL_PAGE;
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

/// Up to `limit` unread quick picks in key order, each page of [`PAGE`] read
/// in its own snapshot and resumed after the last key read.
fn unread_records(vault: &Vault, limit: usize) -> Result<Vec<(EntityId, PersonChangedAnswer)>> {
    let mut unread: Vec<(EntityId, PersonChangedAnswer)> = Vec::new();
    while unread.len() < limit {
        let want = PAGE.min(limit - unread.len());
        let page = {
            let txn = vault.store.env.read_txn()?;
            let start = unread
                .last()
                .map_or(Bound::Unbounded, |(source, _)| Bound::Excluded(source));
            THINK_MISSED
                .iter_range(&vault.store, &txn, start, Bound::Unbounded)?
                .take(want)
                .collect::<Result<Vec<_>>>()?
        };
        let short = page.len() < want;
        unread.extend(page);
        if short {
            break;
        }
    }
    Ok(unread)
}

/// The proposed row of an accepted Coach proposal, or `None` for any other
/// claim under the predicate.
fn accepted_row(body: &ClaimBody, coach: EntityId) -> Option<ThinkThreshold> {
    if body.predicate != COACH_THINK_THRESHOLD_PROPOSAL_PREDICATE
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
        .then_some(ThinkThreshold { threshold, version })
}
