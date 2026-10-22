//! Q3 tuning as the Coach (ARCH-0076 #ask, FIX 8708): every requested
//! override record is read, a page at a time, and the host's policy is asked
//! once over all of them. A batch is never refused for its size; the page is
//! how far one read snapshot reaches, never how much a run may take.
use std::ops::Bound;

use super::super::proposals;
use super::{
    COACH_PERSON_THRESHOLD_FACET, COACH_PERSON_THRESHOLD_PROPOSAL_PREDICATE, PERSON_CHANGED,
    PERSON_CHANGED_READ, PersonThresholdPolicy,
};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::llm::decision::{PersonChangedAnswer, PersonThreshold};
use crate::{EntityId, Error, Result, Vault};

/// Override records one read snapshot takes: a page of the read, never a cap
/// on the batch.
const PAGE: usize = 1024;

impl Vault {
    /// Q3 tuning as the Coach, under a leased `coach.person_threshold` attempt:
    /// reads up to `limit` unread override records once, in pages of 1,024
    /// (a `limit` of 0 reads nothing and proposes nothing), asks `policy` once
    /// over all of them for a threshold and files it as a Proposed row, with
    /// every record it read marked read in the same write. Records past
    /// `limit` stay unread for a later run; a policy or storage failure marks
    /// none read. The Coach never sets the live row; an accepted proposal
    /// does. Returns the proposal, if the policy made one.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, a threshold the
    /// policy returns outside `(0, 1]`, the policy's own errors, or storage
    /// errors.
    pub fn run_coach_person_threshold(
        &self,
        attempt: &DreamerAdmittedAttempt,
        current: Option<PersonThreshold>,
        policy: &dyn PersonThresholdPolicy,
        limit: usize,
        now: u64,
    ) -> Result<Option<EntityId>> {
        self.require_coach_attempt(attempt, COACH_PERSON_THRESHOLD_FACET)?;
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
                    "changed": records.len(),
                    "sources": unread.iter().map(|(source, _)| source.to_hex()).collect::<Vec<_>>(),
                }))
            }
            Some(_) => {
                return Err(Error::InvalidConfig(
                    "the person threshold policy returned an invalid threshold".into(),
                ));
            }
            None => None,
        };
        // The run tray's keys, so the owner's run review can accept it.
        let envelope = proposals::run_tray_envelope(
            self,
            COACH_PERSON_THRESHOLD_FACET,
            attempt.status.attempt.id,
        )?;
        let subject = envelope.actor().entity_ref();
        self.with_write_txn_grouped(|txn| {
            // A second run that read the same records first has already
            // proposed from them.
            for (source, _) in &unread {
                if PERSON_CHANGED_READ.contains(&self.store, &*txn, source)? {
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
                        COACH_PERSON_THRESHOLD_PROPOSAL_PREDICATE,
                        value,
                        &unread.iter().map(|(source, _)| *source).collect::<Vec<_>>(),
                        &envelope,
                        now,
                    )
                })
                .transpose()?;
            for (source, _) in &unread {
                PERSON_CHANGED.delete(&self.store, txn, source)?;
                PERSON_CHANGED_READ.put(&self.store, txn, source, &now)?;
            }
            Ok(proposal)
        })
    }
}

/// Up to `limit` unread override records in key order, each page of
/// [`PAGE`] read in its own snapshot and resumed after the last key read.
fn unread_records(vault: &Vault, limit: usize) -> Result<Vec<(EntityId, PersonChangedAnswer)>> {
    let mut unread: Vec<(EntityId, PersonChangedAnswer)> = Vec::new();
    while unread.len() < limit {
        let want = PAGE.min(limit - unread.len());
        let page = {
            let txn = vault.store.env.read_txn()?;
            let start = unread
                .last()
                .map_or(Bound::Unbounded, |(source, _)| Bound::Excluded(source));
            PERSON_CHANGED
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
