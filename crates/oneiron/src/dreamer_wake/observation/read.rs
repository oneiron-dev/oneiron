//! The wake observation's typed read: an attempt's or a pass's durable rows
//! from one snapshot, one page at a time, then the live pass sampled after
//! and labelled apart. Engine-side only: a door adds its caller's binding,
//! release and wire shapes.

use std::ops::Bound;

use super::live::ActiveWake;
use super::{
    ATTEMPTS, CALLS, CHECKPOINTS, LATEST, MEMBERS, Rows, WAKES, WakeObservedAttempt,
    WakeObservedCall, WakeObservedCheckpoint, WakeObservedHeader, WakeRef, attempt_key, call_key,
    checkpoint_key, latest_key, member_key, row_key, wake_key,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{Named, SideCodec};

pub use crate::memory::wake_observation::WAKE_OBSERVATION_PAGE_DEFAULT;

pub use crate::memory::wake_observation::WAKE_OBSERVATION_PAGE_MAX;

pub use crate::memory::wake_observation::WakeObservationSelector;

pub use crate::memory::wake_observation::WakeObservationCursor;

pub use crate::memory::wake_observation::WakeObservationRequest;

pub use crate::memory::wake_observation::WakeObservedGeneration;

pub use crate::memory::wake_observation::WakeObservation;

pub use crate::memory::wake_observation::WakeLiveState;

pub use crate::memory::wake_observation::WakeLiveCall;

impl Vault {
    /// The wake observation an attempt or a pass recorded (DOOR-144): one
    /// page of its durable rows from one snapshot, then, once that snapshot
    /// is released, the live pass if a root on this handle runs it. `None`
    /// for an attempt or a pass no observed wake recorded.
    ///
    /// # Errors
    ///
    /// A cursor of the other selector's kind, or a failed store read.
    pub fn dreamer_wake_observation(
        &self,
        request: &WakeObservationRequest,
    ) -> Result<Option<WakeObservation>> {
        let limit = request
            .limit
            .unwrap_or(WAKE_OBSERVATION_PAGE_DEFAULT)
            .clamp(1, WAKE_OBSERVATION_PAGE_MAX);
        let observation = {
            let rtxn = self.store.env.read_txn()?;
            match request.selector {
                WakeObservationSelector::Attempt { attempt, wake } => {
                    attempt_page_in_txn(self, &rtxn, attempt, wake, request.cursor, limit)?
                }
                WakeObservationSelector::Wake { wake } => {
                    wake_page_in_txn(self, &rtxn, wake, request.cursor, limit)?
                }
            }
        };
        Ok(observation.map(|mut observation| {
            observation.live = self
                .active_wakes
                .get(observation.wake)
                .as_deref()
                .map(ActiveWake::sample);
            observation
        }))
    }
}

fn attempt_page_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    wake: Option<WakeRef>,
    cursor: Option<WakeObservationCursor>,
    limit: usize,
) -> Result<Option<WakeObservation>> {
    let after = match cursor {
        None => None,
        Some(WakeObservationCursor::Call(call)) => Some(call),
        Some(WakeObservationCursor::Member { .. }) => {
            return Err(Error::InvalidConfig(
                "an attempt's wake observation page continues from a call".into(),
            ));
        }
    };
    let generation = match wake {
        None => LATEST
            .get(&vault.store, txn, &latest_key(attempt))?
            .map(|latest| (latest.wake, latest.attempt_count)),
        Some(wake) => {
            let members = row_key(
                b'm',
                &[wake.0.as_bytes().as_slice(), attempt.as_bytes().as_slice()],
            );
            MEMBERS
                .iter_rev_from(&vault.store, txn, &members)?
                .next()
                .transpose()?
                .map(|(_, member)| (wake, member.attempt_count))
        }
    };
    let Some((wake, attempt_count)) = generation else {
        return Ok(None);
    };
    let Some(header) = WAKES.get(&vault.store, txn, &wake_key(wake))? else {
        return Ok(None);
    };
    let Some(generation) = generation_in_txn(vault, txn, attempt, attempt_count)? else {
        return Ok(None);
    };
    let prefix = row_key(
        b'c',
        &[wake.0.as_bytes().as_slice(), attempt.as_bytes().as_slice()],
    );
    let after = after.map(|call| call_key(wake, attempt, call));
    let (calls, more) = page_in_txn(CALLS, vault, txn, &prefix, after, limit)?;
    let next = calls
        .last()
        .filter(|_| more)
        .map(|call| WakeObservationCursor::Call(call.call));
    Ok(Some(WakeObservation {
        wake,
        header,
        generation: Some(generation),
        members: Vec::new(),
        calls,
        next,
        live: None,
    }))
}

fn wake_page_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wake: WakeRef,
    cursor: Option<WakeObservationCursor>,
    limit: usize,
) -> Result<Option<WakeObservation>> {
    let after = match cursor {
        None => None,
        Some(WakeObservationCursor::Member {
            attempt,
            attempt_count,
        }) => Some(member_key(wake, attempt, attempt_count)),
        Some(WakeObservationCursor::Call(_)) => {
            return Err(Error::InvalidConfig(
                "a pass's wake observation page continues from an attempt generation".into(),
            ));
        }
    };
    let Some(header) = WAKES.get(&vault.store, txn, &wake_key(wake))? else {
        return Ok(None);
    };
    let prefix = row_key(b'm', &[wake.0.as_bytes().as_slice()]);
    let (page, more) = page_in_txn(MEMBERS, vault, txn, &prefix, after, limit)?;
    let mut members = Vec::with_capacity(page.len());
    for member in &page {
        if let Some(generation) =
            generation_in_txn(vault, txn, member.attempt, member.attempt_count)?
        {
            members.push(generation);
        }
    }
    let next = page
        .last()
        .filter(|_| more)
        .map(|member| WakeObservationCursor::Member {
            attempt: member.attempt,
            attempt_count: member.attempt_count,
        });
    Ok(Some(WakeObservation {
        wake,
        header,
        generation: None,
        members,
        calls: Vec::new(),
        next,
        live: None,
    }))
}

fn generation_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    attempt_count: u32,
) -> Result<Option<WakeObservedGeneration>> {
    let key = attempt_key(attempt, attempt_count);
    let Some(admitted) = ATTEMPTS.get(&vault.store, txn, &key)? else {
        return Ok(None);
    };
    let cut = |park: Option<EntityId>| match park {
        Some(park) => CHECKPOINTS.get(&vault.store, txn, &checkpoint_key(park)),
        None => Ok(None),
    };
    let checkpoint = cut(admitted.park)?;
    let after_cut = cut(admitted.after_cut)?;
    Ok(Some(WakeObservedGeneration {
        attempt: admitted,
        checkpoint,
        after_cut,
    }))
}

/// One page of `table`'s rows under `prefix`, after the full key `after`
/// when a cursor names one, and whether more rows follow it.
fn page_in_txn<V>(
    table: Rows<V>,
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prefix: &[u8],
    after: Option<Vec<u8>>,
    limit: usize,
) -> Result<(Vec<V>, bool)>
where
    V: 'static,
    Named: SideCodec<V>,
{
    let start = after.map_or_else(|| Bound::Included(prefix.to_vec()), Bound::Excluded);
    let end = past(prefix);
    let end = end.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    let mut page = Vec::new();
    for row in table
        .iter_range(&vault.store, txn, start.as_ref(), end)?
        .take(limit.saturating_add(1))
    {
        page.push(row?.1);
    }
    let more = page.len() > limit;
    page.truncate(limit);
    Ok((page, more))
}

/// The first key past every key under `prefix`.
fn past(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if let Some(next) = last.checked_add(1) {
            end.push(next);
            return Some(end);
        }
    }
    None
}
