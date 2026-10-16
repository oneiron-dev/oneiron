//! The participant read (OF-529): `vault.rooms.participants` folds the
//! participation stream of a room, or of one of its threads, per subject:
//! every cause it took part for, since when, and whether it may take part
//! now. Room seats, pending offers and presence are other reads.

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::history::PAGE_LIMIT;
use super::participation::{
    FACTS, Fact, FactKey, JoinCause, agent_standing_in_txn, participant_in_txn,
    person_standing_in_txn, place_prefix,
};
use super::{invalid, turns_readable};
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::workspace_roster::JoinSubject;
use crate::{EntityId, Vault};

/// One page of a room's, or one thread's, participants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParticipantsRequest {
    pub room: EntityId,
    /// A thread of the room, by its root turn; `None` reads the room itself.
    #[serde(default)]
    pub branch: Option<EntityId>,
    /// The `next_after` of the page before.
    #[serde(default)]
    pub after: Option<String>,
    /// Rows per page, 1 to the room message page's bound; that bound when
    /// unset.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One participant, folded from its facts in one place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantView {
    pub subject: JoinSubject,
    /// Every cause recorded for it here that the reader may read.
    pub causes: Vec<JoinCause>,
    /// When it first took part here, on the recorded-at clock (unix seconds).
    pub since: u64,
    /// Whether it may take part here now: a person's room standing today; an
    /// agent's seat, or a Ready receipt for the thread or the room.
    pub currently_eligible: bool,
    /// The receipt it stands on now, else the first it took part on.
    pub receipt_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantsPage {
    pub rows: Vec<ParticipantView>,
    /// Explicit end marker: `None` means no further page.
    pub next_after: Option<String>,
}

/// A page cursor: the subject a page ended on.
fn cursor(subject: &JoinSubject) -> String {
    match subject {
        JoinSubject::Person(id) => format!("person:{}", id.to_hex()),
        JoinSubject::Agent(id) => format!("agent:{}", id.to_hex()),
    }
}

fn parse_cursor(value: &str) -> Option<JoinSubject> {
    let (kind, id) = value.split_once(':')?;
    let id = EntityId::from_hex(id).ok()?;
    match kind {
        "person" => Some(JoinSubject::Person(id)),
        "agent" => Some(JoinSubject::Agent(id)),
        _ => None,
    }
}

/// The reader's entry: a person reads from its room audience seat (itself
/// or the pen it acts through), an agent from its seat or a Ready receipt for
/// the requested thread or the room.
fn require_reader_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    actor: EntityId,
) -> Result<()> {
    let now = vault.store.clock.now_recorded_at();
    let reads = match participant_in_txn(vault, txn, actor, now)? {
        Some(JoinSubject::Agent(agent)) => {
            agent_standing_in_txn(vault, txn, room, branch, agent, None)?.is_some()
        }
        subject => {
            let audience = vault.room_audience_members_in_txn(txn, room)?;
            audience.contains(&actor)
                || subject.is_some_and(|subject| audience.contains(&subject.id()))
        }
    };
    if reads { Ok(()) } else { Err(invalid()) }
}

/// One subject's facts and its standing now, before the reader's lane
/// filters its causes.
struct Folded {
    subject: JoinSubject,
    facts: Vec<Fact>,
    currently_eligible: bool,
    standing_receipt: Option<String>,
}

impl Memory<'_> {
    /// One page of who took part in a room, or in one of its threads: each
    /// subject once, with its causes, its first `since` and whether it may
    /// take part now. Only a reader of the room reads it: a person from its
    /// seat, an agent from its seat or a Ready receipt. A cause naming a
    /// turn or TASK the reader's lane withholds is left out, and a subject
    /// with no cause left is no row; a page reads on until it fills.
    pub fn rooms_participants(
        &self,
        request: &ParticipantsRequest,
    ) -> MemoryResult<ParticipantsPage> {
        let limit = request.limit.map_or(Ok(PAGE_LIMIT), usize::try_from);
        let limit = match limit {
            Ok(limit) if (1..=PAGE_LIMIT).contains(&limit) => limit,
            _ => return Err(MemoryError::from(invalid())),
        };
        let mut start = match request.after.as_deref() {
            Some(after) => Some(parse_cursor(after).ok_or_else(invalid)?),
            None => None,
        };
        let (room, branch, actor) = (request.room, request.branch, self.actor());
        {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            require_reader_in_txn(self.vault(), &txn, room, branch, actor)?;
        }
        if !turns_readable(&self.room_read_worlds(room)?) {
            return Ok(ParticipantsPage {
                rows: Vec::new(),
                next_after: None,
            });
        }
        let mut rows = Vec::new();
        loop {
            let (folded, exhausted) = self.participants_after(room, branch, start, limit + 1)?;
            start = folded.last().map(|row| row.subject).or(start);
            rows.extend(self.readable_participants(folded)?);
            if rows.len() > limit || exhausted {
                break;
            }
        }
        let next_after = (rows.len() > limit).then(|| cursor(&rows[limit - 1].subject));
        rows.truncate(limit);
        Ok(ParticipantsPage { rows, next_after })
    }

    /// Up to `window` subjects after `start`, each with its facts and its
    /// standing now, from one snapshot in which the reader still reads the
    /// room; `true` when the place has no subject past them.
    fn participants_after(
        &self,
        room: EntityId,
        branch: Option<EntityId>,
        start: Option<JoinSubject>,
        window: usize,
    ) -> MemoryResult<(Vec<Folded>, bool)> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        require_reader_in_txn(vault, &txn, room, branch, self.actor())?;
        let place = place_prefix(room, branch);
        let place_branch: [u8; 16] = place[16..].try_into().map_err(|_| invalid())?;
        // Past every fact of the subject the last page ended on.
        let past = start.map(|subject| FactKey {
            room,
            branch: place_branch,
            subject,
            cause: (0xff, [0xff; 16]),
        });
        let rows: Box<dyn Iterator<Item = Result<(FactKey, Fact)>> + '_> = match &past {
            Some(past) => Box::new(
                FACTS
                    .iter_range(&vault.store, &txn, Bound::Excluded(past), Bound::Unbounded)?
                    .take_while(move |row| {
                        !matches!(row, Ok((key, _)) if key.room != room || key.branch != place_branch)
                    }),
            ),
            None => Box::new(FACTS.iter_from(&vault.store, &txn, &place)?),
        };
        let mut folded: Vec<Folded> = Vec::new();
        let mut exhausted = true;
        for row in rows {
            let (key, fact) = row?;
            if fact.cause.kind() != key.cause.0 || fact.cause.key_id() != key.cause.1 {
                return Err(Error::CorruptedIndex("participation fact names another cause").into());
            }
            if let Some(last) = folded.last_mut()
                && last.subject == key.subject
            {
                last.facts.push(fact);
                continue;
            }
            if folded.len() == window {
                exhausted = false;
                break;
            }
            folded.push(Folded {
                subject: key.subject,
                facts: vec![fact],
                currently_eligible: false,
                standing_receipt: None,
            });
        }
        for row in &mut folded {
            match row.subject {
                JoinSubject::Person(person) => {
                    row.currently_eligible =
                        person_standing_in_txn(vault, &txn, room, person, None)? == Some(true);
                }
                JoinSubject::Agent(agent) => {
                    let standing = agent_standing_in_txn(vault, &txn, room, branch, agent, None)?;
                    row.currently_eligible = standing.is_some();
                    row.standing_receipt = standing
                        .as_ref()
                        .and_then(|standing| standing.receipt())
                        .map(|receipt| receipt.as_str().to_owned());
                }
            }
        }
        Ok((folded, exhausted))
    }

    /// The rows among `folded` with a cause the reader's lane admits: a
    /// cause naming a turn or TASK is kept only when that record is.
    fn readable_participants(&self, folded: Vec<Folded>) -> MemoryResult<Vec<ParticipantView>> {
        let ids: BTreeSet<EntityId> = folded
            .iter()
            .flat_map(|row| {
                row.facts
                    .iter()
                    .filter_map(|fact| cause_record(&fact.cause))
            })
            .collect();
        let ids: Vec<_> = ids.into_iter().collect();
        let mut admitted = BTreeSet::new();
        if !ids.is_empty() {
            let lane = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
            for chunk in ids.chunks(128) {
                let reads: Vec<_> = chunk
                    .iter()
                    .copied()
                    .map(crate::claim::PointRead::id)
                    .collect();
                let found = lane.read(&reads, None)?.value;
                admitted.extend(
                    chunk
                        .iter()
                        .zip(found)
                        .filter_map(|(id, row)| row.map(|_| *id)),
                );
            }
        }
        Ok(folded
            .into_iter()
            .filter_map(|row| {
                let mut facts: Vec<Fact> = row
                    .facts
                    .into_iter()
                    .filter(|fact| {
                        cause_record(&fact.cause).is_none_or(|id| admitted.contains(&id))
                    })
                    .collect();
                facts.sort_by_key(|fact| fact.at);
                let since = facts.first()?.at;
                let first_receipt = facts.iter().find_map(|fact| fact.join_ref.clone());
                Some(ParticipantView {
                    subject: row.subject,
                    since,
                    currently_eligible: row.currently_eligible,
                    receipt_ref: row.standing_receipt.or(first_receipt),
                    causes: facts.into_iter().map(|fact| fact.cause).collect(),
                })
            })
            .collect())
    }
}

/// The record a cause names, which the reader's lane must admit.
fn cause_record(cause: &JoinCause) -> Option<EntityId> {
    match cause {
        JoinCause::Wrote { turn } | JoinCause::Addressed { turn } => Some(*turn),
        JoinCause::Task { task } => Some(*task),
        JoinCause::Offer { .. } => None,
    }
}
