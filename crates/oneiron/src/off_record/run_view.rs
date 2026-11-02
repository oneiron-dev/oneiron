//! A code run bound to an off-record session, read outside its entries
//! (FIX 4284): the cards of its named results, one read of one of them, and
//! the wait it is parked on, with its runner's answer to that wait. Each
//! goes through the stretch the run's entries bind, as the participant they
//! run as, along the route their run binds: never through the vault's
//! canonical readers, so nothing of the room is read from or copied to
//! base. Nothing here enters the run. An answered run goes on when its
//! runner enters it again, as `self.off_record.execute` does.

use serde_json::Value;

use super::OffRecordSession;
use crate::code_run::{
    ExecutorStorage, ResultFacet, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    WaitDeliveries, WaitKey, read_result_in, result_cards_in,
};
use crate::engine_executor::{EngineExecutorError, parked_wait_now};
use crate::memory::{MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};
use crate::{EntityId, Result};

/// One session-bound run, as the participant its entries run as reads it.
pub struct SessionCodeRun<'v> {
    storage: ExecutorStorage<'v>,
    deliveries: WaitDeliveries<'v>,
    run_ref: String,
    run_id: EntityId,
}

/// One page of a session run's result cards, newest name first.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRunCards {
    /// Each card as the run's own reader makes it: a preview and a shape
    /// only of a clean body, and no guest read path.
    pub cards: Vec<Value>,
    /// How many names the run has bound.
    pub count: usize,
    /// Where the next page starts, when names remain past this one.
    pub next_offset: Option<usize>,
    /// The rows the run's answers were served from stay where the reader is
    /// not, so no card is shown.
    pub withheld: bool,
    /// The rows the run's answers were served from, as its record keeps
    /// them; `None` when it keeps no set.
    pub served_rows: Option<Vec<EntityId>>,
}

/// One read of a session run's result, as the run's own reader answers it.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRunRead {
    /// `{"output": ...}`, or a `denied` refusal.
    pub reply: Value,
    /// The rows the run's answers were served from; `None` when its record
    /// keeps no set.
    pub served_rows: Option<Vec<EntityId>>,
}

/// The wait a session run is parked on now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRunWait {
    /// The key its reply is delivered under.
    pub key: WaitKey,
    pub wait: SelfDurableWait,
    /// Whether its runner's reply answers it ([`SessionCodeRun::answer_wait`]).
    pub answerable: bool,
    /// When a reply was delivered to it, if one was: the run takes it at its
    /// next entry.
    pub delivered_at_ms: Option<u64>,
}

/// What an answer to a session run's wait did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionWaitAnswer {
    pub key: WaitKey,
    /// Another reply settled the wait first, before this call or beside
    /// it; that first reply stands and this one was not delivered.
    pub already_answered: bool,
    /// When the reply that stands was delivered.
    pub delivered_at_ms: u64,
}

impl<'v> OffRecordSession<'v> {
    /// The run `run_id` (`run_ref`, its runner's handle) in this stretch, as
    /// `participant` runs it: bound as an entry of it binds, along the route
    /// it binds, with its participant checked on every read.
    ///
    /// # Errors
    ///
    /// A stretch that is closing, or a participant no longer in its room.
    pub fn code_run(
        &self,
        participant: EntityId,
        run_ref: &str,
        run_id: EntityId,
    ) -> Result<SessionCodeRun<'v>> {
        Ok(SessionCodeRun {
            storage: ExecutorStorage::for_session(self, participant)?,
            deliveries: WaitDeliveries::for_session(self, participant)?,
            run_ref: run_ref.to_owned(),
            run_id,
        })
    }
}

impl SessionCodeRun<'_> {
    /// The run's id in its stretch.
    #[must_use]
    pub fn run_id(&self) -> EntityId {
        self.run_id
    }

    /// The run's record in the stretch; a typed not-found when it has none.
    fn record(&self) -> MemoryResult<crate::code_run::CodeRunReplayRecord> {
        self.storage
            .get_code_run_replay_record(&self.run_id)?
            .ok_or_else(|| {
                MemoryError::not_found(format!(
                    "no run {} in this off-record session",
                    self.run_ref
                ))
            })
    }

    /// The cards of the run's named results, newest first: the `offset`
    /// newest names passed over, then `limit` of them (all when `None`).
    /// `withholds` says whether the rows the run's answers were served from
    /// (`None` when its record keeps no set) stay where the reader is not;
    /// then no card is shown.
    ///
    /// # Errors
    ///
    /// No record of the run in the stretch, or a storage error.
    pub fn result_cards(
        &self,
        offset: usize,
        limit: Option<usize>,
        withholds: impl FnOnce(Option<&[EntityId]>) -> Result<bool>,
    ) -> MemoryResult<SessionRunCards> {
        let record = self.record()?;
        let served_rows = record.agent_verb_rows();
        let count = record.bindings.len();
        if withholds(served_rows.as_deref())? {
            return Ok(SessionRunCards {
                cards: Vec::new(),
                count,
                next_offset: None,
                withheld: true,
                served_rows,
            });
        }
        let remaining = count.saturating_sub(offset);
        let take = limit.map_or(remaining, |limit| limit.min(remaining));
        let (cards, _) = result_cards_in(&self.storage, &record, offset, take)?;
        Ok(SessionRunCards {
            cards,
            count,
            next_offset: (take < remaining).then_some(offset + take),
            withheld: false,
            served_rows,
        })
    }

    /// One read of the run's result `reference` names (a name it bound, a
    /// handle, `occurrence:<hex>`, or a range of one), as the run's own
    /// reader answers a caller outside the run: its card when `facet` is
    /// `None`, else that facet of it from `input`, under `withholds` and the
    /// result's taint.
    ///
    /// # Errors
    ///
    /// No record of the run in the stretch, or a storage error.
    pub fn read_result(
        &self,
        reference: &str,
        facet: Option<ResultFacet>,
        input: Value,
        withholds: impl FnOnce(Option<&[EntityId]>) -> Result<bool>,
    ) -> MemoryResult<SessionRunRead> {
        let record = self.record()?;
        let served_rows = record.agent_verb_rows();
        // A session run keeps no type diagnostics beside its results.
        let reply = read_result_in(
            &self.storage,
            &record,
            &[],
            reference,
            facet,
            input,
            withholds,
        )?;
        Ok(SessionRunRead { reply, served_rows })
    }

    /// The wait the run is parked on now, and whether a reply was delivered
    /// to it; `None` when it waits on nothing.
    ///
    /// # Errors
    ///
    /// No record of the run in the stretch, or a storage error.
    pub fn wait(&self) -> MemoryResult<Option<SessionRunWait>> {
        let record = self.record()?;
        let Some((key, wait)) = parked_wait_now(&self.storage, &record).map_err(engine_error)?
        else {
            return Ok(None);
        };
        let delivered_at_ms = self
            .deliveries
            .delivery(&key)?
            .map(|delivery| delivery.delivered_at_ms);
        Ok(Some(SessionRunWait {
            key,
            answerable: answerable(&wait),
            wait,
            delivered_at_ms,
        }))
    }

    /// Delivers `reply` to the wait the run is parked on now, once: the run
    /// takes it at its next entry. `expected_wait` and `expected_generation`,
    /// each when given, name the wait the answer is for, so an answer meant
    /// for a wait the run has since left answers nothing. A reply already
    /// delivered stands, and this one is not delivered.
    ///
    /// # Errors
    ///
    /// No record of the run in the stretch; a run that waits on nothing, on
    /// another wait than the one expected, or on a wait whose own settler
    /// answers it ([`answerable`]); a storage error.
    pub fn answer_wait(
        &self,
        expected_wait: Option<EntityId>,
        expected_generation: Option<u64>,
        reply: &Value,
    ) -> MemoryResult<SessionWaitAnswer> {
        let record = self.record()?;
        let Some((key, wait)) = parked_wait_now(&self.storage, &record).map_err(engine_error)?
        else {
            return Err(invalid_state(
                format!("run {} waits on nothing", self.run_ref),
                "Enter the run again with self.off_record.execute.",
            ));
        };
        if expected_wait.is_some_and(|wait_id| wait_id != key.wait_id)
            || expected_generation.is_some_and(|generation| generation != key.generation)
        {
            return Err(invalid_state(
                format!("run {} waits on another wait now", self.run_ref),
                "Read the run's wait with self.off_record.waits.get, then answer that one.",
            ));
        }
        if !answerable(&wait) {
            return Err(invalid_state(
                format!(
                    "run {} waits on a {} that its own settler answers, not a reply",
                    self.run_ref,
                    wait.effect.as_str()
                ),
                "Enter the run again with self.off_record.execute once it has settled.",
            ));
        }
        // Whose reply stands is the settle's own put-if-absent, so two
        // concurrent answers never both hear that theirs was delivered.
        let (won, settled) =
            self.deliveries
                .settle_reporting(key.wait_id, reply, crate::unix_millis_now())?;
        Ok(SessionWaitAnswer {
            key,
            already_answered: !won,
            delivered_at_ms: settled.delivered_at_ms,
        })
    }
}

/// Whether a reply from the run's runner is what `wait` waits for: a human
/// input, or the approval of an effect the run raised itself. A peer's
/// result (a task, a reader child's finding, a summary, a hook's ask) and a
/// connector call's or a code consent's settlement are answered by their
/// own settlers, never by a reply (lead ruling, FIX 4284).
#[must_use]
pub fn answerable(wait: &SelfDurableWait) -> bool {
    wait.reason != SelfDurableWaitReason::PeerResult && wait.effect != SelfEffect::AgentVerb
}

fn invalid_state(message: String, suggestion: &str) -> MemoryError {
    MemoryError::new(MEMORY_CODE_INVALID_STATE, message, &[suggestion])
}

fn engine_error(error: EngineExecutorError) -> MemoryError {
    match error {
        EngineExecutorError::Engine(error) => MemoryError::from(error),
        other => MemoryError::new(MEMORY_CODE_INTERNAL, other.to_string(), &[]),
    }
}
