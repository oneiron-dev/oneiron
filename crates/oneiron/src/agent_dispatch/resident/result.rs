//! Durable result TURNs and the bodies their records hold.

use crate::agent_dispatch::AgentDispatcher;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, SetAttemptResult,
};
use crate::code_run::CodeRunReplayRecord;
use crate::error::{Error, Result};
use crate::provenance::body::{BodyLocation, BodyRef, BodyState, OwnedBody};
use crate::{EntityId, TimeRange};
use rmpv::Value;

/// A completed agent run's result TURN. Parts: attempt.
const RUN_RESULT: &[u8] = b"oneiron:agent-run-result:v1";
/// The run's answer body, as the result TURN holds it. Parts: result TURN.
const RUN_RESULT_BODY: &[u8] = b"oneiron:agent-run-result-body:v1";

struct PreparedRunResult {
    id: EntityId,
    bytes: Vec<u8>,
    held: Option<OwnedBody>,
}

impl AgentDispatcher<'_> {
    /// Gives a completed agent run its durable result before the runner
    /// completes the attempt: one TURN naming the answer of the run's
    /// finished step, which holds that body for as long as the TURN lives
    /// (OF-597), set as the attempt's result so the task highway's Done
    /// resolves it. The TURN's id derives from the attempt, so a replayed
    /// completion finds the TURN it made.
    pub fn attach_agent_run_result(
        &self,
        attempt: &AttemptRecord,
        lease_owner: &str,
        run: &CodeRunReplayRecord,
        now: u64,
    ) -> Result<EntityId> {
        let result = self.prepare_agent_run_result(attempt, run)?;
        let mut txn = self.vault.store.env.write_txn()?;
        self.put_agent_run_result_in_txn(&mut txn, &result, now)?;
        AttemptQueue::new(self.vault).set_result_in_txn(
            &mut txn,
            SetAttemptResult {
                id: attempt.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: attempt.attempt_count,
                result_ref: AttemptResultRef::new(result.id.to_hex())?,
                now,
            },
        )?;
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(result.id)
    }

    /// Records this run's own complete answer for attribution without changing
    /// the attempt's result. A self-settled TASK keeps its existing result
    /// handle; another actor's TASK result is not evidence of this run's output.
    /// No complete answer or no retained body leaves the output unknown.
    pub fn attach_agent_run_attribution_output(
        &self,
        attempt: &AttemptRecord,
        lease_owner: &str,
        run: &CodeRunReplayRecord,
        now: u64,
    ) -> Result<Option<EntityId>> {
        let Some(answer) = run
            .outputs
            .iter()
            .rev()
            .find(|output| output.complete && output.path.ends_with(".observation.txt"))
        else {
            return Ok(None);
        };
        if self.vault.get_code_run_raw_output(answer)?.is_none() {
            return Ok(None);
        }
        let result = self.prepare_agent_run_result(attempt, run)?;
        let mut txn = self.vault.store.env.write_txn()?;
        AttemptQueue::new(self.vault).require_skill_load_lease_in_txn(
            &txn,
            attempt.id,
            lease_owner,
            attempt.attempt_count,
        )?;
        // FIX 4747: the run's result TURN, only while its run TASK names the
        // holding its claim took.
        crate::agent_dispatch::fence_agent_run_settlement_in_txn(self.vault, &txn, attempt.id)?;
        self.put_agent_run_result_in_txn(&mut txn, &result, now)?;
        txn.commit()?;
        Ok(Some(result.id))
    }

    fn prepare_agent_run_result(
        &self,
        attempt: &AttemptRecord,
        run: &CodeRunReplayRecord,
    ) -> Result<PreparedRunResult> {
        let result_ref = EntityId::derive(RUN_RESULT, &[attempt.id.as_bytes().as_slice()])?;
        // The finished step's observation, never a marker or a file the run
        // wrote after it.
        let answer = run
            .outputs
            .iter()
            .rev()
            .find(|output| output.complete && output.path.ends_with(".observation.txt"));
        let field = |key: &str, value: Value| (Value::from(key), value);
        let artifact = Value::Map(vec![
            field("kind", Value::from("agent.run_result")),
            field(
                "attempt_ref",
                Value::from(crate::entity_id::bytes_to_hex_lower(attempt.id.as_bytes())),
            ),
            field("run_ref", Value::from(run.run_id.to_hex())),
            field(
                "task_ref",
                attempt.task_ref.clone().map_or(Value::Nil, Value::from),
            ),
            field(
                "answer",
                answer.map_or(Value::Nil, |output| {
                    Value::Map(vec![
                        field("path", Value::from(output.path.clone())),
                        field("handle", Value::from(output.handle.clone())),
                        field("bytes", Value::from(output.raw_len)),
                        field("lines", Value::from(output.lines)),
                    ])
                }),
            ),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &artifact)
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        // An inline body lives in the run's own rows; only a file needs a holder.
        let held = match answer {
            Some(output)
                if self
                    .vault
                    .store
                    .body_file_present(&output.raw_blake3, output.raw_len)? =>
            {
                Some(OwnedBody {
                    owner: result_ref,
                    occurrence: EntityId::derive(
                        RUN_RESULT_BODY,
                        &[result_ref.as_bytes().as_slice()],
                    )?,
                    state: BodyState::Complete {
                        body: BodyRef {
                            blake3: output.raw_blake3,
                            bytes: output.raw_len,
                            location: BodyLocation::File,
                        },
                    },
                    result: None,
                })
            }
            _ => None,
        };
        Ok(PreparedRunResult {
            id: result_ref,
            bytes,
            held,
        })
    }

    fn put_agent_run_result_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        result: &PreparedRunResult,
        now: u64,
    ) -> Result<()> {
        if self
            .vault
            .get_entity_type_in_txn(txn, &result.id)?
            .is_none()
        {
            self.vault
                .batch_in()
                .put(
                    &result.id,
                    crate::registry::ENTITY_TYPE_TURN,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &result.bytes,
                )
                .apply(txn)?;
        }
        if let Some(held) = &result.held {
            crate::provenance::body::publish_body_in_txn(&self.vault.store, txn, held)?;
        }
        Ok(())
    }

    /// The answer a completed agent run's result names, for a reader that
    /// must see exactly what the run produced (a seal check, OF-544):
    /// `result_ref` is the TURN [`Self::attach_agent_run_result`] made for
    /// `attempt`, and the answer is that run's own complete output, as its
    /// digest and length. `None` for any other result, a TURN with no answer,
    /// or a run that no longer holds that output. The TURN's id is never read
    /// as an output digest.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn agent_run_answer(
        &self,
        attempt: AttemptId,
        result_ref: &str,
    ) -> Result<Option<crate::compaction::output::OutputRef>> {
        Ok(self
            .agent_run_answer_with_turn(attempt, result_ref)?
            .map(|(answer, _)| answer))
    }

    /// [`Self::agent_run_answer`] with the result TURN it read the answer
    /// from (FIX 7103): one source of a seal check's prompt, never the whole
    /// set, since the answer's bytes and the check's objectives have their own.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn agent_run_answer_with_turn(
        &self,
        attempt: AttemptId,
        result_ref: &str,
    ) -> Result<Option<(crate::compaction::output::OutputRef, EntityId)>> {
        let Ok(turn) = EntityId::from_hex(result_ref) else {
            return Ok(None);
        };
        if turn != EntityId::derive(RUN_RESULT, &[attempt.as_bytes().as_slice()])? {
            return Ok(None);
        }
        let Some(bytes) = self.vault.get(&turn)? else {
            return Ok(None);
        };
        let Ok(artifact) = rmpv::decode::read_value(&mut bytes.as_slice()) else {
            return Ok(None);
        };
        let root = Some(&artifact);
        let attempt_ref = crate::entity_id::bytes_to_hex_lower(attempt.as_bytes());
        let kind = result_field(root, "kind").and_then(Value::as_str);
        let of = result_field(root, "attempt_ref").and_then(Value::as_str);
        if kind != Some("agent.run_result") || of != Some(attempt_ref.as_str()) {
            return Ok(None);
        }
        let answer = result_field(root, "answer");
        let run = result_field(root, "run_ref")
            .and_then(Value::as_str)
            .and_then(|run| EntityId::from_hex(run).ok());
        let handle = result_field(answer, "handle").and_then(Value::as_str);
        let length = result_field(answer, "bytes").and_then(Value::as_u64);
        let (Some(run), Some(handle), Some(length)) = (run, handle, length) else {
            return Ok(None);
        };
        let Some(replay) = self.vault.get_code_run_replay_record(&run)? else {
            return Ok(None);
        };
        Ok(replay
            .outputs
            .iter()
            .find(|output| output.complete && output.handle == handle && output.raw_len == length)
            .map(|output| (output.output_ref(), turn)))
    }
}

/// One key of a result TURN's map.
fn result_field<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    value?
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}
