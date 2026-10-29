//! Retained result doors. They inspect the durable record and use the same
//! result reader as MCP; recovery enters no run and invokes no effect.
//! The run-wide view is the owner's. A content handle is never authority.
mod types;
pub use types::*;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::code_run::{CodeRunRawOutput, CodeRunReplayRecord, ResultFacet, ResultOccurrence};
use crate::consent::AuthenticatedOwner;
use crate::engine_executor::is_result_output_path;
use crate::secret_rotation::ArtifactTaintState;

impl Memory<'_> {
    fn result_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<()> {
        if owner.revalidate(self.vault)? != self.actor
            || self.actor_class != crate::EdgeActorClass::Human
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "retained run results require the authenticated owner's own handle",
                &[],
            ));
        }
        if self.off_record_session.is_some() || self.room_turn.is_some() {
            return Err(MemoryError::bad_request(
                "canonical retained results are not read inside a session or room turn",
            ));
        }
        Ok(())
    }

    fn result_sources(&self, rows: Option<&[EntityId]>) -> crate::Result<bool> {
        self.produced_from(rows.into_iter().flatten().copied());
        if self.locality() == crate::claim::CallerLocality::OnDevice {
            return Ok(false);
        }
        let Some(rows) = rows else {
            return Ok(true);
        };
        let txn = self.vault.store.env.read_txn()?;
        let kept = crate::settings::device_local_worlds_for(self.vault, &txn, self.destination())?;
        for row in rows {
            if crate::settings::device_local_keeps_among(&self.vault.store, &txn, &kept, row)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The owner inspects already-published occurrences and pre-publication
    /// body descriptors. No missing body is represented as an empty success.
    pub fn result_status_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ResultRunRequest,
    ) -> MemoryResult<ResultRunStatus> {
        self.result_owner(owner)?;
        let record = self.vault.get_code_run_replay_record(&input.run_id)?;
        let rows = record
            .as_ref()
            .and_then(CodeRunReplayRecord::agent_verb_rows);
        if self.result_sources(rows.as_deref())? {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "result_withheld",
                &[],
            ));
        }
        let bodies = self
            .vault
            .owned_bodies(&input.run_id)?
            .into_iter()
            .map(|body| ResultBodyStatus {
                occurrence: body.occurrence,
                complete: body.state.is_complete(),
                retained: body.state.held().map(|held| ResultRetainedBody {
                    blake3: crate::entity_id::bytes_to_hex_lower(&held.blake3),
                    bytes: held.bytes,
                }),
            })
            .collect();
        let mut status = ResultRunStatus {
            run_id: input.run_id,
            replay_present: record.is_some(),
            checkpoint_count: 0,
            effects: Vec::new(),
            bodies,
            occurrences: Vec::new(),
        };
        if let Some(record) = record {
            status.checkpoint_count = record.step_checkpoints.len();
            status.effects = record
                .bridge_calls
                .iter()
                .map(|call| ResultEffectRecord {
                    seq: call.seq,
                    effect: call.effect.as_str().to_owned(),
                    action_digest: call.action_digest.clone(),
                    started_at_ms: call.started_at_ms,
                    finished_at_ms: call.finished_at_ms,
                })
                .collect();
            for output in record
                .outputs
                .iter()
                .filter(|output| is_result_output_path(&output.path))
            {
                status
                    .occurrences
                    .push(self.result_manifest(&record, output)?);
            }
        }
        Ok(status)
    }

    pub fn result_read_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ResultOccurrenceRequest,
    ) -> MemoryResult<ResultReadView> {
        self.result_owner(owner)?;
        let reply = self.result_read(input.run_id, input.occurrence, None, json!({}))?;
        if reply.get("denied").is_some() {
            return Ok(ResultReadView::Denied {
                refusal: decode(reply)?,
            });
        }
        let manifest = self.result_occurrence(input.run_id, input.occurrence)?;
        let card: ResultCard = decode(reply["output"].clone())?;
        Ok(ResultReadView::Available { manifest, card })
    }

    pub fn result_slice_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ResultSliceRequest,
    ) -> MemoryResult<ResultSliceView> {
        self.result_owner(owner)?;
        let selection = serde_json::to_value(input.selection).map_err(|_| {
            MemoryError::from(crate::Error::InvariantViolation("result selection encodes"))
        })?;
        let reply = self.result_read(
            input.run_id,
            input.occurrence,
            Some(ResultFacet::Slice),
            selection,
        )?;
        if reply.get("denied").is_some() {
            return Ok(ResultSliceView::Denied {
                refusal: decode(reply)?,
            });
        }
        let manifest = self.result_occurrence(input.run_id, input.occurrence)?;
        Ok(ResultSliceView::Available {
            manifest,
            page: decode(reply["output"].clone())?,
        })
    }

    fn result_read(
        &self,
        run_id: EntityId,
        occurrence: EntityId,
        facet: Option<ResultFacet>,
        input: Value,
    ) -> MemoryResult<Value> {
        Ok(self.vault.read_code_run_result(
            run_id,
            &format!("occurrence:{}", occurrence.to_hex()),
            facet,
            input,
            |rows| self.result_sources(rows),
        )?)
    }

    fn result_occurrence(
        &self,
        run_id: EntityId,
        occurrence: EntityId,
    ) -> MemoryResult<ResultOccurrenceManifest> {
        let record = self
            .vault
            .get_code_run_replay_record(&run_id)?
            .ok_or_else(|| MemoryError::not_found("result run not found"))?;
        for output in record
            .outputs
            .iter()
            .filter(|output| is_result_output_path(&output.path))
        {
            if ResultOccurrence::owned(run_id, &output.path)?.id() == occurrence {
                return self.result_manifest(&record, output);
            }
        }
        Err(MemoryError::not_found("result occurrence not found"))
    }

    fn result_manifest(
        &self,
        record: &CodeRunReplayRecord,
        output: &CodeRunRawOutput,
    ) -> MemoryResult<ResultOccurrenceManifest> {
        let owner = Some(record.run_id);
        let state = self.vault.code_run_raw_output_taint_state(owner, output)?;
        Ok(ResultOccurrenceManifest {
            run_id: record.run_id,
            occurrence: ResultOccurrence::owned(record.run_id, &output.path)?.id(),
            path: output.path.clone(),
            handle: output.handle.clone(),
            blake3: crate::entity_id::bytes_to_hex_lower(&output.raw_blake3),
            bytes: output.raw_len,
            kind: match output.kind {
                crate::code_run::CodeRunOutputKind::Text => ResultBodyKind::Text,
                crate::code_run::CodeRunOutputKind::Binary => ResultBodyKind::Binary,
            },
            lines: output.lines,
            complete: output.complete,
            taint: ResultTaint {
                state: match state {
                    ArtifactTaintState::Clean => ResultTaintState::Clean,
                    ArtifactTaintState::TaintedLive => ResultTaintState::TaintedLive,
                    ArtifactTaintState::TaintedStale => ResultTaintState::TaintedStale,
                },
                secret: self.vault.code_run_raw_output_secret(owner, output)?,
            },
            taint_refs: self
                .vault
                .code_run_raw_output_taint_refs(owner, output)?
                .into_iter()
                .map(|reference| ResultTaintReference {
                    secret_ref: reference.secret_ref,
                    generation: reference.generation,
                })
                .collect(),
            source_rows: record.agent_verb_rows(),
        })
    }
}

fn decode<T: DeserializeOwned>(value: Value) -> MemoryResult<T> {
    serde_json::from_value(value).map_err(|_| {
        MemoryError::from(crate::Error::InvariantViolation(
            "retained result reply has its typed shape",
        ))
    })
}
