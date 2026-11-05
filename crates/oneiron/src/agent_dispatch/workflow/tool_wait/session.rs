//! Native ephemeral checkpoint location and publication, beside its queue fence.

use heed::RoTxn;

use super::{
    CheckpointContent, CheckpointRow, TABLE, WorkflowToolProgress, WorkflowToolTranscript,
    body_owner, check_progress_in_txn, fence, identity_in_txn, invalid, key,
    lineage_identity_in_txn, output, release_in_txn, validate_transcript,
};
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptResumePoint, HoldAttemptForHook};
use crate::off_record::{OffRecordMode, OffRecordSession, SessionWriteRoute};
use crate::session_overlay::RouteTarget;
use crate::{Result, Vault};

pub(super) struct LocatedCheckpoint<'vault> {
    pub(super) row: CheckpointRow,
    pub(super) session: Option<OffRecordSession<'vault>>,
}

fn sessions_in_txn<'vault>(
    vault: &'vault Vault,
    txn: &RoTxn<'_>,
    actual: &AttemptRecord,
) -> Result<Vec<(OffRecordSession<'vault>, OffRecordMode)>> {
    let (actor, room) = lineage_identity_in_txn(vault, txn, actual)?;
    let Some(room) = room else {
        return Ok(Vec::new());
    };
    // A positive deletion is a lost payload, not a new roster/join error
    // that would keep an eligible fenced leaf waiting forever.
    if crate::ports::owner_gone_in_txn(&vault.store, txn, &actor.entity_ref())?
        || crate::ports::owner_gone_in_txn(&vault.store, txn, &room)?
    {
        return Ok(Vec::new());
    }
    let subject = crate::workspace_roster::join_subject_for_actor_in_txn(
        vault,
        txn,
        actor.entity_ref(),
        vault.store.clock.now_recorded_at(),
    )?;
    let factory = vault.off_record_session_vault();
    factory
        .room_stretches_for(room, subject.id())?
        .into_iter()
        .map(|(key, instance, mode)| {
            let session = factory
                .bind_for(&key, subject.id())?
                .for_participant(subject.id())?;
            let record = vault
                .off_record_session(&key)?
                .ok_or_else(|| invalid("workflow session disappeared while binding"))?;
            if record.instance_ref != instance {
                return Err(invalid("workflow session instance changed"));
            }
            Ok((session, mode))
        })
        .collect()
}

/// The canonical row wins only while it really exists. Migration removes it
/// in the fence writer; a close or crash can never fall back to its old body.
/// The native publication barrier closes BASE-commit -> segment-publish for
/// queue writers, without holding a session-state mutex across a writer.
pub(super) fn locate_in_txn<'vault>(
    vault: &'vault Vault,
    txn: &RoTxn<'_>,
    actual: &AttemptRecord,
) -> Result<Option<LocatedCheckpoint<'vault>>> {
    let k = key(actual.id)?;
    if let Some(row) = TABLE.get(&vault.store, txn, &k)? {
        return Ok(Some(LocatedCheckpoint { row, session: None }));
    }
    if !fence::check(&vault.store, txn, actual)? {
        return Ok(None);
    }
    let mut found = None;
    for (session, _) in sessions_in_txn(vault, txn, actual)? {
        let row = {
            let view = session.checkpoint_view_in_txn(txn)?;
            TABLE.get(&view, txn, &k)?
        };
        if let Some(row) = row {
            if found.is_some() {
                return Err(invalid("workflow checkpoint has multiple live sessions"));
            }
            found = Some(LocatedCheckpoint {
                row,
                session: Some(session),
            });
        }
    }
    Ok(found)
}

impl LocatedCheckpoint<'_> {
    pub(super) fn generation_matches(&self, actual: &AttemptRecord) -> bool {
        self.row.attempt == actual.id
            && if self.session.is_some() {
                // The canonical fence carries every claim's generation. Session
                // metadata is rewritten only when its next payload is published.
                self.row.generation <= actual.attempt_count
            } else {
                self.row.generation == actual.attempt_count
            }
    }

    pub(super) fn transcript_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
    ) -> Result<Option<WorkflowToolTranscript>> {
        let Some(session) = &self.session else {
            return super::transcript_in_txn(vault, txn, &self.row);
        };
        let Some(content) = &self.row.content else {
            return Ok(None);
        };
        let view = session.checkpoint_view_in_txn(txn)?;
        let current = TABLE
            .get(&view, txn, &key(self.row.attempt)?)?
            .ok_or_else(|| invalid("workflow session checkpoint disappeared"))?;
        if current.attempt != self.row.attempt
            || current.generation != self.row.generation
            || current.content.as_ref() != Some(content)
        {
            return Err(invalid(
                "workflow session checkpoint changed during its read",
            ));
        }
        let transcript = session
            .checkpoint_body_in_txn(&view, txn, content.body_owner, &output(content))?
            .map(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("stored workflow transcript does not decode"))
            })
            .transpose()?;
        session.admit_participant()?;
        Ok(transcript)
    }
}

/// One model/tool run's actual session route, captured before its first
/// request. It contains no raw-payload map or durable session locator.
pub struct WorkflowToolCheckpointWriter<'vault> {
    vault: &'vault Vault,
    leased: AttemptRecord,
    session: Option<(OffRecordSession<'vault>, SessionWriteRoute)>,
    first_publication: bool,
}

impl<'vault> crate::agent_dispatch::AgentDispatcher<'vault> {
    pub fn workflow_tool_checkpoint_writer(
        &self,
        leased: &AttemptRecord,
    ) -> Result<WorkflowToolCheckpointWriter<'vault>> {
        let mut writer = WorkflowToolCheckpointWriter {
            vault: self.vault,
            leased: leased.clone(),
            session: None,
            first_publication: false,
        };
        let txn = self.vault.store.env.read_txn()?;
        let actual = super::runtime::leased_row(self.vault, &txn, leased)?;
        if let Some(located) = locate_in_txn(self.vault, &txn, &actual)? {
            if let Some(session) = located.session {
                writer.bind(session)?;
            }
        } else if fence::check(&self.vault.store, &txn, &actual)? {
            return Err(invalid("workflow checkpoint payload is unavailable"));
        }
        writer.bind_live_in_txn(&txn, &actual)?;
        Ok(writer)
    }
}

impl<'vault> WorkflowToolCheckpointWriter<'vault> {
    fn bind(&mut self, session: OffRecordSession<'vault>) -> Result<()> {
        let route = session.write_route()?;
        if route.target() == RouteTarget::Base {
            return Err(invalid("workflow session checkpoint route changed"));
        }
        self.session = Some((session, route));
        Ok(())
    }

    fn bind_live_in_txn(&mut self, txn: &RoTxn<'_>, actual: &AttemptRecord) -> Result<()> {
        if let Some((_, route)) = &self.session {
            // Capture anonymous talk too; only retaining a checkpoint invokes
            // its native OffRecordTalkOnly refusal.
            return route.revalidate();
        }
        // room_stretches_for is in registry-key order. Keep that actual
        // instance for the entire run; never re-mint after a flip or close.
        for (session, mode) in sessions_in_txn(self.vault, txn, actual)? {
            if mode != OffRecordMode::OnRecord {
                self.bind(session)?;
                break;
            }
        }
        Ok(())
    }

    fn reserve_first_publication(&mut self) -> Result<()> {
        if !self
            .session
            .as_ref()
            .is_some_and(|(_, route)| route.target() == RouteTarget::Overlay)
        {
            return Ok(());
        }
        let mut txn = self.vault.store.env.write_txn()?;
        let actual = super::runtime::leased_row(self.vault, &txn, &self.leased)?;
        if !fence::check(&self.vault.store, &txn, &actual)? {
            if TABLE
                .get(&self.vault.store, &txn, &key(actual.id)?)?
                .is_some()
            {
                return Err(invalid("workflow checkpoint is missing its fence"));
            }
            // The host has a paid response/tool result to retain. If its
            // first session publication fails, a lost payload is never Fresh.
            // Provider failures before save() still use ordinary retries.
            fence::put(&self.vault.store, &mut txn, &actual)?;
            txn.commit()?;
            self.first_publication = true;
        }
        Ok(())
    }

    pub fn save(
        &mut self,
        transcript: &WorkflowToolTranscript,
        progress: WorkflowToolProgress,
        park_at: Option<u64>,
    ) -> Result<()> {
        if progress.wait.is_some() != park_at.is_some() {
            return Err(invalid("workflow checkpoint wait and park disagree"));
        }
        self.reserve_first_publication()?;
        // Recheck at publication: a room may have gone off record while its
        // model/tool ran. No canonical sink exists before this route check.
        let vault = self.vault;
        let txn = vault.store.env.read_txn()?;
        let actual = super::runtime::leased_row(vault, &txn, &self.leased)?;
        self.bind_live_in_txn(&txn, &actual)?;
        drop(txn);
        self.reserve_first_publication()?;
        if let Some((session, route)) = &self.session {
            let result = self.write_session(session, route, transcript, progress, park_at);
            if result.is_ok() {
                self.first_publication = false;
            }
            result
        } else {
            if progress.no_record_at_arrival {
                return Err(invalid("workflow no-record session is unavailable"));
            }
            crate::agent_dispatch::AgentDispatcher::new(self.vault).write_workflow_tool_progress(
                &self.leased,
                transcript,
                progress,
                park_at,
            )
        }
    }

    fn write_session(
        &self,
        session: &OffRecordSession<'_>,
        route: &SessionWriteRoute,
        transcript: &WorkflowToolTranscript,
        mut progress: WorkflowToolProgress,
        park_at: Option<u64>,
    ) -> Result<()> {
        progress.no_record_at_arrival = true;
        let bytes = serde_json::to_vec(transcript)
            .map_err(|error| invalid(&format!("workflow transcript: {error}")))?;
        validate_transcript(transcript, &progress)?;
        let body: crate::code_run::SessionCheckpointBody =
            session.stage_checkpoint_body(route, super::BODY_PATH.to_owned(), &bytes)?;
        let admitted: WorkflowToolTranscript =
            serde_json::from_slice(&body.admitted_bytes(session)?)
                .map_err(|_| invalid("admitted workflow transcript does not decode"))?;
        validate_transcript(&admitted, &progress)?;
        session.routed_side_txn(route, |txn, read, write| {
            let crate::side_table::RoutedDbs::Session(view) = write else {
                return Err(invalid("workflow session checkpoint route changed"));
            };
            let actual = super::runtime::leased_row(self.vault, txn, &self.leased)?;
            let (actor, room) = identity_in_txn(self.vault, txn, &actual)?;
            check_progress_in_txn(self.vault, txn, &actual, actor, &progress)?;
            let k = key(actual.id)?;
            let prior = TABLE.get(&read, txn, &k)?;
            let fenced = fence::check(&self.vault.store, txn, &actual)?;
            if fenced != prior.is_some() && !(self.first_publication && fenced && prior.is_none()) {
                return Err(invalid("workflow checkpoint payload is unavailable"));
            }
            let owner = body_owner(actual.id)?;
            if let Some(prior) = &prior {
                if prior.attempt != actual.id
                    || prior.generation > actual.attempt_count
                    || prior.content.is_none()
                {
                    return Err(invalid("workflow checkpoint is unavailable"));
                }
                let content = prior
                    .content
                    .as_ref()
                    .ok_or_else(|| invalid("workflow checkpoint is unavailable"))?;
                if content.body_owner != owner {
                    return Err(invalid("workflow checkpoint has foreign body owner"));
                }
                for source in &content.progress.known_sources {
                    if !progress.known_sources.contains(source) {
                        progress.known_sources.push(*source);
                    }
                }
            }
            for source in progress.known_sources.iter().copied().chain(room) {
                if crate::ports::owner_gone_in_txn(&self.vault.store, txn, &source)? {
                    return Err(invalid("workflow checkpoint source is erased"));
                }
            }
            // The canonical predecessor contains only earlier on-record
            // bytes. Remove its checkpoint pointer in this same writer so
            // close/crash never makes it a continuation fallback.
            if let Some(canonical) = TABLE.get(&self.vault.store, txn, &k)? {
                if let Some(content) = canonical.content {
                    release_in_txn(&self.vault.store, txn, &content)?;
                }
                TABLE.delete(&self.vault.store, txn, &k)?;
            }
            session.put_checkpoint_body_in_txn(route, view, txn, &body, owner)?;
            let row = CheckpointRow {
                attempt: actual.id,
                generation: actual.attempt_count,
                content: Some(CheckpointContent {
                    actor: actor.entity_ref(),
                    actor_class: actor.actor_class(),
                    room,
                    progress: progress.clone(),
                    body_owner: owner,
                    body: body.output().output_ref(),
                    published_digests: Vec::new(),
                }),
                retained: None,
            };
            TABLE.put(view, txn, &k, &row)?;
            fence::put(&self.vault.store, txn, &actual)?;
            if let Some(now) = park_at {
                let wait = progress
                    .wait
                    .as_ref()
                    .ok_or_else(|| invalid("workflow tool park has no wait"))?;
                AttemptQueue::new(self.vault).hold_for_hook_in_txn(
                    txn,
                    HoldAttemptForHook {
                        id: actual.id,
                        lease_owner: actual
                            .lease_owner
                            .ok_or_else(|| invalid("workflow lease is missing"))?,
                        attempt_count: actual.attempt_count,
                        invocation: wait.invocation,
                        resume_point: AttemptResumePoint::new("workflow-step:tool-hook", now),
                        now,
                    },
                )?;
            }
            Ok(())
        })?;
        if park_at.is_some() {
            self.vault.store.notify_attempt_observers();
        }
        session.admit_participant()
    }
}
