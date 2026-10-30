//! A job's submit kept before it goes out, and keyed replays (FIX 2248,
//! FIX 2962, FIX 465). A job's ticket is minted, held here and kept in its
//! row before its provider hears of the job, and its submit goes out under
//! the ticket as its idempotency key. A restart that cut the submit short
//! finds the row with no provider job: a wire that dedupes by the key is
//! sent it again to learn the job it started, and any other keeps the row
//! as lost, ended, never dropped.
//!
//! A call that carries a replay key (a durable step's, or its caller's
//! own) is known by it. A job's repeat answers the first's ticket and is
//! never sent again, and its polls answer from that ticket. A call's
//! repeat answers the answer kept for the first, unpaid, until it expires.
//! A call in a banked voice is never replayed: a voice its owner withdrew
//! since speaks no more. With no key, every call goes out as before.
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::llm::media::MediaReplayKey;

use super::job_lifecycle::JobWrite;
use super::{
    Arc, FatalLlmError, Held, JobRow, JobStore, KeptJob, LlmError, LlmResult, MediaAnswer,
    MediaJobState, MediaRequest, MediaResponse, MediaRuntime, MediaTicket, ModelId, PayerPerson,
    RungVoices, submit_stamps,
};

/// What a job's ticket begins with.
pub(super) const JOB_TICKET: &str = "job_";

/// What a replayed call's kept answer begins with: no job a poll reaches.
const REPLAY_TICKET: &str = "memo_";

/// How long a replayed call's kept answer answers its repeats (FIX 2962).
const MEDIA_REPLAY_KEEP_SECS: u64 = 86_400;

/// Sets apart two fresh tickets minted in the same nanosecond.
static MINTED: AtomicU64 = AtomicU64::new(0);

/// Whether `ticket` names a replayed call's kept answer, not a job.
pub(super) fn is_replay(ticket: &str) -> bool {
    ticket.starts_with(REPLAY_TICKET)
}

/// Lets go of the replayed call's kept answer `ticket` once it expired.
pub(super) fn reclaim_replay(store: &JobStore, ticket: &str) {
    let expired = match store.read(ticket, false) {
        Some(KeptJob::Row(row)) => row.replay_until_s.is_none_or(|until| until <= now_s()),
        Some(KeptJob::Erased) | None => false,
    };
    if expired && let Err(error) = store.delete(ticket) {
        tracing::warn!(%error, ticket, "an expired media answer was not let go");
    }
}

/// A fresh job's ticket: the server's own id, minted before its provider
/// is asked, so a caller never names a provider's id.
pub(super) fn fresh_ticket() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let mut digest = blake3::Hasher::new();
    digest.update(&nanos.to_le_bytes());
    digest.update(&MINTED.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    digest.update(&std::process::id().to_le_bytes());
    format!("{JOB_TICKET}{}", &digest.finalize().to_hex()[..24])
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl MediaRuntime {
    /// [`Self::submit`], known by `replay` when its caller has one (FIX
    /// 2962, FIX 465): a repeat answers the first's ticket and nothing is
    /// sent again. Its row is kept before its provider hears of the job, and
    /// its submit goes out under its ticket (FIX 2248).
    pub async fn submit_replayed(
        &self,
        request: MediaRequest,
        payer: Option<PayerPerson>,
        actor: Option<oneiron::EntityId>,
        sources: Option<Vec<oneiron::EntityId>>,
        replay: Option<MediaReplayKey>,
    ) -> LlmResult<MediaTicket> {
        if !request.operation.is_job() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let operation = request.operation;
        let id = match &replay {
            Some(key) => format!("{JOB_TICKET}{}", key.memo_id()),
            None => fresh_ticket(),
        };
        let ticket = |model: &ModelId| MediaTicket {
            job: id.clone(),
            model: model.to_string(),
            operation,
        };
        if let Some(model) = self.claim_submit(&id, &request.model, replay.is_some()) {
            return Ok(ticket(&model));
        }
        let mut row = self.store.as_ref().map(|_| JobRow {
            model: request.model.clone(),
            operation,
            provider_job: None,
            request: request.clone(),
            ended: None,
            receipt: None,
            payer: payer.clone(),
            stamps: submit_stamps(actor, &request),
            erased: false,
            replay_until_s: None,
            paid: false,
            line: None,
        });
        // A row the vault refuses here is written again once the job is
        // known.
        let intent = match (&self.store, &row) {
            (Some(store), Some(row)) => store.put(&id, row.clone()),
            _ => Ok(false),
        };
        if let Err(error) = &intent {
            tracing::error!(
                %error,
                ticket = %id,
                "a media job's submit was not kept before it went out"
            );
        }
        let intent = matches!(intent, Ok(true));
        let answer = match self.walk(request, None, payer, sources, Some(id.clone())) {
            Ok(walk) => walk.await,
            Err(error) => Err(error),
        };
        let job = match answer {
            Ok(MediaAnswer::Job(job)) => job,
            Ok(MediaAnswer::Done(_)) => {
                self.unclaim(&id, intent);
                return Err(FatalLlmError::EmptyResponse.into());
            }
            Err(error) => {
                self.unclaim(&id, intent);
                return Err(error);
            }
        };
        if let Some(row) = &mut row {
            row.model = job.model.clone();
            row.provider_job = Some(job.provider_job.clone());
            row.receipt = job.receipt.clone();
        }
        let answer = ticket(&job.model);
        self.keep_submitted(&id, row, intent);
        self.lock_jobs()
            .insert(id, Held::Running(Arc::new(tokio::sync::Mutex::new(job))));
        Ok(answer)
    }

    /// [`Self::run`], or [`Self::run_voiced`] in `voices`, known by
    /// `replay` when its caller has one (FIX 2962): a repeat of the call
    /// under its key answers the answer kept for the first, unpaid, until
    /// it expires, and one an erase took answers that it was erased. A call
    /// in a banked voice is never replayed or kept. Its kept answer is
    /// stamped with `actor` and its request's subject, as a job's row is
    /// (KS-2B2).
    pub(crate) async fn run_replayed(
        &self,
        request: MediaRequest,
        voices: Option<&RungVoices>,
        payer: Option<PayerPerson>,
        sources: Option<Vec<oneiron::EntityId>>,
        actor: Option<oneiron::EntityId>,
        replay: Option<MediaReplayKey>,
    ) -> LlmResult<MediaResponse> {
        let (Some(key), None) = (&replay, voices) else {
            return self.run_in(request, voices, payer, sources).await;
        };
        if let Some(answer) = self.replay_answer(key) {
            return answer;
        }
        let kept = request.clone();
        let response = self.run_in(request, None, payer.clone(), sources).await?;
        self.keep_replay_answer(key, &kept, &response, actor, payer);
        Ok(response)
    }

    /// The answer the call `key` knows keeps for its repeats, when one
    /// answers: the first's answer while it is fresh, or that an erase
    /// took it. None when nothing kept answers, or nothing is kept.
    pub(super) fn replay_answer(&self, key: &MediaReplayKey) -> Option<LlmResult<MediaResponse>> {
        let store = self.store.as_ref()?;
        let id = format!("{REPLAY_TICKET}{}", key.memo_id());
        match store.get(&id) {
            Some(KeptJob::Erased) => Some(Err(FatalLlmError::ResponseErased.into())),
            Some(KeptJob::Row(row)) if row.erased => {
                Some(Err(FatalLlmError::ResponseErased.into()))
            }
            Some(KeptJob::Row(JobRow {
                ended: Some(MediaJobState::Done { response }),
                replay_until_s: Some(until),
                ..
            })) if until > now_s() => Some(Ok(response)),
            _ => None,
        }
    }

    /// Keeps `response` as the answer the call `key` knows, for its repeats:
    /// stamped with `actor` and its request's subject, as a job's row is,
    /// unpaid, answered until it expires. A write the vault refuses keeps
    /// nothing, and the call still answers.
    pub(super) fn keep_replay_answer(
        &self,
        key: &MediaReplayKey,
        request: &MediaRequest,
        response: &MediaResponse,
        actor: Option<oneiron::EntityId>,
        payer: Option<PayerPerson>,
    ) {
        let Some(store) = &self.store else {
            return;
        };
        let id = format!("{REPLAY_TICKET}{}", key.memo_id());
        let row = JobRow {
            model: response.model.clone(),
            operation: request.operation,
            provider_job: None,
            stamps: submit_stamps(actor, request),
            request: request.clone(),
            ended: Some(MediaJobState::Done {
                response: response.clone(),
            }),
            receipt: None,
            payer,
            erased: false,
            replay_until_s: Some(now_s().saturating_add(MEDIA_REPLAY_KEEP_SECS)),
            paid: false,
            line: None,
        };
        if let Err(error) = store.put(&id, row) {
            tracing::warn!(%error, "a media call's answer was not kept for its repeats");
        }
    }

    /// Holds `id` as a submit going out now, unless it is held here already
    /// or, when `keyed`, kept: then the model its ticket names.
    pub(super) fn claim_submit(&self, id: &str, model: &ModelId, keyed: bool) -> Option<ModelId> {
        let mut jobs = self.lock_jobs();
        if let Some(held) = jobs.get(id) {
            return Some(match held {
                Held::Submitting(model) => model.clone(),
                Held::Unsent(row) => row.model.clone(),
                Held::Running(_) | Held::Unkept(_) | Held::Ended(_) => self
                    .kept_model(id)
                    .flatten()
                    .unwrap_or_else(|| model.clone()),
            });
        }
        if keyed && let Some(kept) = self.kept_model(id) {
            return Some(kept.unwrap_or_else(|| model.clone()));
        }
        jobs.insert(id.to_owned(), Held::Submitting(model.clone()));
        None
    }

    /// The model job `id`'s kept row names, read without its clips, when a
    /// row is kept; `Some(None)` for an erased job's, which names none.
    fn kept_model(&self, id: &str) -> Option<Option<ModelId>> {
        match self.store.as_ref()?.read(id, false)? {
            KeptJob::Row(row) => Some(Some(row.model)),
            KeptJob::Erased => Some(None),
        }
    }

    /// Lets go of the submit `id` that went out and started no job: its
    /// intent row, when kept, goes too, so a repeat goes out afresh.
    pub(super) fn unclaim(&self, id: &str, intent: bool) {
        let mut jobs = self.lock_jobs();
        if intent
            && let Some(store) = &self.store
            && let Err(error) = store.delete(id)
        {
            tracing::error!(
                %error,
                ticket = id,
                "a failed submit's row was not dropped; a restart reads it lost"
            );
        }
        jobs.remove(id);
    }

    /// Keeps the row of job `id` its provider answered, over its intent row
    /// when that was kept. A row the vault refuses is kept as the job's held
    /// write (FIX 2963), and one refused there too leaves the job running
    /// here only.
    fn keep_submitted(&self, id: &str, row: Option<JobRow>, intent: bool) {
        let (Some(store), Some(row)) = (&self.store, row) else {
            return;
        };
        let row_kept = row.clone();
        let kept = match intent {
            true => store
                .update(id, row.clone())
                .and_then(|written| match written {
                    JobWrite::Kept | JobWrite::Erased => Ok(true),
                    JobWrite::Deleted => store.put(id, row),
                }),
            false => store.put(id, row),
        };
        // FIX 2963: a row the vault refuses is held as the job's held write.
        if let Err(error) = kept.or_else(|_| store.hold(id, row_kept).map(|()| true)) {
            tracing::error!(%error, ticket = id, "a media job was not kept: it runs held here");
        }
    }

    /// What a kept job a restart cut short before its provider answered is
    /// held as (FIX 2248): one to send again under its key, when every rung
    /// that could have taken it dedupes by the key, else ended as lost.
    pub(super) fn unsent(&self, id: &str, row: JobRow) -> Held {
        if self.submit_dedupes(&row.request) {
            return Held::Unsent(Box::new(row));
        }
        Held::Ended(self.lost(id, row))
    }

    /// Sends kept job `id`'s submit again under its key, to a wire that
    /// dedupes by it, so the job its first submit started is learned and
    /// taken up on a fresh permit (FIX 2248). A job a spend scope funds is
    /// sent on a fresh guard of that scope's own, as its take-up runs
    /// ([`Self::job_run`]), and what that guard used is booked on the scope
    /// when its permit settles (FIX 11726); any other goes on the media
    /// meter. A send that fails leaves it to its next poll, its scope booked
    /// with what the send charged; one that starts no job ends it as lost.
    pub(super) async fn resubmit_kept(&self, id: &str, row: JobRow) -> LlmResult<MediaJobState> {
        if self.claim_submit(id, &row.model, false).is_some() {
            return Ok(MediaJobState::Queued);
        }
        let answer = if row.line.as_ref().is_some_and(|line| line.scope.is_some()) {
            match self
                .job_run(id, &row)
                .and_then(|run| Ok((self.ladder(&row.request)?, run)))
            {
                Ok((ladder, run)) => {
                    let run = run.submit_keyed(Some(id.to_owned()));
                    let deadline = crate::models::CallDeadline::Open;
                    ladder
                        .media_by(&run, row.request.clone(), None, None, deadline)
                        .await
                }
                Err(error) => Err(error),
            }
        } else {
            let sent = self.walk(
                row.request.clone(),
                None,
                row.payer.clone(),
                None,
                Some(id.to_owned()),
            );
            match sent {
                Ok(walk) => walk.await,
                Err(error) => Err(error),
            }
        };
        let job = match answer {
            Ok(MediaAnswer::Job(job)) => job,
            Ok(MediaAnswer::Done(_)) => {
                self.lock_jobs().remove(id);
                self.book_job_scope(id);
                return Ok(self.lost(id, row));
            }
            Err(error) => {
                self.lock_jobs().remove(id);
                self.book_job_scope(id);
                return Err(error);
            }
        };
        let mut row = row;
        row.model = job.model.clone();
        row.provider_job = Some(job.provider_job.clone());
        row.receipt = job.receipt.clone();
        self.keep_submitted(id, Some(row), true);
        self.lock_jobs().insert(
            id.to_owned(),
            Held::Running(Arc::new(tokio::sync::Mutex::new(job))),
        );
        Ok(MediaJobState::Queued)
    }

    /// Ends kept job `id` as lost (FIX 2248): its submit went out, its
    /// provider's answer never reached its row, and nothing here can find
    /// the job again; it may still run and bill there. The row keeps the
    /// end, so its ticket says so on every poll, and the loss is logged. An
    /// end the vault refuses is answered all the same.
    fn lost(&self, id: &str, mut row: JobRow) -> MediaJobState {
        tracing::error!(
            reason = "media_job_lost",
            ticket = id,
            model = %row.model,
            "a media job's submit went out unanswered, and its job cannot be found again"
        );
        let state = MediaJobState::Failed {
            error: LlmError::Fatal(FatalLlmError::EmptyResponse),
        };
        row.ended = Some(state.clone());
        if let Some(store) = &self.store
            && let Err(error) = store
                .update(id, row.clone())
                .or_else(|_| store.hold(id, row).map(|()| JobWrite::Kept))
        {
            tracing::error!(%error, ticket = id, "a lost media job's end was not kept");
        }
        state
    }

    /// Whether every rung that could take `request`'s job starts it once
    /// per idempotency key (FIX 2248).
    fn submit_dedupes(&self, request: &MediaRequest) -> bool {
        let Some(seat) = self.seats.get(&request.operation) else {
            return false;
        };
        let rungs: Vec<&ModelId> = if request.model == seat.model {
            seat.rungs.keys().collect()
        } else {
            vec![&request.model]
        };
        !rungs.is_empty()
            && rungs.into_iter().all(|model| {
                self.job_rungs
                    .get(model)
                    .and_then(|rung| rung.media.as_ref())
                    .is_some_and(|media| media.backend.submit_dedupes())
            })
    }
}
