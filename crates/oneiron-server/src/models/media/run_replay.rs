//! One in-flight media run per replay key, without keeping another durable memo.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use oneiron::llm::media::{MediaReplayKey, MediaResponse};
use oneiron::{LlmResult, RetryableLlmError};
use tokio::sync::watch;

type Answer = Arc<RunAnswer>;
type Receiver = watch::Receiver<Option<Answer>>;

pub(super) struct RunAnswer {
    pub(super) result: LlmResult<MediaResponse>,
    pub(super) admitted: bool,
}

#[derive(Default)]
pub(super) struct ReplayRuns {
    active: Mutex<BTreeMap<String, Receiver>>,
}

pub(super) enum Claim<'a> {
    Leader(Leader<'a>),
    Follower(Follower),
}

pub(super) struct Leader<'a> {
    runs: &'a ReplayRuns,
    key: String,
    answer: watch::Sender<Option<Answer>>,
}

pub(super) struct Follower(Receiver);

impl ReplayRuns {
    pub(super) fn claim(&self, key: &MediaReplayKey) -> Claim<'_> {
        let key = key.memo_id();
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(answer) = active.get(&key) {
            return Claim::Follower(Follower(answer.clone()));
        }
        let (answer, receiver) = watch::channel(None);
        active.insert(key.clone(), receiver);
        Claim::Leader(Leader {
            runs: self,
            key,
            answer,
        })
    }
}

impl Leader<'_> {
    pub(super) fn finish(
        self,
        result: LlmResult<MediaResponse>,
        admitted: bool,
    ) -> LlmResult<MediaResponse> {
        let answer = Arc::new(RunAnswer { result, admitted });
        let _ = self.answer.send_replace(Some(Arc::clone(&answer)));
        drop(self);
        Arc::try_unwrap(answer)
            .map(|answer| answer.result)
            .unwrap_or_else(|answer| answer.result.clone())
    }
}

impl Drop for Leader<'_> {
    fn drop(&mut self) {
        self.runs
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
    }
}

impl Follower {
    pub(super) async fn answer(mut self) -> LlmResult<Answer> {
        loop {
            let answer = self.0.borrow_and_update().clone();
            if let Some(answer) = answer {
                return Ok(answer);
            }
            if self.0.changed().await.is_err() {
                return Err(RetryableLlmError::StreamCut.into());
            }
        }
    }
}
