//! Caller-retained session opens and causal queues for their actor/machine key.

use super::*;
use oneiron::runtime_hooks::verb::VerbHookWaitStatus;

#[derive(Debug)]
pub(super) struct HintWork {
    envelope: QueuedSessionHint,
    prepared: Option<SessionOpenHint>,
    waiting: Option<OpenWait>,
}

#[derive(Debug, Clone, Copy)]
struct OpenWait {
    ask: EntityId,
    deadline_ms: Option<u64>,
}

impl HintWork {
    fn new(envelope: QueuedSessionHint) -> Self {
        Self {
            envelope,
            prepared: None,
            waiting: None,
        }
    }

    fn acknowledge(&mut self, effect: SessionHintEffect) {
        if let Some(completion) = self.envelope.completion.take() {
            let _ = completion.send(effect);
        }
    }
}

pub(super) async fn sleep_until_lifecycle_due(clock: &NowMillis, due: Option<u64>) {
    match due {
        Some(due) => sleep_until_due(clock, due).await,
        None => std::future::pending::<()>().await,
    }
}

impl<T: TickSource> SessionTicks<'_, T> {
    pub(super) fn apply_guarded_hint(&mut self, envelope: QueuedSessionHint) -> bool {
        let mut work = HintWork::new(envelope);
        if let Some(queue) = self.parked_hints.get_mut(&work.envelope.carrier.key) {
            // A later tracked open reports the key's pending ask, not a mint.
            if work.envelope.carrier.hint == SessionHint::AppOpen
                && let Some(wait) = queue.front().and_then(|front| front.waiting)
            {
                work.acknowledge(SessionHintEffect::OpenPending(wait.ask));
            }
            queue.push_back(work);
            return true;
        }
        self.apply_work(work)
    }

    fn apply_work(&mut self, mut work: HintWork) -> bool {
        let carrier = work.envelope.carrier;
        let applied = self
            .lifecycle
            .apply_hint_carrier(carrier, &mut work.prepared);
        match applied {
            Ok(SessionHintEffect::OpenPending(ask)) => {
                let prepared = work.prepared.as_ref().expect("pending open was prepared");
                let deadline = match self.lifecycle.vault.session_open_hook_wait(prepared, ask) {
                    Ok((_, deadline)) => deadline,
                    Err(error) => {
                        self.retry_hint = Some(work);
                        tracing::error!(
                            ?error,
                            "session hook wait read failed; retained for retry"
                        );
                        return false;
                    }
                };
                work.waiting = Some(OpenWait {
                    ask,
                    deadline_ms: deadline,
                });
                work.acknowledge(SessionHintEffect::OpenPending(ask));
                self.parked_hints
                    .entry(carrier.key)
                    .or_default()
                    .push_front(work);
                true
            }
            Ok(effect) => {
                work.acknowledge(effect);
                if !matches!(effect, SessionHintEffect::Ended(_)) {
                    self.pending_hints.push_back(crate::tick::HintSignal {
                        session: Some(carrier.hint),
                    });
                }
                true
            }
            Err(error) => {
                self.retry_hint = Some(work);
                tracing::error!(?error, "session hint apply failed; retained for retry");
                false
            }
        }
    }

    fn redrive_parked_hints(&mut self) -> bool {
        let keys: Vec<_> = self.parked_hints.keys().copied().collect();
        for key in keys {
            let mut queue = self.parked_hints.remove(&key).expect("retained key");
            while let Some(mut work) = queue.pop_front() {
                if let Some(wait) = work.waiting {
                    let prepared = work.prepared.as_ref().expect("pending open was prepared");
                    match self
                        .lifecycle
                        .vault
                        .session_open_hook_wait(prepared, wait.ask)
                    {
                        Ok((VerbHookWaitStatus::Waiting, deadline)) => {
                            work.waiting = Some(OpenWait {
                                ask: wait.ask,
                                deadline_ms: deadline,
                            });
                            queue.push_front(work);
                            self.parked_hints.insert(key, queue);
                            break;
                        }
                        Ok((VerbHookWaitStatus::Unavailable, _)) => {
                            // Never restart an erased/mismatched saved invocation as fresh.
                            work.acknowledge(SessionHintEffect::NoOp);
                            self.pending_hints.push_back(crate::tick::HintSignal {
                                session: Some(work.envelope.carrier.hint),
                            });
                            continue;
                        }
                        Ok((VerbHookWaitStatus::Ready, _)) => work.waiting = None,
                        Err(error) => {
                            self.retry_hint = Some(work);
                            self.parked_hints.insert(key, queue);
                            tracing::error!(
                                ?error,
                                "session hook wait read failed; retained for retry"
                            );
                            return false;
                        }
                    }
                }
                if !self.apply_work(work) {
                    self.parked_hints.entry(key).or_default().extend(queue);
                    return false;
                }
                if let Some(parked) = self.parked_hints.get_mut(&key) {
                    parked.extend(queue);
                    break;
                }
            }
        }
        true
    }

    pub(super) fn drain_buffered_hints(&mut self) -> bool {
        if let Some(work) = self.retry_hint.take()
            && !self.apply_work(work)
        {
            return false;
        }
        if !self.redrive_parked_hints() {
            return false;
        }
        while let Some(envelope) = self.inner.take_buffered_session_hint_carrier() {
            if !self.apply_guarded_hint(envelope) {
                return false;
            }
        }
        true
    }

    pub(super) fn next_hook_deadline_ms(&self) -> Option<u64> {
        self.parked_hints
            .values()
            .filter_map(|queue| queue.front()?.waiting?.deadline_ms)
            .min()
    }
}
