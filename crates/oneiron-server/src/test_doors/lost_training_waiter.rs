//! Door for `tests/role_training_execute.rs`: a training run whose waiter is
//! lost, as after a host restart. The run is dispatched as the host's step
//! dispatches it and its trainer's job runs to its receipt, but the waiter
//! records nothing until the test lets it rejoin, so in between only a
//! recovery step (`step` on a Running run) records the job's result.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use oneiron::llm::run_admission::RunAdmission;
use oneiron::training_pack::{
    PollFuture, TrainRequest, TrainingConnector, TrainingFuture, TrainingRun, TrainingState,
};
use oneiron::{EntityId, Error};

use crate::ai_host::training_pack::{trainer_binding, training_connector, training_declaration};
use crate::server::SyncServer;

/// How long the door waits for the dispatch to commit the run as sent.
const DISPATCHED_WITHIN: Duration = Duration::from_secs(10);

/// The waiter of a run [`dispatch_with_lost_waiter`] dispatched. Dropped, it
/// rejoins without being waited for.
pub struct LostWaiter {
    rejoin: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl LostWaiter {
    /// Lets the waiter record its job's result, as a live waiter that lost
    /// the race to a recovery does (the run's writer admits one completion),
    /// and waits for it. Blocking.
    pub fn rejoin(mut self) {
        drop(self.rejoin.take());
        if let Some(thread) = self.thread.take() {
            // A panicked waiter leaves the run's durable state as the record.
            drop(thread.join());
        }
    }
}

/// The run's own trainer, whose output the waiter holds until rejoined.
struct HeldOutput {
    trainer: Box<dyn TrainingConnector + Send + Sync>,
    rejoin: Mutex<Option<Receiver<()>>>,
}

impl TrainingConnector for HeldOutput {
    fn train<'a>(
        &'a self,
        request: TrainRequest,
        admission: &'a RunAdmission,
    ) -> TrainingFuture<'a> {
        Box::pin(async move {
            let output = self.trainer.train(request, admission).await;
            let rejoin = self.rejoin.lock().ok().and_then(|mut rejoin| rejoin.take());
            if let Some(rejoin) = rejoin {
                // Nothing is ever sent: the waiter rejoins when the sender drops.
                let _ = rejoin.recv();
            }
            output
        })
    }

    fn poll<'a>(&'a self, run: &EntityId, spec_blake3: &[u8; 32]) -> PollFuture<'a> {
        self.trainer.poll(run, spec_blake3)
    }
}

/// Dispatches the authorized `run` as the host's step does, on a waiter that
/// holds what its trainer returns: the run commits Running, its job runs to
/// its receipt, and the run moves on only by a recovery step until
/// [`LostWaiter::rejoin`]. Blocking: it returns once the run is sent.
///
/// # Errors
///
/// A run this host has no trainer for, a quote with no admission, or a
/// dispatch that ends before the run is sent.
pub fn dispatch_with_lost_waiter(
    server: &SyncServer,
    run: &EntityId,
) -> oneiron::Result<LostWaiter> {
    let vault = Arc::clone(server.vault());
    let stored = vault
        .training_run(run)?
        .ok_or_else(|| Error::InvalidConfig("training run not found".into()))?;
    let (Some(binding), Some(trainer)) = (
        trainer_binding(server, &stored.compute.connector),
        training_connector(server, &stored),
    ) else {
        return Err(Error::InvalidConfig(
            "this host has no trainer for the run".into(),
        ));
    };
    let admission = server
        .ai
        .declared_run(stored.admission_ref(), training_declaration(&stored)?, None)
        .admission()
        .clone();
    let (rejoin, held) = channel();
    let connector = HeldOutput {
        trainer,
        rejoin: Mutex::new(Some(held)),
    };
    let id = *run;
    let waiter_vault = Arc::clone(&vault);
    let thread = crate::engine_thread(format!("lost-training-waiter-{}", id.to_hex()))
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            // The run's own durable state is the record, as for the host's
            // waiter.
            drop(
                runtime.block_on(waiter_vault.execute_authorized_training_pack_for(
                    &id, &admission, &binding, &connector, None,
                )),
            );
        })
        .map_err(|_| Error::InvalidConfig("the waiter's thread did not start".into()))?;
    let started = Instant::now();
    loop {
        let current = vault.training_run(&id)?;
        if current.as_ref().is_some_and(sent) {
            return Ok(LostWaiter {
                rejoin: Some(rejoin),
                thread: Some(thread),
            });
        }
        // Authorized until the dispatch commits it Running, then sent.
        let waits = current.as_ref().is_some_and(|current| {
            matches!(
                current.state,
                TrainingState::Authorized | TrainingState::Running
            )
        });
        if !waits || thread.is_finished() || started.elapsed() > DISPATCHED_WITHIN {
            return Err(Error::InvalidConfig(
                "the dispatch did not send the run".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether the dispatch committed `run` Running and sent to its trainer, as a
/// completion requires.
fn sent(run: &TrainingRun) -> bool {
    run.state == TrainingState::Running
        && run
            .dispatch
            .as_ref()
            .is_some_and(|dispatch| dispatch.dispatched)
}
