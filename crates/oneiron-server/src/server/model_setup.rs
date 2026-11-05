//! Live first-run model slots and the workers a setup attaches after startup.
//!
//! Startup builds the same slot pair and initial workers. The owner setup act
//! may fill that pair only while both are empty; replacing a serving slot is a
//! separate operation. Late workers share the host's admission and are joined
//! or aborted by the same ordered shutdown as the startup workers.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::{Mutex, MutexGuard, watch};
use tokio::task::JoinHandle;

use crate::embedder::EmbedderSlot;
use crate::oneironer::TaggerSlot;

use super::{HousekeepingAdmission, PassControl, SyncServer};

/// The nonsecret serving facts an open-vault setup must keep unchanged.
#[derive(Clone)]
pub(crate) struct ModelSetupConfig {
    /// The startup resolution layers, so a setup re-read layers the same
    /// settings file and holder overrides instead of the bare file.
    pub(crate) startup_args: crate::config::ServeArgs,
    pub(crate) config_path: Option<PathBuf>,
    pub(crate) vault_path: PathBuf,
    pub(crate) dimensions: usize,
    pub(crate) map_size: usize,
    pub(crate) gpu: Option<crate::runtime::GpuPoolConfig>,
}

/// One atomic view of the two model slots. Readers never see one half of a
/// first-run attach beside the other half's old state.
#[derive(Clone, Default)]
pub(crate) struct ModelSlots {
    pub(crate) embedder: Option<Arc<EmbedderSlot>>,
    pub(crate) tagger: Option<Arc<TaggerSlot>>,
}

pub(crate) type SharedModelSlots = ArcSwap<ModelSlots>;

/// What a running plain or embedded host needs to start late model workers.
/// The setup mutex also serializes worker startup against ordered shutdown.
pub(crate) struct ModelSetupRuntime {
    setup: Mutex<()>,
    /// The serving runtime late workers spawn on: setup runs inside a
    /// blocking closure with no runtime context, so spawns enter this.
    handle: tokio::runtime::Handle,
    admission: HousekeepingAdmission,
    drain_tagging: bool,
    stopping: watch::Sender<bool>,
    tagging: Mutex<Option<JoinHandle<()>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl ModelSetupRuntime {
    pub(crate) fn new(
        handle: tokio::runtime::Handle,
        admission: HousekeepingAdmission,
        drain_tagging: bool,
    ) -> Self {
        let (stopping, _) = watch::channel(false);
        Self {
            setup: Mutex::new(()),
            handle,
            admission,
            drain_tagging,
            stopping,
            tagging: Mutex::new(None),
            workers: Mutex::new(Vec::new()),
        }
    }

    /// One first-run setup at a time, on the owner route's blocking thread.
    pub(crate) fn setup(&self) -> MutexGuard<'_, ()> {
        self.setup.blocking_lock()
    }

    /// Starts the newly attached slots' workers. The caller holds `setup()` and
    /// has already installed both slots, so each spawn sees its configured slot.
    pub(crate) fn start_workers(
        self: &Arc<Self>,
        server: &Arc<SyncServer>,
        gpu_poller: Option<JoinHandle<()>>,
    ) {
        if *self.stopping.borrow() {
            return;
        }
        // No runtime context reaches here (the owner route runs setup in a
        // blocking closure): every late spawn enters the serving runtime.
        let _entered = self.handle.enter();
        let mut workers = Vec::new();
        workers.extend(gpu_poller);
        workers.extend(server.spawn_embedding_worker_admitted(self.admission.clone()));
        if self.drain_tagging {
            let mut stopped = self.stopping.subscribe();
            let tagging = server.spawn_tagging_worker_until(
                PassControl::unpaused(self.admission.clone()),
                async move {
                    let _ = stopped.wait_for(|stop| *stop).await;
                },
            );
            *self.tagging.blocking_lock() = tagging;
        } else {
            workers.extend(
                server.spawn_tagging_worker_admitted(PassControl::unpaused(self.admission.clone())),
            );
        }
        *self.workers.blocking_lock() = workers;
    }

    /// Stops late tagging before the slot closes, then aborts the same workers
    /// embedded serve aborts. Holding `setup` excludes a concurrent attach.
    pub(crate) async fn shutdown(&self) {
        let _setup = self.setup.lock().await;
        let _ = self.stopping.send_replace(true);
        let tagging = self.tagging.lock().await.take();
        if let Some(tagging) = tagging {
            let _ = tagging.await;
        }
        let workers = std::mem::take(&mut *self.workers.lock().await);
        for worker in workers {
            worker.abort();
            let _ = worker.await;
        }
    }
}
