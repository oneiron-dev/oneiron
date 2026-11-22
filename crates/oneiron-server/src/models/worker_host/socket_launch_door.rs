//! Doors for `tests/supervised_rerank_socket.rs` (L9-15): a stub worker
//! started in a supervisor's custody, as a launch's child is, and recorded
//! as a hosted `listen = "unix"` worker's current launch, so the reranker's
//! peer check runs against it exactly as against a launched llama-server;
//! and the reranker seat's on-device view. Compiled only under
//! `--cfg oneiron_test_support`.
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{CacheIdentity, WorkerMode};
use oneiron_driver::RunningWorker as _;

use super::HOST;
use super::launch_manifest::LaunchRecord;
use super::launcher::HealthRoute;
use super::process::ProcessWorker;
use crate::config::models::WorkerListen;
use crate::models::{ModelRuntime, OfferLadder};

/// A stub worker process in a supervisor's custody, as a launched worker's
/// child is: the peer a recorded launch is checked against.
pub struct SocketStub {
    worker: ProcessWorker,
}

impl SocketStub {
    /// Starts `program` with `args` in custody, its group its own.
    ///
    /// # Errors
    /// When the process does not start.
    pub fn start(program: &Path, args: &[String]) -> std::io::Result<Self> {
        let mut command: tokio::process::Command = oneiron_spawn::command(program).into();
        command.args(args).stdin(Stdio::null());
        let health = HealthRoute {
            url: "http://localhost/health".to_owned(),
            socket: None,
        };
        Ok(Self {
            worker: ProcessWorker::spawn(command, &health, None, None)?,
        })
    }

    /// Stops the stub as a supervisor stops a worker: TERM to its group,
    /// then KILL.
    pub async fn stop(&self) {
        self.worker.terminate(Duration::from_secs(2)).await;
    }
}

/// Records a launch serving HTTP on `socket`, whose supervised child is
/// `child`'s, as hosted worker `worker_id`'s current launch. False when no
/// hosted row with that id has a `listen = "unix"` launch.
///
/// The row's artifacts are absent, so its supervisor parks and never makes
/// a launch ready, and a parked supervisor fails every call before the
/// reranker reads the slot (`OfferLadder::hold_worker`). The recorded stub
/// stands for a ready launch, so the row is released from the supervisor's
/// lease as an external row is. The slot stays the one the reranker's route
/// captured when the runtime was built: the call still sends on `socket`
/// alone, checked against `child`.
#[must_use]
pub fn record_socket_launch(worker_id: &str, socket: &Path, child: &SocketStub) -> bool {
    let Some(host) = HOST.get() else {
        return false;
    };
    let slot = {
        let mut workers = host.lock();
        let Some(hosted) = workers.get_mut(worker_id) else {
            return false;
        };
        // The launch's own listen, not `Hosted::socket_slot`: that asks for a
        // managed row, and an earlier call may have released this one.
        let listens_on_socket = hosted
            .row
            .launch
            .as_ref()
            .is_some_and(|launch| launch.listen == WorkerListen::Unix);
        let Some(slot) = hosted
            .slot
            .as_ref()
            .filter(|_| listens_on_socket)
            .map(Arc::clone)
        else {
            return false;
        };
        hosted.row.mode = WorkerMode::External;
        slot
    };
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(LaunchRecord {
        manifest_sha256: String::new(),
        llama_alias: None,
        pins: CacheIdentity::default(),
        native_socket: None,
        http_socket: Some(socket.to_path_buf()),
        native_peer: Some(child.worker.native_peer()),
        scheduling: None,
    });
    true
}

/// The reranker seat's on-device view (I2-LOCAL) in `runtime`, when it has
/// one, and whether every rung of it sends only over a supervised worker's
/// checked channel, on this device (`OfferLadder::native_local`).
#[must_use]
pub fn reranker_on_device_view(runtime: &ModelRuntime) -> Option<(Arc<OfferLadder>, bool)> {
    let view = runtime.seat(ModelRole::Reranker)?.on_device.clone()?;
    let native = view.native_local();
    Some((view, native))
}
