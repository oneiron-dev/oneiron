//! Row GPU-WORKER-BACKEND-HOUSEKEEPING-UNCALLED (pass 33 row R4, 8.5): the GPU job worker's
//! pass gives every registered backend one housekeeping pass
//! (`GpuJobConnector::housekeeping`), which the `vault_machine` backend uses to ask its live
//! orphan keys to stop again and to return the results it still owes. Two counting backends on
//! a served vault with no offer, no job and no work order; the pass is the one `serve` runs
//! every `step_secs` (`test_doors::gpu_backend::run_gpu_job_worker_pass`).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test gpu_job_worker_housekeeping`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::gpu_job::{
    GpuConnectorError, GpuJobConnector, GpuJobSignal, GpuJobSpec, GpuResourceRef,
    GpuResourceStatus, GpuTermination,
};
use oneiron::{Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::gpu_backend::{
    register_gpu_backend, run_gpu_job_worker_pass, unregister_gpu_backend,
};
use oneiron_server::{config::SyncServerConfig, server::SyncServer};

/// A backend that provisions nothing and counts its housekeeping passes.
#[derive(Default)]
struct CountingBackend {
    housekeeping_passes: AtomicUsize,
}

impl CountingBackend {
    fn passes(&self) -> usize {
        self.housekeeping_passes.load(Ordering::SeqCst)
    }
}

fn unavailable() -> GpuConnectorError {
    GpuConnectorError::Unavailable {
        reason: "this test backend provisions nothing".to_owned(),
    }
}

impl GpuJobConnector for CountingBackend {
    fn create(&self, _key: &str, _spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        Err(unavailable())
    }

    fn find(&self, _key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        Err(unavailable())
    }

    fn status(&self, _resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        Err(unavailable())
    }

    fn signal(
        &self,
        _resource: &GpuResourceRef,
        _signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        Err(unavailable())
    }

    fn terminate(&self, _resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        Err(unavailable())
    }

    fn housekeeping(&self) {
        self.housekeeping_passes.fetch_add(1, Ordering::SeqCst);
    }
}

/// A served vault with no `[gpu_jobs]` offer.
fn served() -> (tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some("gpu-job-worker-housekeeping".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    (dir, server)
}

#[test]
fn each_worker_pass_gives_every_registered_backend_one_housekeeping_pass() {
    let (_dir, server) = served();
    let first = Arc::new(CountingBackend::default());
    let second = Arc::new(CountingBackend::default());
    register_gpu_backend(
        &server,
        "first",
        Arc::clone(&first) as Arc<dyn GpuJobConnector>,
    );
    register_gpu_backend(
        &server,
        "second",
        Arc::clone(&second) as Arc<dyn GpuJobConnector>,
    );

    run_gpu_job_worker_pass(&server);
    assert_eq!(
        (first.passes(), second.passes()),
        (1, 1),
        "one worker pass, one housekeeping pass of each backend"
    );

    run_gpu_job_worker_pass(&server);
    assert_eq!((first.passes(), second.passes()), (2, 2));

    unregister_gpu_backend(&server, "second");
    run_gpu_job_worker_pass(&server);
    assert_eq!(
        (first.passes(), second.passes()),
        (3, 2),
        "a backend no longer registered gets no pass"
    );
}
