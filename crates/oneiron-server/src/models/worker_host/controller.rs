use futures_util::future::join_all;

use super::{BTreeSet, HOST, InferenceWorker, WorkerHost, configure, permit_worker_launch};
use crate::config::models::ModelsConfig;

/// The dedicated, non-vault CLI process owns the host's original supervisors.
pub(crate) struct WorkerController {
    host: &'static WorkerHost,
    workers: Vec<InferenceWorker>,
}

pub(crate) fn start_worker_controller(config: &ModelsConfig) -> WorkerController {
    permit_worker_launch();
    configure(&config.workers, &config.providers);
    let host = HOST.get_or_init(WorkerHost::default);
    let workers = host
        .lock()
        .values()
        .map(|hosted| hosted.worker.clone())
        .collect();
    WorkerController { host, workers }
}

impl WorkerController {
    /// Mark every supervisor retiring together, then wait for their existing drain.
    pub(crate) async fn shutdown(self) {
        join_all(self.workers.iter().map(InferenceWorker::retire)).await;
        let mut devices = BTreeSet::new();
        {
            let mut hosted = self.host.lock();
            for worker in &self.workers {
                let id = &worker.spec().worker_id;
                if hosted
                    .get(id)
                    .is_some_and(|current| current.worker.same_instance(worker))
                    && let Some(device) = hosted
                        .remove(id)
                        .and_then(|row| row.row.launch)
                        .and_then(|launch| launch.device)
                {
                    devices.insert(device);
                }
            }
        }
        for device in devices {
            super::stop_device_admission_if_unused(self.host, &device);
        }
    }
}
