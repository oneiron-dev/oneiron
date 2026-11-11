//! Replacement cleanup outlives the serving runtime that configured it.
//! Bootstrap failures keep the same cleanup owned by the process's worker host.

use std::sync::{Arc, PoisonError};

use super::{InferenceWorker, WorkerHost, WorkerMode, stop_device_admission_if_unused};

pub(super) struct Replacement {
    old: InferenceWorker,
    new: InferenceWorker,
    old_device: Option<String>,
}

impl WorkerHost {
    pub(super) fn replace_workers(
        &'static self,
        replacements: Vec<(InferenceWorker, InferenceWorker, Option<String>)>,
    ) {
        let mut pending = {
            let mut pending = self
                .pending_replacements
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *pending)
        };
        pending.extend(replacements.into_iter().map(|(old, new, old_device)| {
            Arc::new(Replacement {
                old,
                new,
                old_device,
            })
        }));
        for replacement in pending {
            let owned = Arc::clone(&replacement);
            let thread = std::thread::Builder::new()
                .name("oneiron-worker-replace".to_owned())
                .stack_size(crate::ENGINE_THREAD_STACK_BYTES)
                .spawn(move || {
                    match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime.block_on(async move {
                            owned.old.retire().await;
                            if let Some(device) = owned.old_device.as_deref() {
                                stop_device_admission_if_unused(self, device);
                            }
                            match owned.new.spec().mode {
                                WorkerMode::Managed => self.begin(&owned.new),
                                WorkerMode::External => owned.new.probe_once().await,
                            }
                        }),
                        Err(error) => self.defer_replacement(owned, error),
                    }
                });
            if let Err(error) = thread {
                self.defer_replacement(replacement, error);
            }
        }
    }

    fn defer_replacement(&self, replacement: Arc<Replacement>, error: std::io::Error) {
        tracing::warn!(
            worker = %replacement.new.spec().worker_id,
            %error,
            "model worker replacement executor did not start"
        );
        self.pending_replacements
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(replacement);
    }
}
