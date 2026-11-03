//! Owned recall workers, so HyDE waits hold no shared blocking-pool thread.

/// Runs one recall on its own thread and answers through a Tokio oneshot.
pub(crate) fn spawn_hyde_recall_oneshot<R: Send + 'static>(
    work: impl FnOnce() -> R + Send + 'static,
) -> tokio::sync::oneshot::Receiver<R> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("oneiron-hyde-recall".to_owned())
        .spawn(move || {
            let _ = sender.send(work());
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "HyDE recall worker spawn failed");
    }
    receiver
}

/// Runs one run-door recall on its own thread and answers through std mpsc.
pub(crate) fn spawn_hyde_recall_mpsc<R: Send + 'static>(
    work: impl FnOnce() -> R + Send + 'static,
) -> std::sync::mpsc::Receiver<R> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name("oneiron-hyde-recall".to_owned())
        .spawn(move || {
            let _ = sender.send(work());
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "HyDE recall worker spawn failed");
    }
    receiver
}
