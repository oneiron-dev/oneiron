//! Owned recall workers, so HyDE waits hold no shared blocking-pool thread.

/// Runs one recall on its own thread and answers through a Tokio oneshot.
pub(crate) fn spawn_hyde_recall_oneshot<R: Send + 'static>(
    work: impl FnOnce() -> R + Send + 'static,
) -> tokio::sync::oneshot::Receiver<R> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("oneiron-hyde-recall".to_owned())
        .spawn(move || {
            let _ = sender.send(work());
        });
    receiver
}

/// Runs one run-door recall on its own thread and answers through std mpsc.
pub(crate) fn spawn_hyde_recall_mpsc<R: Send + 'static>(
    work: impl FnOnce() -> R + Send + 'static,
) -> std::sync::mpsc::Receiver<R> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("oneiron-hyde-recall".to_owned())
        .spawn(move || {
            let _ = sender.send(work());
        });
    receiver
}
