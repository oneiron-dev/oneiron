//! One-shot bindings supplied by the existing private-connection owner.
//! No admission, listener, output client, provider or budget is created here.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use oneiron::voice_cascade::{Brain, CascadeControl, TtsSeamClient};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

use super::{HostError, VoiceHost, VoiceOutputs};
use crate::managed::ShutdownSignal;

type ServeFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
type Serve = Box<dyn FnOnce(VoiceHost, ShutdownSignal) -> ServeFuture + Send>;

/// A pre-admitted stream and existing brain/TTS/control submissions.
/// Clones share one slot: only one pass can consume the connection.
#[derive(Clone)]
pub struct VoiceServeBindings(Arc<Mutex<Option<VoiceServeConnection>>>);

impl VoiceServeBindings {
    /// The owner must admit `stream` from its 0600 socket below the active
    /// owner-only vault runtime directory before calling this constructor.
    /// These bindings do not establish or attest that admission themselves.
    pub fn new<B, T, C>(stream: UnixStream, mut outputs: VoiceOutputs<B, T, C>) -> Self
    where
        B: Brain + Send + 'static,
        T: TtsSeamClient + Send + 'static,
        C: CascadeControl + Send + 'static,
    {
        let serve: Serve = Box::new(move |host, stop| {
            Box::pin(async move { host.serve_until(stream, &mut outputs, stop).await })
        });
        Self(Arc::new(Mutex::new(Some(VoiceServeConnection(serve)))))
    }

    /// Claims the owner connection once, including across config clones.
    pub fn take(&self) -> Result<Option<VoiceServeConnection>, HostError> {
        self.0
            .lock()
            .map_err(|_| HostError::Stopped)
            .map(|mut slot| slot.take())
    }
}

/// A claimed connection, never a replacement stream or a background task.
pub struct VoiceServeConnection(Serve);

impl VoiceServeConnection {
    /// Polls serve alongside the pass on the existing runtime. Pass completion
    /// cancels extraction and dispatches output stops without triggering global
    /// shutdown. ManagedShutdown still stops serve through the attached host.
    /// The owner remains responsible for remote stop delivery/acknowledgement.
    pub async fn serve_for_pass<F: Future>(
        self,
        host: VoiceHost,
        pass: F,
    ) -> (F::Output, io::Result<()>) {
        let (stop, stopped) = oneshot::channel();
        let serving = (self.0)(
            host,
            Box::pin(async move {
                let _ = stopped.await;
            }),
        );
        let pass = async move {
            let result = pass.await;
            let _ = stop.send(());
            result
        };
        tokio::join!(pass, serving)
    }
}
