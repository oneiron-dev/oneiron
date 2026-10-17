//! One-shot bindings supplied by the existing private-connection owner.
//! No admission, listener, output client, provider or budget is created here.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use oneiron::voice_cascade::{Brain, CascadeControl, TtsSeamClient};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

use super::{HostError, VoiceHost, VoiceMediaBindings, VoiceOutputs, VoiceWireBindings};
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

    /// [`Self::new`] with the host's own speech and hearing on the media
    /// seats ([`VoiceMediaBindings`]): the connection's TTS seam is the
    /// bridge's. Heard utterances go to the session as finals and on to
    /// `brain`, which hands its events back on the bindings' `brain_out`;
    /// its sentences are spoken past the session's safeguards, and spoken
    /// audio goes to the bindings' playout past the session's filter. A
    /// vault with no live voice row for either lane, a banked voice whose
    /// render consent does not reach the TTS route, or an unusable cadence,
    /// refuses here.
    pub fn with_media<B, C>(
        stream: UnixStream,
        brain: B,
        control: C,
        media: VoiceMediaBindings,
    ) -> Result<Self, HostError>
    where
        B: Brain + Send + 'static,
        C: CascadeControl + Send + 'static,
    {
        let (tts, mut bridge, worker) = media.build()?;
        let mut outputs = VoiceOutputs {
            brain,
            tts,
            control,
        };
        let serve: Serve = Box::new(move |host, stop| {
            Box::pin(async move {
                let serving = host.serve_media_until(stream, &mut outputs, &mut bridge, stop);
                // The worker outlives no connection: once serving ends, its
                // call in flight is dropped and settles as dropped.
                tokio::select! {
                    result = serving => result,
                    () = worker.run() => Err(io::Error::other("voice media worker stopped")),
                }
            })
        });
        let bindings = Self(Arc::new(Mutex::new(Some(VoiceServeConnection(serve)))));
        Ok(bindings)
    }

    /// [`Self::with_media`] with the audio side on `stream` itself
    /// ([`VoiceWireBindings`]): the sibling's microphone audio, cuts, VAD,
    /// roster changes and drains arrive as wire ops, and spoken audio,
    /// generation ends, flushes and controls leave as wire frames. The
    /// connection's control seam is the wire's own.
    pub fn with_wire<B>(
        stream: UnixStream,
        brain: B,
        media: VoiceWireBindings,
    ) -> Result<Self, HostError>
    where
        B: Brain + Send + 'static,
    {
        let (tts, mut bridge, worker, wire, control) = media.build()?;
        let mut outputs = VoiceOutputs {
            brain,
            tts,
            control,
        };
        let serve: Serve = Box::new(move |host, stop| {
            Box::pin(async move {
                let serving = host.serve_wire_until(stream, &mut outputs, &mut bridge, wire, stop);
                tokio::select! {
                    result = serving => result,
                    () = worker.run() => Err(io::Error::other("voice media worker stopped")),
                }
            })
        });
        let bindings = Self(Arc::new(Mutex::new(Some(VoiceServeConnection(serve)))));
        Ok(bindings)
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
