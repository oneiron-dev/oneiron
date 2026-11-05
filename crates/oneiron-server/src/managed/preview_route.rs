//! A held native preview registration on the supervisor's authenticated socket.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use oneiron_vault_contract::preview::PreviewSessionManifest;
use oneiron_vault_contract::{
    MAX_CTL_LINE, PREVIEW_ROUTE_OPEN_OP, PreviewRouteAck, PreviewRouteBinding, PreviewRouteRequest,
    TokenHex, now_ts,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;

use super::{ManagedShutdown, ShutdownSignal};

/// A distinct caller on the same native socket and spawn identity as WakeLedger.
#[derive(Clone)]
pub struct PreviewRouteClient {
    socket: PathBuf,
    vault: String,
    token: TokenHex,
}

impl PreviewRouteClient {
    pub(super) fn new(socket: PathBuf, vault: String, token: TokenHex) -> Self {
        Self {
            socket,
            vault,
            token,
        }
    }

    /// No binding means only that the supervisor explicitly has no domain.
    /// Protocol, authentication and transport failures remain errors.
    pub async fn open(
        &self,
        manifest: &PreviewSessionManifest,
    ) -> anyhow::Result<Option<PreviewRouteGuard>> {
        let request = PreviewRouteRequest {
            op: PREVIEW_ROUTE_OPEN_OP.to_owned(),
            vault: self.vault.clone(),
            token: self.token.clone(),
            manifest: manifest.clone(),
        };
        request.validate(now_ts())?;
        let stream = UnixStream::connect(&self.socket).await?;
        let (reader, mut writer) = stream.into_split();
        let mut frame = zeroize::Zeroizing::new(serde_json::to_vec(&request)?);
        anyhow::ensure!(frame.len() < MAX_CTL_LINE, "preview registration too long");
        frame.push(b'\n');
        writer.write_all(&frame).await?;
        writer.flush().await?;
        let mut reader = BufReader::new(reader);
        let mut response = Vec::new();
        let read = (&mut reader)
            .take((MAX_CTL_LINE + 1) as u64)
            .read_until(b'\n', &mut response)
            .await?;
        anyhow::ensure!(
            read > 0 && read <= MAX_CTL_LINE && response.last() == Some(&b'\n'),
            "incomplete or oversized preview registration response"
        );
        let ack: PreviewRouteAck = serde_json::from_slice(&response)?;
        anyhow::ensure!(
            ack.ok,
            "preview registration refused: {}",
            ack.error.as_deref().unwrap_or("unspecified")
        );
        anyhow::ensure!(
            ack.error.is_none(),
            "inconsistent preview registration response"
        );
        let Some(binding) = ack.binding else {
            return Ok(None);
        };
        anyhow::ensure!(
            binding.manifest == *manifest,
            "preview registration manifest mismatch"
        );
        binding
            .manifest
            .validate(now_ts())
            .map_err(anyhow::Error::msg)?;
        // The origin is supplied by the trusted supervisor, never assembled
        // from session or lease references. It must be an origin, not a URL.
        let origin: axum::http::Uri = binding.origin.parse()?;
        anyhow::ensure!(
            matches!(origin.scheme_str(), Some("http" | "https"))
                && origin
                    .authority()
                    .is_some_and(|authority| !authority.as_str().contains('@'))
                && origin.path() == "/"
                && origin.query().is_none()
                && !binding.origin.ends_with('/')
                && !binding.lease_handle.is_empty(),
            "invalid preview registration origin"
        );
        let stopped = ManagedShutdown::new();
        let writer = Arc::new(Mutex::new(Some(writer)));
        let monitor_writer = Arc::clone(&writer);
        let monitor_stop = stopped.clone();
        tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            tokio::select! {
                biased;
                () = monitor_stop.triggered() => {},
                _ = reader.read(&mut byte) => {},
            }
            monitor_stop.trigger();
            monitor_writer.lock().expect("preview route lock").take();
        });
        Ok(Some(PreviewRouteGuard {
            binding,
            writer,
            stopped,
        }))
    }
}

/// The lease owns the write half. Dropping it shuts write even while the read
/// monitor lives, so the supervisor sees EOF and retires its route.
pub struct PreviewRouteGuard {
    binding: PreviewRouteBinding,
    writer: Arc<Mutex<Option<OwnedWriteHalf>>>,
    stopped: ManagedShutdown,
}

impl PreviewRouteGuard {
    pub fn binding(&self) -> &PreviewRouteBinding {
        &self.binding
    }

    pub fn stopped(&self) -> ShutdownSignal {
        self.stopped.triggered()
    }

    pub(crate) fn shutdown(&self) -> ManagedShutdown {
        self.stopped.clone()
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.is_triggered()
    }

    pub fn close(&self) {
        self.stopped.trigger();
        self.writer.lock().expect("preview route lock").take();
    }
}

impl Drop for PreviewRouteGuard {
    fn drop(&mut self) {
        self.close();
    }
}
