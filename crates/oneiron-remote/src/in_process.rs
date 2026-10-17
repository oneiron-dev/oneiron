//! A served client (OF-237): the remote backend over an `oneiron-server`
//! this process runs, with no socket between them.
//!
//! [`OneironClient::connect_in_process`] binds what [`OneironClient::connect`]
//! binds, over an [`InProcessTransport`] instead of the network. Every verb,
//! retry, lens-frame event and close is the request a connected handle
//! sends: the facade route, the caller's own credential and a fresh holder
//! proof, its room turn and its invocation id. The server's Router admits
//! and dispatches it, host doors included, and its reply is read by the same
//! code a network reply is, receipt ref and refusal envelope alike. The
//! handle never rebinds its actor (`as_actor` refuses, as on any connected
//! handle) and claims no authority of its own.
//!
//! This crate holds no server type. The binding that runs the server
//! implements the transport over the server's buffered request.

use std::sync::Arc;

use oneiron::memory::MemoryError;

use crate::remote::{RemoteClient, parse_credential};
use crate::{Backend, OneironClient};

/// One buffered HTTP/1.1 exchange with an `oneiron-server` this process
/// runs.
pub trait InProcessTransport: Send + Sync {
    /// Sends `request` and returns the whole reply; a 4xx or 5xx status is a
    /// reply. `Err` is a request that reached no server, in words a caller
    /// may read; it never repeats the request's headers.
    fn exchange(&self, request: InProcessRequest) -> Result<InProcessReply, String>;
}

/// One request a served client sends. Its headers carry the caller's
/// credential: hand them to the server and nowhere else.
pub struct InProcessRequest {
    pub method: String,
    /// Origin form: the path and query, such as
    /// `/v1/core/facade/vault.recall`.
    pub path: String,
    /// Every header, in order.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// The server's reply to one [`InProcessRequest`].
pub struct InProcessReply {
    pub status: u16,
    /// Every header the reply carried, repeats included.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl OneironClient {
    /// Binds the server `transport` reaches, as [`Self::connect`] binds one
    /// over the network. `key` is the caller's own credential, passed
    /// verbatim: the credential [`Self::pair`] returned, or the host secret
    /// as a bare bearer. Every request carries it, with a fresh holder proof
    /// for a paired credential, and the server decides each verb from it.
    /// This call makes no request.
    pub fn connect_in_process(
        transport: Arc<dyn InProcessTransport>,
        key: &str,
    ) -> Result<Self, MemoryError> {
        let (bearer, holder) = parse_credential(key)?;
        Ok(Self {
            backend: Backend::Remote(RemoteClient::in_process(transport, &bearer, holder)?),
        })
    }
}
