//! The built-in Google Sheets connector's credential-broker leg (FIX 4862).
//!
//! The engine builds each Sheets request whole and calls [`SheetsBroker`]
//! twice for it: once to check it as the broker will and connect, before any
//! credential is read, and once inside the grant's custody door with the
//! access token, which goes to the broker with that one request. The broker
//! adds it as `Authorization: Bearer`, sends once over verified TLS to
//! Google's Sheets origin, and strips it from the reply. Only broker clients
//! and the serve runtime are kept here, never the key door, so the vault's
//! transports hold no reference back to the vault.

use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use oneiron::channel_identity_provider::sheets::{
    SHEETS_API_ORIGIN, SHEETS_WIRE_MODEL, SheetsBrokerCall, SheetsBrokerHost, SheetsEndpoint,
    SheetsWireOutcome, SheetsWireRequest,
};
use oneiron_broker::{BrokerClient, BrokerConnection, BrokerError, CallHeader, Outcome, Shape};
use serde_json::Value;
use zeroize::Zeroizing;

use super::super::broker::{BrokerSite, REPLY_MARGIN};
use super::{BrokerContext, is_cloud_node};
use crate::config::models::{BrokerConfig, ModelsConfig};

/// How long one Sheets send may run in the broker.
const SHEETS_SEND: Duration = Duration::from_secs(30);

/// Where the Sheets leg's broker client comes from.
enum Site {
    /// The serve context's broker, or why it has none.
    Shared(Result<BrokerClient, String>),
    /// No serve context: the broker `[models.broker]` names, by default the
    /// same-user child, made at the first Sheets call.
    Deferred {
        broker: BrokerConfig,
        client: OnceLock<Result<BrokerClient, String>>,
    },
}

/// The host's Sheets broker leg.
struct SheetsBroker {
    runtime: tokio::runtime::Handle,
    site: Site,
}

impl fmt::Debug for SheetsBroker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SheetsBroker").finish_non_exhaustive()
    }
}

impl BrokerContext {
    /// The Sheets leg over this context's broker.
    pub(crate) fn sheets_broker(&self) -> Arc<dyn SheetsBrokerHost> {
        let client = self
            .inner
            .site
            .as_ref()
            .map_err(Clone::clone)
            .and_then(sheets_client);
        Arc::new(SheetsBroker {
            runtime: self.inner.runtime.clone(),
            site: Site::Shared(client),
        })
    }

    /// The Sheets leg of a serve that made no broker context, since nothing
    /// in its config takes a vault-secret key: the broker `models` names,
    /// made at the first Sheets call, so a host that never calls Sheets
    /// starts no broker. `None` outside a runtime.
    pub(crate) fn sheets_broker_from_config(
        models: Option<&ModelsConfig>,
    ) -> Option<Arc<dyn SheetsBrokerHost>> {
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let broker = models.map_or_else(BrokerConfig::default, |models| models.broker.clone());
        Some(Arc::new(SheetsBroker {
            runtime,
            site: Site::Deferred {
                broker,
                client: OnceLock::new(),
            },
        }))
    }
}

/// A client on `site` whose reply waits out one Sheets send.
fn sheets_client(site: &BrokerSite) -> Result<BrokerClient, String> {
    site.client(SHEETS_SEND + REPLY_MARGIN)
        .map_err(|error| error.to_string())
}

impl SheetsBroker {
    fn client(&self) -> Result<&BrokerClient, String> {
        let client = match &self.site {
            Site::Shared(client) => client,
            Site::Deferred { broker, client } => client.get_or_init(|| {
                BrokerSite::with_timeout(broker, SHEETS_SEND)
                    .map_err(|error| error.to_string())
                    .and_then(|site| sheets_client(&site))
            }),
        };
        client.as_ref().map_err(Clone::clone)
    }
}

impl SheetsBrokerHost for SheetsBroker {
    fn prepare(
        &self,
        request: &SheetsWireRequest,
        call: &str,
    ) -> Result<Box<dyn SheetsBrokerCall>, String> {
        let (shape, headers) = match request.endpoint() {
            SheetsEndpoint::SpreadsheetGet => (Shape::SheetsSpreadsheetGet, Vec::new()),
            SheetsEndpoint::ValuesBatchGet => (Shape::SheetsValuesBatchGet, Vec::new()),
            SheetsEndpoint::ValuesBatchUpdate => (Shape::SheetsValuesBatchUpdate, json_content()),
            SheetsEndpoint::BatchUpdate => (Shape::SheetsBatchUpdate, json_content()),
        };
        let header = CallHeader::new(
            call.to_owned(),
            shape,
            SHEETS_API_ORIGIN.to_owned(),
            request.path().to_owned(),
            headers,
            SHEETS_WIRE_MODEL.to_owned(),
            is_cloud_node(),
            request.body(),
        );
        header
            .check(request.body())
            .map_err(|refusal| refusal.to_string())?;
        let client = self.client()?;
        let connection = on_runtime(&self.runtime, || client.connect())
            .ok_or_else(|| "the credential broker connection did not run".to_owned())?
            .map_err(|error| error.to_string())?;
        Ok(Box::new(SheetsCall {
            runtime: self.runtime.clone(),
            connection,
            header,
            body: request.body().to_vec(),
        }))
    }
}

/// One checked Sheets request on a connected broker.
struct SheetsCall {
    runtime: tokio::runtime::Handle,
    connection: BrokerConnection,
    header: CallHeader,
    body: Vec<u8>,
}

impl SheetsBrokerCall for SheetsCall {
    fn present(self: Box<Self>, access_token: &[u8]) -> SheetsWireOutcome {
        let Self {
            runtime,
            connection,
            header,
            body,
        } = *self;
        let mut key = Zeroizing::new(Vec::with_capacity(access_token.len()));
        key.extend_from_slice(access_token);
        let sent = on_runtime(&runtime, move || async move {
            connection.call(&header, &body, key).await
        });
        match sent {
            Some(Ok(reply)) => match reply.outcome {
                Outcome::Answered { status, .. } => SheetsWireOutcome::Answered {
                    status,
                    body: serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
                },
                Outcome::Refused { reason } => {
                    SheetsWireOutcome::NotSent(format!("sheets_broker_refused: {reason}"))
                }
                Outcome::Failed { reason } => {
                    SheetsWireOutcome::Uncertain(format!("sheets_broker_failed: {reason}"))
                }
            },
            Some(Err(error @ (BrokerError::Unreachable | BrokerError::Peer))) => {
                SheetsWireOutcome::NotSent(format!("sheets_broker_unreachable: {error}"))
            }
            Some(Err(error @ BrokerError::Refused(_))) => {
                SheetsWireOutcome::NotSent(format!("sheets_broker_refused: {error}"))
            }
            Some(Err(BrokerError::Lost)) => {
                SheetsWireOutcome::Uncertain("sheets_broker_reply_lost".to_owned())
            }
            None => SheetsWireOutcome::Uncertain("sheets_broker_thread_failed".to_owned()),
        }
    }
}

/// The content type a Sheets write's JSON body goes with.
fn json_content() -> Vec<(String, String)> {
    vec![("content-type".to_owned(), "application/json".to_owned())]
}

/// Runs the future `make` builds to its end on the serve runtime: on this
/// thread when it is outside any runtime, else on a scoped thread, as
/// [`BrokerContext::send_blocking`] runs its send. `None` when that thread
/// panicked.
fn on_runtime<F: Future>(
    runtime: &tokio::runtime::Handle,
    make: impl FnOnce() -> F + Send,
) -> Option<F::Output>
where
    F::Output: Send,
{
    let run = || runtime.block_on(make());
    if tokio::runtime::Handle::try_current().is_err() {
        return Some(run());
    }
    std::thread::scope(|scope| scope.spawn(run).join().ok())
}
