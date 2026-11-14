//! The built-in workspace connectors' credential-broker leg (FIX 4862;
//! L3-17).
//!
//! The engine builds each workspace request whole and calls
//! [`WorkspaceBroker`] twice for it: once to check it as the broker will and
//! connect, before any credential is read, and once inside the grant's
//! custody door with the access token, which goes to the broker with that
//! one request. The broker adds it as `Authorization: Bearer`, sends once
//! over verified TLS to the endpoint's origin, and strips it from the reply.
//! Only broker clients and the serve runtime are kept here, never the key
//! door, so the vault's transports hold no reference back to the vault.

use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use oneiron::channel_identity_provider::workspace_connector::{
    WorkspaceBrokerCall, WorkspaceBrokerHost, WorkspaceEndpoint, WorkspaceWireOutcome,
    WorkspaceWireRequest,
};
use oneiron_broker::{BrokerClient, BrokerConnection, BrokerError, CallHeader, Outcome, Shape};
use serde_json::Value;
use zeroize::Zeroizing;

use super::super::broker::{BrokerSite, REPLY_MARGIN};
use super::{BrokerContext, is_cloud_node};
use crate::config::models::{BrokerConfig, ModelsConfig};

/// How long one workspace send may run in the broker.
const WORKSPACE_SEND: Duration = Duration::from_secs(30);

/// Where the workspace leg's broker client comes from.
enum Site {
    /// The serve context's broker, or why it has none.
    Shared(Result<BrokerClient, String>),
    /// No serve context: the broker `[models.broker]` names, by default the
    /// same-user child, made at the first workspace call.
    Deferred {
        broker: BrokerConfig,
        client: OnceLock<Result<BrokerClient, String>>,
    },
}

/// The host's workspace broker leg.
struct WorkspaceBroker {
    runtime: tokio::runtime::Handle,
    site: Site,
}

impl fmt::Debug for WorkspaceBroker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkspaceBroker").finish_non_exhaustive()
    }
}

impl BrokerContext {
    /// The workspace leg over this context's broker.
    pub(crate) fn workspace_broker(&self) -> Arc<dyn WorkspaceBrokerHost> {
        let client = self
            .inner
            .site
            .as_ref()
            .map_err(Clone::clone)
            .and_then(workspace_client);
        Arc::new(WorkspaceBroker {
            runtime: self.inner.runtime.clone(),
            site: Site::Shared(client),
        })
    }

    /// The workspace leg of a serve that made no broker context, since
    /// nothing in its config takes a vault-secret key: the broker `models`
    /// names, made at the first workspace call, so a host that never calls a
    /// workspace connector starts no broker. `None` outside a runtime.
    pub(crate) fn workspace_broker_from_config(
        models: Option<&ModelsConfig>,
    ) -> Option<Arc<dyn WorkspaceBrokerHost>> {
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let broker = models.map_or_else(BrokerConfig::default, |models| models.broker.clone());
        Some(Arc::new(WorkspaceBroker {
            runtime,
            site: Site::Deferred {
                broker,
                client: OnceLock::new(),
            },
        }))
    }
}

/// A client on `site` whose reply waits out one workspace send.
fn workspace_client(site: &BrokerSite) -> Result<BrokerClient, String> {
    site.client(WORKSPACE_SEND + REPLY_MARGIN)
        .map_err(|error| error.to_string())
}

impl WorkspaceBroker {
    fn client(&self) -> Result<&BrokerClient, String> {
        let client = match &self.site {
            Site::Shared(client) => client,
            Site::Deferred { broker, client } => client.get_or_init(|| {
                BrokerSite::with_timeout(broker, WORKSPACE_SEND)
                    .map_err(|error| error.to_string())
                    .and_then(|site| workspace_client(&site))
            }),
        };
        client.as_ref().map_err(Clone::clone)
    }
}

/// The broker shape row `endpoint` names.
const fn shape(endpoint: WorkspaceEndpoint) -> Shape {
    match endpoint {
        WorkspaceEndpoint::SheetsSpreadsheetGet => Shape::SheetsSpreadsheetGet,
        WorkspaceEndpoint::SheetsValuesBatchGet => Shape::SheetsValuesBatchGet,
        WorkspaceEndpoint::SheetsValuesBatchUpdate => Shape::SheetsValuesBatchUpdate,
        WorkspaceEndpoint::SheetsBatchUpdate => Shape::SheetsBatchUpdate,
        WorkspaceEndpoint::DocsDocumentGet => Shape::DocsDocumentGet,
        WorkspaceEndpoint::DocsBatchUpdate => Shape::DocsBatchUpdate,
        WorkspaceEndpoint::SlidesPresentationGet => Shape::SlidesPresentationGet,
        WorkspaceEndpoint::SlidesBatchUpdate => Shape::SlidesBatchUpdate,
        WorkspaceEndpoint::ExcelCreateSession => Shape::ExcelCreateSession,
        WorkspaceEndpoint::ExcelRangeGet => Shape::ExcelRangeGet,
        WorkspaceEndpoint::ExcelRangeUpdate => Shape::ExcelRangeUpdate,
        WorkspaceEndpoint::ExcelCloseSession => Shape::ExcelCloseSession,
    }
}

impl WorkspaceBrokerHost for WorkspaceBroker {
    fn prepare(
        &self,
        request: &WorkspaceWireRequest,
        call: &str,
    ) -> Result<Box<dyn WorkspaceBrokerCall>, String> {
        let endpoint = request.endpoint();
        // A write's body is JSON; a read sends none. The request's own
        // headers (a Graph workbook session) follow.
        let mut headers = if endpoint.method() == "GET" {
            Vec::new()
        } else {
            vec![("content-type".to_owned(), "application/json".to_owned())]
        };
        headers.extend(
            request
                .headers()
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone())),
        );
        let header = CallHeader::new(
            call.to_owned(),
            shape(endpoint),
            endpoint.origin().to_owned(),
            request.path().to_owned(),
            headers,
            endpoint.wire_model().to_owned(),
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
        Ok(Box::new(WorkspaceCall {
            runtime: self.runtime.clone(),
            connection,
            header,
            body: request.body().to_vec(),
        }))
    }
}

/// One checked workspace request on a connected broker.
struct WorkspaceCall {
    runtime: tokio::runtime::Handle,
    connection: BrokerConnection,
    header: CallHeader,
    body: Vec<u8>,
}

impl WorkspaceBrokerCall for WorkspaceCall {
    fn present(self: Box<Self>, access_token: &[u8]) -> WorkspaceWireOutcome {
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
                Outcome::Answered { status, .. } => WorkspaceWireOutcome::Answered {
                    status,
                    body: serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
                },
                Outcome::Refused { reason } => {
                    WorkspaceWireOutcome::NotSent(format!("workspace_broker_refused: {reason}"))
                }
                Outcome::Failed { reason } => {
                    WorkspaceWireOutcome::Uncertain(format!("workspace_broker_failed: {reason}"))
                }
            },
            Some(Err(error @ (BrokerError::Unreachable | BrokerError::Peer))) => {
                WorkspaceWireOutcome::NotSent(format!("workspace_broker_unreachable: {error}"))
            }
            Some(Err(error @ BrokerError::Refused(_))) => {
                WorkspaceWireOutcome::NotSent(format!("workspace_broker_refused: {error}"))
            }
            Some(Err(BrokerError::Lost)) => {
                WorkspaceWireOutcome::Uncertain("workspace_broker_reply_lost".to_owned())
            }
            None => WorkspaceWireOutcome::Uncertain("workspace_broker_thread_failed".to_owned()),
        }
    }
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
