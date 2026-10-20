//! The HTTP custody anchor (FIX 5788, CALLS CUSTODY_ANCHOR_URL): a host whose
//! own disks would roll back with its vault anchors its custody head on
//! another install's door, `GET`/`POST <url>/v1/owner/custody-anchor`, on
//! the same keyless contract as a mounted anchor root. A read answers the
//! lineage's current record (hex) or `null`; an advance sends the BLAKE3 of
//! the record it read (`null`: none) and the record to make current, and
//! answers `false` when another writer moved it first. The door's store
//! refuses a record that does not extend the current one; this install
//! checks the record's tag under its own control secret. The owner
//! credential the door admits is the one this process was handed on its
//! pipe ([`CustodyAnchorCredentials`], `--custody-anchor-credentials-fd`):
//! its bearer, with a holder proof its binding seed signs when it carries
//! one. Without it the door is not called. Neither, nor the URL, is ever in
//! an error, a status or a log line: a failure names only what went wrong
//! and the HTTP status.

use std::sync::Arc;
use std::time::Duration;

use oneiron::store::custody_protocol::{
    AnchorAdvance, AnchorStore, CustodyNamespace, CustodyVaultId,
};
use reqwest::blocking::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::CustodyAnchorCredentials;
use crate::owner::vault_key::hex;

const ROUTE: &str = "/v1/owner/custody-anchor";
/// How long one call to the door may take before the pass leaves the
/// anchor step pending.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct RecordView {
    record: Option<String>,
}

#[derive(Serialize)]
struct AdvanceRequest {
    expected: Option<String>,
    record: String,
}

#[derive(Deserialize)]
struct AdvanceView {
    advanced: bool,
}

fn failed(what: &str) -> oneiron::Error {
    oneiron::Error::Io(std::io::Error::other(format!(
        "the custody anchor door {what}"
    )))
}

fn unhex(text: &str) -> oneiron::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(failed("answered a record that is not hex"));
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            text.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| failed("answered a record that is not hex"))
        })
        .collect()
}

/// Another install's custody anchor door, and the owner credential it is
/// called with.
pub(crate) struct HttpAnchor {
    url: String,
    credentials: Option<Arc<CustodyAnchorCredentials>>,
}

/// `request` with the owner credential, and with the holder proof its
/// binding seed signs when it carries one.
fn credentialed(
    request: RequestBuilder,
    credentials: &CustodyAnchorCredentials,
) -> oneiron::Result<RequestBuilder> {
    let request = request.bearer_auth(credentials.bearer());
    let Some(seed) = credentials.binding_seed() else {
        return Ok(request);
    };
    let binding = crate::commands::api::signed_binding_with_seed(credentials.bearer(), seed)
        .map_err(|_| failed("credential's binding seed does not sign its slip"))?;
    Ok(request.header("x-oneiron-binding", binding))
}

impl HttpAnchor {
    /// The door under `base` (`https://host[:port]`), called with
    /// `credentials`, the owner credential this process was handed on its
    /// pipe. With none, each call fails before anything is sent: the door is
    /// never called without its credential.
    pub(crate) fn with_credentials(
        base: &str,
        credentials: Option<Arc<CustodyAnchorCredentials>>,
    ) -> Self {
        Self {
            url: format!("{}{ROUTE}", base.trim_end_matches('/')),
            credentials,
        }
    }

    /// One call to the door, on a thread of its own: a blocking HTTP client
    /// is never made, used or dropped on an async runtime's thread (the CLI
    /// runs its commands on one).
    fn call<T: DeserializeOwned + Send>(
        &self,
        request: impl FnOnce(&Client, &str) -> RequestBuilder + Send,
    ) -> oneiron::Result<T> {
        let credentials = self.credentials.as_deref().ok_or_else(|| {
            failed("has no owner credential: none was handed to this process on its pipe")
        })?;
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let client = Client::builder()
                        .timeout(CALL_TIMEOUT)
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .map_err(|_| failed("has no HTTP client on this host"))?;
                    let response = credentialed(request(&client, &self.url), credentials)?
                        .send()
                        .map_err(|_| failed("is out of reach"))?;
                    let status = response.status();
                    if !status.is_success() {
                        let refused = format!("refused the call (HTTP {})", status.as_u16());
                        return Err(failed(&refused));
                    }
                    response
                        .json::<T>()
                        .map_err(|_| failed("answered outside its contract"))
                })
                .join()
        })
        .map_err(|_| failed("call stopped"))?
    }
}

impl AnchorStore for HttpAnchor {
    fn read(
        &self,
        vault: CustodyVaultId,
        namespace: CustodyNamespace,
    ) -> oneiron::Result<Option<Vec<u8>>> {
        let query = [
            ("vault", hex(vault.as_bytes())),
            ("namespace", hex(namespace.as_bytes())),
        ];
        let view: RecordView = self.call(|client, url| client.get(url).query(&query))?;
        view.record.as_deref().map(unhex).transpose()
    }

    fn advance(&self, expected: Option<[u8; 32]>, record: &[u8]) -> oneiron::Result<AnchorAdvance> {
        let body = AdvanceRequest {
            expected: expected.map(|expected| hex(&expected)),
            record: hex(record),
        };
        let view: AdvanceView = self.call(|client, url| client.post(url).json(&body))?;
        Ok(if view.advanced {
            AnchorAdvance::Advanced
        } else {
            AnchorAdvance::Moved
        })
    }
}
