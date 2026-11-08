//! The direct transport of Git-LFS exchanges: this daemon's own HTTPS
//! client to one https remote's batch API
//! (`<remote>.git/info/lfs/objects/batch`) and to the actions its answers
//! return (FIX 919, FIX 7596, FIX 19876).
//!
//! https only, no redirects, no proxy. The one credential is the
//! `Authorization` value the caller hands this transport inside the
//! custody door; it rides a batch call that names the remote's credential,
//! to the remote's own host alone, and each action's own headers ride that
//! action's request alone. An action goes to an https href with no
//! credential whose every address is global, pinned so the name is not
//! resolved again; another public host is allowed. An object is streamed,
//! never held whole in memory.

use std::time::Duration;

use super::LFS_JSON_MEDIA_TYPE;
use super::transport::{
    LfsAction, LfsBatchCredential, LfsBatchRequest, LfsReply, LfsRequest, LfsTransport, invalid,
};
use crate::error::Result;

/// How long one batch or verify call may take.
const LFS_BATCH_TIMEOUT: Duration = Duration::from_secs(60);

/// How long one object's transfer may take.
const LFS_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// One https Git-LFS remote, named by its Git URL: its batch API and the
/// client its batch calls go through.
pub(crate) struct DirectLfsRemote {
    batch_url: String,
    client: reqwest::blocking::Client,
}

impl DirectLfsRemote {
    /// The batch API of the Git remote `remote`, an https URL with no
    /// credential, query or fragment.
    ///
    /// # Errors
    /// Another scheme, or a client that cannot be built.
    pub(crate) fn of(remote: &str) -> Result<Self> {
        if !remote.starts_with("https://") || remote.contains(['?', '#', '@']) {
            return Err(invalid("an LFS remote is an https URL with no credential"));
        }
        let base = remote.trim_end_matches('/');
        let batch_url = if base.ends_with(".git") {
            format!("{base}/info/lfs/objects/batch")
        } else {
            format!("{base}.git/info/lfs/objects/batch")
        };
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| invalid("the LFS client is unavailable"))?;
        Ok(Self { batch_url, client })
    }

    /// The transport to this remote that installs `authorization`, the
    /// full header value, on each batch call naming the remote's
    /// credential.
    pub(crate) fn transport<'a>(
        &'a self,
        authorization: Option<&'a str>,
    ) -> DirectLfsTransport<'a> {
        DirectLfsTransport {
            remote: self,
            authorization,
        }
    }

    /// One batch call under `authorization` when it names one.
    fn batch(
        &self,
        authorization: Option<&str>,
        request: &LfsBatchRequest,
    ) -> Result<reqwest::blocking::Response> {
        let mut call = self
            .client
            .post(&self.batch_url)
            .timeout(LFS_BATCH_TIMEOUT)
            .header(reqwest::header::ACCEPT, LFS_JSON_MEDIA_TYPE)
            .header(reqwest::header::CONTENT_TYPE, LFS_JSON_MEDIA_TYPE);
        if let Some(authorization) = authorization {
            let mut value = reqwest::header::HeaderValue::from_str(authorization)
                .map_err(|_| invalid("an LFS credential is not a header value"))?;
            value.set_sensitive(true);
            call = call.header(reqwest::header::AUTHORIZATION, value);
        }
        call.body(request.body().to_vec())
            .send()
            .map_err(|_| invalid("the LFS batch call failed"))
    }

    /// A request to `action`'s https href carrying its own headers only.
    fn action(
        &self,
        method: reqwest::Method,
        action: &LfsAction,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        if !action.href().starts_with("https://") {
            return Err(invalid("an LFS action names no https href"));
        }
        let url = reqwest::Url::parse(action.href())
            .map_err(|_| invalid("an LFS action names no valid href"))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid("an LFS action href carries a credential"));
        }
        let host = url
            .host_str()
            .ok_or_else(|| invalid("an LFS action names no host"))?;
        let addresses = url
            .socket_addrs(|| Some(443))
            .map_err(|_| invalid("an LFS action host did not resolve"))?;
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|address| !oneiron_sandbox_contract::network::global_address(address.ip()))
        {
            return Err(invalid("an LFS action names a non-global address"));
        }
        // LFS storage may live on another public host. Pin the admitted
        // addresses so reqwest cannot resolve the name again after admission.
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| invalid("the LFS action client is unavailable"))?;
        let mut request = client.request(method, url);
        for (name, value) in action.header() {
            request = request.header(name.as_str(), value.as_str());
        }
        Ok(request)
    }
}

/// The direct transport to one remote, holding the `Authorization` value
/// the custody door released for its batch calls, if any.
pub(crate) struct DirectLfsTransport<'a> {
    remote: &'a DirectLfsRemote,
    authorization: Option<&'a str>,
}

impl LfsTransport for DirectLfsTransport<'_> {
    fn exchange(&self, request: LfsRequest<'_>) -> Result<LfsReply> {
        let response = match request {
            LfsRequest::Batch(batch) => {
                let authorization = match batch.credential() {
                    LfsBatchCredential::Anonymous => None,
                    LfsBatchCredential::Remote => Some(self.authorization.ok_or_else(|| {
                        invalid("an LFS batch names a credential its transport does not hold")
                    })?),
                };
                self.remote.batch(authorization, batch)?
            }
            LfsRequest::ObjectUpload { action, body } => self
                .remote
                .action(reqwest::Method::PUT, action.action())?
                .timeout(LFS_TRANSFER_TIMEOUT)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(reqwest::blocking::Body::sized(body, action.size()))
                .send()
                .map_err(|_| invalid("an LFS upload failed"))?,
            LfsRequest::Verify { action, body } => self
                .remote
                .action(reqwest::Method::POST, action.action())?
                .timeout(LFS_BATCH_TIMEOUT)
                .header(reqwest::header::ACCEPT, LFS_JSON_MEDIA_TYPE)
                .header(reqwest::header::CONTENT_TYPE, LFS_JSON_MEDIA_TYPE)
                .body(body)
                .send()
                .map_err(|_| invalid("an LFS verify failed"))?,
            LfsRequest::ObjectDownload(action) => self
                .remote
                .action(reqwest::Method::GET, action.action())?
                .timeout(LFS_TRANSFER_TIMEOUT)
                .send()
                .map_err(|_| invalid("an LFS download failed"))?,
        };
        Ok(LfsReply {
            status: response.status().as_u16(),
            body: Box::new(response),
        })
    }
}
