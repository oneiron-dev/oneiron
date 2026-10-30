//! An owner's sealed custody change past the facade's request ceiling (FIX
//! 11454). A `vault.secrets.custody.submit` whose body is over
//! [`MAX_REMOTE_REQUEST_BYTES`](crate::caps::MAX_REMOTE_REQUEST_BYTES) goes
//! to `POST /v1/owner/secrets/custody`, the owner route that spools a sealed
//! input of any length, under the same credential, in place of the facade
//! verb. The route's custody reply is the
//! verb's `SecretCustodyReply` field for field (its receipt, why the change
//! stayed here, delivery, the words and the manifest check), so it decodes
//! as the verb's answer. A body within the ceiling takes the verb as before.

use oneiron::memory::MemoryError;
use reqwest::Method;
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use serde::de::DeserializeOwned;

use super::response::read_error_envelope;
use super::{RemoteClient, accept_json, read_json};
use crate::error::transport_error;

/// The verb whose body past the ceiling is sent to the owner route.
pub(super) const CUSTODY_SUBMIT_VERB: &str = "vault.secrets.custody.submit";
/// The owner route that spools a sealed custody change whatever its length.
const OWNER_CUSTODY_ROUTE: &str = "v1/owner/secrets/custody";

impl RemoteClient {
    /// Posts `body`, a `vault.secrets.custody.submit` input past the
    /// facade's ceiling, to the owner route under this handle's credential,
    /// and decodes its reply as the verb's. The route keeps no call receipt.
    pub(super) fn custody_submit_spooled<R: DeserializeOwned>(
        &self,
        body: Vec<u8>,
    ) -> Result<R, MemoryError> {
        let url = self.base_url.join(OWNER_CUSTODY_ROUTE).map_err(|error| {
            transport_error(format!("could not build the custody route URL: {error}"))
        })?;
        let mut headers = self.credential_headers()?;
        accept_json(&mut headers);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        // A body this size rides the long client's total timeout, sent as it
        // is: the route spools the raw bytes.
        let reply = self.send(Method::POST, url, headers, Some(body), true)?;
        self.note_reply_receipt(&reply.headers);
        let status = reply.status;
        if !status.is_success() {
            return Err(read_error_envelope(reply.body, status));
        }
        read_json(reply.body, status, CUSTODY_SUBMIT_VERB)
    }
}
