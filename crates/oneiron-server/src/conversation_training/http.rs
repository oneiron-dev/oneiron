//! The anonymous training window's HTTP client (TL-6, CALLS TL6_HTTP_CLIENT):
//! one private blocking client per intake, for every request a self-hosted
//! vault makes there, the descriptor's now and the shipper's with it.
//!
//! Its settings are the feedback transport's: no redirect is followed, a
//! request has 30 s in all and 10 s to connect, rustls verifies the origin's
//! certificate, and a proxy the environment names is used as reqwest does by
//! default. A request carries no bearer, cookie, User-Agent, idempotency key,
//! install key or vault id: nothing in it names the vault or its install.
//!
//! The client is made on its first use, on a blocking thread: reqwest's
//! blocking client is never made or used on the async runtime.

use std::sync::OnceLock;
use std::time::Duration;

use oneiron_vault_contract::conversation_training::PIECE_ROUTE_PREFIX;
use reqwest::StatusCode;
use reqwest::blocking::Client;

use super::retry::{Failure, retry_after};

/// A request's whole time.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// A connection's time to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The publisher's intake, as one self-hosted vault reaches it.
pub(super) struct Intake {
    /// The intake's origin, with no trailing `/`.
    origin: String,
    /// The client, made on first use.
    client: OnceLock<Client>,
}

impl Intake {
    /// The intake at `origin`, an origin the serve config already checked
    /// (`validate_intake_origin`).
    pub(super) fn new(origin: &str) -> Self {
        Self {
            origin: origin.trim_end_matches('/').to_owned(),
            client: OnceLock::new(),
        }
    }

    /// `GET`s `route` under the window's prefix: the body of a success.
    ///
    /// # Errors
    /// A [`Failure`]: no reply, a busy one with the wait it names, or any
    /// other status. Neither the URL nor a body is ever in it.
    pub(super) fn get(&self, route: &str) -> Result<Vec<u8>, Failure> {
        let url = format!("{}{PIECE_ROUTE_PREFIX}{route}", self.origin);
        let response = self
            .client()?
            .get(url)
            .send()
            .map_err(|_| Failure::Network)?;
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE {
            return Err(Failure::Busy {
                status: status.as_u16(),
                retry_after: retry_after(response.headers()),
            });
        }
        if !status.is_success() {
            return Err(Failure::Reply(Some(status.as_u16())));
        }
        response
            .bytes()
            .map(|body| body.to_vec())
            .map_err(|_| Failure::Network)
    }

    /// The client, made on its first use.
    fn client(&self) -> Result<&Client, Failure> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let made = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|_| Failure::Network)?;
        Ok(self.client.get_or_init(|| made))
    }
}
