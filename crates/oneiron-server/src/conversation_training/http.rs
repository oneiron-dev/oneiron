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
//!
//! The shipper's `POST`s (`shipper`) keep the client's settings but take a
//! time of their own, 30 s plus a second for each 64 KiB of the body (CALLS
//! TL6_UPLOAD_TIMEOUT), and carry one header, the body's type. Their answer
//! tells a `413` and a request whose time ran out apart from the other
//! failures, since the shipper splits its windows on both.

use std::sync::OnceLock;
use std::time::Duration;

use oneiron_vault_contract::conversation_training::{
    PIECE_ROUTE_PREFIX, PieceErrorBodyV1, PieceErrorV1,
};
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use reqwest::header::CONTENT_TYPE;

use super::retry::{Failure, retry_after};

/// A request's whole time; a `POST` adds its body's share
/// (CALLS TL6_UPLOAD_TIMEOUT).
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// A connection's time to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// What a `POST` to the intake came back with, past the failures every
/// request shares.
pub(super) enum Posted {
    /// A success: its body.
    Body(Vec<u8>),
    /// `413`: the request does not fit the intake's bounds. The refusal's
    /// body, with the bounds it advertises, when it decodes.
    Split(Option<PieceErrorBodyV1>),
    /// The request's time ran out after it connected: its body may be too
    /// large for the uplink to carry in that time.
    TimedOut,
}

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

    /// `POST`s `body`, of `content_type`, to `route` under the window's
    /// prefix, with `timeout` for the whole request: a success's body, a
    /// `413`'s refusal, or a request whose time ran out. It sends no header
    /// but the body's type.
    ///
    /// # Errors
    /// A [`Failure`]: no reply; a busy one, waiting the longer of the waits
    /// its `Retry-After` and its body name; or any other status. Neither the
    /// URL nor a body is ever in it.
    pub(super) fn post(
        &self,
        route: &str,
        content_type: &str,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Posted, Failure> {
        let url = format!("{}{PIECE_ROUTE_PREFIX}{route}", self.origin);
        let sent = self
            .client()?
            .post(url)
            .header(CONTENT_TYPE, content_type)
            .body(body)
            .timeout(timeout)
            .send();
        let response = match sent {
            Ok(response) => response,
            Err(error) if timed_out(&error) => return Ok(Posted::TimedOut),
            Err(_) => return Err(Failure::Network),
        };
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE {
            let header = retry_after(response.headers());
            let named = refusal(response)
                .and_then(|error| error.retry_after_secs)
                .map(Duration::from_secs);
            return Err(Failure::Busy {
                status: status.as_u16(),
                retry_after: header.max(named),
            });
        }
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            return Ok(Posted::Split(refusal(response)));
        }
        if !status.is_success() {
            return Err(Failure::Reply(Some(status.as_u16())));
        }
        match response.bytes() {
            Ok(body) => Ok(Posted::Body(body.to_vec())),
            Err(error) if timed_out(&error) => Ok(Posted::TimedOut),
            Err(_) => Err(Failure::Network),
        }
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

/// Whether a request failed because its whole time ran out once it had
/// connected; a connection that did not open in time is no reply.
fn timed_out(error: &reqwest::Error) -> bool {
    error.is_timeout() && !error.is_connect()
}

/// A refused request's body, when it decodes.
fn refusal(response: Response) -> Option<PieceErrorBodyV1> {
    let body = response.bytes().ok()?;
    serde_json::from_slice::<PieceErrorV1>(&body)
        .ok()
        .map(|refused| refused.error)
}
