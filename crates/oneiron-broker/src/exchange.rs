//! What the broker's spooled exchanges share: a git exchange (OSH-3,
//! `git_http`) and an LFS exchange (`lfs_http`). Each runs the same steps on
//! one connection: the daemon writes its frame's opening word, its header
//! and its body in chunks; the broker spools the body to a private unnamed
//! file, takes its digest again as it passes, and acknowledges; only then
//! does the daemon write its credential segment; the broker sends once and
//! streams the reply, cut rather than rewritten when it holds a literal
//! form of the credential (an LFS batch reply's exact echoes in its action
//! headers alone are rewritten first, `lfs_http`). Each adapter keeps its
//! own target, digest domain, headers and request; these modules hold the
//! rest.
//!
//! - [`client`]: the daemon's side, from the opening word to the reply's
//!   end.
//! - [`spool`]: the broker's spool of the body, its acknowledgement, and
//!   the spool as the request's body.
//! - [`send`]: the one send, dropped on the daemon's hang-up and timed by
//!   the idle bound.
//! - [`relay`]: the reply, relayed byte for byte under the echo watch.
//! - [`credential`]: the one `Authorization` value the daemon hands over.

use std::future::Future;
use std::io;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::Refusal;

pub(crate) mod client;
pub(crate) mod credential;
pub(crate) mod relay;
pub(crate) mod send;
pub(crate) mod spool;

/// The broker's acknowledgement of an exchange's header and body: the body
/// is spooled and its digest is the header's, so the daemon may hand over
/// the credential; or the exchange is refused, and nothing was sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) version: u32,
    pub(crate) call: String,
    pub(crate) digest: String,
    pub(crate) refused: Option<Refusal>,
}

/// One step on the daemon's socket, within `idle`.
pub(crate) async fn idle_bound<T>(
    idle: Duration,
    step: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(idle, step)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}
