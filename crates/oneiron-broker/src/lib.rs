//! The credential broker (ARCH-0069 `#credential-broker`, `#broker-design`).
//!
//! A small process that holds a model key for one call at a time. The daemon
//! admits the call under its run, frames the exact request it wants sent and
//! hands over the key on a private channel. The broker re-checks the request
//! against its digest and its shape row, adds the auth header, sends once over
//! verified TLS, strips every form of the key from the reply and answers. A
//! binary reply ([`Shape::streams`]) streams back in chunks instead, checked
//! for the key and passed unchanged, or cut.
//!
//! It runs no model and no generated code, and it does not link the engine.
//! The daemon side ([`BrokerClient`]) and the broker side ([`serve`]) share the
//! checks in [`CallHeader::check`], so the daemon refuses a bad request before
//! it reads any key, and the broker refuses it again before it sends.

mod call;
pub mod cli;
mod digest;
mod error;
mod form;
mod frame;
mod send;
mod shape;
mod strip;
#[cfg(feature = "test-support")]
pub mod testing;

#[cfg(unix)]
mod child;
#[cfg(unix)]
mod client;
#[cfg(unix)]
mod peer;
#[cfg(unix)]
mod serve;

pub use call::{CallHeader, Outcome, ReplyHeader};
pub use digest::{is_auth_header, request_digest};
pub use error::{BrokerError, Failure, Refusal};
pub use form::FormData;
pub use frame::{MAX_BODY, MAX_SECRET, MAX_STREAM, PROTOCOL_VERSION};
pub use send::SendPolicy;
pub use shape::Shape;
pub use strip::{MARKER, strip};

#[cfg(unix)]
pub use child::ChildBroker;
#[cfg(unix)]
pub use client::{BrokerClient, BrokerConnection, BrokerReply, BrokerStream, StreamPart};
#[cfg(unix)]
pub use serve::{LISTENING, ServeConfig, serve};

use serde::{Deserialize, Serialize};

/// How the broker is kept apart from the runner, as receipts name it
/// (`broker_isolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// Its own OS user (or container) on a peer-checked Unix socket (OSH-2).
    SeparateUser,
    /// A child of the daemon under the daemon's uid, non-dumpable
    /// ([`ChildBroker`], `#broker-same-user-open`). Receipts carry the
    /// unproven badge.
    SameUser,
}

impl Isolation {
    /// The receipt spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SeparateUser => "separate_user",
            Self::SameUser => "same_user",
        }
    }
}
