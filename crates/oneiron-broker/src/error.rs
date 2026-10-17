//! Why a call stopped. Every variant is a fixed code: none carries a key, a
//! body or a header value, so any of them can go into a receipt or a log.

use serde::{Deserialize, Serialize};

/// Why a call was refused before anything left for the provider. The daemon
/// can release the call's reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// The frame names a protocol version this broker does not speak.
    #[error("unsupported broker protocol version")]
    Version,
    /// A frame was cut, oversized or not the expected JSON.
    #[error("malformed broker frame")]
    Frame,
    /// The request's bytes do not hash to the digest the permit bound.
    #[error("request digest does not match")]
    Digest,
    /// The method is not the shape row's.
    #[error("method is not the shape's")]
    Method,
    /// The path is not the shape row's, or is not in its plain form.
    #[error("path is not the shape's")]
    Path,
    /// The origin is not one exact `https` origin.
    #[error("origin is not one https origin")]
    Origin,
    /// A request header is an auth, hop-by-hop or encoding header, repeated,
    /// or not a plain token and visible-ASCII value.
    #[error("request header refused")]
    Header,
    /// The body, or its content type, is not the shape's: one JSON object,
    /// one plain multipart form, or nothing for a shape that sends no body.
    #[error("body is not the shape's")]
    Body,
    /// The body has no top-level `model`, or its form no `model` field.
    #[error("body names no model")]
    SelectorMissing,
    /// The body names the model more than once, or names one beside the
    /// path's.
    #[error("body names the model twice")]
    SelectorRepeated,
    /// The `model` is not a string, or its form field is a file or typed.
    #[error("model is not a string")]
    SelectorNotString,
    /// The body carries a top-level `models`, `route` or `provider` key, or a
    /// form field of that name, which picks the model or the route by another
    /// way.
    #[error("body carries a route override")]
    RouteOverride,
    /// The selector is not the offer's wire model.
    #[error("model is not the admitted one")]
    WireModel,
    /// The key is empty, too short or too long, or holds a byte outside the
    /// strip rule's alphabet (one a URL holds, less the percent sign), or is
    /// part of the marker the rule writes.
    #[error("secret refused")]
    Secret,
    /// The provider could not be reached; no request byte was written.
    #[error("provider unreachable")]
    Connect,
}

/// Why a call that may have reached the provider has no answer. The call keeps
/// its reservation, as a started call does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    /// The send or the reply broke after the request may have left.
    #[error("send failed after the request may have left")]
    Send,
    /// The call ran out of time.
    #[error("call timed out")]
    Timeout,
    /// The reply is over the broker's buffer bound.
    #[error("reply is too large")]
    ReplyTooLarge,
    /// The reply is content-encoded, so the key could not be stripped from it.
    #[error("reply is content-encoded")]
    ReplyEncoded,
    /// The provider redirected where the shape does not follow, or again
    /// after the one redirect it follows.
    #[error("reply redirected where the shape does not follow")]
    Redirect,
    /// A streamed reply holds a form of the key, or a run too long to rule
    /// one out. A binary body is cut, never rewritten.
    #[error("streamed reply holds the key")]
    ReplyHoldsKey,
}

/// The daemon side's error for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    /// The broker's socket could not be reached. Nothing was written.
    #[error("broker socket unreachable")]
    Unreachable,
    /// The peer on the socket is not the configured broker user, or that user
    /// is the daemon's own. Nothing was written.
    #[error("broker peer refused")]
    Peer,
    /// The daemon refused the call itself, before any key was read.
    #[error("refused: {0}")]
    Refused(Refusal),
    /// The connection broke after the frame was written, or the reply was
    /// malformed or answered another call. The request may have left.
    #[error("broker reply lost or malformed")]
    Lost,
}
