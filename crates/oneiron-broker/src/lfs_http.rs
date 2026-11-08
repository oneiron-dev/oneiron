//! The Git LFS adapter (ARCH-0069, the broker's third adapter, beside git's
//! smart HTTP): one request of a repository's Git LFS batch API, or one of
//! the basic-transfer actions a batch reply named, its repository
//! credential installed by the broker alone.
//!
//! The daemon names a typed target ([`LfsTarget`]):
//!
//! - a batch: `POST` to the batch endpoint of a repository on one exact
//!   `https` origin ([`GitRepository`]), its path ending in
//!   `.git/info/lfs/objects/batch`, under one operation (upload or
//!   download). It carries no header of the daemon's: its media types
//!   follow from the target, and its one credential, when the repository
//!   asks for one, is the complete `Authorization` value the daemon hands
//!   over after the acknowledgement, as a git exchange's is;
//! - an object download (`GET`), an object upload (`PUT`) or a verify
//!   (`POST`): to the `https` href a batch reply named for one requested
//!   object, with the headers that reply named for that action, as given.
//!   Its storage may live on another public host, so the href's host is
//!   admitted when the broker resolves it: every address it resolves to
//!   must be a global one, and the send reaches those addresses alone. An
//!   action carries the repository credential only where the broker put
//!   [`LFS_CREDENTIAL_PLACEHOLDER`] in its place (see below).
//!
//! The method and the media types follow from the target. The request
//! digest binds the target (repository, operation or action, and for an
//! action the batch it came from, the object and its size), the method, the
//! URL, every header (an action's own `Authorization` too, the placeholder
//! as given), the body's length and its bytes, in its own digest domain, so
//! an LFS digest never equals a git or model one.
//!
//! One exchange is one connection, in a git exchange's steps
//! (`crate::exchange`): the frame's opening word ([`crate::frame`]'s
//! `LFS_CALL`), the [`LfsCallHeader`] and the body in chunks; the broker's
//! spool, its digest check and, for an action, the admission of its host;
//! one acknowledgement; then one credential segment, which is the
//! `Authorization` value for a batch, or empty for an anonymous batch and
//! for an action (the same value only on an action that names the
//! placeholder); then the reply as a streamed reply.
//!
//! A repository may hand the batch's own `Authorization` value back in the
//! headers of the actions it names, for the client to send on them. The
//! broker reads a batch reply whole, within the reply limit the daemon
//! names ([`LfsCallHeader::reply_limit`]; past it the reply is cut,
//! [`crate::Failure::ReplyTooLarge`]), and where it is the batch JSON it
//! rewrites to the placeholder each action header value, in an object with
//! no error, that is the installed value byte for byte; it tells the daemon
//! how many it rewrote, never what. Then it watches the reply for every
//! literal form of the credential (the whole value too, raw and as JSON
//! spells it, whatever its length): one left anywhere cuts the reply
//! ([`crate::Failure::ReplyHoldsKey`]). Any other reply, not JSON or not
//! the batch JSON, is never rewritten, only watched. The broker installs
//! the credential again, in place of the placeholder and under that
//! header's own name, on an action with a header of the placeholder (under
//! any name) whose URL has the
//! repository's own origin (scheme, host and port), and watches that
//! action's reply as it watches a batch's. A placeholder on an action at
//! another origin, or a credential on an action that names none, is
//! refused before anything is sent. Every other action carries no
//! credential, and its reply goes byte for byte. A cut reply is no answer:
//! a batch's JSON or an object's bytes count only once the end is clean.
//!
//! As for git, no step has a call deadline, and only a batch reply has a
//! size bound: an object can be any size and take any time. Each step waits
//! at most the exchange's idle bound without progress, the spool needs the
//! disk room for the body, and the daemon's hang-up cancels the exchange.
//! No redirect is followed and nothing is resent.

use reqwest::Url;
use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::digest::{BodyDigest, field, is_hex_digest};
use crate::git_http::{GitRepository, MAX_GIT_HEADER_VALUE};
use crate::{PROTOCOL_VERSION, Refusal};

#[cfg(unix)]
mod client;
#[cfg(unix)]
mod serve;

#[cfg(unix)]
pub use client::{LfsReply, PreparedLfsCall};
#[cfg(unix)]
pub(crate) use serve::serve_lfs;

/// The blake3 key-derivation context of an LFS request digest.
const DIGEST_CONTEXT: &str = "oneiron-broker 2026-11-06 lfs request digest v1";

/// The value the broker writes in a batch reply's action header in place of
/// the repository's `Authorization` value, which the repository handed back
/// for the action: the daemon sees this, never the value. It has no space,
/// so it is never an `Authorization` value the broker installs (a scheme,
/// a space, then credentials).
pub const LFS_CREDENTIAL_PLACEHOLDER: &str = "oneiron-broker-repository-credential";

/// The media type of a batch request and its reply, and of a verify.
const LFS_JSON_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";

/// The media type of an uploaded object's bytes.
const LFS_OBJECT_MEDIA_TYPE: &str = "application/octet-stream";

/// Headers an action may not carry: the HTTP stack writes the connection
/// and the host itself, and the broker asks for identity coding, so the
/// reply's bytes are the object's. An action's `Content-Length` and
/// `Transfer-Encoding` are checked against the body instead
/// ([`check_lfs_headers`]).
const RESERVED_ACTION_HEADERS: [&str; 9] = [
    "accept-encoding",
    "connection",
    "content-encoding",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// A batch's operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LfsOperation {
    /// A mirror's objects go up.
    Upload,
    /// An import's objects come down.
    Download,
}

impl LfsOperation {
    /// The operation's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }
}

/// A batch call's target: the repository whose LFS batch API it calls, and
/// the operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LfsBatchTarget {
    pub repository: GitRepository,
    pub operation: LfsOperation,
}

impl LfsBatchTarget {
    /// The batch endpoint: the repository's URL with `.git` once, then
    /// `/info/lfs/objects/batch`.
    #[must_use]
    pub fn endpoint(&self) -> String {
        let origin = self.repository.origin();
        let path = self.repository.path();
        if path.ends_with(".git") {
            format!("{origin}{path}/info/lfs/objects/batch")
        } else {
            format!("{origin}{path}.git/info/lfs/objects/batch")
        }
    }

    /// The URL the batch is sent to, its repository checked first.
    ///
    /// # Errors
    ///
    /// [`Refusal::Origin`] or [`Refusal::Path`] for a repository not in its
    /// plain form.
    pub fn url(&self) -> Result<Url, Refusal> {
        self.repository.check()?;
        Url::parse(&self.endpoint()).map_err(|_| Refusal::Path)
    }
}

/// One action a batch reply named: the repository whose batch named it,
/// that batch call's digest, the requested object and its size, and the
/// href, exactly as the reply gave it. The daemon names only an action the
/// reply to that batch gave for that object; the broker, which keeps no
/// state between exchanges, binds the association into the digest but
/// cannot prove it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LfsActionTarget {
    pub repository: GitRepository,
    /// The digest of the batch call whose reply named the action.
    pub batch: String,
    /// The object's SHA-256, lowercase hex.
    pub oid: String,
    /// The object's size the batch requested.
    pub size: u64,
    /// The action's href.
    pub href: String,
}

impl LfsActionTarget {
    /// The URL the action is sent to: its href, literal `https`, with a
    /// host and no credential or fragment. Its path and its query (a signed
    /// one included) go as given, and its host may be another than the
    /// repository's. The repository is checked too.
    ///
    /// # Errors
    ///
    /// [`Refusal::Origin`] for a repository not in its plain form, or an
    /// href that is not one credential-free `https` URL with a host;
    /// [`Refusal::Path`] for a repository path not in its plain form, or a
    /// fragment.
    pub fn url(&self) -> Result<Url, Refusal> {
        self.repository.check()?;
        if !self.href.starts_with("https://") {
            return Err(Refusal::Origin);
        }
        let url = Url::parse(&self.href).map_err(|_| Refusal::Origin)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.host().is_none()
        {
            return Err(Refusal::Origin);
        }
        if url.fragment().is_some() {
            return Err(Refusal::Path);
        }
        Ok(url)
    }
}

/// One LFS exchange's typed target. Its method and media types follow from
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LfsTarget {
    /// `POST` to the repository's batch endpoint, under the repository
    /// credential when it asks for one.
    Batch(LfsBatchTarget),
    /// `GET` an object from a download action.
    ObjectDownload(LfsActionTarget),
    /// `PUT` an object to an upload action.
    ObjectUpload(LfsActionTarget),
    /// `POST` an uploaded object's id and size to a verify action.
    Verify(LfsActionTarget),
}

impl LfsTarget {
    /// The repository the exchange is for.
    #[must_use]
    pub const fn repository(&self) -> &GitRepository {
        match self {
            Self::Batch(batch) => &batch.repository,
            Self::ObjectDownload(action) | Self::ObjectUpload(action) | Self::Verify(action) => {
                &action.repository
            }
        }
    }

    /// The action, for any target but a batch.
    #[must_use]
    pub const fn action(&self) -> Option<&LfsActionTarget> {
        match self {
            Self::Batch(_) => None,
            Self::ObjectDownload(action) | Self::ObjectUpload(action) | Self::Verify(action) => {
                Some(action)
            }
        }
    }

    /// Whether the target is a batch, the one exchange that may carry the
    /// repository credential.
    #[must_use]
    pub const fn is_batch(&self) -> bool {
        matches!(self, Self::Batch(_))
    }

    /// The exchange's method.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Batch(_) | Self::Verify(_) => "POST",
            Self::ObjectDownload(_) => "GET",
            Self::ObjectUpload(_) => "PUT",
        }
    }

    /// The URL the exchange is sent to, as text: a batch's endpoint, or an
    /// action's href as given.
    #[must_use]
    pub fn endpoint(&self) -> String {
        match self {
            Self::Batch(batch) => batch.endpoint(),
            Self::ObjectDownload(action) | Self::ObjectUpload(action) | Self::Verify(action) => {
                action.href.clone()
            }
        }
    }

    /// The URL the exchange is sent to, its target checked first.
    ///
    /// # Errors
    ///
    /// [`Refusal::Origin`] or [`Refusal::Path`] ([`LfsBatchTarget::url`],
    /// [`LfsActionTarget::url`]).
    pub fn url(&self) -> Result<Url, Refusal> {
        match self {
            Self::Batch(batch) => batch.url(),
            Self::ObjectDownload(action) | Self::ObjectUpload(action) | Self::Verify(action) => {
                action.url()
            }
        }
    }

    /// Whether the request carries a body: all but a download.
    #[must_use]
    pub const fn carries_body(&self) -> bool {
        !matches!(self, Self::ObjectDownload(_))
    }

    /// The `Accept` the broker sends, unless an action names its own.
    pub(crate) const fn accept(&self) -> Option<&'static str> {
        match self {
            Self::Batch(_) | Self::Verify(_) => Some(LFS_JSON_MEDIA_TYPE),
            Self::ObjectDownload(_) | Self::ObjectUpload(_) => None,
        }
    }

    /// The `Content-Type` the broker sends with the body, unless an action
    /// names its own.
    pub(crate) const fn content_type(&self) -> Option<&'static str> {
        match self {
            Self::Batch(_) | Self::Verify(_) => Some(LFS_JSON_MEDIA_TYPE),
            Self::ObjectUpload(_) => Some(LFS_OBJECT_MEDIA_TYPE),
            Self::ObjectDownload(_) => None,
        }
    }

    /// The target's kind, as the digest binds it.
    const fn kind(&self) -> &'static str {
        match self {
            Self::Batch(_) => "batch",
            Self::ObjectDownload(_) => "object_download",
            Self::ObjectUpload(_) => "object_upload",
            Self::Verify(_) => "verify",
        }
    }
}

/// Whether `headers` are the ones an exchange to `target` with a body of
/// `body_len` bytes may carry. A batch carries none: its media types follow
/// from its target and its credential from the broker. An action carries
/// the headers its batch reply named, as given, its own `Authorization`
/// among them: each a header name and value HTTP can send unchanged, none
/// of [`RESERVED_ACTION_HEADERS`], a `Content-Length` only of `body_len`,
/// and a `Transfer-Encoding` only `chunked`.
///
/// # Errors
///
/// [`Refusal::Header`].
pub fn check_lfs_headers(
    target: &LfsTarget,
    headers: &[(String, String)],
    body_len: u64,
) -> Result<(), Refusal> {
    if target.is_batch() {
        return if headers.is_empty() {
            Ok(())
        } else {
            Err(Refusal::Header)
        };
    }
    for (name, value) in headers {
        if HeaderName::from_bytes(name.as_bytes()).is_err() || HeaderValue::from_str(value).is_err()
        {
            return Err(Refusal::Header);
        }
        let lower = name.to_ascii_lowercase();
        let admitted = match lower.as_str() {
            "content-length" => *value == body_len.to_string(),
            "transfer-encoding" => value.trim().eq_ignore_ascii_case("chunked"),
            other => !RESERVED_ACTION_HEADERS.contains(&other),
        };
        if !admitted {
            return Err(Refusal::Header);
        }
    }
    Ok(())
}

/// Whether an action header's `value` is one the broker installs the
/// repository credential in: exactly [`LFS_CREDENTIAL_PLACEHOLDER`], under
/// any header name, since the batch reply's rewrite puts it in place of the
/// installed value in whichever action header held it.
pub(crate) fn is_credential_placeholder(value: &str) -> bool {
    value == LFS_CREDENTIAL_PLACEHOLDER
}

/// The digest of one LFS request, taken as its body passes, in its own
/// digest domain: the target's kind and repository; a batch's operation, or
/// an action's batch digest, object id and size; the method and URL it
/// derives; every header, in its order, as given; the body's length and
/// its bytes. Each field is length-prefixed. The daemon takes it as it
/// spools the body; the broker takes it again as it receives the body and
/// sends nothing whose digest differs.
pub struct LfsRequestDigest {
    body: BodyDigest,
}

impl LfsRequestDigest {
    /// The digest of a request to `target` with `headers` and a body of
    /// `body_len` bytes, before its body.
    #[must_use]
    pub fn new(target: &LfsTarget, headers: &[(String, String)], body_len: u64) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(DIGEST_CONTEXT);
        field(&mut hasher, target.kind().as_bytes());
        let repository = target.repository();
        field(&mut hasher, repository.origin().as_bytes());
        field(&mut hasher, repository.path().as_bytes());
        match target {
            LfsTarget::Batch(batch) => field(&mut hasher, batch.operation.as_str().as_bytes()),
            LfsTarget::ObjectDownload(action)
            | LfsTarget::ObjectUpload(action)
            | LfsTarget::Verify(action) => {
                field(&mut hasher, action.batch.as_bytes());
                field(&mut hasher, action.oid.as_bytes());
                hasher.update(&action.size.to_le_bytes());
            }
        }
        field(&mut hasher, target.method().as_bytes());
        field(&mut hasher, target.endpoint().as_bytes());
        hasher.update(&(headers.len() as u64).to_le_bytes());
        for (name, value) in headers {
            field(&mut hasher, name.as_bytes());
            field(&mut hasher, value.as_bytes());
        }
        Self {
            body: BodyDigest::new(hasher, body_len),
        }
    }

    /// Takes the next `bytes` of the body.
    pub fn update(&mut self, bytes: &[u8]) {
        self.body.update(bytes);
    }

    /// The digest, as lowercase hex, once the whole body passed.
    ///
    /// # Errors
    ///
    /// [`Refusal::Body`] when the body's bytes are not the length the
    /// digest began with.
    pub fn finish(self) -> Result<String, Refusal> {
        self.body.finish()
    }

    /// Its body half, for the broker's spool to take the body into.
    #[cfg(unix)]
    pub(crate) fn into_body(self) -> BodyDigest {
        self.body
    }
}

/// The digest of one whole LFS request.
///
/// # Errors
///
/// None in practice: the body's length is its own.
pub fn lfs_request_digest(
    target: &LfsTarget,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<String, Refusal> {
    let mut digest = LfsRequestDigest::new(target, headers, body.len() as u64);
    digest.update(body);
    digest.finish()
}

/// One LFS exchange as the daemon asks the broker to send it. Its body
/// follows in chunks, and its credential segment only after the broker's
/// acknowledgement (see the module's steps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LfsCallHeader {
    /// [`PROTOCOL_VERSION`].
    pub version: u32,
    /// The daemon's id for the exchange, echoed in every answer.
    pub call: String,
    /// The batch or the action.
    pub target: LfsTarget,
    /// The request's headers ([`check_lfs_headers`]).
    pub headers: Vec<(String, String)>,
    /// The body's length in bytes.
    pub body_len: u64,
    /// [`LfsRequestDigest`] of the target, the headers and the body.
    pub digest: String,
    /// How long, in milliseconds, each step of the exchange may wait
    /// without progress: the host's transfer idle limit. Transport context,
    /// outside the digest.
    pub idle_ms: u64,
    /// The largest batch reply, in bytes, the broker reads whole to rewrite
    /// and watch it: the daemon's own bound on a batch answer, so a reply
    /// past it is cut as the daemon would refuse it. A batch carries one;
    /// an action, whose reply streams, carries none. Transport context,
    /// outside the digest.
    pub reply_limit: Option<u64>,
}

impl LfsCallHeader {
    /// The exchange `call` to `target`, whose body of `body_len` bytes had
    /// `digest` as the daemon spooled it, each step waiting at most `idle`
    /// without progress, a batch's reply read whole up to `reply_limit`
    /// bytes (none for an action).
    #[must_use]
    pub fn new(
        call: String,
        target: LfsTarget,
        headers: Vec<(String, String)>,
        body_len: u64,
        digest: String,
        idle: std::time::Duration,
        reply_limit: Option<u64>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            call,
            target,
            headers,
            body_len,
            digest,
            idle_ms: u64::try_from(idle.as_millis()).unwrap_or(u64::MAX),
            reply_limit,
        }
    }

    /// The exchange's idle bound.
    #[must_use]
    pub const fn idle(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.idle_ms)
    }

    /// A batch's reply limit; none for an action.
    #[cfg(unix)]
    pub(crate) fn batch_reply_limit(&self) -> Option<u64> {
        self.reply_limit.filter(|_| self.target.is_batch())
    }

    /// Whether the exchange is an action with a header of
    /// [`LFS_CREDENTIAL_PLACEHOLDER`], under any name: the one action the
    /// broker installs the repository credential on again, under that
    /// header's own name, so the daemon opens it with that credential
    /// (`PreparedLfsCall::open`). Its URL has the repository's own origin,
    /// or [`Self::check`] refuses it.
    #[must_use]
    pub fn names_credential_placeholder(&self) -> bool {
        !self.target.is_batch()
            && self
                .headers
                .iter()
                .any(|(_, value)| is_credential_placeholder(value))
    }

    /// Every check on the exchange's header, with no I/O: the daemon runs it
    /// before it connects, and the broker again before it spools. Returns
    /// the URL the exchange goes to. The broker admits an action's host
    /// after this, as it resolves it.
    ///
    /// # Errors
    ///
    /// [`Refusal::Version`], [`Refusal::Frame`] for an empty or long call
    /// id, a zero idle bound, a batch with no reply limit or an action with
    /// one, a header refusal, [`Refusal::Body`] for a download with a body
    /// or an upload whose body is not the object's size,
    /// [`Refusal::Digest`] for a digest, a batch digest or an object id not
    /// in its hex form, a target refusal, [`Refusal::Secret`] for an action
    /// with a header of [`LFS_CREDENTIAL_PLACEHOLDER`] whose URL's origin
    /// (scheme, host and port) is not the repository's.
    pub fn check(&self) -> Result<Url, Refusal> {
        if self.version != PROTOCOL_VERSION {
            return Err(Refusal::Version);
        }
        if self.call.is_empty()
            || self.call.len() > MAX_GIT_HEADER_VALUE
            || self.idle_ms == 0
            || self.reply_limit.is_some() != self.target.is_batch()
        {
            return Err(Refusal::Frame);
        }
        check_lfs_headers(&self.target, &self.headers, self.body_len)?;
        let sized = match &self.target {
            LfsTarget::Batch(_) | LfsTarget::Verify(_) => true,
            LfsTarget::ObjectDownload(_) => self.body_len == 0,
            LfsTarget::ObjectUpload(action) => self.body_len == action.size,
        };
        if !sized {
            return Err(Refusal::Body);
        }
        if !is_hex_digest(&self.digest)
            || self
                .target
                .action()
                .is_some_and(|action| !(is_hex_digest(&action.batch) && is_hex_digest(&action.oid)))
        {
            return Err(Refusal::Digest);
        }
        let url = self.target.url()?;
        let placeholder = self
            .headers
            .iter()
            .any(|(_, value)| is_credential_placeholder(value));
        if placeholder && url.origin().ascii_serialization() != self.target.repository().origin() {
            return Err(Refusal::Secret);
        }
        Ok(url)
    }
}

/// The LFS frame between an answered batch reply's header and its body:
/// how many action header values the broker rewrote to
/// [`LFS_CREDENTIAL_PLACEHOLDER`]. A count, never a value.
#[cfg(unix)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchRewrites {
    pub(crate) credential_rewrites: u64,
}
