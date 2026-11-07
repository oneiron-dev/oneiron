//! The git smart-HTTP adapter (ARCH-0069 OSH-3, the broker's second adapter
//! after model keys): one exchange of git's smart HTTP protocol with one
//! repository, its credential installed by the broker alone.
//!
//! The daemon names a typed target: a repository on one exact `https`
//! origin, one service (`git-upload-pack` or `git-receive-pack`) and one
//! exchange (the ref advertisement or the RPC). The method, the path, the
//! query and the content types follow from the target, so no call can pair
//! a repository with another path, or a service with another endpoint. The
//! request digest binds the target as well as the bytes, in its own digest
//! domain, so a git digest never equals a model one.
//!
//! One exchange is one connection, in steps:
//!
//! 1. The daemon writes the frame's opening word ([`crate::frame`]'s
//!    `GIT_CALL`), the [`GitCallHeader`], then the body in chunks of at most
//!    one stream chunk each and an empty segment. The daemon spooled the body
//!    first and took its digest; it holds no key yet.
//! 2. The broker checks the header, spools the body to a private unnamed
//!    file, takes the digest again as it passes, and answers one
//!    acknowledgement: prepared, or refused. A refused exchange ends there,
//!    and nothing was sent.
//! 3. Only once prepared does the daemon read the credential at its custody
//!    door and write it, a complete `Authorization` value, as one segment.
//!    Its copy is wiped once written.
//! 4. The broker installs that value as the one auth header, streams the
//!    spool to the repository, and writes the reply as a streamed reply: its
//!    header, its body in chunks exactly as they came, and the end. A reply
//!    that holds a literal form of the credential is cut
//!    ([`crate::Failure::ReplyHoldsKey`]) before any byte of the form goes,
//!    never rewritten: a rewrite would break pkt-line lengths and pack
//!    checksums. The model strip's rule of marking a run of escapes it cannot
//!    settle does not apply: a ref name or a pack full of escapes passes.
//!
//! No step has a call deadline or a total size bound: a pack can be any
//! size and take any time. Each step waits at most the exchange's own idle
//! bound without progress (the host's transfer idle limit, which the
//! header carries, so a model send's timeout never shortens it), the spool
//! needs the disk room for the body, and the daemon's hang-up cancels the
//! exchange. The broker alone times the repository: the daemon waits for
//! the reply's chunks as long as the broker relays them, since the broker
//! may hold bytes back while it watches them for the credential. No
//! redirect is followed and nothing is resent.

use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::digest::{field, sorted_headers};
use crate::{PROTOCOL_VERSION, Refusal};

#[cfg(unix)]
mod client;
#[cfg(unix)]
mod serve;

#[cfg(unix)]
pub use client::{GitReply, PreparedGitCall};
#[cfg(unix)]
pub(crate) use serve::serve_git;

/// The blake3 key-derivation context of a git request digest.
const DIGEST_CONTEXT: &str = "oneiron-broker 2026-11-06 git request digest v1";

/// The longest value the one header a git call may carry can hold.
const MAX_GIT_HEADER_VALUE: usize = 1024;

/// The one request header a git call may carry: the protocol version stock
/// git negotiates, kept the same across one conversation.
const GIT_PROTOCOL_HEADER: &str = "git-protocol";

/// A git repository on one exact `https` origin: its origin as
/// `https://host[:port]` and its path, no credential, query or fragment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitRepository {
    origin: String,
    path: String,
}

impl GitRepository {
    /// The repository `url` names: one `https` URL with a host, no
    /// credential, query or fragment, and a path of non-empty segments. A
    /// trailing slash is dropped.
    ///
    /// # Errors
    ///
    /// [`Refusal::Origin`] for anything but one credential-free `https`
    /// origin; [`Refusal::Path`] for a query, a fragment, or an empty or
    /// empty-segment path.
    pub fn parse(url: &str) -> Result<Self, Refusal> {
        let parsed = Url::parse(url).map_err(|_| Refusal::Origin)?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.host().is_none()
        {
            return Err(Refusal::Origin);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(Refusal::Path);
        }
        let repository = Self {
            origin: parsed.origin().ascii_serialization(),
            path: parsed.path().trim_end_matches('/').to_owned(),
        };
        repository.check()?;
        Ok(repository)
    }

    /// Whether this repository is in its plain form: one canonical `https`
    /// origin, and a path of non-empty segments, none `.` or `..`, that
    /// joins onto the origin unchanged. A frame's repository is checked
    /// again on both sides.
    ///
    /// # Errors
    ///
    /// [`Refusal::Origin`] or [`Refusal::Path`].
    pub fn check(&self) -> Result<(), Refusal> {
        let base = Url::parse(&self.origin).map_err(|_| Refusal::Origin)?;
        if base.scheme() != "https"
            || !base.username().is_empty()
            || base.password().is_some()
            || base.host().is_none()
            || base.origin().ascii_serialization() != self.origin
        {
            return Err(Refusal::Origin);
        }
        let Some(rest) = self.path.strip_prefix('/') else {
            return Err(Refusal::Path);
        };
        if rest
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
            || self.path.contains(['?', '#'])
        {
            return Err(Refusal::Path);
        }
        let joined =
            Url::parse(&format!("{}{}", self.origin, self.path)).map_err(|_| Refusal::Path)?;
        if joined.origin() != base.origin() || joined.path() != self.path {
            return Err(Refusal::Path);
        }
        Ok(())
    }

    /// Its `https://host[:port]`.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Its path under the origin, without a trailing slash.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// A git service over smart HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitService {
    /// Fetch and clone: `git-upload-pack`.
    UploadPack,
    /// Push: `git-receive-pack`.
    ReceivePack,
}

impl GitService {
    /// The service's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }
}

/// One of the two exchanges of a smart-HTTP conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitExchange {
    /// `GET …/info/refs?service=<service>`: the ref advertisement, no body.
    Advertisement,
    /// `POST …/<service>`: the negotiation or the pack, and its result.
    Rpc,
}

/// One git exchange's typed target: its repository, its service and its
/// exchange. Everything the request's line and content types hold follows
/// from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitTarget {
    pub repository: GitRepository,
    pub service: GitService,
    pub exchange: GitExchange,
}

impl GitTarget {
    /// The exchange's method.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self.exchange {
            GitExchange::Advertisement => "GET",
            GitExchange::Rpc => "POST",
        }
    }

    /// The path and query the exchange is sent to.
    #[must_use]
    pub fn path(&self) -> String {
        let repository = self.repository.path();
        let service = self.service.as_str();
        match self.exchange {
            GitExchange::Advertisement => format!("{repository}/info/refs?service={service}"),
            GitExchange::Rpc => format!("{repository}/{service}"),
        }
    }

    /// The URL the exchange is sent to, its target checked first.
    ///
    /// # Errors
    ///
    /// [`Refusal::Origin`] or [`Refusal::Path`] for a repository not in its
    /// plain form.
    pub fn url(&self) -> Result<Url, Refusal> {
        self.repository.check()?;
        Url::parse(&format!("{}{}", self.repository.origin(), self.path()))
            .map_err(|_| Refusal::Path)
    }

    /// The request's content type: the RPC's, none for an advertisement.
    #[must_use]
    pub fn request_content_type(&self) -> Option<String> {
        match self.exchange {
            GitExchange::Advertisement => None,
            GitExchange::Rpc => Some(format!("application/x-{}-request", self.service.as_str())),
        }
    }

    /// The content type the reply of a served exchange carries, which the
    /// request asks for.
    #[must_use]
    pub fn reply_content_type(&self) -> String {
        let service = self.service.as_str();
        match self.exchange {
            GitExchange::Advertisement => format!("application/x-{service}-advertisement"),
            GitExchange::Rpc => format!("application/x-{service}-result"),
        }
    }
}

/// Whether `headers` are the ones a git call may carry: at most one
/// `git-protocol`, lowercase, its value visible ASCII. Its content types
/// follow from its target and its credential from the broker, so no other
/// header rides.
///
/// # Errors
///
/// [`Refusal::Header`].
pub fn check_git_headers(headers: &[(String, String)]) -> Result<(), Refusal> {
    let mut seen = false;
    for (name, value) in headers {
        let visible = value.len() <= MAX_GIT_HEADER_VALUE
            && value.bytes().all(|byte| (0x20..0x7f).contains(&byte));
        if name != GIT_PROTOCOL_HEADER || seen || !visible {
            return Err(Refusal::Header);
        }
        seen = true;
    }
    Ok(())
}

/// The digest of one git request, taken as its body passes, in its own
/// digest domain: the target (origin, repository, service, exchange), the
/// method and path it derives, the sorted non-auth headers, the body's
/// length and its bytes. Each field is length-prefixed. The daemon takes it
/// as it spools the body; the broker takes it again as it receives the body
/// and sends nothing whose digest differs.
pub struct GitRequestDigest {
    hasher: blake3::Hasher,
    expected: u64,
    seen: u64,
}

impl GitRequestDigest {
    /// The digest of a request to `target` with `headers` and a body of
    /// `body_len` bytes, before its body.
    #[must_use]
    pub fn new(target: &GitTarget, headers: &[(String, String)], body_len: u64) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(DIGEST_CONTEXT);
        field(&mut hasher, target.repository.origin().as_bytes());
        field(&mut hasher, target.repository.path().as_bytes());
        field(&mut hasher, target.service.as_str().as_bytes());
        field(
            &mut hasher,
            match target.exchange {
                GitExchange::Advertisement => b"advertisement",
                GitExchange::Rpc => b"rpc",
            },
        );
        field(&mut hasher, target.method().as_bytes());
        field(&mut hasher, target.path().as_bytes());
        let sorted = sorted_headers(headers);
        hasher.update(&(sorted.len() as u64).to_le_bytes());
        for (name, value) in &sorted {
            field(&mut hasher, name.as_bytes());
            field(&mut hasher, value.as_bytes());
        }
        hasher.update(&body_len.to_le_bytes());
        Self {
            hasher,
            expected: body_len,
            seen: 0,
        }
    }

    /// Takes the next `bytes` of the body.
    pub fn update(&mut self, bytes: &[u8]) {
        self.seen = self.seen.saturating_add(bytes.len() as u64);
        self.hasher.update(bytes);
    }

    /// The digest, as lowercase hex, once the whole body passed.
    ///
    /// # Errors
    ///
    /// [`Refusal::Body`] when the body's bytes are not the length the
    /// digest began with.
    pub fn finish(self) -> Result<String, Refusal> {
        if self.seen != self.expected {
            return Err(Refusal::Body);
        }
        Ok(self.hasher.finalize().to_hex().to_string())
    }
}

/// One git exchange as the daemon asks the broker to send it. Its body
/// follows in chunks, and its credential only after the broker's
/// acknowledgement (see the module's steps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitCallHeader {
    /// [`PROTOCOL_VERSION`].
    pub version: u32,
    /// The daemon's id for the exchange, echoed in every answer.
    pub call: String,
    /// The repository, service and exchange.
    pub target: GitTarget,
    /// The request's headers ([`check_git_headers`]).
    pub headers: Vec<(String, String)>,
    /// The body's length in bytes.
    pub body_len: u64,
    /// [`GitRequestDigest`] of the target, the headers and the body.
    pub digest: String,
    /// How long, in milliseconds, each step of the exchange may wait
    /// without progress: the host's transfer idle limit. Transport context,
    /// outside the digest.
    pub idle_ms: u64,
}

impl GitCallHeader {
    /// The exchange `call` to `target`, whose body of `body_len` bytes had
    /// `digest` as the daemon spooled it, each step waiting at most `idle`
    /// without progress.
    #[must_use]
    pub fn new(
        call: String,
        target: GitTarget,
        headers: Vec<(String, String)>,
        body_len: u64,
        digest: String,
        idle: std::time::Duration,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            call,
            target,
            headers,
            body_len,
            digest,
            idle_ms: u64::try_from(idle.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// The exchange's idle bound.
    #[must_use]
    pub const fn idle(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.idle_ms)
    }

    /// Every check on the exchange's header, with no I/O: the daemon runs it
    /// before it connects, and the broker again before it spools. Returns
    /// the URL the exchange goes to.
    ///
    /// # Errors
    ///
    /// [`Refusal::Version`], [`Refusal::Frame`] for an empty or long call
    /// id or a zero idle bound, a target or header refusal, [`Refusal::Body`]
    /// for an advertisement with a body, [`Refusal::Digest`] for a digest
    /// not in its hex form.
    pub fn check(&self) -> Result<Url, Refusal> {
        if self.version != PROTOCOL_VERSION {
            return Err(Refusal::Version);
        }
        if self.call.is_empty() || self.call.len() > MAX_GIT_HEADER_VALUE || self.idle_ms == 0 {
            return Err(Refusal::Frame);
        }
        check_git_headers(&self.headers)?;
        if self.target.exchange == GitExchange::Advertisement && self.body_len != 0 {
            return Err(Refusal::Body);
        }
        if self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Refusal::Digest);
        }
        self.target.url()
    }
}

/// The broker's acknowledgement of a git exchange's header and body: the
/// body is spooled and its digest is the header's, so the daemon may hand
/// over the credential; or the exchange is refused, and nothing was sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GitPrepared {
    pub(crate) version: u32,
    pub(crate) call: String,
    pub(crate) digest: String,
    pub(crate) refused: Option<Refusal>,
}

/// The digest of one whole git request.
///
/// # Errors
///
/// None in practice: the body's length is its own.
pub fn git_request_digest(
    target: &GitTarget,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<String, Refusal> {
    let mut digest = GitRequestDigest::new(target, headers, body.len() as u64);
    digest.update(body);
    digest.finish()
}
