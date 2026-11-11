//! The port every Git-LFS exchange goes through (FIX 19876): a batch call
//! to one remote's batch API, and each object action its answer returned,
//! an object's upload, its verify and an object's download.
//!
//! The batch client keeps the algorithm and every check: the batches,
//! which answer names which requested object, the objects still missing,
//! the upload-then-verify order, the bound of a batch answer, the store's
//! size and SHA-256 checks before an upload, and the upload door's scan,
//! SHA-256 and size checks on a download. A transport carries each exchange
//! once and judges no answer. A served host's credential broker carries a
//! mirror's upload and an outside import's download; a vault opened with no
//! host sends a mirror's upload through the direct HTTPS client.
//!
//! No request holds a credential. A batch call names its credential slot:
//! none, or the remote's own credential (a mirror's push credential, an
//! outside import source's binding), which the transport installs. An
//! object action carries the headers its batch answer named for it, as
//! given, and never the remote's credential. A body is a file or bytes,
//! and a reply's body streams.
//!
//! A served host's transport sends each exchange through its credential
//! broker, which alone installs the remote's credential; the host answers
//! how its exchanges went with the orchestration's own answer
//! ([`LfsTransferReport`]).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use serde::Deserialize;

use super::LfsOid;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::BrokerIsolation;
use crate::origin::smart_http::SpillFloor;

/// An LFS exchange or answer refused, `why` naming the step.
pub(super) fn invalid(why: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidLfsObject(why))
}

/// The transport one Git-LFS remote's exchanges go through. A transport
/// speaks to one remote, whose batch API it finds by its own rule.
pub trait LfsTransport {
    /// Sends `request` once and answers the remote's reply, its body as it
    /// streams. The caller judges the reply's status and reads its body.
    ///
    /// # Errors
    /// A request this transport refuses to send, or one it could not send
    /// or get an answer to.
    fn exchange(&self, request: LfsRequest<'_>) -> Result<LfsReply>;

    /// The free disk an upload's spool keeps: each write of an object's
    /// bytes to the spool its upload goes from first asks it for room above
    /// its reserve, as a served host's git relay spool does. `None`, the
    /// direct transport's, keeps none.
    fn spool_floor(&self) -> Option<&dyn SpillFloor> {
        None
    }
}

/// How one remote's Git-LFS transfer through a host's transport went: the
/// orchestration's answer, and what the host's credential broker did.
pub struct LfsTransferReport {
    /// The objects the remote is still not known to hold (an upload) or
    /// that did not arrive (a download), or the batch failure that stopped
    /// the transfer.
    pub missing: Result<BTreeSet<LfsOid>>,
    /// How the credential broker the exchanges went through is kept apart
    /// from the daemon; `None` when no exchange reached it.
    pub broker_isolation: Option<BrokerIsolation>,
    /// How many action header values of the batch replies the broker
    /// rewrote to its placeholder, each the remote's installed credential
    /// handed back, counted over replies that ended clean: a count, never a
    /// value.
    pub credential_rewrites: u64,
}

/// One exchange with a Git-LFS remote.
pub enum LfsRequest<'a> {
    /// A batch call to the remote's batch API, its body the encoded batch.
    Batch(&'a LfsBatchRequest),
    /// An object's bytes sent to its upload action. `body` is a rewound
    /// file of the action's size, spooled from this vault's store after
    /// its every chunk and its SHA-256 were checked.
    ObjectUpload {
        action: LfsActionRequest<'a>,
        body: std::fs::File,
    },
    /// An uploaded object's verify call. `body` is its encoded
    /// `{oid, size}`.
    Verify {
        action: LfsActionRequest<'a>,
        body: Vec<u8>,
    },
    /// An object fetched from its download action, with no body; the
    /// reply's body is the object, which the caller streams into the vault's
    /// LFS upload door.
    ObjectDownload(LfsActionRequest<'a>),
}

/// The operation a batch call asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LfsOperation {
    /// This vault's objects go to the remote.
    Upload,
    /// The remote's objects come to this vault.
    Download,
}

impl LfsOperation {
    /// Its batch API spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }
}

/// The credential a batch call goes under. It names a slot, never a
/// value: the transport installs the credential the slot names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LfsBatchCredential {
    /// No credential: an anonymous outside import's batch call.
    Anonymous,
    /// The remote's own credential: a mirror's push credential, or an
    /// outside import source's binding.
    Remote,
}

/// One batch call: its operation, its credential slot and its encoded
/// JSON body.
pub struct LfsBatchRequest {
    pub(super) operation: LfsOperation,
    pub(super) credential: LfsBatchCredential,
    pub(super) body: Vec<u8>,
}

impl LfsBatchRequest {
    /// The operation the call asks for.
    pub fn operation(&self) -> LfsOperation {
        self.operation
    }

    /// The credential slot the call goes under.
    pub fn credential(&self) -> LfsBatchCredential {
        self.credential
    }

    /// The encoded batch the call sends.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// An object action a batch answer returned: its href, and the headers the
/// remote named for it, both as given.
#[derive(Deserialize)]
pub struct LfsAction {
    href: String,
    #[serde(default)]
    header: BTreeMap<String, String>,
}

impl LfsAction {
    /// The href the action is sent to.
    pub fn href(&self) -> &str {
        &self.href
    }

    /// The headers the action's request carries.
    pub fn header(&self) -> &BTreeMap<String, String> {
        &self.header
    }
}

/// One object action: the batch call whose answer returned it, the object
/// it is for with the size the batch call asked for, and the action.
#[derive(Clone, Copy)]
pub struct LfsActionRequest<'a> {
    pub(super) batch: &'a LfsBatchRequest,
    pub(super) oid: LfsOid,
    pub(super) size: u64,
    pub(super) action: &'a LfsAction,
}

impl<'a> LfsActionRequest<'a> {
    /// The batch call whose answer returned the action.
    pub fn batch(&self) -> &'a LfsBatchRequest {
        self.batch
    }

    /// The object the action is for.
    pub fn oid(&self) -> LfsOid {
        self.oid
    }

    /// The object's size, as the batch call asked for it.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The action, as the batch answer gave it.
    pub fn action(&self) -> &'a LfsAction {
        self.action
    }
}

/// A remote's reply: its HTTP status, and its body as it streams. A body a
/// transport saw cut or broken ends with a read error, never a clean end.
pub struct LfsReply {
    pub status: u16,
    pub body: Box<dyn Read + Send>,
}

impl LfsReply {
    /// Whether the remote answered with a 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}
