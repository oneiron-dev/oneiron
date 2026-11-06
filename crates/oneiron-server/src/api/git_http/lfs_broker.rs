//! A Git-LFS transfer through the credential broker on a served host
//! (ARCH-0069 OSH-3, FIX 19876): the transport the engine's LFS
//! orchestration (`oneiron::origin::lfs::upload_lfs_objects` for a mirror,
//! `download_lfs_objects` for an outside import) sends each batch call and
//! object action of one remote through. The orchestration keeps the
//! batches, their order, which answer names which object, and every store
//! and door check; this transport carries each exchange once.
//!
//! - **Exchange.** Each exchange is judged again by the remote's custody
//!   (a mirror still the destination its run read; an import's call
//!   credential not revoked and its binding, if any, still admitting it),
//!   then framed as the broker's typed target: a batch call to the remote's
//!   repository under its operation, or an action under the digest of the
//!   batch call whose answer named it, the object's id and the size the
//!   batch asked for, its href and the headers that answer named for it, as
//!   given. Its body (the encoded batch, a verify's `{oid, size}`, or an
//!   upload's spool, which the orchestration wrote above the vault disk's
//!   reserve) is digested in the LFS digest domain and handed to the
//!   broker, which spools it and acknowledges. Only then is the remote's
//!   credential released at the custody door (a mirror's, the same
//!   `Authorization` value the direct path builds; an import's, its
//!   binding's header), copied once and handed to the broker: for a batch
//!   call that names the remote's credential, and for an action of such a
//!   call whose headers name the broker's placeholder for it. Every other
//!   exchange goes with no credential: an anonymous batch call and each of
//!   its actions too.
//! - **Reply.** A batch call's or a download's body streams to the
//!   orchestration as a reader whose end is clean only when the broker's
//!   is: a cut or broken reply is a read error, never a short body. An
//!   upload's or a verify's reply is read to its end here, and its status
//!   stands only once the broker's end is clean. A batch reply's credential
//!   rewrite count is counted once its body ended clean.
//! - **Report.** The broker's isolation, once an exchange reached it, and
//!   the rewrite count go on the transfer's report beside the
//!   orchestration's answer.
//!
//! No call time or object size is bounded here: each step waits at most the
//! host's transfer idle limit without progress, and a batch reply is
//! bounded by the engine's own batch answer bound. No host allowlist
//! applies.

use std::collections::BTreeSet;
use std::io::{self, Read, Seek as _, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use oneiron::origin::lfs::{
    LFS_BATCH_ANSWER_MAX_BYTES, LfsActionRequest, LfsBatchCredential, LfsOid, LfsOperation,
    LfsReply, LfsRequest, LfsTransferReport, LfsTransport,
};
use oneiron::origin::smart_http::SpillFloor;
use oneiron_broker::{
    GitRepository, Isolation, LfsActionTarget, LfsBatchTarget, LfsCallHeader, LfsRequestDigest,
    LfsTarget, Outcome, StreamPart, lfs_request_digest,
};
use tokio::io::AsyncRead;
use tokio::runtime::Handle;
use zeroize::Zeroizing;

use super::broker_relay::{SPOOL_READ, broker_code, broker_isolation, code};
use crate::machine::DiskFloor;
use crate::models::BrokerContext;

/// The custody one remote's Git-LFS exchanges go under.
pub(super) trait LfsCustody {
    /// Whether the remote is still the one the transfer was asked for,
    /// judged again now; otherwise its refusal code, and nothing is sent.
    fn admitted(&self) -> Result<(), String>;

    /// The remote's complete `Authorization` value, released at the custody
    /// door once the broker acknowledged an exchange's body, and copied once
    /// into a buffer wiped on drop; otherwise its refusal code.
    fn credential(&self) -> Result<Zeroizing<Vec<u8>>, String>;
}

/// The transport of one remote's Git-LFS exchanges through the broker.
pub(super) struct BrokeredLfsTransport<'a> {
    broker: &'a BrokerContext,
    custody: &'a dyn LfsCustody,
    /// The remote's repository, which every exchange's target names.
    repository: GitRepository,
    /// The host's transfer idle limit.
    idle: Duration,
    /// The vault disk's floor, which an upload's spool keeps.
    floor: &'a DiskFloor,
    /// The prefix of every refusal code an exchange answers.
    prefix: &'static str,
    /// The call id every exchange's begins with: the prefix and this
    /// transfer's random id.
    call: String,
    sequence: AtomicU64,
    /// The broker's isolation, once an exchange reached it.
    isolation: OnceLock<Isolation>,
    /// The batch replies' credential rewrites, each counted once its reply
    /// ended clean.
    credential_rewrites: Arc<AtomicU64>,
}

/// One exchange as the broker takes it, before its digest.
struct Framed<'r> {
    target: LfsTarget,
    headers: Vec<(String, String)>,
    body: ExchangeBody<'r>,
    /// Whether the batch call names the remote's credential: a batch
    /// call's own slot, or an action's, the slot of the batch call whose
    /// answer named it.
    remote_credential: bool,
}

/// An exchange's body as the daemon hands it to the broker.
enum ExchangeBody<'r> {
    /// A download's: none.
    Empty,
    /// A batch call's encoded batch.
    Batch(&'r [u8]),
    /// A verify's encoded `{oid, size}`.
    Verify(Vec<u8>),
    /// An upload's spool, rewound.
    Spool(std::fs::File),
}

impl<'r> ExchangeBody<'r> {
    /// The body as the broker's call reads it.
    fn into_reader(self) -> Box<dyn AsyncRead + Unpin + Send + 'r> {
        match self {
            Self::Empty => Box::new(tokio::io::empty()),
            Self::Batch(bytes) => Box::new(bytes),
            Self::Verify(bytes) => Box::new(std::io::Cursor::new(bytes)),
            Self::Spool(file) => Box::new(tokio::fs::File::from_std(file)),
        }
    }
}

impl<'a> BrokeredLfsTransport<'a> {
    /// The transport of the remote at `repository` through `broker`, under
    /// `custody`, each step waiting at most the transfer idle limit `idle`,
    /// an upload's spool keeping the vault disk's floor `floor`, each
    /// refusal code beginning with `prefix`.
    pub(super) fn new(
        broker: &'a BrokerContext,
        custody: &'a dyn LfsCustody,
        repository: GitRepository,
        idle: Duration,
        floor: &'a DiskFloor,
        prefix: &'static str,
    ) -> Self {
        let mut id = [0_u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        let id: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
        Self {
            broker,
            custody,
            repository,
            idle,
            floor,
            prefix,
            call: format!("{prefix}/{id}"),
            sequence: AtomicU64::new(0),
            isolation: OnceLock::new(),
            credential_rewrites: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The transfer's report: the orchestration's answer `missing`, the
    /// broker's isolation and the credential rewrites counted.
    pub(super) fn report(&self, missing: oneiron::Result<BTreeSet<LfsOid>>) -> LfsTransferReport {
        LfsTransferReport {
            missing,
            broker_isolation: self.isolation.get().copied().map(broker_isolation),
            credential_rewrites: self.credential_rewrites.load(Ordering::SeqCst),
        }
    }

    /// Sends one exchange through the broker: judged again, framed, its
    /// body digested and handed over, the broker's acknowledgement taken,
    /// the credential released and handed over when the exchange carries
    /// it, then the reply. Answers the reply, or the refusal's code.
    fn send(&self, request: LfsRequest<'_>) -> Result<LfsReply, String> {
        let prefix = self.prefix;
        self.custody.admitted()?;
        let Framed {
            target,
            headers,
            mut body,
            remote_credential,
        } = self.frame(request)?;
        let (digest, body_len) = self.digest(&target, &headers, &mut body)?;
        let reply_limit = target.is_batch().then_some(LFS_BATCH_ANSWER_MAX_BYTES);
        let call = format!(
            "{}/{}",
            self.call,
            self.sequence.fetch_add(1, Ordering::Relaxed)
        );
        let header = LfsCallHeader::new(
            call,
            target,
            headers,
            body_len,
            digest,
            self.idle,
            reply_limit,
        );
        // An action carries the credential only where its batch call
        // installed it and the reply handed it back: an anonymous batch's
        // placeholder is the remote's own text, sent as given.
        let carries = remote_credential
            && (header.target.is_batch() || header.names_credential_placeholder());
        let runtime = self.broker.runtime();
        let (prepared, isolation) = runtime.block_on(async {
            let (connection, isolation) =
                self.broker
                    .git_connection(self.idle)
                    .await
                    .map_err(|error| {
                        tracing::warn!(%error, "no credential broker for a Git-LFS transfer");
                        format!("{prefix}_broker_unavailable")
                    })?;
            let mut reader = body.into_reader();
            let prepared = connection
                .prepare_lfs(&header, &mut reader)
                .await
                .map_err(|error| broker_code(prefix, error))?;
            Ok::<_, String>((prepared, isolation))
        })?;
        let secret = if carries {
            Some(self.custody.credential()?)
        } else {
            None
        };
        let _ = self.isolation.set(isolation);
        let mut reply = runtime
            .block_on(async {
                match secret {
                    Some(secret) => prepared.open(secret).await,
                    None => prepared.open_without_credential().await,
                }
            })
            .map_err(|error| broker_code(prefix, error))?;
        let status = match reply.outcome() {
            Outcome::Answered { status, .. } => *status,
            Outcome::Refused { reason } => {
                return Err(format!("{prefix}_refused_{}", code(reason)));
            }
            Outcome::Failed { reason } => return Err(format!("{prefix}_failed_{}", code(reason))),
        };
        tracing::info!(
            exchange = exchange_kind(&header.target),
            digest = %header.digest,
            isolation = isolation.as_str(),
            "a Git-LFS exchange went through the credential broker"
        );
        let body: Box<dyn Read + Send> = match &header.target {
            LfsTarget::Batch(_) => {
                let rewrites = reply.credential_rewrites();
                Box::new(BrokeredLfsBody::new(
                    reply,
                    runtime.clone(),
                    Some((Arc::clone(&self.credential_rewrites), rewrites)),
                ))
            }
            LfsTarget::ObjectDownload(_) => {
                Box::new(BrokeredLfsBody::new(reply, runtime.clone(), None))
            }
            LfsTarget::ObjectUpload(_) | LfsTarget::Verify(_) => {
                self.drain(runtime, &mut reply)?;
                Box::new(io::empty())
            }
        };
        Ok(LfsReply { status, body })
    }

    /// `request` as the broker's typed exchange: its target, the headers an
    /// action's batch answer named for it, as given, and its body.
    fn frame<'r>(&self, request: LfsRequest<'r>) -> Result<Framed<'r>, String> {
        Ok(match request {
            LfsRequest::Batch(batch) => Framed {
                target: LfsTarget::Batch(self.batch_target(batch.operation())),
                headers: Vec::new(),
                body: ExchangeBody::Batch(batch.body()),
                remote_credential: batch.credential() == LfsBatchCredential::Remote,
            },
            LfsRequest::ObjectUpload { action, body } => Framed {
                target: LfsTarget::ObjectUpload(self.action_target(action)?),
                headers: action_headers(action),
                body: ExchangeBody::Spool(body),
                remote_credential: names_remote_credential(action),
            },
            LfsRequest::Verify { action, body } => Framed {
                target: LfsTarget::Verify(self.action_target(action)?),
                headers: action_headers(action),
                body: ExchangeBody::Verify(body),
                remote_credential: names_remote_credential(action),
            },
            LfsRequest::ObjectDownload(action) => Framed {
                target: LfsTarget::ObjectDownload(self.action_target(action)?),
                headers: action_headers(action),
                body: ExchangeBody::Empty,
                remote_credential: names_remote_credential(action),
            },
        })
    }

    /// The batch call to the remote's repository under `operation`.
    fn batch_target(&self, operation: LfsOperation) -> LfsBatchTarget {
        LfsBatchTarget {
            repository: self.repository.clone(),
            operation: match operation {
                LfsOperation::Upload => oneiron_broker::LfsOperation::Upload,
                LfsOperation::Download => oneiron_broker::LfsOperation::Download,
            },
        }
    }

    /// The target of `action`: the digest of the batch call whose answer
    /// named it, taken as that call's was, the object it is for, the size
    /// the batch call asked for, and its href as given.
    fn action_target(&self, action: LfsActionRequest<'_>) -> Result<LfsActionTarget, String> {
        let batch = action.batch();
        let named_by = LfsTarget::Batch(self.batch_target(batch.operation()));
        let batch_digest =
            lfs_request_digest(&named_by, &[], batch.body()).map_err(|_| self.spool_failed())?;
        Ok(LfsActionTarget {
            repository: self.repository.clone(),
            batch: batch_digest,
            oid: action.oid().to_hex(),
            size: action.size(),
            href: action.action().href().to_owned(),
        })
    }

    /// The digest of an exchange to `target` with `headers` and `body`, and
    /// the body's length; a spool is read through and rewound.
    fn digest(
        &self,
        target: &LfsTarget,
        headers: &[(String, String)],
        body: &mut ExchangeBody<'_>,
    ) -> Result<(String, u64), String> {
        match body {
            ExchangeBody::Empty => self.whole_digest(target, headers, &[]),
            ExchangeBody::Batch(bytes) => self.whole_digest(target, headers, bytes),
            ExchangeBody::Verify(bytes) => self.whole_digest(target, headers, bytes.as_slice()),
            ExchangeBody::Spool(file) => {
                let failed = |_: io::Error| self.spool_failed();
                let len = file.metadata().map_err(failed)?.len();
                let mut digest = LfsRequestDigest::new(target, headers, len);
                let mut buffer = vec![0; SPOOL_READ];
                loop {
                    let read = file.read(&mut buffer).map_err(failed)?;
                    if read == 0 {
                        break;
                    }
                    digest.update(&buffer[..read]);
                }
                file.seek(SeekFrom::Start(0)).map_err(failed)?;
                let digest = digest.finish().map_err(|_| self.spool_failed())?;
                Ok((digest, len))
            }
        }
    }

    /// The digest of an exchange to `target` with `headers` and the whole
    /// body `bytes`, and its length.
    fn whole_digest(
        &self,
        target: &LfsTarget,
        headers: &[(String, String)],
        bytes: &[u8],
    ) -> Result<(String, u64), String> {
        let digest = lfs_request_digest(target, headers, bytes).map_err(|_| self.spool_failed())?;
        Ok((digest, bytes.len() as u64))
    }

    /// Reads an upload's or a verify's reply to its end: its status stands
    /// only once the broker's end is clean.
    fn drain(&self, runtime: &Handle, reply: &mut oneiron_broker::LfsReply) -> Result<(), String> {
        let prefix = self.prefix;
        runtime.block_on(async {
            loop {
                match reply.next().await {
                    Ok(StreamPart::Chunk(_)) => {}
                    Ok(StreamPart::End) => return Ok(()),
                    Ok(StreamPart::Cut(reason)) => {
                        return Err(format!("{prefix}_cut_{}", code(&reason)));
                    }
                    Err(_) => return Err(format!("{prefix}_broker_lost")),
                }
            }
        })
    }

    /// The code of a body that could not be read, digested or rewound.
    fn spool_failed(&self) -> String {
        format!("{}_request_spool_failed", self.prefix)
    }
}

impl LfsTransport for BrokeredLfsTransport<'_> {
    fn exchange(&self, request: LfsRequest<'_>) -> oneiron::Result<LfsReply> {
        self.send(request).map_err(|refusal| {
            tracing::warn!(
                %refusal,
                "a Git-LFS exchange did not go through the credential broker"
            );
            oneiron::Error::Refused(format!(
                "{refusal}: the Git-LFS exchange did not go through the credential broker"
            ))
        })
    }

    fn spool_floor(&self) -> Option<&dyn SpillFloor> {
        Some(self.floor)
    }
}

/// Whether the batch call whose answer named `action` went under the
/// remote's credential.
fn names_remote_credential(action: LfsActionRequest<'_>) -> bool {
    action.batch().credential() == LfsBatchCredential::Remote
}

/// The headers the batch answer named for `action`, as given, in the order
/// the direct transport sends them.
fn action_headers(action: LfsActionRequest<'_>) -> Vec<(String, String)> {
    action
        .action()
        .header()
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// The receipt spelling of an exchange's target.
const fn exchange_kind(target: &LfsTarget) -> &'static str {
    match target {
        LfsTarget::Batch(_) => "batch",
        LfsTarget::ObjectDownload(_) => "object_download",
        LfsTarget::ObjectUpload(_) => "object_upload",
        LfsTarget::Verify(_) => "verify",
    }
}

/// How a brokered reply's body ended, once it has.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyEnd {
    /// Still streaming.
    Open,
    /// The broker ended it clean: the chunks are the whole of it.
    Clean,
    /// The broker cut it, or the connection broke.
    Broken,
}

/// A brokered reply's body as the orchestration reads it: each chunk as it
/// comes, waited for on the serve runtime from the transfer's blocking
/// thread; a clean end only after the broker's, and after a cut or a broken
/// connection a read error on every read. A batch reply's credential
/// rewrites are counted once it ended clean. Dropping it cancels the rest.
struct BrokeredLfsBody {
    reply: Option<oneiron_broker::LfsReply>,
    runtime: Handle,
    chunk: Zeroizing<Vec<u8>>,
    /// Bytes of `chunk` already read.
    taken: usize,
    end: BodyEnd,
    /// Where a batch reply's rewrites are counted, and how many it holds.
    rewrites: Option<(Arc<AtomicU64>, u64)>,
}

impl BrokeredLfsBody {
    fn new(
        reply: oneiron_broker::LfsReply,
        runtime: Handle,
        rewrites: Option<(Arc<AtomicU64>, u64)>,
    ) -> Self {
        Self {
            reply: Some(reply),
            runtime,
            chunk: Zeroizing::new(Vec::new()),
            taken: 0,
            end: BodyEnd::Open,
            rewrites,
        }
    }
}

impl Read for BrokeredLfsBody {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            let left: &[u8] = &self.chunk[self.taken..];
            if !left.is_empty() {
                let count = output.len().min(left.len());
                output[..count].copy_from_slice(&left[..count]);
                self.taken += count;
                return Ok(count);
            }
            match self.end {
                BodyEnd::Open => {}
                BodyEnd::Clean => return Ok(0),
                BodyEnd::Broken => {
                    return Err(io::Error::other("the brokered Git-LFS reply was cut"));
                }
            }
            let Some(reply) = self.reply.as_mut() else {
                self.end = BodyEnd::Broken;
                continue;
            };
            match self.runtime.block_on(reply.next()) {
                Ok(StreamPart::Chunk(chunk)) => {
                    self.chunk = chunk;
                    self.taken = 0;
                }
                Ok(StreamPart::End) => {
                    self.end = BodyEnd::Clean;
                    self.reply = None;
                    if let Some((counted, rewrites)) = self.rewrites.take() {
                        counted.fetch_add(rewrites, Ordering::SeqCst);
                    }
                }
                Ok(StreamPart::Cut(_)) | Err(_) => {
                    self.end = BodyEnd::Broken;
                    self.reply = None;
                }
            }
        }
    }
}
