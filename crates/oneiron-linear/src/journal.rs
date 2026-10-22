//! Host delivery state beneath the engine outbound dispatch, not a second gate.
//!
//! The frozen request and a delivered mutation's response are bytes of the
//! TASK the mutation mirrors, so they live in that TASK's body custody in the
//! vault ([`oneiron::Vault::linear_freeze_body`], FIX 8609), a file each
//! however large (FIX 8610), and go when the TASK is erased. This journal is
//! device-local and content-free: per operation, the TASK a request ref
//! resolves through, and the delivery state (pending, delivered with the
//! provider's issue id, or refused by the endpoint). A pending entry after a
//! crash is uncertain and never blindly resent; an erased body is never
//! read, resent or rebuilt.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::linear_sync::{LinearBody, LinearBodyRole, LinearFreeze};
use oneiron::{EntityId, LinearSyncError, LinearSyncResult, Vault};
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::{Value, json};

use crate::http::{GraphQlBody, LinearBodyLine, decode_held};
use crate::{GraphQlCall, GraphQlExecutor, GraphQlTransportError, invalid};

/// The `content_ref` an operation's frozen request resolves by.
pub(crate) fn request_ref(id: &[u8; 32]) -> String {
    format!("linear:request:v1:{}", blake3::Hash::from(*id).to_hex())
}

/// One operation's delivery state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Delivery {
    /// The request may be on the wire; its outcome is not known.
    Pending,
    /// Delivered: the provider's issue id, its response kept in custody.
    Delivered { issue: String },
    /// The authenticated endpoint refused the credential (FIX 8611): nothing
    /// ran, and a governed retry may send it again.
    Rejected { status: u16 },
}

impl Delivery {
    fn to_json(&self) -> Value {
        match self {
            Self::Pending => json!({"state": "pending"}),
            Self::Delivered { issue } => json!({"state": "delivered", "issue": issue}),
            Self::Rejected { status } => json!({"state": "rejected", "status": status}),
        }
    }

    fn of_json(value: &Value) -> Option<Self> {
        match value.get("state")?.as_str()? {
            "pending" => Some(Self::Pending),
            "delivered" => Some(Self::Delivered {
                issue: value.get("issue")?.as_str()?.to_owned(),
            }),
            "rejected" => Some(Self::Rejected {
                status: u16::try_from(value.get("status")?.as_u64()?).ok()?,
            }),
            _ => None,
        }
    }
}

/// The fields of a mutation's answer that say whether it ran, read from its
/// bytes without keeping the rest: the issue's text never enters memory here.
#[derive(Deserialize)]
struct Answer {
    errors: Option<Vec<IgnoredAny>>,
    data: Option<AnswerData>,
}

#[derive(Deserialize)]
struct AnswerData {
    #[serde(rename = "issueCreate")]
    create: Option<AnswerResult>,
    #[serde(rename = "issueUpdate")]
    update: Option<AnswerResult>,
}

#[derive(Deserialize)]
struct AnswerResult {
    success: Option<bool>,
    issue: Option<AnswerIssue>,
}

#[derive(Deserialize)]
struct AnswerIssue {
    id: Option<String>,
}

impl Answer {
    /// The issue a successful `create` or update names; `None` when the
    /// answer does not prove the mutation ran.
    fn issue(self, create: bool) -> Option<String> {
        if self.errors.is_some_and(|errors| !errors.is_empty()) {
            return None;
        }
        let data = self.data?;
        let result = if create { data.create } else { data.update }?;
        if result.success != Some(true) {
            return None;
        }
        result.issue?.id
    }
}

pub(crate) struct LinearResponseJournal<'v, T> {
    vault: &'v Vault,
    transport: T,
    journal_dir: PathBuf,
    body_line: Option<Arc<dyn LinearBodyLine>>,
}

impl<'v, T> LinearResponseJournal<'v, T> {
    pub(crate) fn new(
        vault: &'v Vault,
        transport: T,
        journal_dir: PathBuf,
    ) -> LinearSyncResult<Self> {
        if !journal_dir.is_dir() {
            return Err(invalid("Linear outbound response directory does not exist"));
        }
        Ok(Self {
            vault,
            transport,
            journal_dir,
            body_line: None,
        })
    }

    /// Decodes a kept response or request on the host's memory `line`.
    pub(crate) fn set_body_line(&mut self, line: Arc<dyn LinearBodyLine>) {
        self.body_line = Some(line);
    }

    pub(crate) fn into_transport(self) -> T {
        self.transport
    }

    fn path(&self, id: &[u8; 32]) -> PathBuf {
        self.journal_dir
            .join(blake3::Hash::from(*id).to_hex().as_str())
    }

    /// Freezes the exact GraphQL request in `task`'s body custody before the
    /// engine dispatch, and names the TASK in a content-free host file. The
    /// common receipt carries only the resolvable ref, including on denial
    /// (when no transport or response journal runs).
    pub(crate) fn stage_request(
        &self,
        id: &[u8; 32],
        task: EntityId,
        call: &GraphQlCall,
    ) -> LinearSyncResult<String> {
        self.stage_request_with(id, task, call, |_| Ok(()))
    }

    /// The injection point models a host dying after a partial temporary write
    /// but before it publishes a final operation name. Production supplies a
    /// no-op; tests can interrupt this exact staging path.
    pub(crate) fn stage_request_with(
        &self,
        id: &[u8; 32],
        task: EntityId,
        call: &GraphQlCall,
        before_write: impl FnOnce(&mut tempfile::NamedTempFile) -> LinearSyncResult<()>,
    ) -> LinearSyncResult<String> {
        let reference = request_ref(id);
        let mut digest = blake3::Hasher::new();
        serde_json::to_writer(&mut digest, &call.body())
            .map_err(|_| invalid("Linear request cannot be encoded"))?;
        let digest = *digest.finalize().as_bytes();
        let reused = || invalid("Linear operation ID was reused for another request");
        let erased = || invalid("Linear request's TASK was erased; nothing is sent");
        match self
            .vault
            .linear_body_digest(task, id, LinearBodyRole::Request)?
        {
            LinearBody::Held(held) if held == digest => {}
            LinearBody::Held(_) => return Err(reused()),
            LinearBody::Erased => return Err(erased()),
            LinearBody::Absent => {
                match self
                    .vault
                    .linear_freeze_body(task, id, LinearBodyRole::Request, |out| {
                        serde_json::to_writer(out, &call.body()).map_err(std::io::Error::other)
                    })? {
                    LinearFreeze::Frozen => {}
                    LinearFreeze::Other => return Err(reused()),
                    LinearFreeze::Erased => return Err(erased()),
                }
            }
        }
        let path = self.path(id).with_extension("request");
        let pointer = json!({"task": task.to_hex()});
        if let Some(staged) =
            read_json(&path).map_err(|_| invalid("Linear request ref cannot be read"))?
        {
            if staged != pointer {
                return Err(reused());
            }
            return Ok(reference);
        }
        // The temporary file lives in the SAME private directory. An
        // interrupted/partial write leaves only an unbound orphan, never the
        // final operation name the next attempt must read. persist_noclobber
        // atomically links the fully synced bytes without replacing a winner.
        let mut staged = tempfile::NamedTempFile::new_in(&self.journal_dir)
            .map_err(|_| invalid("Linear request could not be staged"))?;
        before_write(&mut staged)?;
        let bytes = serde_json::to_vec(&pointer)
            .map_err(|_| invalid("Linear request cannot be encoded"))?;
        staged
            .as_file_mut()
            .write_all(&bytes)
            .and_then(|()| staged.as_file().sync_all())
            .map_err(|_| invalid("Linear request could not be synced"))?;
        match staged.persist_noclobber(&path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A concurrent writer won the name. Accept only the same TASK.
                if read_json(&path).map_err(|_| invalid("Linear request ref cannot be read"))?
                    != Some(pointer)
                {
                    return Err(reused());
                }
            }
            Err(_) => return Err(invalid("Linear request could not be published")),
        }
        self.sync_directory()
            .map_err(oneiron::LinearSyncError::from)?;
        Ok(reference)
    }

    /// The exact request `reference` names, while its TASK lives. `None` for
    /// a ref this journal does not hold.
    ///
    /// # Errors
    /// A request erased with its TASK, a decode that waited out its memory
    /// turn, and storage errors.
    pub(crate) fn read_request(&self, reference: &str) -> LinearSyncResult<Option<Value>> {
        let Some(suffix) = reference.strip_prefix("linear:request:v1:") else {
            return Ok(None);
        };
        let Ok(id) = blake3::Hash::from_hex(suffix) else {
            return Ok(None);
        };
        let id = *id.as_bytes();
        let Some(pointer) = read_json(&self.path(&id).with_extension("request"))
            .map_err(|_| invalid("Linear request ref cannot be read"))?
        else {
            return Ok(None);
        };
        let task = pointer
            .get("task")
            .and_then(Value::as_str)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or_else(|| invalid("Linear request ref is corrupt"))?;
        self.kept(task, &id, LinearBodyRole::Request)
    }

    /// The response a delivered operation kept, while its TASK lives: the
    /// exact answer every replay returns. `None` when none was kept.
    ///
    /// # Errors
    /// A response erased with its TASK, a decode that waited out its memory
    /// turn, and storage errors.
    pub(crate) fn response(
        &self,
        id: &[u8; 32],
        task: EntityId,
    ) -> LinearSyncResult<Option<Value>> {
        self.kept(task, id, LinearBodyRole::Response)
    }

    /// `task`'s `role` body of `id`, decoded on the host's memory line.
    fn kept(
        &self,
        task: EntityId,
        id: &[u8; 32],
        role: LinearBodyRole,
    ) -> LinearSyncResult<Option<Value>> {
        let erased = || invalid("Linear body was erased with its TASK; nothing is read again");
        let len = match self.vault.linear_body_len(task, id, role)? {
            LinearBody::Held(len) => len,
            LinearBody::Absent => return Ok(None),
            LinearBody::Erased => return Err(erased()),
        };
        let line = self.body_line.as_deref();
        match self.vault.linear_read_body(task, id, role, |reader| {
            decode_held(line, len, reader).map_err(LinearSyncError::from)
        })? {
            LinearBody::Held(value) => Ok(Some(value)),
            LinearBody::Absent => Ok(None),
            LinearBody::Erased => Err(erased()),
        }
    }

    fn sync_directory(&self) -> Result<(), GraphQlTransportError> {
        File::open(&self.journal_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| GraphQlTransportError::Uncertain)
    }

    /// The delivery state of `id`; `None` for an operation never sent. A
    /// state this journal cannot read is uncertain.
    fn delivery(&self, id: &[u8; 32]) -> Result<Option<Delivery>, GraphQlTransportError> {
        read_json(&self.path(id))
            .map_err(|_| GraphQlTransportError::Uncertain)?
            .map(|value| Delivery::of_json(&value).ok_or(GraphQlTransportError::Uncertain))
            .transpose()
    }

    /// Replaces `id`'s delivery state with `delivery`, synced.
    fn put_delivery(
        &self,
        id: &[u8; 32],
        delivery: &Delivery,
    ) -> Result<(), GraphQlTransportError> {
        let mut staged = tempfile::NamedTempFile::new_in(&self.journal_dir)
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        let bytes = serde_json::to_vec(&delivery.to_json())
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        staged
            .as_file_mut()
            .write_all(&bytes)
            .and_then(|()| staged.as_file().sync_all())
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        staged
            .persist(self.path(id))
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        self.sync_directory()
    }

    /// Keeps a delivered answer in `task`'s custody, and the delivery, once
    /// the answer proves the mutation ran: the provider's issue id. A TASK
    /// erased meanwhile keeps none of it; the delivery stays a fact.
    fn keep_answer(
        &self,
        id: &[u8; 32],
        task: EntityId,
        call: &GraphQlCall,
        body: GraphQlBody,
    ) -> Result<String, GraphQlTransportError> {
        let create = call.query.contains("issueCreate(");
        let (issue, frozen) = match body {
            GraphQlBody::Decoded(value) => {
                let issue = Answer::deserialize(&value)
                    .ok()
                    .and_then(|answer| answer.issue(create))
                    .ok_or(GraphQlTransportError::Uncertain)?;
                let frozen =
                    self.vault
                        .linear_freeze_body(task, id, LinearBodyRole::Response, |out| {
                            serde_json::to_writer(out, &value).map_err(std::io::Error::other)
                        });
                (issue, frozen)
            }
            GraphQlBody::Spooled(mut file) => {
                use std::io::{Seek, SeekFrom};
                let issue = serde_json::from_reader::<_, Answer>(std::io::BufReader::new(&file))
                    .ok()
                    .and_then(|answer| answer.issue(create))
                    .ok_or(GraphQlTransportError::Uncertain)?;
                file.seek(SeekFrom::Start(0))
                    .map_err(|_| GraphQlTransportError::Uncertain)?;
                let frozen =
                    self.vault
                        .linear_freeze_body(task, id, LinearBodyRole::Response, |out| {
                            std::io::copy(&mut file, out).map(|_| ())
                        });
                (issue, frozen)
            }
        };
        match frozen.map_err(|_| GraphQlTransportError::Uncertain)? {
            LinearFreeze::Frozen | LinearFreeze::Erased => {}
            LinearFreeze::Other => return Err(GraphQlTransportError::Uncertain),
        }
        self.put_delivery(
            id,
            &Delivery::Delivered {
                issue: issue.clone(),
            },
        )?;
        Ok(issue)
    }
}

impl<T: GraphQlExecutor> LinearResponseJournal<'_, T> {
    /// Only called from an `OutboundExecutionSink` *inside* the engine door:
    /// the provider's issue id of `id`'s delivered mutation of `task`.
    pub(crate) fn dispatch(
        &mut self,
        id: [u8; 32],
        task: EntityId,
        call: &GraphQlCall,
    ) -> Result<String, GraphQlTransportError> {
        let path = self.path(&id);
        match self.delivery(&id)? {
            Some(Delivery::Delivered { issue }) => return Ok(issue),
            Some(Delivery::Pending) => {
                // A response kept before its delivery was written proves the
                // mutation ran; anything else stays uncertain.
                return match self
                    .vault
                    .linear_body_len(task, &id, LinearBodyRole::Response)
                {
                    Ok(LinearBody::Held(_)) => {
                        let issue = self
                            .response(&id, task)
                            .ok()
                            .flatten()
                            .and_then(|value| {
                                let create = call.query.contains("issueCreate(");
                                Answer::deserialize(&value).ok()?.issue(create)
                            })
                            .ok_or(GraphQlTransportError::Uncertain)?;
                        self.put_delivery(
                            &id,
                            &Delivery::Delivered {
                                issue: issue.clone(),
                            },
                        )?;
                        Ok(issue)
                    }
                    _ => Err(GraphQlTransportError::Uncertain),
                };
            }
            // FIX 8611: the engine's governed retry of an operation the
            // endpoint refused: pending again, durably, before the wire.
            Some(Delivery::Rejected { .. }) => self.put_delivery(&id, &Delivery::Pending)?,
            None => {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut pending = options
                    .open(&path)
                    .map_err(|_| GraphQlTransportError::Uncertain)?;
                let bytes = serde_json::to_vec(&Delivery::Pending.to_json())
                    .map_err(|_| GraphQlTransportError::Uncertain)?;
                pending
                    .write_all(&bytes)
                    .and_then(|()| pending.sync_all())
                    .map_err(|_| GraphQlTransportError::Uncertain)?;
                self.sync_directory()?;
            }
        }
        let body = match self.transport.execute_body(call) {
            Ok(body) => body,
            Err(GraphQlTransportError::NotSent) => {
                // No bytes left the host. Undo the pending marker durably so
                // the engine's definite-non-delivery replay can send again.
                fs::remove_file(&path).map_err(|_| GraphQlTransportError::Uncertain)?;
                self.sync_directory()?;
                return Err(GraphQlTransportError::NotSent);
            }
            Err(GraphQlTransportError::Rejected { status }) => {
                // FIX 8611: nothing ran. The pending marker becomes the
                // endpoint's content-free refusal, durably.
                self.put_delivery(&id, &Delivery::Rejected { status })?;
                return Err(GraphQlTransportError::Rejected { status });
            }
            Err(GraphQlTransportError::Uncertain | GraphQlTransportError::Waiting) => {
                return Err(GraphQlTransportError::Uncertain);
            }
        };
        self.keep_answer(&id, task, call, body)
    }
}

/// A small content-free journal file's JSON; `None` when it is absent.
fn read_json(path: &Path) -> std::io::Result<Option<Value>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(std::io::Error::other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
