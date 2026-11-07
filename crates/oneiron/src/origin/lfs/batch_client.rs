//! The outbound Git-LFS batch client: one remote's batch API and its basic
//! transfer. A mirror's objects go up, an upload and its verify call per
//! object the remote does not hold yet (FIX 919); an outside import's come
//! down, each installed through the vault-LFS upload door, its scan,
//! SHA-256 and size checks included (FIX 7596).
//!
//! The client keeps the algorithm and every check: which answer names which
//! requested object, the objects still missing, the upload-then-verify
//! order, the bound of a batch answer, the store's checks before an upload
//! and the door's checks on a download. Each exchange goes through an
//! [`LfsTransport`], which carries it alone (FIX 19876). An object is
//! streamed, never held whole in memory. A batch carries at most
//! [`LFS_BATCH_OBJECTS`] objects, more go in further batches, so no count
//! is refused. An upload's spool keeps the free disk its transport names
//! ([`LfsTransport::spool_floor`]).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Seek, SeekFrom, Write};

use serde::{Deserialize, Serialize};

use super::transport::{
    LfsAction, LfsActionRequest, LfsBatchCredential, LfsBatchRequest, LfsOperation, LfsRequest,
    LfsTransport, invalid,
};
use super::{LFS_BASIC_TRANSFER, LfsOid};
use crate::error::Result;
use crate::origin::smart_http::{AtDiskFloor, SpillFloor};
use crate::{TimeRange, Vault};

/// Objects one batch call names: the size Git-LFS servers commonly take.
const LFS_BATCH_OBJECTS: usize = 100;

/// The bound of one batch answer read into memory. A host's credential
/// broker reads a batch reply whole within it too.
pub const LFS_BATCH_ANSWER_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Serialize)]
struct BatchBody<'a> {
    operation: &'a str,
    transfers: [&'a str; 1],
    objects: Vec<BatchObjectRef>,
    hash_algo: &'a str,
}

#[derive(Serialize)]
struct BatchObjectRef {
    oid: String,
    size: u64,
}

#[derive(Deserialize)]
struct BatchAnswer {
    objects: Vec<BatchObject>,
}

#[derive(Deserialize)]
struct BatchObject {
    oid: String,
    #[serde(default)]
    actions: Option<BatchActions>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct BatchActions {
    #[serde(default)]
    upload: Option<LfsAction>,
    #[serde(default)]
    verify: Option<LfsAction>,
    #[serde(default)]
    download: Option<LfsAction>,
}

/// Sends each of `objects` the remote does not hold yet from `vault`'s
/// store through `transport`, each batch call under the remote's own
/// credential. Answers the objects the remote is still not known to hold:
/// one it refused, one this vault lacks, one whose transfer or verify
/// failed, or one its answer left out. A served host runs it over its
/// credential broker's transport (FIX 19876).
///
/// # Errors
/// A batch call that fails or answers what does not decode.
pub fn upload_lfs_objects(
    vault: &Vault,
    transport: &dyn LfsTransport,
    objects: &[(LfsOid, u64)],
) -> Result<BTreeSet<LfsOid>> {
    let mut missing = BTreeSet::new();
    for chunk in objects.chunks(LFS_BATCH_OBJECTS) {
        let sizes: BTreeMap<LfsOid, u64> = chunk.iter().copied().collect();
        let mut answered = BTreeSet::new();
        let request = batch_request(LfsOperation::Upload, LfsBatchCredential::Remote, chunk)?;
        for object in batch(transport, &request)?.objects {
            let Ok(oid) = LfsOid::parse_hex(&object.oid) else {
                continue;
            };
            let Some(&size) = sizes.get(&oid) else {
                continue;
            };
            answered.insert(oid);
            if object.error.is_some() {
                missing.insert(oid);
                continue;
            }
            // No action: the remote holds it already.
            let Some(actions) = object.actions else {
                continue;
            };
            let sent = match &actions.upload {
                Some(upload) => put_object(
                    vault,
                    transport,
                    LfsActionRequest {
                        batch: &request,
                        oid,
                        size,
                        action: upload,
                    },
                ),
                None => Ok(true),
            };
            let held = match sent {
                Ok(true) => match &actions.verify {
                    Some(verify) => verify_object(
                        transport,
                        LfsActionRequest {
                            batch: &request,
                            oid,
                            size,
                            action: verify,
                        },
                    ),
                    None => Ok(true),
                },
                other => other,
            };
            match held {
                Ok(true) => {}
                Ok(false) => {
                    missing.insert(oid);
                }
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "an LFS object did not reach the remote");
                    missing.insert(oid);
                }
            }
        }
        missing.extend(sizes.into_keys().filter(|oid| !answered.contains(oid)));
    }
    Ok(missing)
}

/// Fetches each of `objects` from the remote through `transport`, each
/// batch call under `credential`, and installs it through `vault`'s LFS
/// upload door at `now`. Answers the objects that did not arrive: one the
/// remote refused or left out, one whose transfer failed, or one the door
/// refused. A served host runs it over its credential broker's transport
/// for an outside import (FIX 19876).
///
/// # Errors
/// A batch call that fails or answers what does not decode.
pub fn download_lfs_objects(
    vault: &Vault,
    transport: &dyn LfsTransport,
    credential: LfsBatchCredential,
    objects: &[(LfsOid, u64)],
    now: u64,
) -> Result<BTreeSet<LfsOid>> {
    let mut missing = BTreeSet::new();
    for chunk in objects.chunks(LFS_BATCH_OBJECTS) {
        let sizes: BTreeMap<LfsOid, u64> = chunk.iter().copied().collect();
        let mut arrived = BTreeSet::new();
        let request = batch_request(LfsOperation::Download, credential, chunk)?;
        for object in batch(transport, &request)?.objects {
            let Ok(oid) = LfsOid::parse_hex(&object.oid) else {
                continue;
            };
            let (Some(&size), None, Some(download)) = (
                sizes.get(&oid),
                &object.error,
                object.actions.and_then(|actions| actions.download),
            ) else {
                continue;
            };
            let action = LfsActionRequest {
                batch: &request,
                oid,
                size,
                action: &download,
            };
            match get_object(vault, transport, action, now) {
                Ok(()) => {
                    arrived.insert(oid);
                }
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "an LFS object did not arrive");
                }
            }
        }
        missing.extend(sizes.into_keys().filter(|oid| !arrived.contains(oid)));
    }
    Ok(missing)
}

/// The batch call for `objects` under `operation` and `credential`.
fn batch_request(
    operation: LfsOperation,
    credential: LfsBatchCredential,
    objects: &[(LfsOid, u64)],
) -> Result<LfsBatchRequest> {
    let body = BatchBody {
        operation: operation.as_str(),
        transfers: [LFS_BASIC_TRANSFER],
        objects: objects
            .iter()
            .map(|(oid, size)| BatchObjectRef {
                oid: oid.to_hex(),
                size: *size,
            })
            .collect(),
        hash_algo: "sha256",
    };
    let body = serde_json::to_vec(&body).map_err(|_| invalid("an LFS batch did not encode"))?;
    Ok(LfsBatchRequest {
        operation,
        credential,
        body,
    })
}

/// Sends one batch call through `transport` and reads its answer.
fn batch(transport: &dyn LfsTransport, request: &LfsBatchRequest) -> Result<BatchAnswer> {
    let reply = transport.exchange(LfsRequest::Batch(request))?;
    if !reply.is_success() {
        return Err(invalid("the LFS batch call was refused"));
    }
    let mut answer = Vec::new();
    reply
        .body
        .take(LFS_BATCH_ANSWER_MAX_BYTES + 1)
        .read_to_end(&mut answer)
        .map_err(|_| invalid("the LFS batch answer did not read"))?;
    if answer.len() as u64 > LFS_BATCH_ANSWER_MAX_BYTES {
        return Err(invalid("the LFS batch answer passed its bound"));
    }
    serde_json::from_slice(&answer).map_err(|_| invalid("the LFS batch answer did not decode"))
}

/// Sends the object `action` is for from `vault`'s verified store to the
/// action's href; `false` when this vault does not hold it.
fn put_object(
    vault: &Vault,
    transport: &dyn LfsTransport,
    action: LfsActionRequest<'_>,
) -> Result<bool> {
    let mut spool = UploadSpool {
        file: tempfile::tempfile_in(vault.lfs_storage_dir())?,
        floor: transport.spool_floor(),
    };
    if !vault.has_lfs_object(action.oid, action.size)?
        || !vault.write_lfs_object_to(action.oid, &mut spool)?
    {
        return Ok(false);
    }
    let mut spool = spool.file;
    spool.seek(SeekFrom::Start(0))?;
    let reply = transport.exchange(LfsRequest::ObjectUpload {
        action,
        body: spool,
    })?;
    Ok(reply.is_success())
}

/// The file an upload goes from, each write to which first asks `floor`,
/// when there is one, for room above its reserve.
struct UploadSpool<'a> {
    file: std::fs::File,
    floor: Option<&'a dyn SpillFloor>,
}

impl Write for UploadSpool<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .floor
            .is_some_and(|floor| !floor.has_room_for(bytes.len() as u64))
        {
            return Err(io::Error::new(io::ErrorKind::StorageFull, AtDiskFloor));
        }
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Asks the href of `action` to verify the uploaded object it is for.
fn verify_object(transport: &dyn LfsTransport, action: LfsActionRequest<'_>) -> Result<bool> {
    let body = serde_json::to_vec(&BatchObjectRef {
        oid: action.oid.to_hex(),
        size: action.size,
    })
    .map_err(|_| invalid("an LFS verify did not encode"))?;
    let reply = transport.exchange(LfsRequest::Verify { action, body })?;
    Ok(reply.is_success())
}

/// Streams the object `action` is for from the action's href through
/// `vault`'s LFS upload door, which checks its scan, SHA-256 and size
/// before it stores it.
fn get_object(
    vault: &Vault,
    transport: &dyn LfsTransport,
    action: LfsActionRequest<'_>,
    now: u64,
) -> Result<()> {
    let reply = transport.exchange(LfsRequest::ObjectDownload(action))?;
    if !reply.is_success() {
        return Err(invalid("an LFS download was refused"));
    }
    vault.put_lfs_object_stream(
        action.oid,
        Some(action.size),
        reply.body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(())
}
