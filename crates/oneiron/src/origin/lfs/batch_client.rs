//! The outbound Git-LFS batch client: one https remote's batch API
//! (`<remote>.git/info/lfs/objects/batch`) and its basic transfer. A
//! mirror's objects go up, an upload and its verify call per object the
//! remote does not hold yet (FIX 919); an outside import's come down, each
//! installed through the vault-LFS upload door, its scan, SHA-256 and size
//! checks included (FIX 7596).
//!
//! https only, no redirects, no proxy. The one credential is the
//! `Authorization` value the caller hands it inside the custody door; it
//! rides the batch call to the remote's own host alone, and each action's
//! own headers ride that action's request alone. An object is streamed,
//! never held whole in memory. A batch carries at most
//! [`LFS_BATCH_OBJECTS`] objects, more go in further batches, so no count
//! is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{LFS_BASIC_TRANSFER, LFS_JSON_MEDIA_TYPE, LfsOid};
use crate::error::{ArtifactError, Error, Result};
use crate::{TimeRange, Vault};

/// Objects one batch call names: the size Git-LFS servers commonly take.
const LFS_BATCH_OBJECTS: usize = 100;

/// The bound of one batch answer read into memory.
const LFS_BATCH_ANSWER_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// How long one batch or verify call may take.
const LFS_BATCH_TIMEOUT: Duration = Duration::from_secs(60);

/// How long one object's transfer may take.
const LFS_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);

fn invalid(why: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidLfsObject(why))
}

#[derive(Serialize)]
struct BatchRequest<'a> {
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
    upload: Option<BatchAction>,
    #[serde(default)]
    verify: Option<BatchAction>,
    #[serde(default)]
    download: Option<BatchAction>,
}

#[derive(Deserialize)]
struct BatchAction {
    href: String,
    #[serde(default)]
    header: BTreeMap<String, String>,
}

/// One https Git-LFS remote, named by its Git URL.
pub(crate) struct LfsBatchRemote {
    batch_url: String,
    client: reqwest::blocking::Client,
}

impl LfsBatchRemote {
    /// The batch API of the Git remote `remote`, an https URL with no
    /// credential, query or fragment.
    ///
    /// # Errors
    /// Another scheme, or a client that cannot be built.
    pub(crate) fn of(remote: &str) -> Result<Self> {
        if !remote.starts_with("https://") || remote.contains(['?', '#', '@']) {
            return Err(invalid("an LFS remote is an https URL with no credential"));
        }
        let base = remote.trim_end_matches('/');
        let batch_url = if base.ends_with(".git") {
            format!("{base}/info/lfs/objects/batch")
        } else {
            format!("{base}.git/info/lfs/objects/batch")
        };
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| invalid("the LFS client is unavailable"))?;
        Ok(Self { batch_url, client })
    }

    /// Sends each of `objects` the remote does not hold yet from this
    /// vault's store, under `authorization`, the full header value. Answers
    /// the objects the remote is still not known to hold: one it refused,
    /// one this vault lacks, one whose transfer or verify failed, or one
    /// its answer left out.
    ///
    /// # Errors
    /// A batch call that fails or answers what does not decode.
    pub(crate) fn upload(
        &self,
        vault: &Vault,
        authorization: &str,
        objects: &[(LfsOid, u64)],
    ) -> Result<BTreeSet<LfsOid>> {
        let mut missing = BTreeSet::new();
        for chunk in objects.chunks(LFS_BATCH_OBJECTS) {
            let sizes: BTreeMap<LfsOid, u64> = chunk.iter().copied().collect();
            let mut answered = BTreeSet::new();
            for object in self.batch(Some(authorization), "upload", chunk)?.objects {
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
                    Some(upload) => self.put_object(vault, oid, size, upload),
                    None => Ok(true),
                };
                let held = match sent {
                    Ok(true) => match &actions.verify {
                        Some(verify) => self.verify_object(oid, size, verify),
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

    /// Fetches each of `objects` from the remote, under `authorization`
    /// when one is named, and installs it through this vault's LFS upload
    /// door at `now`. Answers the objects that did not arrive: one the
    /// remote refused or left out, one whose transfer failed, or one the
    /// door refused.
    ///
    /// # Errors
    /// A batch call that fails or answers what does not decode.
    pub(crate) fn download(
        &self,
        vault: &Vault,
        authorization: Option<&str>,
        objects: &[(LfsOid, u64)],
        now: u64,
    ) -> Result<BTreeSet<LfsOid>> {
        let mut missing = BTreeSet::new();
        for chunk in objects.chunks(LFS_BATCH_OBJECTS) {
            let sizes: BTreeMap<LfsOid, u64> = chunk.iter().copied().collect();
            let mut arrived = BTreeSet::new();
            for object in self.batch(authorization, "download", chunk)?.objects {
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
                match self.get_object(vault, oid, size, &download, now) {
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

    /// One batch call for `objects` under `operation`.
    fn batch(
        &self,
        authorization: Option<&str>,
        operation: &str,
        objects: &[(LfsOid, u64)],
    ) -> Result<BatchAnswer> {
        let request = BatchRequest {
            operation,
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
        let body =
            serde_json::to_vec(&request).map_err(|_| invalid("an LFS batch did not encode"))?;
        let mut call = self
            .client
            .post(&self.batch_url)
            .timeout(LFS_BATCH_TIMEOUT)
            .header(reqwest::header::ACCEPT, LFS_JSON_MEDIA_TYPE)
            .header(reqwest::header::CONTENT_TYPE, LFS_JSON_MEDIA_TYPE);
        if let Some(authorization) = authorization {
            let mut value = reqwest::header::HeaderValue::from_str(authorization)
                .map_err(|_| invalid("an LFS credential is not a header value"))?;
            value.set_sensitive(true);
            call = call.header(reqwest::header::AUTHORIZATION, value);
        }
        let response = call
            .body(body)
            .send()
            .map_err(|_| invalid("the LFS batch call failed"))?;
        if !response.status().is_success() {
            return Err(invalid("the LFS batch call was refused"));
        }
        let mut answer = Vec::new();
        response
            .take(LFS_BATCH_ANSWER_MAX_BYTES + 1)
            .read_to_end(&mut answer)
            .map_err(|_| invalid("the LFS batch answer did not read"))?;
        if answer.len() as u64 > LFS_BATCH_ANSWER_MAX_BYTES {
            return Err(invalid("the LFS batch answer passed its bound"));
        }
        serde_json::from_slice(&answer).map_err(|_| invalid("the LFS batch answer did not decode"))
    }

    /// Streams `oid` from this vault's verified store to `action`'s href;
    /// `false` when this vault does not hold it.
    fn put_object(
        &self,
        vault: &Vault,
        oid: LfsOid,
        size: u64,
        action: &BatchAction,
    ) -> Result<bool> {
        let mut spool = tempfile::tempfile_in(vault.lfs_storage_dir())?;
        if !vault.has_lfs_object(oid, size)? || !vault.write_lfs_object_to(oid, &mut spool)? {
            return Ok(false);
        }
        spool.seek(SeekFrom::Start(0))?;
        let request = self
            .action(reqwest::Method::PUT, action)?
            .timeout(LFS_TRANSFER_TIMEOUT)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(reqwest::blocking::Body::sized(spool, size));
        Ok(request
            .send()
            .map_err(|_| invalid("an LFS upload failed"))?
            .status()
            .is_success())
    }

    /// Asks `action`'s href to verify the uploaded `oid`.
    fn verify_object(&self, oid: LfsOid, size: u64, action: &BatchAction) -> Result<bool> {
        let body = serde_json::to_vec(&BatchObjectRef {
            oid: oid.to_hex(),
            size,
        })
        .map_err(|_| invalid("an LFS verify did not encode"))?;
        Ok(self
            .action(reqwest::Method::POST, action)?
            .timeout(LFS_BATCH_TIMEOUT)
            .header(reqwest::header::ACCEPT, LFS_JSON_MEDIA_TYPE)
            .header(reqwest::header::CONTENT_TYPE, LFS_JSON_MEDIA_TYPE)
            .body(body)
            .send()
            .map_err(|_| invalid("an LFS verify failed"))?
            .status()
            .is_success())
    }

    /// Streams `oid` from `action`'s href through this vault's LFS upload
    /// door, which checks its scan, SHA-256 and size before it stores it.
    fn get_object(
        &self,
        vault: &Vault,
        oid: LfsOid,
        size: u64,
        action: &BatchAction,
        now: u64,
    ) -> Result<()> {
        let response = self
            .action(reqwest::Method::GET, action)?
            .timeout(LFS_TRANSFER_TIMEOUT)
            .send()
            .map_err(|_| invalid("an LFS download failed"))?;
        if !response.status().is_success() {
            return Err(invalid("an LFS download was refused"));
        }
        vault.put_lfs_object_stream(
            oid,
            Some(size),
            response,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        Ok(())
    }

    /// A request to `action`'s https href carrying its own headers only.
    fn action(
        &self,
        method: reqwest::Method,
        action: &BatchAction,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        if !action.href.starts_with("https://") {
            return Err(invalid("an LFS action names no https href"));
        }
        let mut request = self.client.request(method, &action.href);
        for (name, value) in &action.header {
            request = request.header(name.as_str(), value.as_str());
        }
        Ok(request)
    }
}
