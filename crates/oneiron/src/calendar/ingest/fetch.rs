//! Custody-door HTTP egress, raw archive, and registry normalize.

use super::admission::ensure_ics_import_actor;
use super::credential;
use super::poll::{IcsFeedPollConfig, ics_feed_poll_dedupe_key};
use crate::calendar::CalendarError;
use crate::calendar::claims::CalendarPassportSource;
use crate::calendar::ics::parse_ics_feed;
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::CALENDAR_ICS_FEED_BLOB;
use crate::ingest::ICS_FEED_SOURCE_ID;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

/// What the door brought back from one conditional fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcsFetchResponse {
    /// The provider's ETag matched: no mutation of any kind, re-enqueue only.
    NotModified {
        /// The ETag the provider echoed, when it sent one.
        etag: Option<String>,
    },
    /// A complete feed body.
    Complete {
        /// The ETag to send as `If-None-Match` next time, when present.
        etag: Option<String>,
        /// The raw `.ics` bytes, archived before any semantic read.
        body: Vec<u8>,
    },
    /// The provider reset or revoked the secret URL (404/410/401/403
    /// family): pause loudly, never interpret as feed content.
    CredentialReset,
}

/// The feed-fetch seam. Implementations resolve `secret_ref` through SECRET
/// custody and touch the URL only at the HTTP egress door; the URL never
/// appears in the return value.
pub trait IcsFeedFetcher: Send + Sync {
    /// Fetches the feed behind `secret_ref`, sending `if_none_match` as the
    /// `If-None-Match` precondition when present.
    ///
    /// # Errors
    ///
    /// [`CalendarError::IcsFetch`] for transport failures and
    /// [`CalendarError::IcsCredential`] for custody resolution/door
    /// failures. Neither may carry the resolved URL.
    fn fetch(
        &self,
        secret_ref: &str,
        if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError>;
}

/// The raw response a host HTTP transport returns to the door. The URL is an
/// input, never part of this row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcsHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// The response `ETag` header value, when present.
    pub etag: Option<String>,
    /// The response body.
    pub body: Vec<u8>,
}

/// Host-injected HTTP egress. The door calls it with the resolved URL; the
/// transport performs one GET and never sees the custody record.
pub trait IcsHttpTransport: Send + Sync {
    /// Performs one GET of `url`, honoring the `If-None-Match` precondition.
    ///
    /// # Errors
    ///
    /// A short diagnostic string. The door scrubs the URL out of it before
    /// the error crosses into the engine.
    fn get(&self, url: &str, if_none_match: Option<&str>) -> Result<IcsHttpResponse, String>;
}

/// The production fetcher: the feed URL is injected at the SECRET-02 door
/// ([`Vault::inject_secret_at_door`]), which applies the one custody admission
/// rule (live record, a `read` binding for `effector`, the tier gate and the
/// credential-door dial) and releases its write txn before the transport
/// runs. The URL is consumed inside the transport call, and every error
/// string the door emits is scrubbed of it.
pub struct CustodyDoorIcsFeedFetcher<'a, T> {
    vault: &'a Vault,
    effector: String,
    transport: T,
}

impl<'a, T: IcsHttpTransport> CustodyDoorIcsFeedFetcher<'a, T> {
    /// Binds the fetcher to a vault, a custody effector name, and the host's
    /// HTTP transport.
    #[must_use]
    pub fn new(vault: &'a Vault, effector: impl Into<String>, transport: T) -> Self {
        Self {
            vault,
            effector: effector.into(),
            transport,
        }
    }
}

impl<T: IcsHttpTransport> IcsFeedFetcher for CustodyDoorIcsFeedFetcher<'_, T> {
    fn fetch(
        &self,
        secret_ref: &str,
        if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError> {
        // The door drops its write txn before it runs this closure, so the
        // HTTP call never holds the vault's writer: one slow feed cannot stall
        // every vault write for the fetch's duration. The URL lives only in
        // the door's zeroized buffer and this closure's borrow of it.
        let mut fetched = None;
        self.vault
            .inject_secret_at_door(secret_ref, &self.effector, &mut |value: &[u8]| {
                let Ok(url) = std::str::from_utf8(value) else {
                    fetched = Some(Err(CalendarError::IcsCredential {
                        reason: format!("custody value for `{secret_ref}` is not a URL string"),
                    }));
                    return Ok(());
                };
                fetched = Some(self.transport.get(url, if_none_match).map_err(|reason| {
                    CalendarError::IcsFetch {
                        reason: reason.replace(url, "<redacted-url>"),
                    }
                }));
                Ok(())
            })
            .map_err(|err| credential("custody door refused the read", &err))?;
        let response = fetched.ok_or_else(|| CalendarError::IcsCredential {
            reason: format!("custody door for `{secret_ref}` returned no value"),
        })??;
        match response.status {
            304 => Ok(IcsFetchResponse::NotModified {
                etag: response.etag,
            }),
            200..=299 => Ok(IcsFetchResponse::Complete {
                etag: response.etag,
                body: response.body,
            }),
            401 | 403 | 404 | 410 => Ok(IcsFetchResponse::CredentialReset),
            status => Err(CalendarError::IcsFetch {
                reason: format!("provider returned HTTP {status}"),
            }),
        }
    }
}

/// The registry-facing ICS source: parse-only normalization of a feed body
/// into text-bearing records. Claim admission belongs to the poll runner,
/// never to `normalize`.
pub struct IcsFeedSource;

impl crate::ingest::IngestSource for IcsFeedSource {
    fn normalize(
        &self,
        input: &str,
    ) -> crate::ingest::IngestResult<crate::ingest::NormalizedIngestBatch> {
        let feed = parse_ics_feed(input.as_bytes()).map_err(|err| {
            crate::ingest::IngestError::InvalidIcsDocument {
                source_id: ICS_FEED_SOURCE_ID,
                message: err.to_string(),
            }
        })?;
        let records = feed
            .events
            .iter()
            .map(|event| crate::ingest::NormalizedIngestRecord {
                source_record_id: event.uid.clone(),
                thread_id: None,
                speaker: None,
                occurred_at: event.starts_at_utc,
                text: event
                    .summary
                    .as_deref()
                    .filter(|summary| !summary.is_empty())
                    .unwrap_or(&event.uid)
                    .to_owned(),
            })
            .collect();
        Ok(crate::ingest::NormalizedIngestBatch {
            source_id: ICS_FEED_SOURCE_ID,
            records,
            claims: Vec::new(),
            entities: Vec::new(),
            note_fallback: None,
        })
    }
}

/// Archives the raw feed body BEFORE any semantic read: one BLOB_ARTIFACT
/// per feed (deterministic id), one content-hash version per distinct body.
/// Re-archiving identical bytes is the blob store's own dedupe no-op.
/// Returns the exact stored artifact/version; source-record labels are only
/// projections of this pair.
pub(super) fn archive_raw_feed(
    vault: &Vault,
    config: &IcsFeedPollConfig,
    body: &[u8],
    now: u64,
) -> Result<CalendarPassportSource, CalendarError> {
    let feed_ref = ics_feed_poll_dedupe_key(config);
    let artifact_id = EntityId::derive(CALENDAR_ICS_FEED_BLOB, &[feed_ref.as_bytes()])?;
    if vault.get_blob_artifact(&artifact_id)?.is_none() {
        vault.put_blob_artifact(
            &artifact_id,
            &crate::blob_artifact::BlobArtifactBody::new(
                format!("ics-feed:{}", config.system),
                "text/calendar",
            ),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
    }
    let actor = ensure_ics_import_actor(vault, now)?;
    let version = vault.append_blob_artifact_version(
        &artifact_id,
        body,
        &crate::blob_artifact::BlobVersionProvenance::AgentRun { run_ref: feed_ref },
        WriteActor::new(actor, crate::edge::EdgeActorClass::System),
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(CalendarPassportSource {
        artifact: artifact_id,
        version: version.version,
    })
}
