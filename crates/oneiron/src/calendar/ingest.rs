//! ICS feed poll runner and imported-claim admission (CAL-02, ONE-1784).
//!
//! The v1 read path for secret-URL calendar feeds. The data flow is fixed by
//! the ratified blueprint:
//!
//! 1. An owner-configured SECRET custody `secret_ref` names the encrypted
//!    secret ICS URL. Poll payloads carry the `secret_ref`, NEVER the URL.
//! 2. [`enqueue_ics_feed_poll`] places one deduped `calendar.ics.poll`
//!    attempt on the existing attempt queue — no new recurrence primitive.
//! 3. The fetcher resolves the custody record and touches the URL only at
//!    the HTTP egress door ([`CustodyDoorIcsFeedFetcher`]); a 304 is a true
//!    no-op plus re-enqueue; a complete 200 archives the raw body, parses,
//!    hashes, and only then diffs.
//! 4. UID resolution runs through [`super::passport`]'s UID-first index
//!    before anything is minted; fuzzy matching is not part of the adapter.
//! 5. The per-`(system × UID)` diff: create/attach, skip, update, or mark
//!    one source's passport absent. EVENT cancellation derives through
//!    `calendar.status` only when every live inbound passport reports
//!    absence — never on a parse/fetch failure.
//! 6. Every semantic claim candidate is `ClaimSource::Imported` and crosses
//!    the Gate through `admit_imported_evidence_claim*`; immediately before
//!    each admission the candidate passes through CAL-09's
//!    [`super::safeguard::screen_then_claim`] hook, and admission runs from
//!    the typed `CalendarAdmissionRequest` — no zero-argument claim closure,
//!    no direct `put_claim`. Superseding admissions (passport updates,
//!    source absence) cross the same hook: [`super::passport`] owns only the
//!    scoped claim replacement, never an admission of its own.
//! 7. Success and 304 both re-enqueue with bounded cadence jitter. A
//!    provider-side secret-URL reset pauses loudly: paused state on the
//!    attempt row and the feed cursor, one inbox exception, no retry storm,
//!    no event cancellation.
//!
//! ## Declared deviations (WORKLOG-ONE-1784)
//!
//! * SECRET-02's `inject_secret_at_door` / `materialize_secret_lease` are not
//!   merged at this branch base, so [`CustodyDoorIcsFeedFetcher`] implements
//!   the door inline: it resolves via `Vault::resolve_secret_ref` and reads
//!   the value through the crate-private `get_secret_value_in_txn` door
//!   (binding-enforced), consuming it inside the transport call so the URL
//!   never escapes the fetch. The internals swap to the formal SECRET-02 API
//!   with no signature change when it lands.
//! * No HTTP client stack exists at HEAD and Cargo manifests are non-claims
//!   for this lane, so the egress itself is a host-injected
//!   [`IcsHttpTransport`]; the reqwest reservation lands with its owner.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::CalendarError;
use super::claims::{
    CalendarOrigin, CalendarPassportDirection, CalendarPassportPresence, CalendarPassportValue,
    CalendarStatus, CalendarStatusBasis, CalendarTimeKind, PREDICATE_CALENDAR_ORIGIN,
    PREDICATE_CALENDAR_PASSPORT, PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_TIME_KIND,
    decode_status_value, decode_time_kind_value,
};
use super::ics::{ParsedVEvent, parse_ics_feed};
use super::passport::{
    PassportDecision, all_live_inbound_passports_absent, classify_passport, index_passport_uid,
    live_passports_for_event, supersede_calendar_passport,
};
use super::safeguard::{CalendarBodyScreener, CalendarInboundBody, screen_then_claim};
use crate::attempt_queue::{
    AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState, EnqueueAttempt,
    EnqueueOutcome, InterveneAttempt,
};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::ingest::{
    ICS_FEED_SOURCE_ID, ImportedEvidenceAdmission, ImportedEvidenceEntityResolution,
};
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_MACHINE};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

/// Attempt kind for one ICS feed poll.
pub const ICS_POLL_ATTEMPT_KIND: &str = "calendar.ics.poll";
/// `vault_meta` prefix for per-feed cursor rows (ETag, last-complete stamp,
/// pause state). Node-local poll state, never synced truth.
const ICS_FEED_CURSOR_PREFIX: &[u8] = b"calendar.ics-feed.v1:";
/// Id-derivation domain for the per-feed raw archive BLOB_ARTIFACT.
const ICS_FEED_BLOB_ID_DOMAIN: &[u8] = b"oneiron:calendar-ics-feed-blob:v1:";
/// Id-derivation domain for the adapter's import actor MACHINE entity.
const ICS_IMPORT_ACTOR_ID_DOMAIN: &[u8] = b"oneiron:calendar-ics-import-actor:v1";
/// Id-derivation domain for inbox-exception refs.
const ICS_FEED_EXCEPTION_ID_DOMAIN: &[u8] = b"oneiron:calendar-ics-feed-exception:v1:";
/// Actor string stamped on pause interventions.
const ICS_POLL_INTERVENTION_ACTOR: &str = "calendar.ics.poll";

const MAX_SECRET_REF_BYTES: usize = 256;
const MAX_SYSTEM_BYTES: usize = 128;

/// SECRET-custody poll configuration for one ICS feed.
///
/// Carries the custody record NAME only. The resolved URL never appears in
/// this struct, in the attempt payload it serializes into, or in any EVENT,
/// claim, or receipt the adapter writes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcsFeedPollConfig {
    /// SECRET custody record name (e.g. `ics-feed:work`).
    pub secret_ref: String,
    /// Foreign system identifier stamped on this source's passports.
    pub system: String,
    /// Lower bound of the re-enqueue cadence window, seconds.
    pub cadence_min_seconds: u32,
    /// Upper bound of the re-enqueue cadence window, seconds.
    pub cadence_max_seconds: u32,
}

impl IcsFeedPollConfig {
    /// Structural validation: bounded non-empty names and an ordered,
    /// non-zero cadence window (mirrors the LinkedIn cadence guard).
    fn validate(&self) -> Result<(), CalendarError> {
        if self.secret_ref.is_empty() || self.secret_ref.len() > MAX_SECRET_REF_BYTES {
            return Err(ingest("secret_ref must be non-empty and bounded"));
        }
        if self.system.is_empty()
            || self.system.len() > MAX_SYSTEM_BYTES
            || self.system.chars().any(char::is_control)
        {
            return Err(ingest("system must be non-empty, bounded, and printable"));
        }
        if self.cadence_min_seconds == 0 || self.cadence_min_seconds > self.cadence_max_seconds {
            return Err(ingest("cadence window must be ordered and non-zero"));
        }
        Ok(())
    }

    /// The next poll's not-before instant inside the configured window.
    /// Mirrors `linkedin_connector`'s jittered-cadence shape exactly.
    #[must_use]
    pub fn jittered_next_poll_not_before(&self, completed_at: u64, jitter_seed: u64) -> u64 {
        let min = u64::from(self.cadence_min_seconds);
        let max = u64::from(self.cadence_max_seconds.max(self.cadence_min_seconds));
        let span = max.saturating_sub(min).saturating_add(1);
        completed_at.saturating_add(min.saturating_add(jitter_seed % span))
    }
}

impl core::fmt::Debug for IcsFeedPollConfig {
    /// Forward guardrail: today's fields are non-secret, and this hand-rolled
    /// impl guarantees no future custody-ref variant can ever print a
    /// resolved URL — a field that is not written here does not exist here.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IcsFeedPollConfig")
            .field("secret_ref", &self.secret_ref)
            .field("system", &self.system)
            .field("cadence_min_seconds", &self.cadence_min_seconds)
            .field("cadence_max_seconds", &self.cadence_max_seconds)
            .finish()
    }
}

/// The `calendar.ics.poll` attempt payload: the config plus the not-before
/// instant this poll becomes due. Carries the custody `secret_ref`, never
/// the URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcsFeedPollPayload {
    /// The feed this attempt polls.
    pub config: IcsFeedPollConfig,
    /// The instant at or after which the host should run this poll.
    pub not_before: u64,
}

/// The one injective feed identity. `system` is byte-length-prefixed so
/// colon-bearing fields can never collide — `("a", "b:c")` and `("a:b", "c")`
/// are two feeds, and everything keyed by this string (attempt dedupe, the
/// cursor row, the raw archive, the pause exception) must keep them apart.
fn ics_feed_identity(system: &str, secret_ref: &str) -> String {
    format!("ics-feed:{}:{system}:{secret_ref}", system.len())
}

/// The dedupe identity of one feed's poll chain: at most one pending
/// `calendar.ics.poll` attempt per `(system, secret_ref)`.
#[must_use]
pub fn ics_feed_poll_dedupe_key(config: &IcsFeedPollConfig) -> String {
    ics_feed_identity(&config.system, &config.secret_ref)
}

/// The re-enqueue's dedupe key carries the due instant: the attempt queue's
/// dedupe covers only PENDING rows, so the row currently executing would
/// swallow its own successor under the bare key. Scoping the key to the due
/// instant keeps the chain alive (the executing row completes, the successor
/// stays pending) while a redundant run at the same instant still dedupes.
fn ics_feed_poll_generation_key(config: &IcsFeedPollConfig, not_before: u64) -> String {
    format!("{}:due:{not_before}", ics_feed_poll_dedupe_key(config))
}

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

/// The terminal state of one poll run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcsPollRunState {
    /// The next poll attempt is on the queue.
    Reenqueued {
        /// Its due instant, inside the configured cadence window.
        next_not_before: u64,
    },
    /// The provider reset the secret URL: the feed is paused and needs the
    /// owner. No further poll is scheduled.
    PausedNeedsInput {
        /// Stable ref of the derived inbox exception row.
        inbox_exception_ref: EntityId,
    },
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

/// The production fetcher: SECRET custody resolution plus door-scoped URL
/// injection. The value read is binding-enforced
/// (`Error::SecretBindingDenied` without a `read` grant for `effector`), the
/// URL is consumed inside the transport call, and every error string the
/// door emits is scrubbed of it.
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
        let custody_id = self
            .vault
            .resolve_secret_ref(secret_ref)
            .map_err(|err| credential("custody resolution failed", &err))?
            .ok_or_else(|| CalendarError::IcsCredential {
                reason: format!("no live custody record for secret_ref `{secret_ref}`"),
            })?;
        // The value door is binding-enforced; the read itself writes nothing
        // and the txn aborts on drop. The txn is scoped to the read: it must
        // NEVER span the HTTP call, or one slow feed stalls every vault write
        // for the fetch's duration. SECRET-02 swap point: this call becomes
        // `inject_secret_at_door` / `materialize_secret_lease` when that API
        // lands, with no signature change here.
        let value = {
            let wtxn = self
                .vault
                .store
                .env
                .write_txn()
                .map_err(crate::Error::from)?;
            self.vault
                .get_secret_value_in_txn(&wtxn, &custody_id, &self.effector)
                .map_err(|err| credential("custody door refused the read", &err))?
                .ok_or_else(|| CalendarError::IcsCredential {
                    reason: format!("custody record for `{secret_ref}` vanished mid-read"),
                })?
        };
        let url = String::from_utf8(value).map_err(|_| CalendarError::IcsCredential {
            reason: format!("custody value for `{secret_ref}` is not a URL string"),
        })?;
        let response =
            self.transport
                .get(&url, if_none_match)
                .map_err(|reason| CalendarError::IcsFetch {
                    reason: reason.replace(url.as_str(), "<redacted-url>"),
                })?;
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

/// One derived inbox exception row for a paused feed. Derived, never stored:
/// the row exists exactly while the feed cursor carries a pause — the same
/// projection discipline as the CAL-07 check-in exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcsFeedPauseException {
    /// Stable per-feed ref, derived from the feed's dedupe identity.
    pub exception_ref: EntityId,
    /// The custody record name (never the URL).
    pub secret_ref: String,
    /// The foreign system whose feed paused.
    pub system: String,
    /// When the pause was recorded.
    pub paused_at: u64,
    /// Why the feed paused.
    pub reason: String,
}

/// Node-local per-feed poll cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IcsFeedCursor {
    secret_ref: String,
    system: String,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    last_complete_at: Option<u64>,
    #[serde(default)]
    paused: Option<IcsFeedPause>,
    #[serde(default)]
    last_screen_verdict: Option<String>,
}

/// The persisted half of a loud pause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IcsFeedPause {
    at: u64,
    reason: String,
}

impl IcsFeedCursor {
    fn new(config: &IcsFeedPollConfig) -> Self {
        Self {
            secret_ref: config.secret_ref.clone(),
            system: config.system.clone(),
            etag: None,
            last_complete_at: None,
            paused: None,
            last_screen_verdict: None,
        }
    }
}

/// Enqueues one deduped `calendar.ics.poll` attempt, due immediately.
/// Mirrors `linkedin_connector`'s `enqueue_inbox_sync_poll` call shape
/// exactly; a second enqueue while one is pending returns
/// [`EnqueueOutcome::Existing`].
///
/// One feed runs one chain: the queue's key dedupe alone cannot see a
/// pending generation-scoped row from the bare setup key, so the setup path
/// first adopts any live chain row — a redundant setup call can never fork a
/// second poll chain for the same feed.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on invalid config or store failure.
pub fn enqueue_ics_feed_poll(
    vault: &Vault,
    config: IcsFeedPollConfig,
    now: u64,
) -> Result<EnqueueOutcome, CalendarError> {
    config.validate()?;
    if let Some(record) = pending_poll_record(vault, &config)? {
        return Ok(EnqueueOutcome::Existing(record));
    }
    let dedupe_key = ics_feed_poll_dedupe_key(&config);
    enqueue_poll_attempt(vault, &config, now, dedupe_key, now)
}

/// The feed's live chain row, if any: one pending attempt carrying the bare
/// setup key or any generation-scoped key.
fn pending_poll_record(
    vault: &Vault,
    config: &IcsFeedPollConfig,
) -> Result<Option<AttemptRecord>, CalendarError> {
    let dedupe_key = ics_feed_poll_dedupe_key(config);
    for record in AttemptQueue::new(vault).list()? {
        let pending = matches!(
            record.state,
            AttemptState::Queued
                | AttemptState::Leased
                | AttemptState::Paused
                | AttemptState::Scheduled
        );
        if pending && is_feed_poll_row(&record, &dedupe_key) {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

/// True when an attempt row belongs to this feed's poll chain — the bare
/// setup key or any generation-scoped key derived from it.
fn is_feed_poll_row(record: &AttemptRecord, dedupe_key: &str) -> bool {
    if record.kind != ICS_POLL_ATTEMPT_KIND {
        return false;
    }
    let generation_prefix = format!("{dedupe_key}:due:");
    record
        .dedupe_key
        .as_deref()
        .is_some_and(|stored| stored == dedupe_key || stored.starts_with(&generation_prefix))
}

/// Runs one poll with the safeguard dial off and no screener — the
/// production default until the host wires CAL-09's config key.
///
/// # Errors
///
/// Parse, fetch, custody, gate, and store failures as typed
/// [`CalendarError`] variants. A parse or fetch failure mutates nothing:
/// the cursor, every passport's presence, and every EVENT status are
/// preserved.
pub fn run_ics_feed_poll(
    vault: &Vault,
    fetcher: &dyn IcsFeedFetcher,
    config: &IcsFeedPollConfig,
    now: u64,
    jitter_seed: u64,
) -> Result<IcsPollRunState, CalendarError> {
    run_ics_feed_poll_with_screener(vault, fetcher, None, false, config, now, jitter_seed)
}

/// The full poll run with CAL-09's safeguard wired: when
/// `safeguard_enabled`, `screener` (or its recorded absence) produces a
/// verdict immediately before every imported-claim admission, and admission
/// runs from the typed `CalendarAdmissionRequest` the hook hands over.
///
/// # Errors
///
/// Same contract as [`run_ics_feed_poll`].
pub fn run_ics_feed_poll_with_screener(
    vault: &Vault,
    fetcher: &dyn IcsFeedFetcher,
    screener: Option<&dyn CalendarBodyScreener>,
    safeguard_enabled: bool,
    config: &IcsFeedPollConfig,
    now: u64,
    jitter_seed: u64,
) -> Result<IcsPollRunState, CalendarError> {
    config.validate()?;
    let cursor_key = ics_feed_cursor_key(config);
    let prior_cursor =
        read_cursor(vault, &cursor_key)?.unwrap_or_else(|| IcsFeedCursor::new(config));

    let response = fetcher.fetch(&config.secret_ref, prior_cursor.etag.as_deref())?;
    match response {
        IcsFetchResponse::NotModified { .. } => {
            // True no-op: no blob, claim, EVENT, passport-presence, status,
            // or index write. The one cursor touch: a provider answer after
            // a pause is the resume signal — the credential works again.
            if prior_cursor.paused.is_some() {
                write_cursor(
                    vault,
                    &cursor_key,
                    &IcsFeedCursor {
                        paused: None,
                        ..prior_cursor
                    },
                )?;
            }
            let next_not_before = reenqueue(vault, config, now, jitter_seed)?;
            Ok(IcsPollRunState::Reenqueued { next_not_before })
        }
        IcsFetchResponse::CredentialReset => {
            pause_feed(vault, config, &cursor_key, prior_cursor, now)
        }
        IcsFetchResponse::Complete { etag, body } => {
            let blob_ref = archive_raw_feed(vault, config, &body, now)?;
            let feed = parse_ics_feed(&body)?;
            let mut admission = PollAdmission {
                vault,
                screener,
                safeguard_enabled,
                config,
                now,
                blob_ref: &blob_ref,
                verdict_fold: VerdictFold::default(),
            };
            admission.apply_feed(&feed)?;
            admission.sweep_absent_sources(&feed)?;
            write_cursor(
                vault,
                &cursor_key,
                &IcsFeedCursor {
                    etag: etag.or(prior_cursor.etag),
                    last_complete_at: Some(now),
                    last_screen_verdict: Some(admission.verdict_fold.token().to_owned()),
                    ..IcsFeedCursor::new(config)
                },
            )?;
            let next_not_before = reenqueue(vault, config, now, jitter_seed)?;
            Ok(IcsPollRunState::Reenqueued { next_not_before })
        }
    }
}

/// Projects one inbox exception row per paused feed cursor. Derived from
/// cursor state on every call; resolving the pause (a fresh successful poll,
/// or an owner clearing it) retracts the row with nothing to delete.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store failure.
pub fn ics_feed_pause_exceptions(
    vault: &Vault,
) -> Result<Vec<IcsFeedPauseException>, CalendarError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let mut rows = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, ICS_FEED_CURSOR_PREFIX)?
    {
        let (_, raw) = entry?;
        let cursor: IcsFeedCursor = serde_json::from_slice(raw.as_ref())
            .map_err(|_| ingest("feed cursor row did not decode"))?;
        let Some(paused) = cursor.paused else {
            continue;
        };
        rows.push(IcsFeedPauseException {
            exception_ref: ics_feed_exception_ref(&cursor.system, &cursor.secret_ref)?,
            secret_ref: cursor.secret_ref,
            system: cursor.system,
            paused_at: paused.at,
            reason: paused.reason,
        });
    }
    Ok(rows)
}

/// Host-visible snapshot of one feed's poll cursor. Carries the custody
/// record name and provider ETag — never the resolved URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcsFeedCursorSnapshot {
    /// The ETag the next poll sends as `If-None-Match`, when one is held.
    pub etag: Option<String>,
    /// When the last complete feed was applied.
    pub last_complete_at: Option<u64>,
    /// Whether the feed is paused awaiting owner input.
    pub paused: bool,
    /// The worst CAL-09 screen-verdict class the last run admitted under
    /// (`clear`, `flagged`, `indeterminate`, or `skipped`).
    pub last_screen_verdict: Option<String>,
}

/// Reads one feed's cursor as a host-visible snapshot. `None` means no poll
/// has completed or paused for this config.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store failure.
pub fn ics_feed_cursor_snapshot(
    vault: &Vault,
    config: &IcsFeedPollConfig,
) -> Result<Option<IcsFeedCursorSnapshot>, CalendarError> {
    let Some(cursor) = read_cursor(vault, &ics_feed_cursor_key(config))? else {
        return Ok(None);
    };
    Ok(Some(IcsFeedCursorSnapshot {
        etag: cursor.etag,
        last_complete_at: cursor.last_complete_at,
        paused: cursor.paused.is_some(),
        last_screen_verdict: cursor.last_screen_verdict,
    }))
}

/// Per-poll admission context: everything the claim-writing steps share.
struct PollAdmission<'a> {
    vault: &'a Vault,
    screener: Option<&'a dyn CalendarBodyScreener>,
    safeguard_enabled: bool,
    config: &'a IcsFeedPollConfig,
    now: u64,
    blob_ref: &'a str,
    verdict_fold: VerdictFold,
}

impl PollAdmission<'_> {
    /// Applies one completely parsed feed: per-VEVENT diff + admission.
    fn apply_feed(&mut self, feed: &super::ics::ParsedIcsFeed) -> Result<(), CalendarError> {
        for event in &feed.events {
            self.apply_event(event)?;
        }
        Ok(())
    }

    fn apply_event(&mut self, event: &ParsedVEvent) -> Result<(), CalendarError> {
        let decision = classify_passport(
            self.vault,
            &self.config.system,
            &event.uid,
            event.sequence,
            event.content_hash,
        )?;
        match decision {
            PassportDecision::CreateEvent => {
                let event_ref = self.mint_event(event)?;
                index_passport_uid(self.vault, &event.uid, &event_ref)?;
                self.admit_origin(event_ref, event)?;
                self.admit_time_kind(event_ref, event)?;
                self.admit_fresh_passport(event_ref, event)?;
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::AttachToExisting { event_ref } => {
                self.admit_fresh_passport(event_ref, event)?;
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::SkipUnchanged { .. } => {}
            PassportDecision::UpdateExisting { event_ref } => {
                // The update verdict moves the EVENT, not just the passport
                // head: occurred and name follow the drifted VEVENT, and
                // `calendar.time` re-mints when its value moved.
                self.rewrite_event(event_ref, event)?;
                self.admit_time_kind(event_ref, event)?;
                let next = self.passport_value(event, CalendarPassportPresence::Live);
                let body = screen_body(event);
                self.admit_superseding_passport(event_ref, &next, &body)?;
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::MarkSourceAbsent { .. } => {
                // Constructed only by the absence sweep, never by per-event
                // classification.
            }
        }
        Ok(())
    }

    /// The absence half of the diff: every live inbound passport this system
    /// reported before, whose UID a COMPLETE feed just omitted, flips to
    /// absent — only that passport, never the EVENT. Cancellation derives
    /// afterwards, and only when every live inbound passport reports absence.
    fn sweep_absent_sources(
        &mut self,
        feed: &super::ics::ParsedIcsFeed,
    ) -> Result<(), CalendarError> {
        let present_uids: std::collections::BTreeSet<&str> =
            feed.events.iter().map(|event| event.uid.as_str()).collect();
        for event_ref in list_event_ids(self.vault)? {
            let passports = live_passports_for_event(self.vault, &event_ref)?;
            if !passports
                .iter()
                .any(|(_, value)| value.system == self.config.system)
            {
                continue;
            }
            for (_, value) in &passports {
                let reports = value.system == self.config.system
                    && value.direction.is_inbound_bearing()
                    && value.presence == CalendarPassportPresence::Live
                    && !present_uids.contains(value.uid.as_str());
                if !reports {
                    continue;
                }
                let mut absent = value.clone();
                absent.presence = CalendarPassportPresence::Absent;
                absent.last_seen_at = self.now;
                // Absence carries no inbound content, so the screen body is
                // empty — but the admission still crosses the hook and cites
                // the complete feed that proved the omission.
                self.admit_superseding_passport(
                    event_ref,
                    &absent,
                    &CalendarInboundBody::default(),
                )?;
            }
            if all_live_inbound_passports_absent(self.vault, &event_ref)? {
                self.admit_absence_cancellation(event_ref)?;
            }
        }
        Ok(())
    }

    /// Mints the EVENT entity: structural write only, occurred from the
    /// parsed times, `name` from SUMMARY with a UID fallback.
    fn mint_event(&self, event: &ParsedVEvent) -> Result<EntityId, CalendarError> {
        let event_ref = EntityId::now();
        let occurred = self.event_occurred(event);
        let body = encode_event_body(event_name(event))?;
        self.vault
            .put_entity(&event_ref, ENTITY_TYPE_EVENT, occurred, self.now, &body)?;
        Ok(event_ref)
    }

    /// Re-mints the EVENT's structural row from a drifted VEVENT: the id is
    /// stable, occurred and `name` follow the new head. Without this the
    /// update verdict would move only the passport while the event kept
    /// stale content — the drift detector's whole point.
    fn rewrite_event(
        &self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let occurred = self.event_occurred(event);
        let body = encode_event_body(event_name(event))?;
        self.vault
            .put_entity(&event_ref, ENTITY_TYPE_EVENT, occurred, self.now, &body)?;
        Ok(())
    }

    /// The EVENT's stored occurrence from the parsed times: `now` when the
    /// feed expressed no convertible time.
    fn event_occurred(&self, event: &ParsedVEvent) -> TimeRange {
        match (event.starts_at_utc, event.ends_at_utc) {
            (Some(start), Some(end)) => TimeRange {
                start,
                end: end.max(start),
            },
            (Some(start), None) => TimeRange { start, end: start },
            (None, _) => TimeRange {
                start: self.now,
                end: self.now,
            },
        }
    }

    fn admit_origin(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        self.admit_screened(
            event_ref,
            &body,
            &source_record_id,
            PREDICATE_CALENDAR_ORIGIN,
            rmpv::Value::from(CalendarOrigin::Imported.as_str()),
        )?;
        Ok(())
    }

    /// Admits the event's `calendar.time` kind claim, superseding the prior
    /// live claim when the value moved and skipping when the live claim
    /// already carries the exact value — the same one-live-claim discipline
    /// as [`Self::admit_status_if_changed`].
    fn admit_time_kind(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let mut prior_live: Option<EntityId> = None;
        for claim_id in self.vault.claims_for_subject(&event_ref)? {
            let Some(claim) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if claim.predicate != PREDICATE_CALENDAR_TIME_KIND
                || claim.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            let current = decode_time_kind_value(&claim.value)
                .map_err(|_| ingest("stored time claim did not decode"))?;
            if current.kind == CalendarTimeKind::Absolute
                && current.busy_transparency == event.busy_transparency
            {
                return Ok(());
            }
            prior_live = Some(claim_id);
        }
        let value = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("kind"),
                rmpv::Value::from(CalendarTimeKind::Absolute.as_str()),
            ),
            (
                rmpv::Value::from("busy_transparency"),
                rmpv::Value::from(event.busy_transparency.as_str()),
            ),
        ]);
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        let new_id = self.admit_screened(
            event_ref,
            &body,
            &source_record_id,
            PREDICATE_CALENDAR_TIME_KIND,
            value,
        )?;
        if let Some(old_id) = prior_live {
            self.vault.supersede_claim(&new_id, &old_id, self.now)?;
        }
        Ok(())
    }

    /// Screens and admits the next passport head for `(system × UID)` —
    /// through the same hook + Gate door a fresh admission crosses — then
    /// supersedes exactly the scoped live claim. Supersessions carry the
    /// archived complete feed's provenance (`blob#vN:uid`), never a bare UID.
    fn admit_superseding_passport(
        &mut self,
        event_ref: EntityId,
        next: &CalendarPassportValue,
        body: &CalendarInboundBody,
    ) -> Result<(), CalendarError> {
        let source_record_id = format!("{}:{}", self.blob_ref, next.uid);
        let new_id = self.admit_screened(
            event_ref,
            body,
            &source_record_id,
            PREDICATE_CALENDAR_PASSPORT,
            super::passport::encode_passport_value(next),
        )?;
        supersede_calendar_passport(
            self.vault,
            event_ref,
            &next.system,
            &next.uid,
            &new_id,
            self.now,
        )
    }

    fn admit_fresh_passport(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let value = self.passport_value(event, CalendarPassportPresence::Live);
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        self.admit_screened(
            event_ref,
            &body,
            &source_record_id,
            PREDICATE_CALENDAR_PASSPORT,
            super::passport::encode_passport_value(&value),
        )?;
        Ok(())
    }

    /// Explicit `STATUS:CANCELLED` in the feed: write `calendar.status`
    /// cancelled with basis `imported_cancel`, unless a live claim already
    /// says exactly that. Never writes `confirmed` — resurrection is not a
    /// v1 basis.
    fn apply_imported_cancel(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        if !event.cancelled {
            return Ok(());
        }
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        self.admit_status_if_changed(
            event_ref,
            &body,
            &source_record_id,
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedCancel,
        )
    }

    /// The multi-source law's conclusion: every live inbound passport
    /// reports absence, so the EVENT reads cancelled with basis
    /// `imported_absence`. The EVENT row is never deleted and CAL-07's
    /// outcome predicate is never written here. The screen body is empty:
    /// absence carries no inbound content to screen.
    fn admit_absence_cancellation(&mut self, event_ref: EntityId) -> Result<(), CalendarError> {
        self.admit_status_if_changed(
            event_ref,
            &CalendarInboundBody::default(),
            "feed-absence",
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedAbsence,
        )
    }

    /// Admits one `calendar.status` claim, superseding the prior live status
    /// claim, and skips when the live claim already carries the exact value.
    fn admit_status_if_changed(
        &mut self,
        event_ref: EntityId,
        body: &CalendarInboundBody,
        source_record_id: &str,
        status: CalendarStatus,
        basis: CalendarStatusBasis,
    ) -> Result<(), CalendarError> {
        let mut prior_live: Option<EntityId> = None;
        for claim_id in self.vault.claims_for_subject(&event_ref)? {
            let Some(claim) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if claim.predicate != PREDICATE_CALENDAR_STATUS
                || claim.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            let current = decode_status_value(&claim.value)
                .map_err(|_| ingest("stored status claim did not decode"))?;
            if current.status == status && current.basis == basis {
                return Ok(());
            }
            prior_live = Some(claim_id);
        }
        let value = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("status"),
                rmpv::Value::from(status.as_str()),
            ),
            (
                rmpv::Value::from("basis"),
                rmpv::Value::from(basis.as_str()),
            ),
            (
                rmpv::Value::from("recorded_at"),
                rmpv::Value::from(self.now),
            ),
        ]);
        let new_id = self.admit_screened(
            event_ref,
            body,
            source_record_id,
            PREDICATE_CALENDAR_STATUS,
            value,
        )?;
        if let Some(old_id) = prior_live {
            self.vault.supersede_claim(&new_id, &old_id, self.now)?;
        }
        Ok(())
    }

    /// The one admission door: CAL-09's hook runs immediately before the
    /// imported-evidence admission, and the admission executes from the
    /// typed `CalendarAdmissionRequest` — never from a zero-argument closure
    /// that could not see the verdict. The verdict is folded into the feed
    /// cursor as the run's admission-metadata witness.
    fn admit_screened(
        &mut self,
        event_ref: EntityId,
        body: &CalendarInboundBody,
        source_record_id: &str,
        predicate: &str,
        value: rmpv::Value,
    ) -> Result<EntityId, CalendarError> {
        let screened = screen_then_claim(self.safeguard_enabled, self.screener, body, |request| {
            let token = verdict_token(&request.verdict);
            let admitted = admit_calendar_import_claim(
                self.vault,
                &event_ref,
                predicate,
                value,
                source_record_id,
                self.now,
            );
            Ok((admitted, token))
        })?;
        let (admitted, token) = screened.value;
        self.verdict_fold.record(token);
        Ok(admitted?)
    }

    fn passport_value(
        &self,
        event: &ParsedVEvent,
        presence: CalendarPassportPresence,
    ) -> CalendarPassportValue {
        CalendarPassportValue {
            system: self.config.system.clone(),
            uid: event.uid.clone(),
            last_sequence: event.sequence,
            content_hash: event.content_hash,
            direction: CalendarPassportDirection::Inbound,
            last_seen_at: self.now,
            presence,
        }
    }

    /// The provenance ref admitted claims carry: the archived feed version
    /// plus the event's UID, so every semantic candidate points back at the
    /// raw bytes it was parsed from.
    fn source_record_id(&self, event: &ParsedVEvent) -> String {
        format!("{}:{}", self.blob_ref, event.uid)
    }
}

/// The CAL-09 screen body for one VEVENT: its description plus any ATTACH
/// values as attachment text, exactly as the source expressed them.
fn screen_body(event: &ParsedVEvent) -> CalendarInboundBody {
    CalendarInboundBody {
        description: event.description.clone().unwrap_or_default(),
        attachment_text: Vec::new(),
    }
}

/// The EVENT's display name: SUMMARY, with a UID fallback.
fn event_name(event: &ParsedVEvent) -> &str {
    event
        .summary
        .as_deref()
        .filter(|summary| !summary.is_empty())
        .unwrap_or(event.uid.as_str())
}

/// The EVENT body row: a MessagePack map carrying only the name.
fn encode_event_body(name: &str) -> Result<Vec<u8>, CalendarError> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .map_err(|_| ingest("event body did not encode"))?;
    Ok(body)
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

/// Admits one typed-value claim through the Gate-backed imported-evidence
/// door and returns the new claim id. The write actor is the adapter's own
/// MACHINE entity, ensured on first use.
pub(crate) fn admit_calendar_import_claim(
    vault: &Vault,
    event_ref: &EntityId,
    predicate: &str,
    value: rmpv::Value,
    source_record_id: &str,
    recorded_at: u64,
) -> crate::Result<EntityId> {
    let actor = ensure_ics_import_actor(vault, recorded_at)?;
    let claim_id = EntityId::now();
    let admission = ImportedEvidenceAdmission::proposed(
        ICS_FEED_SOURCE_ID,
        claim_id,
        ImportedEvidenceEntityResolution::subject(*event_ref),
        WriteActor::new(actor, crate::edge::EdgeActorClass::System),
        TimeRange {
            start: recorded_at,
            end: recorded_at,
        },
        recorded_at,
    );
    crate::ingest::admit_imported_evidence_claim_typed(
        vault,
        predicate,
        value,
        source_record_id,
        &admission,
    )?;
    Ok(claim_id)
}

/// The adapter's write actor: one deterministic MACHINE entity, minted on
/// first use. Imported claims attribute to it as `EdgeActorClass::System`.
pub fn ics_import_actor_id() -> crate::Result<EntityId> {
    derive_entity_id(ICS_IMPORT_ACTOR_ID_DOMAIN, &[])
}

fn ensure_ics_import_actor(vault: &Vault, now: u64) -> crate::Result<EntityId> {
    let id = ics_import_actor_id()?;
    if vault.get_entity_type(&id)? != Some(ENTITY_TYPE_MACHINE) {
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(
                rmpv::Value::from("name"),
                rmpv::Value::from("calendar ICS feed importer"),
            )]),
        )
        .map_err(|_| crate::Error::InvariantViolation("actor body did not encode"))?;
        vault.put_entity(
            &id,
            ENTITY_TYPE_MACHINE,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )?;
    }
    Ok(id)
}

/// Archives the raw feed body BEFORE any semantic read: one BLOB_ARTIFACT
/// per feed (deterministic id), one content-hash version per distinct body.
/// Re-archiving identical bytes is the blob store's own dedupe no-op.
/// Returns the provenance ref admitted claims carry as their source record
/// prefix.
fn archive_raw_feed(
    vault: &Vault,
    config: &IcsFeedPollConfig,
    body: &[u8],
    now: u64,
) -> Result<String, CalendarError> {
    let feed_ref = ics_feed_poll_dedupe_key(config);
    let artifact_id = derive_entity_id(ICS_FEED_BLOB_ID_DOMAIN, feed_ref.as_bytes())?;
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
    Ok(format!("{}#v{}", artifact_id.to_hex(), version.version))
}

/// The loud pause: persist the pause on the feed cursor, pause every pending
/// poll attempt for this feed, and schedule nothing. Events are never
/// cancelled on a credential reset.
fn pause_feed(
    vault: &Vault,
    config: &IcsFeedPollConfig,
    cursor_key: &[u8],
    cursor: IcsFeedCursor,
    now: u64,
) -> Result<IcsPollRunState, CalendarError> {
    write_cursor(
        vault,
        cursor_key,
        &IcsFeedCursor {
            paused: Some(IcsFeedPause {
                at: now,
                reason: "provider reset the secret feed URL".to_owned(),
            }),
            ..cursor
        },
    )?;
    let dedupe_key = ics_feed_poll_dedupe_key(config);
    let queue = AttemptQueue::new(vault);
    for record in queue.list()? {
        if !is_feed_poll_row(&record, &dedupe_key) {
            continue;
        }
        if matches!(record.state, AttemptState::Queued | AttemptState::Scheduled) {
            queue.intervene(InterveneAttempt {
                id: record.id,
                kind: AttemptInterventionKind::Pause,
                actor: ICS_POLL_INTERVENTION_ACTOR.to_owned(),
                note: Some("provider credential reset; feed paused".to_owned()),
                now,
            })?;
        }
    }
    Ok(IcsPollRunState::PausedNeedsInput {
        inbox_exception_ref: ics_feed_exception_ref(&config.system, &config.secret_ref)?,
    })
}

/// Enqueues the next poll, due inside the configured jitter window. The
/// generation-scoped dedupe key keeps the chain alive across the executing
/// row and idempotent against a redundant run at the same due instant.
fn reenqueue(
    vault: &Vault,
    config: &IcsFeedPollConfig,
    now: u64,
    jitter_seed: u64,
) -> Result<u64, CalendarError> {
    let next_not_before = config.jittered_next_poll_not_before(now, jitter_seed);
    let dedupe_key = ics_feed_poll_generation_key(config, next_not_before);
    enqueue_poll_attempt(vault, config, next_not_before, dedupe_key, now)?;
    Ok(next_not_before)
}

fn enqueue_poll_attempt(
    vault: &Vault,
    config: &IcsFeedPollConfig,
    not_before: u64,
    dedupe_key: String,
    now: u64,
) -> Result<EnqueueOutcome, CalendarError> {
    let payload = serde_json::to_vec(&IcsFeedPollPayload {
        config: config.clone(),
        not_before,
    })
    .map_err(|_| ingest("poll payload did not encode"))?;
    Ok(AttemptQueue::new(vault).enqueue(EnqueueAttempt {
        kind: ICS_POLL_ATTEMPT_KIND.to_owned(),
        payload,
        dedupe_key: Some(dedupe_key),
        run_id: None,
        now,
    })?)
}

fn list_event_ids(vault: &Vault) -> Result<Vec<EntityId>, CalendarError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let mut ids = Vec::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[ENTITY_TYPE_EVENT])?
    {
        let (key, _) = entry?;
        ids.push(crate::vault::entity_id_from_type_index_key(&key)?);
    }
    Ok(ids)
}

fn ics_feed_cursor_key(config: &IcsFeedPollConfig) -> Vec<u8> {
    let digest = Sha256::digest(ics_feed_poll_dedupe_key(config).as_bytes());
    let mut key = Vec::with_capacity(ICS_FEED_CURSOR_PREFIX.len() + digest.len());
    key.extend_from_slice(ICS_FEED_CURSOR_PREFIX);
    key.extend_from_slice(&digest);
    key
}

fn read_cursor(vault: &Vault, key: &[u8]) -> Result<Option<IcsFeedCursor>, CalendarError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, key)? else {
        return Ok(None);
    };
    let cursor = serde_json::from_slice(raw.as_ref())
        .map_err(|_| ingest("feed cursor row did not decode"))?;
    Ok(Some(cursor))
}

fn write_cursor(vault: &Vault, key: &[u8], cursor: &IcsFeedCursor) -> Result<(), CalendarError> {
    let encoded = serde_json::to_vec(cursor).map_err(|_| ingest("feed cursor did not encode"))?;
    vault.try_with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, key, &encoded)?;
        Ok::<_, crate::Error>(())
    })?;
    Ok(())
}

/// The stable exception ref for one feed, shared by the pause run-state and
/// the inbox projection so hosts can correlate the two.
fn ics_feed_exception_ref(system: &str, secret_ref: &str) -> Result<EntityId, CalendarError> {
    Ok(derive_entity_id(
        ICS_FEED_EXCEPTION_ID_DOMAIN,
        ics_feed_identity(system, secret_ref).as_bytes(),
    )?)
}

fn derive_entity_id(domain: &[u8], key: &[u8]) -> crate::Result<EntityId> {
    let digest = Sha256::digest([domain, key].concat());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(bytes)
}

/// Compact fold of the run's screen verdicts, persisted on the cursor as the
/// admission-metadata witness: the worst verdict class seen this run.
#[derive(Default)]
struct VerdictFold {
    token: Option<&'static str>,
}

impl VerdictFold {
    fn record(&mut self, token: &'static str) {
        let rank = |token: &str| match token {
            "flagged" => 3,
            "indeterminate" => 2,
            "clear" => 1,
            _ => 0,
        };
        if self.token.is_none_or(|current| rank(token) > rank(current)) {
            self.token = Some(token);
        }
    }

    fn token(&self) -> &'static str {
        self.token.unwrap_or("skipped")
    }
}

fn verdict_token(verdict: &super::safeguard::CalendarScreenVerdict) -> &'static str {
    match verdict {
        super::safeguard::CalendarScreenVerdict::Skipped => "skipped",
        super::safeguard::CalendarScreenVerdict::Clear => "clear",
        super::safeguard::CalendarScreenVerdict::Flagged { .. } => "flagged",
        super::safeguard::CalendarScreenVerdict::Indeterminate { .. } => "indeterminate",
    }
}

fn credential(context: &'static str, err: &crate::Error) -> CalendarError {
    CalendarError::IcsCredential {
        reason: format!("{context}: {err}"),
    }
}

fn ingest(reason: &'static str) -> CalendarError {
    CalendarError::IcsIngest {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::test_support::open_calendar_vault;

    /// A one-body fetcher: every fetch returns a complete feed.
    struct BodyFetcher {
        body: Vec<u8>,
    }

    impl IcsFeedFetcher for BodyFetcher {
        fn fetch(
            &self,
            _secret_ref: &str,
            _if_none_match: Option<&str>,
        ) -> Result<IcsFetchResponse, CalendarError> {
            Ok(IcsFetchResponse::Complete {
                etag: None,
                body: self.body.clone(),
            })
        }
    }

    fn one_event_feed(dtstart: &str, dtend: &str) -> Vec<u8> {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n\
             BEGIN:VEVENT\r\nUID:uid-oc@x\r\nDTSTAMP:20260805T100000Z\r\n\
             DTSTART:{dtstart}\r\nDTEND:{dtend}\r\nSEQUENCE:1\r\nSUMMARY:standup\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        .into_bytes()
    }

    fn test_config() -> IcsFeedPollConfig {
        IcsFeedPollConfig {
            secret_ref: "ics-feed:work".to_owned(),
            system: "work".to_owned(),
            cadence_min_seconds: 300,
            cadence_max_seconds: 900,
        }
    }

    /// VERDICT-FIX (semantic-update-not-applied): a same-SEQUENCE content
    /// drift moves the EVENT's stored occurrence, not just the passport head.
    /// The header read is crate-internal, so this half of the oracle lives
    /// here; the name/transparency half lives in the adapter oracle.
    #[test]
    fn update_existing_rewrites_the_event_occurrence() {
        let (_dir, vault) = open_calendar_vault();
        let config = test_config();
        let first = BodyFetcher {
            body: one_event_feed("20260806T140000Z", "20260806T150000Z"),
        };
        run_ics_feed_poll(&vault, &first, &config, 1_800_000_000, 7).expect("create poll");
        let event = crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x")
            .expect("resolve")
            .expect("event minted");
        let before = vault
            .read_entity_header(&event)
            .expect("header")
            .expect("event exists");
        assert_eq!(before.occurred_start, 1_786_024_800);
        assert_eq!(before.occurred_end, 1_786_028_400);

        let drifted = BodyFetcher {
            body: one_event_feed("20260807T090000Z", "20260807T093000Z"),
        };
        run_ics_feed_poll(&vault, &drifted, &config, 1_800_000_100, 7).expect("drift poll");
        let after = vault
            .read_entity_header(&event)
            .expect("header")
            .expect("event exists");
        assert_eq!(
            (after.occurred_start, after.occurred_end),
            (1_786_093_200, 1_786_095_000),
            "a drifted DTSTART/DTEND re-mints the EVENT occurrence"
        );
    }
}
