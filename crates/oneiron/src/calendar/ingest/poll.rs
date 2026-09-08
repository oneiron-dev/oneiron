//! ICS feed poll queue, cursor store, and poll runner.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::admission::{PollAdmission, VerdictFold};
use super::fetch::{IcsFeedFetcher, IcsFetchResponse, archive_raw_feed};
use super::{derive_entity_id, ingest};
use crate::attempt_queue::{
    AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState, EnqueueAttempt,
    EnqueueOutcome, InterveneAttempt,
};
use crate::calendar::CalendarError;
use crate::calendar::ics::parse_ics_feed;
use crate::calendar::safeguard::CalendarBodyScreener;
use crate::entity_id::EntityId;
use crate::vault::Vault;

/// Attempt kind for one ICS feed poll.
pub const ICS_POLL_ATTEMPT_KIND: &str = "calendar.ics.poll";

/// `vault_meta` prefix for per-feed cursor rows (ETag, last-complete stamp,
/// pause state). Node-local poll state, never synced truth.
const ICS_FEED_CURSOR_PREFIX: &[u8] = b"calendar.ics-feed.v1:";

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
                // A landing poll row has not settled: minting a second one
                // would double-poll the feed while the first still finishes.
                | AttemptState::Landing
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

/// Id-derivation domain for inbox-exception refs.
const ICS_FEED_EXCEPTION_ID_DOMAIN: &[u8] = b"oneiron:calendar-ics-feed-exception:v1:";
