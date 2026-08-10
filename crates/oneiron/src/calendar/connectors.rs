//! Shared calendar connector kernel (CAL-05, ONE-1787).
//!
//! Two provider adapters — [`super::caldav`] and [`super::google_internal`] —
//! sit on this one small kernel. It is deliberately *not* a general connector
//! framework: it owns exactly what a calendar seat needs to pull, echo-suppress,
//! and conditionally write one remote calendar.
//!
//! What lives here:
//!
//! * seat configuration carrying a SECRET custody `secret_ref` (never a
//!   credential, never a URL with one embedded), a provider cursor, and an
//!   explicit kill switch;
//! * bounded, non-zero cadence jitter in the same shape
//!   [`super::ingest::IcsFeedPollConfig`] and `linkedin_connector` use;
//! * the provider-neutral remote rows ([`RemoteCalendarObject`],
//!   [`RemoteCalendarChange`], [`RemoteSyncBatch`], [`RemoteWriteRequest`],
//!   [`RemoteWriteReceipt`]) and the [`CalendarRemoteTransport`] seam. No
//!   HTTP/WebDAV/OAuth type crosses that seam, so the orchestration below is
//!   testable offline with fixtures;
//! * the durable local write outbox row, staged BEFORE any remote mutation;
//! * [`classify_remote_change`], the echo law that keeps a two-way seat from
//!   rewriting its own writes.
//!
//! ## The laws this module implements
//!
//! 1. **ICS truth, not transport truth.** A pulled upsert is re-parsed through
//!    [`super::ics::parse_ics_feed`]; the UID, SEQUENCE, and content hash used
//!    for classification come from that parse, never from the fields a
//!    transport happened to fill in. Time crosses only [`super::tz`].
//! 2. **UID before mint.** [`super::passport::resolve_event_by_uid`] runs before
//!    any EVENT is created, so the same UID seen through two providers is one
//!    EVENT with two system-scoped passports.
//! 3. **Echo suppression.** A same-or-older SEQUENCE with the same content hash
//!    is an acknowledgement: no semantic rewrite, no write-back. A newer
//!    SEQUENCE or a same-SEQUENCE hash drift applies once through the CAL-02
//!    Gate-backed imported-evidence door.
//! 4. **Multi-source law, verbatim from the ratified seam:** feed-absence
//!    cancellation applies ONLY when every live inbound passport for the EVENT
//!    reports absence; a single-source absence supersedes only that passport,
//!    never the EVENT status. The EVENT row is never deleted and CAL-07's
//!    outcome predicate is never written here.
//! 5. **Conditional writes only.** A local write stages an outbox row (action,
//!    UID, intended SEQUENCE, content hash, expected ETag) durably before the
//!    provider call, sends the expected ETag as the precondition, and enters
//!    reconciliation on mismatch instead of overwriting blind.
//! 6. **The kill switch is operational, not destructive.** It stops pulls and
//!    writes, empties the advertised verb catalog, and schedules no next poll;
//!    it erases no EVENT, passport, or outbox evidence.
//!
//! ## Custody posture (SECRET-02 swap point)
//!
//! Seat configs carry the custody record NAME only. This kernel never resolves
//! credential bytes at all — resolution happens below the transport seam, at the
//! provider egress door, exactly as [`super::ingest::CustodyDoorIcsFeedFetcher`]
//! does it today with `Vault::resolve_secret_ref` + the crate-private
//! `get_secret_value_in_txn` value door. When SECRET-02's
//! `inject_secret_at_door` / `materialize_secret_lease` land, that door swaps
//! with no signature change here, because nothing in this module — config,
//! cursor, attempt payload, outbox row, receipt, error, or `Debug` — has a
//! place to hold a credential.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::CalendarError;
use super::claims::{
    CalendarBusyTransparency, CalendarOrigin, CalendarPassportDirection, CalendarPassportPresence,
    CalendarPassportValue, CalendarStatus, CalendarStatusBasis, CalendarTimeKind,
    PREDICATE_CALENDAR_ORIGIN, PREDICATE_CALENDAR_PASSPORT, PREDICATE_CALENDAR_STATUS,
    PREDICATE_CALENDAR_TIME_KIND, decode_status_value, decode_time_kind_value,
};
use super::ics::{ParsedVEvent, parse_ics_feed};
use super::ingest::admit_calendar_import_claim;
use super::passport::{
    all_live_inbound_passports_absent, encode_passport_value, index_passport_uid, live_passport_for,
    live_passports_for_event, resolve_event_by_uid, supersede_calendar_passport,
};
use super::safeguard::{CalendarInboundBody, screen_then_claim};
use super::tz::utc_to_wall;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Attempt kind for one CalDAV seat sync.
pub const CALDAV_SYNC_ATTEMPT_KIND: &str = "calendar.caldav.sync";
/// Attempt kind for one Workspace-Internal Google seat sync.
pub const GOOGLE_INTERNAL_SYNC_ATTEMPT_KIND: &str = "calendar.google_internal.sync";

/// Advertised verb: incremental read of the configured remote calendar.
pub const CALENDAR_CONNECTOR_PULL_VERB: &str = "calendar.connector.pull";
/// Advertised verb: conditional write to the configured remote calendar.
pub const CALENDAR_CONNECTOR_WRITE_VERB: &str = "calendar.connector.write";

/// The verbs a live seat advertises. A killed seat advertises none.
const CALENDAR_CONNECTOR_VERB_CATALOG: &[&str] =
    &[CALENDAR_CONNECTOR_PULL_VERB, CALENDAR_CONNECTOR_WRITE_VERB];

/// `vault_meta` prefix for this module's private rows. Two kinds live under it
/// ([`OUTBOX_ROW_TAG`], [`REMOTE_OBJECT_TAG`]): no second prefix, no entity byte.
const CALENDAR_WRITE_OUTBOX_PREFIX: &[u8] = b"calendar.connector-write.v1:";
/// Sub-tag for durable write-outbox rows.
const OUTBOX_ROW_TAG: &[u8] = b"row:";
/// Sub-tag for the node-local `(system, calendar_ref, uid)` href/ETag cursor.
const REMOTE_OBJECT_TAG: &[u8] = b"obj:";
/// Id-derivation domain for [`CalendarWriteOutboxRow::outbox_id`].
const OUTBOX_ID_DOMAIN: &[u8] = b"oneiron:calendar-connector-write:v1:";
/// The UID domain a locally originated EVENT gets when no passport names it.
/// `.invalid` is the RFC 2606 reserved TLD: a calendar UID must be globally
/// unique, and must never look like a resolvable address.
const LOCAL_UID_DOMAIN: &str = "calendar.invalid";
/// Upper bound for every bounded ref this module accepts.
const MAX_REF_BYTES: usize = 256;

/// Every way one connector run can fail.
#[derive(Debug, thiserror::Error)]
pub enum CalendarConnectorError {
    /// The shared calendar error home: parse, timezone, ingest, and custody
    /// verdicts arrive unchanged.
    #[error(transparent)]
    Calendar(#[from] CalendarError),
    /// The seat's own configuration is structurally invalid.
    #[error("invalid calendar connector seat config: {0}")]
    InvalidSeatConfig(&'static str),
    /// A pull or write was attempted on a killed seat.
    #[error("calendar connector kill switch is engaged")]
    KillSwitchEngaged,
    /// Custody could not produce a credential for this seat. Names the custody
    /// record only.
    #[error("calendar connector credential unavailable: {secret_ref}")]
    CredentialUnavailable {
        /// The custody record name, never the resolved credential.
        secret_ref: String,
    },
    /// The provider transport failed. `detail` is provider diagnostics, scrubbed
    /// by the wire before it crosses the seam.
    #[error("calendar provider {provider} {operation} failed: {detail}")]
    Transport {
        /// Provider key of the failing transport.
        provider: &'static str,
        /// Which transport operation failed.
        operation: &'static str,
        /// What failed, credential-free.
        detail: String,
    },
    /// The conditional write's precondition failed: the remote object moved.
    /// Reconciliation, never a blind overwrite or an unconditional retry.
    #[error("calendar ETag mismatch for {href}")]
    EtagMismatch {
        /// The remote resource whose ETag moved.
        href: String,
        /// The ETag the write expected.
        expected: Option<String>,
        /// The ETag the provider reports now, when it sent one.
        actual: Option<String>,
    },
    /// The durable outbox row itself could not be staged, resumed, or committed.
    #[error("calendar connector outbox {outbox_id:?} failed: {detail}")]
    Outbox {
        /// The deterministic outbox row id.
        outbox_id: [u8; 32],
        /// What failed.
        detail: String,
    },
}

impl From<crate::Error> for CalendarConnectorError {
    fn from(err: crate::Error) -> Self {
        Self::Calendar(CalendarError::from(err))
    }
}

/// The terminal state of one connector sync run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarSyncOutcome {
    /// The run completed and the next attempt is on the queue.
    Reenqueued {
        /// The provider cursor the next run resumes from.
        next_cursor: Option<String>,
        /// The next attempt's due instant, inside the configured jitter window.
        next_not_before: u64,
        /// Semantic applications (create/attach/update through the Gate).
        applied: u32,
        /// Echo acknowledgements that rewrote nothing.
        acknowledged: u32,
        /// Passports this run flipped to `absent` for their own source only.
        source_absences: u32,
        /// EVENTs this run cancelled under the all-live-inbound-absent law.
        status_cancellations: u32,
    },
    /// The kill switch is engaged: no transport I/O ran and nothing was
    /// enqueued. Existing calendar data is untouched.
    Killed,
}

/// One connector seat's configuration.
///
/// Carries the SECRET custody record NAME. No app password, OAuth token, or
/// credential-bearing URL has a field to live in here, and the hand-rolled
/// [`core::fmt::Debug`] below keeps it that way for every future field.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarConnectorSeatConfig {
    /// Stable seat identifier (host vocabulary).
    pub seat_ref: String,
    /// SECRET custody record name for this seat's provider credential.
    pub secret_ref: String,
    /// Foreign system identifier stamped on this seat's passports.
    pub system: String,
    /// The provider-side collection this seat reads and writes.
    pub calendar_ref: String,
    /// Lower bound of the re-enqueue cadence window, seconds.
    pub cadence_jitter_min_seconds: u32,
    /// Upper bound of the re-enqueue cadence window, seconds.
    pub cadence_jitter_max_seconds: u32,
}

impl core::fmt::Debug for CalendarConnectorSeatConfig {
    /// Prints stable non-secret identifiers only. `secret_ref` is an opaque
    /// custody NAME — the credential it points at is resolved below the
    /// transport seam and never enters this struct — so printing the name is
    /// safe and printing anything else is impossible: a field not written here
    /// does not exist here.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CalendarConnectorSeatConfig")
            .field("seat_ref", &self.seat_ref)
            .field("secret_ref", &self.secret_ref)
            .field("system", &self.system)
            .field("calendar_ref", &self.calendar_ref)
            .field("cadence_jitter_min_seconds", &self.cadence_jitter_min_seconds)
            .field("cadence_jitter_max_seconds", &self.cadence_jitter_max_seconds)
            .finish()
    }
}

/// The engaged half of a seat's kill switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarConnectorKillSwitchState {
    /// When the switch was thrown.
    pub killed_at: u64,
    /// The advertised verb catalog is empty while this holds.
    pub verbs_revoked: bool,
    /// No pull, write, or re-enqueue runs while this holds.
    pub polling_stopped: bool,
    /// Host-side reason ref. Never free-form credential-bearing text.
    pub reason_ref: String,
}

/// One connector seat: config, provider cursor, and kill-switch state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarConnectorSeatState {
    /// The seat's configuration.
    pub config: CalendarConnectorSeatConfig,
    /// The provider cursor (CalDAV sync-token / Google sync token) this seat
    /// resumes from. Node-local poll state, never synced truth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Present exactly while the seat is killed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_switch: Option<CalendarConnectorKillSwitchState>,
}

impl CalendarConnectorSeatState {
    /// A live seat with no cursor yet.
    #[must_use]
    pub const fn new(config: CalendarConnectorSeatConfig) -> Self {
        Self {
            config,
            cursor: None,
            kill_switch: None,
        }
    }

    /// The same seat resuming from `cursor`.
    #[must_use]
    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// Structural validation: bounded non-empty refs and an ordered, non-zero
    /// cadence window.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::InvalidSeatConfig`] naming the offending rule.
    pub fn validate(&self) -> Result<(), CalendarConnectorError> {
        let config = &self.config;
        bounded(&config.seat_ref, "seat_ref must be non-empty and bounded")?;
        bounded(
            &config.secret_ref,
            "secret_ref must be non-empty and bounded",
        )?;
        bounded(&config.system, "system must be non-empty and bounded")?;
        bounded(
            &config.calendar_ref,
            "calendar_ref must be non-empty and bounded",
        )?;
        if config.cadence_jitter_min_seconds == 0
            || config.cadence_jitter_min_seconds > config.cadence_jitter_max_seconds
        {
            return Err(CalendarConnectorError::InvalidSeatConfig(
                "cadence jitter window must be ordered and non-zero",
            ));
        }
        Ok(())
    }

    /// The next poll's due instant inside the configured window. Mirrors the
    /// `linkedin_connector` / [`super::ingest`] jitter formula exactly.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::InvalidSeatConfig`] when the window is invalid.
    pub fn jittered_next_poll_at(
        &self,
        completed_at: u64,
        jitter_seed: u64,
    ) -> Result<u64, CalendarConnectorError> {
        self.validate()?;
        let min = u64::from(self.config.cadence_jitter_min_seconds);
        let max = u64::from(
            self.config
                .cadence_jitter_max_seconds
                .max(self.config.cadence_jitter_min_seconds),
        );
        let span = max.saturating_sub(min).saturating_add(1);
        Ok(completed_at.saturating_add(min.saturating_add(jitter_seed % span)))
    }

    /// Throws the kill switch: verbs revoked, polling stopped, data untouched.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::InvalidSeatConfig`] when `reason_ref` is empty
    /// or oversized.
    pub fn mark_killed(
        mut self,
        killed_at: u64,
        reason_ref: impl Into<String>,
    ) -> Result<Self, CalendarConnectorError> {
        let reason_ref = reason_ref.into();
        bounded(
            &reason_ref,
            "kill switch reason ref must be non-empty and bounded",
        )?;
        self.kill_switch = Some(CalendarConnectorKillSwitchState {
            killed_at,
            verbs_revoked: true,
            polling_stopped: true,
            reason_ref,
        });
        Ok(self)
    }

    /// Whether this seat is killed.
    #[must_use]
    pub fn kill_switch_engaged(&self) -> bool {
        self.kill_switch
            .as_ref()
            .is_some_and(|state| state.verbs_revoked && state.polling_stopped)
    }

    /// The verbs this seat advertises — empty once the switch is engaged.
    #[must_use]
    pub fn verb_catalog(&self) -> &'static [&'static str] {
        if self.kill_switch_engaged() {
            &[]
        } else {
            CALENDAR_CONNECTOR_VERB_CATALOG
        }
    }
}

/// One remote calendar object as a provider reported it.
///
/// `uid`, `sequence`, and `content_hash` are the transport's reading. The
/// orchestration re-derives all three from `ics` through
/// [`super::ics::parse_ics_feed`] before it classifies anything, so these
/// fields are a convenience for the wire, never the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCalendarObject {
    /// Provider-side resource path.
    pub href: String,
    /// Provider ETag, when it sent one.
    pub etag: Option<String>,
    /// VEVENT UID as the provider reported it.
    pub uid: String,
    /// VEVENT SEQUENCE as the provider reported it.
    pub sequence: u32,
    /// Content hash as the provider reported it.
    pub content_hash: [u8; 32],
    /// The complete `VCALENDAR` document for this resource.
    pub ics: Vec<u8>,
}

/// One row of a provider's incremental change feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCalendarChange {
    /// The object exists remotely with this content.
    Upsert(RemoteCalendarObject),
    /// The object was removed remotely.
    Delete {
        /// Provider-side resource path.
        href: String,
        /// The VEVENT UID that resource carried.
        uid: String,
    },
}

impl RemoteCalendarChange {
    /// The UID this change concerns.
    #[must_use]
    pub fn uid(&self) -> &str {
        match self {
            Self::Upsert(object) => object.uid.as_str(),
            Self::Delete { uid, .. } => uid.as_str(),
        }
    }

    /// The provider-side resource path this change concerns.
    #[must_use]
    pub fn href(&self) -> &str {
        match self {
            Self::Upsert(object) => object.href.as_str(),
            Self::Delete { href, .. } => href.as_str(),
        }
    }
}

/// One incremental pull: the changes plus the cursor the next pull resumes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSyncBatch {
    /// The cursor to send on the next pull, when the provider issued one.
    pub next_cursor: Option<String>,
    /// The change rows, in provider order.
    pub changes: Vec<RemoteCalendarChange>,
}

/// One conditional remote write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWriteRequest {
    /// The resource to replace; `None` creates one.
    pub href: Option<String>,
    /// The precondition: CalDAV sends it as `If-Match`.
    pub expected_etag: Option<String>,
    /// The UID this write preserves.
    pub uid: String,
    /// The SEQUENCE this write intends.
    pub sequence: u32,
    /// The complete `VCALENDAR` document to store.
    pub ics: Vec<u8>,
}

/// What the provider stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWriteReceipt {
    /// The stored resource path.
    pub href: String,
    /// The stored resource's new ETag, when the provider sent one.
    pub etag: Option<String>,
    /// The UID that was stored.
    pub uid: String,
    /// The SEQUENCE that was stored.
    pub sequence: u32,
    /// The content hash of the stored representation.
    pub content_hash: [u8; 32],
}

/// The provider seam.
///
/// Implementations may use HTTP, WebDAV, and OAuth libraries privately. No
/// library request, response, date, timezone, or token type crosses these
/// signatures, and no method receives a credential — only the custody
/// `secret_ref` the implementation resolves at its own egress door.
pub trait CalendarRemoteTransport {
    /// Stable provider identifier, used for attempt kinds and receipts.
    fn provider_key(&self) -> &'static str;

    /// Pulls the changes after `cursor`.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::Transport`] for provider failures and
    /// [`CalendarConnectorError::CredentialUnavailable`] when custody refuses.
    fn pull(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError>;

    /// Conditionally stores one VEVENT resource.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::EtagMismatch`] when the precondition fails —
    /// never an unconditional retry — plus the transport/custody variants.
    fn upsert(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError>;

    /// Conditionally removes one VEVENT resource.
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::upsert`].
    fn delete(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        href: &str,
        expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError>;
}

/// What a local write intends to do to the remote calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarWriteAction {
    /// Create or replace one resource.
    Upsert,
    /// Remove one resource.
    Delete,
}

impl CalendarWriteAction {
    /// Wire token for this action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
}

/// The four states one durable write-outbox row moves through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarWriteOutboxState {
    /// Staged and durable; the provider has not been called yet.
    Prepared,
    /// The provider accepted the write; the local commit has not landed.
    RemoteApplied,
    /// The precondition failed: resume by reconciling, never by rewriting.
    ReconcileRequired,
    /// The passport and cursor caught up; the row is closed.
    Committed,
}

impl CalendarWriteOutboxState {
    /// Wire token for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::RemoteApplied => "remote_applied",
            Self::ReconcileRequired => "reconcile_required",
            Self::Committed => "committed",
        }
    }
}

/// One durable local write-outbox row.
///
/// Staged under [`CALENDAR_WRITE_OUTBOX_PREFIX`] BEFORE the provider call, so a
/// crash between the remote mutation and the local commit resumes from the row
/// instead of repeating a blind write. Carries refs and hashes only — never a
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarWriteOutboxRow {
    /// Deterministic row id over `(system, calendar_ref, uid, action)`.
    pub outbox_id: [u8; 32],
    /// Where the row is in its lifecycle.
    pub state: CalendarWriteOutboxState,
    /// What the write intends.
    pub action: CalendarWriteAction,
    /// The EVENT this write projects.
    pub event_ref: EntityId,
    /// Provider key of the transport that will run it.
    pub provider: String,
    /// The seat's foreign system identifier.
    pub system: String,
    /// The seat's remote collection.
    pub calendar_ref: String,
    /// The UID the write preserves.
    pub uid: String,
    /// The SEQUENCE the write intends.
    pub sequence: u32,
    /// The content hash the write intends.
    pub content_hash: [u8; 32],
    /// The precondition the write carries.
    pub expected_etag: Option<String>,
    /// The resource the write targets, when one is known.
    pub href: Option<String>,
    /// The provider receipt after the remote mutation has landed.
    pub receipt: Option<RemoteWriteReceipt>,
    /// When the row was first staged.
    pub staged_at: u64,
    /// When the row last moved.
    pub updated_at: u64,
}

/// Node-local href/ETag cursor for one `(system, calendar_ref, uid)`.
///
/// Pulls refresh it; writes read it as their `If-Match` precondition and refresh
/// it from the receipt. It is a lookup accelerator over provider state, never
/// synced truth — the passport claim remains the synced record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarRemoteObjectRow {
    /// The seat's foreign system identifier.
    pub system: String,
    /// The seat's remote collection.
    pub calendar_ref: String,
    /// The VEVENT UID.
    pub uid: String,
    /// Last known resource path.
    pub href: Option<String>,
    /// Last known ETag.
    pub etag: Option<String>,
    /// Last observed SEQUENCE.
    pub last_sequence: u32,
    /// Last observed content hash.
    pub content_hash: [u8; 32],
    /// When the row was last refreshed.
    pub last_seen_at: u64,
}

/// The attempt payload one connector poll carries. Custody NAME only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarConnectorSyncPayload {
    /// The seat this attempt polls.
    pub config: CalendarConnectorSeatConfig,
    /// The provider cursor the run resumes from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// The instant at or after which the host should run this poll.
    pub not_before: u64,
}

/// What one pulled change means against the passport that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoDisposition {
    /// No passport for this `(system, uid)`: import it.
    ApplyInbound,
    /// Same-or-older SEQUENCE with the same content hash: this is our own write
    /// (or a replay) coming back. Acknowledge; rewrite nothing.
    AcknowledgeEcho,
    /// Newer SEQUENCE, or same SEQUENCE with drifted content: apply once.
    ApplyRemoteUpdate,
    /// The provider removed the resource: mark this source absent, once.
    ApplyRemoteDeletion,
}

/// The echo law, as a pure function.
///
/// SEQUENCE-first, exactly like [`super::passport::classify_passport`]: a higher
/// SEQUENCE applies, an equal SEQUENCE with a drifted hash applies, an equal
/// SEQUENCE with the same hash is an echo, and a *lower* SEQUENCE is a stale
/// replay that never regresses passport state. A passport its source previously
/// marked absent re-applies on any re-appearance.
#[must_use]
pub fn classify_remote_change(
    passport: Option<&CalendarPassportValue>,
    change: &RemoteCalendarChange,
) -> EchoDisposition {
    let object = match change {
        RemoteCalendarChange::Delete { .. } => return EchoDisposition::ApplyRemoteDeletion,
        RemoteCalendarChange::Upsert(object) => object,
    };
    let Some(passport) = passport else {
        return EchoDisposition::ApplyInbound;
    };
    if passport.presence == CalendarPassportPresence::Absent
        || object.sequence > passport.last_sequence
        || (object.sequence == passport.last_sequence
            && object.content_hash != passport.content_hash)
    {
        return EchoDisposition::ApplyRemoteUpdate;
    }
    EchoDisposition::AcknowledgeEcho
}

/// Runs one connector sync for `seat`.
///
/// Killed seats short-circuit with [`CalendarSyncOutcome::Killed`]: no transport
/// call, no claim, no re-enqueue. Otherwise the run pulls from the seat cursor,
/// re-parses every upsert through [`super::ics::parse_ics_feed`], classifies it
/// against the live passport, applies semantic changes through the CAL-02
/// Gate-backed imported-evidence door, and re-enqueues one attempt inside the
/// configured jitter window.
///
/// # Errors
///
/// [`CalendarConnectorError`] for seat, transport, parse, timezone, and store
/// failures. A failure applies nothing further and enqueues nothing.
pub fn run_calendar_connector_sync(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    now: u64,
    jitter_seed: u64,
) -> Result<CalendarSyncOutcome, CalendarConnectorError> {
    seat.validate()?;
    if seat.kill_switch_engaged() {
        // No pull, no write, no next attempt — and nothing erased.
        return Ok(CalendarSyncOutcome::Killed);
    }

    let batch = transport.pull(
        &seat.config.secret_ref,
        &seat.config.calendar_ref,
        seat.cursor.as_deref(),
    )?;

    let mut counters = SyncCounters::default();
    for change in &batch.changes {
        apply_remote_change(
            vault,
            seat,
            transport.provider_key(),
            change,
            now,
            &mut counters,
        )?;
    }

    let next_not_before = seat.jittered_next_poll_at(now, jitter_seed)?;
    enqueue_next_sync(
        vault,
        seat,
        transport.provider_key(),
        batch.next_cursor.clone(),
        next_not_before,
        now,
    )?;

    Ok(CalendarSyncOutcome::Reenqueued {
        next_cursor: batch.next_cursor,
        next_not_before,
        applied: counters.applied,
        acknowledged: counters.acknowledged,
        source_absences: counters.source_absences,
        status_cancellations: counters.status_cancellations,
    })
}

/// Writes one local EVENT to the seat's remote calendar.
///
/// The UID is preserved (or minted once for a locally originated EVENT), the
/// SEQUENCE bumps only when this seat already carries a passport for that UID,
/// the durable outbox row is staged BEFORE the provider call, and the expected
/// ETag rides as the conditional precondition. A precondition failure records
/// `reconcile_required`, refreshes the local view of the remote object, and
/// returns [`CalendarConnectorError::EtagMismatch`] — it never overwrites blind.
///
/// # Errors
///
/// [`CalendarConnectorError::KillSwitchEngaged`] on a killed seat, plus the
/// seat, store, parse, and transport variants.
pub fn write_calendar_event(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    now: u64,
) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
    seat.validate()?;
    if seat.kill_switch_engaged() {
        return Err(CalendarConnectorError::KillSwitchEngaged);
    }
    if vault.get_entity_type(&event_ref)? != Some(ENTITY_TYPE_EVENT) {
        return Err(ingest_error("write target is not an EVENT"));
    }

    let system = seat.config.system.as_str();
    let passports = live_passports_for_event(vault, &event_ref)?;
    let own = passports
        .iter()
        .find(|(_, value)| value.system == system)
        .map(|(_, value)| value.clone());
    let uid = match &own {
        Some(value) => value.uid.clone(),
        None => shared_uid(&passports).unwrap_or_else(|| local_uid(&event_ref)),
    };
    let outbox_id = derive_outbox_id(
        system,
        &seat.config.calendar_ref,
        &uid,
        CalendarWriteAction::Upsert,
    );

    if let Some(mut row) = read_outbox_row(vault, &outbox_id)? {
        ensure_outbox_matches(&row, seat, transport, event_ref, &uid)?;
        match row.state {
            CalendarWriteOutboxState::Prepared => {
                let ics = render_owner_vevent(vault, &event_ref, &uid, row.sequence, now)?;
                let rendered_hash = ics_content_hash(&ics, &uid)?;
                if rendered_hash != row.content_hash {
                    return Err(CalendarConnectorError::Outbox {
                        outbox_id,
                        detail: "staged intent no longer matches the local EVENT".to_owned(),
                    });
                }
                let request = RemoteWriteRequest {
                    href: row.href.clone(),
                    expected_etag: row.expected_etag.clone(),
                    uid: uid.clone(),
                    sequence: row.sequence,
                    ics,
                };
                let receipt = issue_prepared_upsert(
                    vault, seat, transport, &uid, now, &mut row, &request,
                )?;
                return finish_remote_applied_write(
                    vault, seat, transport, event_ref, own.as_ref(), &mut row, receipt, now,
                );
            }
            CalendarWriteOutboxState::ReconcileRequired => {
                return Err(reconcile_required_error(
                    vault, seat, transport, &row, &uid, now,
                )?);
            }
            CalendarWriteOutboxState::RemoteApplied => {
                let receipt = row.receipt.clone().ok_or_else(|| {
                    CalendarConnectorError::Outbox {
                        outbox_id,
                        detail: "remote-applied row carries no provider receipt".to_owned(),
                    }
                })?;
                return finish_remote_applied_write(
                    vault, seat, transport, event_ref, own.as_ref(), &mut row, receipt, now,
                );
            }
            CalendarWriteOutboxState::Committed => {
                // A closed row is not an in-flight retry. Derive and stage the
                // next owner mutation below, replacing this stable-key row.
            }
        }
    }

    let sequence = match &own {
        // A UID this seat already tracks: the mutation is an update, so the
        // calendar contract requires the bump.
        Some(value) => value.last_sequence.saturating_add(1),
        // First write of this UID to this seat: carry the highest SEQUENCE any
        // sibling source reported, so a two-provider EVENT stays ordered.
        None => passports
            .iter()
            .filter(|(_, value)| value.uid == uid)
            .map(|(_, value)| value.last_sequence)
            .max()
            .unwrap_or(0),
    };
    let ics = render_owner_vevent(vault, &event_ref, &uid, sequence, now)?;
    let content_hash = ics_content_hash(&ics, &uid)?;
    let object = read_remote_object(vault, system, &seat.config.calendar_ref, &uid)?;
    let expected_etag = object.as_ref().and_then(|row| row.etag.clone());
    let href = object.as_ref().and_then(|row| row.href.clone());
    let mut row = CalendarWriteOutboxRow {
        outbox_id,
        state: CalendarWriteOutboxState::Prepared,
        action: CalendarWriteAction::Upsert,
        event_ref,
        provider: transport.provider_key().to_owned(),
        system: system.to_owned(),
        calendar_ref: seat.config.calendar_ref.clone(),
        uid: uid.clone(),
        sequence,
        content_hash,
        expected_etag: expected_etag.clone(),
        href: href.clone(),
        receipt: None,
        staged_at: now,
        updated_at: now,
    };
    write_outbox_row(vault, &row)?;

    let request = RemoteWriteRequest {
        href,
        expected_etag,
        uid: uid.clone(),
        sequence,
        ics,
    };
    let receipt = issue_prepared_upsert(
        vault, seat, transport, &uid, now, &mut row, &request,
    )?;
    finish_remote_applied_write(
        vault, seat, transport, event_ref, own.as_ref(), &mut row, receipt, now,
    )
}

fn ensure_outbox_matches(
    row: &CalendarWriteOutboxRow,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    uid: &str,
) -> Result<(), CalendarConnectorError> {
    if row.action != CalendarWriteAction::Upsert
        || row.event_ref != event_ref
        || row.provider != transport.provider_key()
        || row.system != seat.config.system
        || row.calendar_ref != seat.config.calendar_ref
        || row.uid != uid
    {
        return Err(CalendarConnectorError::Outbox {
            outbox_id: row.outbox_id,
            detail: "stable outbox key resolves to a different write".to_owned(),
        });
    }
    Ok(())
}

fn issue_prepared_upsert(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    uid: &str,
    now: u64,
    row: &mut CalendarWriteOutboxRow,
    request: &RemoteWriteRequest,
) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
    let receipt = match transport.upsert(
        &seat.config.secret_ref,
        &seat.config.calendar_ref,
        request,
    ) {
        Ok(receipt) => receipt,
        Err(CalendarConnectorError::EtagMismatch {
            href,
            expected,
            actual,
        }) => {
            row.state = CalendarWriteOutboxState::ReconcileRequired;
            row.updated_at = now;
            write_outbox_row(vault, row)?;
            // Reconciliation reads the current remote state so a caller can
            // intentionally rebase. Blind retries remain blocked on this row.
            reconcile_remote_object(vault, seat, transport, uid, now);
            return Err(CalendarConnectorError::EtagMismatch {
                href,
                expected,
                actual,
            });
        }
        // Any other failure leaves the row `prepared`: the retry replays it.
        Err(err) => return Err(err),
    };

    row.state = CalendarWriteOutboxState::RemoteApplied;
    row.href = Some(receipt.href.clone());
    row.receipt = Some(receipt.clone());
    row.updated_at = now;
    write_outbox_row(vault, row)?;
    Ok(receipt)
}

fn reconcile_required_error(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    row: &CalendarWriteOutboxRow,
    uid: &str,
    now: u64,
) -> Result<CalendarConnectorError, CalendarConnectorError> {
    let mut object = read_remote_object(vault, &row.system, &row.calendar_ref, uid)?;
    let still_stale = object
        .as_ref()
        .and_then(|current| current.etag.as_ref())
        == row.expected_etag.as_ref();
    if object.is_none() || still_stale {
        reconcile_remote_object(vault, seat, transport, uid, now);
        object = read_remote_object(vault, &row.system, &row.calendar_ref, uid)?;
    }
    Ok(CalendarConnectorError::EtagMismatch {
        href: row
            .href
            .clone()
            .or_else(|| object.as_ref().and_then(|current| current.href.clone()))
            .unwrap_or_else(|| uid.to_owned()),
        expected: row.expected_etag.clone(),
        actual: object.and_then(|current| current.etag),
    })
}

fn finish_remote_applied_write(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    own: Option<&CalendarPassportValue>,
    row: &mut CalendarWriteOutboxRow,
    receipt: RemoteWriteReceipt,
    now: u64,
) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
    // UID and SEQUENCE are provider-preserved invariants. The receipt hash
    // describes the stored representation and is committed below as ground truth.
    if receipt.uid != row.uid || receipt.sequence != row.sequence {
        return Err(CalendarConnectorError::Outbox {
            outbox_id: row.outbox_id,
            detail: "provider receipt does not match the staged intent".to_owned(),
        });
    }

    write_remote_object(
        vault,
        &CalendarRemoteObjectRow {
            system: row.system.clone(),
            calendar_ref: row.calendar_ref.clone(),
            uid: row.uid.clone(),
            href: Some(receipt.href.clone()),
            etag: receipt.etag.clone(),
            last_sequence: receipt.sequence,
            content_hash: receipt.content_hash,
            last_seen_at: now,
        },
    )?;

    // Direction is a routing fact: a seat that also reads this UID is two-way,
    // a seat that only writes it is outbound. Neither is an approval gate.
    let direction = if own.is_some_and(|value| value.direction.is_inbound_bearing()) {
        CalendarPassportDirection::TwoWay
    } else {
        CalendarPassportDirection::Outbound
    };
    let next = CalendarPassportValue {
        system: row.system.clone(),
        uid: row.uid.clone(),
        last_sequence: receipt.sequence,
        content_hash: receipt.content_hash,
        direction,
        last_seen_at: now,
        presence: CalendarPassportPresence::Live,
    };
    let current = live_passport_for(vault, &event_ref, &row.system, &row.uid)?;
    let already_applied = current.as_ref().is_some_and(|(_, value)| {
        value.last_sequence == next.last_sequence
            && value.content_hash == next.content_hash
            && value.direction == next.direction
            && value.presence == next.presence
    });
    if !already_applied {
        let source_record_id = write_source_record_id(transport.provider_key(), seat, &row.uid);
        let new_id = admit_screened(
            vault,
            event_ref,
            &CalendarInboundBody::default(),
            &source_record_id,
            PREDICATE_CALENDAR_PASSPORT,
            encode_passport_value(&next),
            now,
        )?;
        if current.is_some() {
            supersede_calendar_passport(
                vault,
                event_ref,
                &row.system,
                &row.uid,
                &new_id,
                now,
            )?;
        }
    }
    index_passport_uid(vault, &row.uid, &event_ref)?;

    // The outbox closes before the next poll can run, so the echo the poll sees
    // is already known to be ours.
    row.state = CalendarWriteOutboxState::Committed;
    row.updated_at = now;
    write_outbox_row(vault, row)?;

    Ok(receipt)
}

/// Every durable write-outbox row, in key order.
///
/// # Errors
///
/// [`CalendarConnectorError::Calendar`] on store or row-decode failure.
pub fn calendar_write_outbox_rows(
    vault: &Vault,
) -> Result<Vec<CalendarWriteOutboxRow>, CalendarConnectorError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let mut prefix = CALENDAR_WRITE_OUTBOX_PREFIX.to_vec();
    prefix.extend_from_slice(OUTBOX_ROW_TAG);
    let mut rows = Vec::new();
    for entry in vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
        let (_, raw) = entry?;
        let stored: StoredOutboxRow = serde_json::from_slice(raw.as_ref())
            .map_err(|_| ingest_error("connector outbox row did not decode"))?;
        rows.push(stored.into_row()?);
    }
    Ok(rows)
}

/// One durable write-outbox row by id.
///
/// # Errors
///
/// [`CalendarConnectorError::Calendar`] on store or row-decode failure.
pub fn calendar_write_outbox_row(
    vault: &Vault,
    outbox_id: &[u8; 32],
) -> Result<Option<CalendarWriteOutboxRow>, CalendarConnectorError> {
    read_outbox_row(vault, outbox_id)
}

/// The node-local href/ETag cursor for one `(system, calendar_ref, uid)`.
///
/// # Errors
///
/// [`CalendarConnectorError::Calendar`] on store or row-decode failure.
pub fn calendar_remote_object_row(
    vault: &Vault,
    system: &str,
    calendar_ref: &str,
    uid: &str,
) -> Result<Option<CalendarRemoteObjectRow>, CalendarConnectorError> {
    read_remote_object(vault, system, calendar_ref, uid)
}

/// The attempt kind one provider's poll chain uses.
#[must_use]
pub fn calendar_sync_attempt_kind(provider_key: &str) -> String {
    match provider_key {
        super::caldav::CALDAV_PROVIDER_KEY => CALDAV_SYNC_ATTEMPT_KIND.to_owned(),
        super::google_internal::GOOGLE_INTERNAL_PROVIDER_KEY => {
            GOOGLE_INTERNAL_SYNC_ATTEMPT_KIND.to_owned()
        }
        other => format!("calendar.{other}.sync"),
    }
}

/// Per-run counters folded into [`CalendarSyncOutcome::Reenqueued`].
#[derive(Default)]
struct SyncCounters {
    applied: u32,
    acknowledged: u32,
    source_absences: u32,
    status_cancellations: u32,
}

/// Applies one pulled change under the echo law.
fn apply_remote_change(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    change: &RemoteCalendarChange,
    now: u64,
    counters: &mut SyncCounters,
) -> Result<(), CalendarConnectorError> {
    let system = seat.config.system.as_str();
    match change {
        RemoteCalendarChange::Upsert(object) => {
            // ICS truth, not transport truth: UID/SEQUENCE/hash come from the
            // parse, and every time value crosses the CAL-01 border inside it.
            let parsed = parse_remote_object(object)?;
            let normalized = RemoteCalendarChange::Upsert(RemoteCalendarObject {
                href: object.href.clone(),
                etag: object.etag.clone(),
                uid: parsed.uid.clone(),
                sequence: parsed.sequence,
                content_hash: parsed.content_hash,
                ics: object.ics.clone(),
            });
            let event_ref = resolve_event_by_uid(vault, &parsed.uid)?;
            let current = match event_ref {
                Some(event_ref) => live_passport_for(vault, &event_ref, system, &parsed.uid)?
                    .map(|(_, value)| value),
                None => None,
            };
            match classify_remote_change(current.as_ref(), &normalized) {
                EchoDisposition::AcknowledgeEcho => {
                    // Acknowledgement only: the provider's view of the resource
                    // is refreshed, no semantic claim is rewritten, and nothing
                    // is written back.
                    counters.acknowledged += 1;
                }
                EchoDisposition::ApplyInbound | EchoDisposition::ApplyRemoteUpdate => {
                    apply_inbound_event(vault, seat, provider, event_ref, &parsed, now)?;
                    counters.applied += 1;
                }
                EchoDisposition::ApplyRemoteDeletion => {
                    return Err(ingest_error("an upsert can never classify as a deletion"));
                }
            }
            write_remote_object(
                vault,
                &CalendarRemoteObjectRow {
                    system: system.to_owned(),
                    calendar_ref: seat.config.calendar_ref.clone(),
                    uid: parsed.uid.clone(),
                    href: Some(object.href.clone()),
                    etag: object.etag.clone(),
                    last_sequence: parsed.sequence,
                    content_hash: parsed.content_hash,
                    last_seen_at: now,
                },
            )?;
            Ok(())
        }
        RemoteCalendarChange::Delete { uid, .. } => {
            debug_assert_eq!(
                classify_remote_change(None, change),
                EchoDisposition::ApplyRemoteDeletion
            );
            apply_remote_deletion(vault, seat, provider, uid, now, counters)
        }
    }
}

/// A remote deletion marks exactly one source's passport absent, once.
///
/// Multi-source law, verbatim: feed-absence cancellation applies ONLY when every
/// live inbound passport for the EVENT reports absence; a single-source absence
/// supersedes only that passport, never the EVENT status. The EVENT is never
/// deleted, CAL-07's outcome predicate is never written, and no delete is bounced
/// back to any provider.
fn apply_remote_deletion(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    uid: &str,
    now: u64,
    counters: &mut SyncCounters,
) -> Result<(), CalendarConnectorError> {
    let system = seat.config.system.as_str();
    let Some(event_ref) = resolve_event_by_uid(vault, uid)? else {
        return Ok(());
    };
    let Some((_, current)) = live_passport_for(vault, &event_ref, system, uid)? else {
        return Ok(());
    };
    if current.presence == CalendarPassportPresence::Absent {
        // Applied once: a repeated delete row is idempotent.
        return Ok(());
    }

    let mut absent = current.clone();
    absent.presence = CalendarPassportPresence::Absent;
    absent.last_seen_at = now;
    let source_record_id = pull_source_record_id(provider, seat, uid);
    let new_id = admit_screened(
        vault,
        event_ref,
        &CalendarInboundBody::default(),
        &source_record_id,
        PREDICATE_CALENDAR_PASSPORT,
        encode_passport_value(&absent),
        now,
    )?;
    supersede_calendar_passport(vault, event_ref, system, uid, &new_id, now)?;
    counters.source_absences += 1;

    if all_live_inbound_passports_absent(vault, &event_ref)?
        && admit_status_if_changed(
            vault,
            event_ref,
            &source_record_id,
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedCancel,
            now,
        )?
    {
        counters.status_cancellations += 1;
    }
    Ok(())
}

/// Applies one inbound VEVENT: mint-or-rewrite the EVENT, then admit the
/// `calendar.*` heads through the CAL-02 Gate-backed imported door.
fn apply_inbound_event(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    event_ref: Option<EntityId>,
    parsed: &ParsedVEvent,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    let system = seat.config.system.as_str();
    let source_record_id = pull_source_record_id(provider, seat, &parsed.uid);
    let body = inbound_body(parsed);
    let occurred = parsed_occurred(parsed, now);
    let event_body = encode_event_body(event_display_name(parsed))?;

    let (event_ref, minted) = match event_ref {
        Some(event_ref) => {
            // The update verdict moves the EVENT, not just the passport head.
            vault.put_entity(&event_ref, ENTITY_TYPE_EVENT, occurred, now, &event_body)?;
            (event_ref, false)
        }
        None => {
            let event_ref = EntityId::now();
            vault.put_entity(&event_ref, ENTITY_TYPE_EVENT, occurred, now, &event_body)?;
            index_passport_uid(vault, &parsed.uid, &event_ref)?;
            (event_ref, true)
        }
    };

    if minted {
        admit_screened(
            vault,
            event_ref,
            &body,
            &source_record_id,
            PREDICATE_CALENDAR_ORIGIN,
            rmpv::Value::from(CalendarOrigin::Imported.as_str()),
            now,
        )?;
    }
    admit_time_kind_if_changed(
        vault,
        event_ref,
        &body,
        &source_record_id,
        parsed.busy_transparency,
        now,
    )?;

    let current = live_passport_for(vault, &event_ref, system, &parsed.uid)?;
    let next = CalendarPassportValue {
        system: system.to_owned(),
        uid: parsed.uid.clone(),
        last_sequence: parsed.sequence,
        content_hash: parsed.content_hash,
        // A pulled row preserves the seat's established routing and mints
        // `Inbound` for a source seen for the first time.
        direction: current
            .as_ref()
            .map_or(CalendarPassportDirection::Inbound, |(_, value)| {
                value.direction
            }),
        last_seen_at: now,
        presence: CalendarPassportPresence::Live,
    };
    let new_id = admit_screened(
        vault,
        event_ref,
        &body,
        &source_record_id,
        PREDICATE_CALENDAR_PASSPORT,
        encode_passport_value(&next),
        now,
    )?;
    if current.is_some() {
        supersede_calendar_passport(vault, event_ref, system, &parsed.uid, &new_id, now)?;
    }

    if parsed.cancelled {
        admit_status_if_changed(
            vault,
            event_ref,
            &source_record_id,
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedCancel,
            now,
        )?;
    }
    Ok(())
}

/// Admits `calendar.time_kind` when its value moved, superseding the prior live
/// claim. `busy_transparency` is CAL-02's ingest truth carried through unchanged
/// — the connector invents no second field.
fn admit_time_kind_if_changed(
    vault: &Vault,
    event_ref: EntityId,
    body: &CalendarInboundBody,
    source_record_id: &str,
    transparency: CalendarBusyTransparency,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    let mut prior_live: Option<EntityId> = None;
    for claim_id in vault.claims_for_subject(&event_ref)? {
        let Some(claim) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if claim.predicate != PREDICATE_CALENDAR_TIME_KIND
            || claim.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let current = decode_time_kind_value(&claim.value)
            .map_err(|_| ingest_error("stored time claim did not decode"))?;
        if current.kind == CalendarTimeKind::Absolute
            && current.busy_transparency == transparency
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
            rmpv::Value::from(transparency.as_str()),
        ),
    ]);
    let new_id = admit_screened(
        vault,
        event_ref,
        body,
        source_record_id,
        PREDICATE_CALENDAR_TIME_KIND,
        value,
        now,
    )?;
    if let Some(old_id) = prior_live {
        vault.supersede_claim(&new_id, &old_id, now)?;
    }
    Ok(())
}

/// Admits one `calendar.status` claim, superseding the prior live one. Returns
/// whether a claim was actually written.
fn admit_status_if_changed(
    vault: &Vault,
    event_ref: EntityId,
    source_record_id: &str,
    status: CalendarStatus,
    basis: CalendarStatusBasis,
    now: u64,
) -> Result<bool, CalendarConnectorError> {
    let mut prior_live: Option<EntityId> = None;
    for claim_id in vault.claims_for_subject(&event_ref)? {
        let Some(claim) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if claim.predicate != PREDICATE_CALENDAR_STATUS
            || claim.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let current = decode_status_value(&claim.value)
            .map_err(|_| ingest_error("stored status claim did not decode"))?;
        if current.status == status && current.basis == basis {
            return Ok(false);
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
        (rmpv::Value::from("recorded_at"), rmpv::Value::from(now)),
    ]);
    let new_id = admit_screened(
        vault,
        event_ref,
        &CalendarInboundBody::default(),
        source_record_id,
        PREDICATE_CALENDAR_STATUS,
        value,
        now,
    )?;
    if let Some(old_id) = prior_live {
        vault.supersede_claim(&new_id, &old_id, now)?;
    }
    Ok(true)
}

/// The one admission door for both connectors.
///
/// Every semantic candidate crosses CAL-09's ordering hook and then CAL-02's
/// Gate-backed imported-evidence door — never `put_claim`. The seat surface
/// wires no screener of its own (CAL-09's dial lives on the feed poll runner),
/// so the verdict is `Skipped`, which is explicitly not "assume clear".
fn admit_screened(
    vault: &Vault,
    event_ref: EntityId,
    body: &CalendarInboundBody,
    source_record_id: &str,
    predicate: &str,
    value: rmpv::Value,
    now: u64,
) -> Result<EntityId, CalendarConnectorError> {
    let screened = screen_then_claim(false, None, body, |_request| {
        admit_calendar_import_claim(vault, &event_ref, predicate, value, source_record_id, now)
    })
    .map_err(CalendarError::from)?;
    Ok(screened.value)
}

/// Enqueues the next poll attempt, due inside the configured jitter window.
///
/// Attempt-queue work, not a new recurrence primitive: the generation-scoped
/// dedupe key keeps one chain per seat alive across the executing row and stays
/// idempotent for a redundant run at the same due instant.
fn enqueue_next_sync(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    cursor: Option<String>,
    not_before: u64,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    let payload = serde_json::to_vec(&CalendarConnectorSyncPayload {
        config: seat.config.clone(),
        cursor,
        not_before,
    })
    .map_err(|_| ingest_error("connector sync payload did not encode"))?;
    let dedupe_key = format!("{}:due:{not_before}", seat_identity(provider, &seat.config));
    AttemptQueue::new(vault).enqueue(EnqueueAttempt {
        kind: calendar_sync_attempt_kind(provider),
        payload,
        dedupe_key: Some(dedupe_key),
        run_id: None,
        now,
    })?;
    Ok(())
}

/// Refreshes the local view of one remote object after a precondition failure.
/// Best-effort by design: the mismatch verdict is what the caller must see, and
/// a reconciliation pull that itself fails must not mask it.
fn reconcile_remote_object(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    uid: &str,
    now: u64,
) {
    let Ok(batch) = transport.pull(
        &seat.config.secret_ref,
        &seat.config.calendar_ref,
        seat.cursor.as_deref(),
    ) else {
        return;
    };
    for change in &batch.changes {
        let RemoteCalendarChange::Upsert(object) = change else {
            continue;
        };
        if object.uid != uid {
            continue;
        }
        let Ok(parsed) = parse_remote_object(object) else {
            continue;
        };
        let _ = write_remote_object(
            vault,
            &CalendarRemoteObjectRow {
                system: seat.config.system.clone(),
                calendar_ref: seat.config.calendar_ref.clone(),
                uid: uid.to_owned(),
                href: Some(object.href.clone()),
                etag: object.etag.clone(),
                last_sequence: parsed.sequence,
                content_hash: parsed.content_hash,
                last_seen_at: now,
            },
        );
    }
}

/// Parses one remote resource and returns the VEVENT it carries for `uid`.
fn parse_remote_object(object: &RemoteCalendarObject) -> Result<ParsedVEvent, CalendarError> {
    let feed = parse_ics_feed(&object.ics)?;
    feed.events
        .iter()
        .find(|event| event.uid == object.uid)
        .or_else(|| feed.events.first())
        .cloned()
        .ok_or_else(|| CalendarError::IcsParse {
            reason: "remote calendar object carries no VEVENT".to_owned(),
        })
}

/// The canonical content hash of a rendered VEVENT, read back through the same
/// parser the pull side uses so a local write and its echo hash identically.
fn ics_content_hash(ics: &[u8], uid: &str) -> Result<[u8; 32], CalendarError> {
    let feed = parse_ics_feed(ics)?;
    feed.events
        .iter()
        .find(|event| event.uid == uid)
        .map(|event| event.content_hash)
        .ok_or_else(|| CalendarError::IcsParse {
            reason: "rendered VEVENT did not read back".to_owned(),
        })
}

/// Renders the owner-calendar `VCALENDAR` document for one EVENT.
///
/// Private on purpose: CAL-04 owns the universal invite-out emit half in
/// [`super::ics`]. This is the minimum a conditional own-calendar PUT needs, and
/// every instant it prints crosses [`super::tz::utc_to_wall`] — the module keeps
/// no second date library and no third-party time type.
fn render_owner_vevent(
    vault: &Vault,
    event_ref: &EntityId,
    uid: &str,
    sequence: u32,
    now: u64,
) -> Result<Vec<u8>, CalendarConnectorError> {
    let header = vault
        .read_entity_header(event_ref)?
        .ok_or_else(|| ingest_error("write target EVENT has no header"))?;
    let name = vault
        .get(event_ref)?
        .as_deref()
        .and_then(read_event_name)
        .unwrap_or_else(|| uid.to_owned());

    let mut transparency = CalendarBusyTransparency::Busy;
    let mut cancelled = false;
    for claim_id in vault.claims_for_subject(event_ref)? {
        let Some(claim) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if claim.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        if claim.predicate == PREDICATE_CALENDAR_TIME_KIND
            && let Ok(value) = decode_time_kind_value(&claim.value)
        {
            transparency = value.busy_transparency;
        }
        if claim.predicate == PREDICATE_CALENDAR_STATUS
            && let Ok(value) = decode_status_value(&claim.value)
        {
            cancelled = value.status == CalendarStatus::Cancelled;
        }
    }

    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//calendar//EN\r\nBEGIN:VEVENT\r\n");
    out.push_str(&format!("UID:{}\r\n", escape_ics_text(uid)));
    out.push_str(&format!("DTSTAMP:{}\r\n", format_utc(now)?));
    out.push_str(&format!(
        "DTSTART:{}\r\n",
        format_utc(header.occurred_start)?
    ));
    out.push_str(&format!(
        "DTEND:{}\r\n",
        format_utc(header.occurred_end.max(header.occurred_start))?
    ));
    out.push_str(&format!("SEQUENCE:{sequence}\r\n"));
    out.push_str(&format!("SUMMARY:{}\r\n", escape_ics_text(&name)));
    out.push_str(&format!(
        "TRANSP:{}\r\n",
        match transparency {
            CalendarBusyTransparency::Busy => super::claims::ICS_TRANSP_OPAQUE,
            CalendarBusyTransparency::Free => super::claims::ICS_TRANSP_TRANSPARENT,
        }
    ));
    if cancelled {
        out.push_str("STATUS:CANCELLED\r\n");
    }
    out.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    Ok(out.into_bytes())
}

/// `YYYYMMDDTHHMMSSZ` through the CAL-01 border.
fn format_utc(utc: u64) -> Result<String, CalendarError> {
    let wall = utc_to_wall(utc, "UTC")?;
    Ok(format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        wall.y, wall.mo, wall.d, wall.h, wall.mi, wall.s
    ))
}

/// RFC 5545 TEXT escaping for the fields this module renders.
fn escape_ics_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            _ => out.push(ch),
        }
    }
    out
}

/// The EVENT's stored occurrence from the parsed times.
fn parsed_occurred(parsed: &ParsedVEvent, now: u64) -> TimeRange {
    match (parsed.starts_at_utc, parsed.ends_at_utc) {
        (Some(start), Some(end)) => TimeRange {
            start,
            end: end.max(start),
        },
        (Some(start), None) => TimeRange { start, end: start },
        (None, _) => TimeRange {
            start: now,
            end: now,
        },
    }
}

/// The EVENT's display name: SUMMARY, with a UID fallback.
fn event_display_name(parsed: &ParsedVEvent) -> &str {
    parsed
        .summary
        .as_deref()
        .filter(|summary| !summary.is_empty())
        .unwrap_or(parsed.uid.as_str())
}

/// The CAL-09 screen body for one pulled VEVENT.
fn inbound_body(parsed: &ParsedVEvent) -> CalendarInboundBody {
    CalendarInboundBody {
        description: parsed.description.clone().unwrap_or_default(),
        attachment_text: Vec::new(),
    }
}

/// The EVENT body row: a MessagePack map carrying only the name.
fn encode_event_body(name: &str) -> Result<Vec<u8>, CalendarError> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .map_err(|_| ingest_reason("event body did not encode"))?;
    Ok(body)
}

/// Reads the EVENT body's `name` field, tolerating non-map bodies.
fn read_event_name(body: &[u8]) -> Option<String> {
    let mut cursor = std::io::Cursor::new(body);
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some("name"))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    })
}

/// The UID a sibling source already carries for this EVENT, lexicographically
/// smallest so every node picks the same one.
fn shared_uid(passports: &[(EntityId, CalendarPassportValue)]) -> Option<String> {
    passports
        .iter()
        .map(|(_, value)| value.uid.clone())
        .min()
}

/// The UID a locally originated EVENT gets on its first outbound write.
fn local_uid(event_ref: &EntityId) -> String {
    format!("{}@{LOCAL_UID_DOMAIN}", event_ref.to_hex())
}

/// Provenance ref for a pulled candidate.
fn pull_source_record_id(
    provider: &str,
    seat: &CalendarConnectorSeatState,
    uid: &str,
) -> String {
    format!(
        "calendar-connector:{provider}:{}:{}:{uid}",
        seat.config.system, seat.config.calendar_ref
    )
}

/// Provenance ref for a locally originated write's passport head.
fn write_source_record_id(
    provider: &str,
    seat: &CalendarConnectorSeatState,
    uid: &str,
) -> String {
    format!(
        "calendar-connector-write:{provider}:{}:{}:{uid}",
        seat.config.system, seat.config.calendar_ref
    )
}

/// One seat's injective poll-chain identity. Every segment is length-prefixed so
/// colon-bearing refs can never collide two seats into one chain.
fn seat_identity(provider: &str, config: &CalendarConnectorSeatConfig) -> String {
    let mut out = String::from("calendar-connector:v1");
    for part in [
        provider,
        config.system.as_str(),
        config.calendar_ref.as_str(),
        config.seat_ref.as_str(),
    ] {
        out.push(':');
        out.push_str(&part.len().to_string());
        out.push(':');
        out.push_str(part);
    }
    out
}

/// The deterministic outbox row id: the same intent resumes the same row.
fn derive_outbox_id(
    system: &str,
    calendar_ref: &str,
    uid: &str,
    action: CalendarWriteAction,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OUTBOX_ID_DOMAIN);
    for part in [system, calendar_ref, uid, action.as_str()] {
        hasher.update(part.len().to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// The stored form of a write-outbox row. `EntityId` and `[u8; 32]` travel as
/// byte arrays so the row round-trips without a hex convention of its own.
#[derive(Serialize, Deserialize)]
struct StoredOutboxRow {
    outbox_id: [u8; 32],
    state: CalendarWriteOutboxState,
    action: CalendarWriteAction,
    event_ref: [u8; 16],
    provider: String,
    system: String,
    calendar_ref: String,
    uid: String,
    sequence: u32,
    content_hash: [u8; 32],
    #[serde(default)]
    expected_etag: Option<String>,
    #[serde(default)]
    href: Option<String>,
    #[serde(default)]
    receipt: Option<RemoteWriteReceipt>,
    staged_at: u64,
    updated_at: u64,
}

impl StoredOutboxRow {
    fn from_row(row: &CalendarWriteOutboxRow) -> Self {
        Self {
            outbox_id: row.outbox_id,
            state: row.state,
            action: row.action,
            event_ref: *row.event_ref.as_bytes(),
            provider: row.provider.clone(),
            system: row.system.clone(),
            calendar_ref: row.calendar_ref.clone(),
            uid: row.uid.clone(),
            sequence: row.sequence,
            content_hash: row.content_hash,
            expected_etag: row.expected_etag.clone(),
            href: row.href.clone(),
            receipt: row.receipt.clone(),
            staged_at: row.staged_at,
            updated_at: row.updated_at,
        }
    }

    fn into_row(self) -> Result<CalendarWriteOutboxRow, CalendarConnectorError> {
        Ok(CalendarWriteOutboxRow {
            outbox_id: self.outbox_id,
            state: self.state,
            action: self.action,
            event_ref: EntityId::from_bytes(self.event_ref)
                .map_err(|_| ingest_error("outbox row carries no entity id"))?,
            provider: self.provider,
            system: self.system,
            calendar_ref: self.calendar_ref,
            uid: self.uid,
            sequence: self.sequence,
            content_hash: self.content_hash,
            expected_etag: self.expected_etag,
            href: self.href,
            receipt: self.receipt,
            staged_at: self.staged_at,
            updated_at: self.updated_at,
        })
    }
}

/// The stored form of a remote-object cursor row.
#[derive(Serialize, Deserialize)]
struct StoredRemoteObjectRow {
    system: String,
    calendar_ref: String,
    uid: String,
    #[serde(default)]
    href: Option<String>,
    #[serde(default)]
    etag: Option<String>,
    last_sequence: u32,
    content_hash: [u8; 32],
    last_seen_at: u64,
}

fn outbox_row_key(outbox_id: &[u8; 32]) -> Vec<u8> {
    let mut key = CALENDAR_WRITE_OUTBOX_PREFIX.to_vec();
    key.extend_from_slice(OUTBOX_ROW_TAG);
    key.extend_from_slice(outbox_id);
    key
}

fn remote_object_key(system: &str, calendar_ref: &str, uid: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in [system, calendar_ref, uid] {
        hasher.update(part.len().to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let mut key = CALENDAR_WRITE_OUTBOX_PREFIX.to_vec();
    key.extend_from_slice(REMOTE_OBJECT_TAG);
    key.extend_from_slice(&hasher.finalize());
    key
}

fn read_outbox_row(
    vault: &Vault,
    outbox_id: &[u8; 32],
) -> Result<Option<CalendarWriteOutboxRow>, CalendarConnectorError> {
    let key = outbox_row_key(outbox_id);
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    let stored: StoredOutboxRow = serde_json::from_slice(raw.as_ref())
        .map_err(|_| ingest_error("connector outbox row did not decode"))?;
    Ok(Some(stored.into_row()?))
}

fn write_outbox_row(
    vault: &Vault,
    row: &CalendarWriteOutboxRow,
) -> Result<(), CalendarConnectorError> {
    let encoded = serde_json::to_vec(&StoredOutboxRow::from_row(row)).map_err(|_| {
        CalendarConnectorError::Outbox {
            outbox_id: row.outbox_id,
            detail: "outbox row did not encode".to_owned(),
        }
    })?;
    let key = outbox_row_key(&row.outbox_id);
    vault.try_with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok::<_, crate::Error>(())
    })?;
    Ok(())
}

fn read_remote_object(
    vault: &Vault,
    system: &str,
    calendar_ref: &str,
    uid: &str,
) -> Result<Option<CalendarRemoteObjectRow>, CalendarConnectorError> {
    let key = remote_object_key(system, calendar_ref, uid);
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    let stored: StoredRemoteObjectRow = serde_json::from_slice(raw.as_ref())
        .map_err(|_| ingest_error("connector remote-object row did not decode"))?;
    Ok(Some(CalendarRemoteObjectRow {
        system: stored.system,
        calendar_ref: stored.calendar_ref,
        uid: stored.uid,
        href: stored.href,
        etag: stored.etag,
        last_sequence: stored.last_sequence,
        content_hash: stored.content_hash,
        last_seen_at: stored.last_seen_at,
    }))
}

fn write_remote_object(
    vault: &Vault,
    row: &CalendarRemoteObjectRow,
) -> Result<(), CalendarConnectorError> {
    let encoded = serde_json::to_vec(&StoredRemoteObjectRow {
        system: row.system.clone(),
        calendar_ref: row.calendar_ref.clone(),
        uid: row.uid.clone(),
        href: row.href.clone(),
        etag: row.etag.clone(),
        last_sequence: row.last_sequence,
        content_hash: row.content_hash,
        last_seen_at: row.last_seen_at,
    })
    .map_err(|_| ingest_error("connector remote-object row did not encode"))?;
    let key = remote_object_key(&row.system, &row.calendar_ref, &row.uid);
    vault.try_with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok::<_, crate::Error>(())
    })?;
    Ok(())
}

fn bounded(value: &str, reason: &'static str) -> Result<(), CalendarConnectorError> {
    if value.is_empty() || value.len() > MAX_REF_BYTES || value.chars().any(char::is_control) {
        return Err(CalendarConnectorError::InvalidSeatConfig(reason));
    }
    Ok(())
}

fn ingest_reason(reason: &'static str) -> CalendarError {
    CalendarError::IcsIngest {
        reason: reason.to_owned(),
    }
}

fn ingest_error(reason: &'static str) -> CalendarConnectorError {
    CalendarConnectorError::Calendar(ingest_reason(reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CalendarConnectorSeatConfig {
        CalendarConnectorSeatConfig {
            seat_ref: "seat-1".to_owned(),
            secret_ref: "caldav:work".to_owned(),
            system: "caldav-work".to_owned(),
            calendar_ref: "personal".to_owned(),
            cadence_jitter_min_seconds: 300,
            cadence_jitter_max_seconds: 900,
        }
    }

    fn passport(sequence: u32, hash: [u8; 32]) -> CalendarPassportValue {
        CalendarPassportValue {
            system: "caldav-work".to_owned(),
            uid: "uid-1@example.com".to_owned(),
            last_sequence: sequence,
            content_hash: hash,
            direction: CalendarPassportDirection::TwoWay,
            last_seen_at: 1_800_000_000,
            presence: CalendarPassportPresence::Live,
        }
    }

    fn upsert(sequence: u32, hash: [u8; 32]) -> RemoteCalendarChange {
        RemoteCalendarChange::Upsert(RemoteCalendarObject {
            href: "/cal/uid-1.ics".to_owned(),
            etag: Some("etag-1".to_owned()),
            uid: "uid-1@example.com".to_owned(),
            sequence,
            content_hash: hash,
            ics: Vec::new(),
        })
    }

    #[test]
    fn echo_law_is_sequence_first_then_hash() {
        let live = passport(3, [7_u8; 32]);
        assert_eq!(
            classify_remote_change(None, &upsert(0, [7_u8; 32])),
            EchoDisposition::ApplyInbound
        );
        assert_eq!(
            classify_remote_change(Some(&live), &upsert(3, [7_u8; 32])),
            EchoDisposition::AcknowledgeEcho
        );
        assert_eq!(
            classify_remote_change(Some(&live), &upsert(2, [7_u8; 32])),
            EchoDisposition::AcknowledgeEcho,
            "a stale replay never regresses passport state"
        );
        assert_eq!(
            classify_remote_change(Some(&live), &upsert(3, [9_u8; 32])),
            EchoDisposition::ApplyRemoteUpdate,
            "same-SEQUENCE hash drift applies"
        );
        assert_eq!(
            classify_remote_change(Some(&live), &upsert(4, [7_u8; 32])),
            EchoDisposition::ApplyRemoteUpdate
        );

        let mut absent = passport(3, [7_u8; 32]);
        absent.presence = CalendarPassportPresence::Absent;
        assert_eq!(
            classify_remote_change(Some(&absent), &upsert(3, [7_u8; 32])),
            EchoDisposition::ApplyRemoteUpdate,
            "a source that comes back is applied, not acknowledged"
        );

        assert_eq!(
            classify_remote_change(
                Some(&live),
                &RemoteCalendarChange::Delete {
                    href: "/cal/uid-1.ics".to_owned(),
                    uid: "uid-1@example.com".to_owned(),
                }
            ),
            EchoDisposition::ApplyRemoteDeletion
        );
    }

    #[test]
    fn seat_identity_is_injective_over_colon_bearing_refs() {
        let left = CalendarConnectorSeatConfig {
            system: "a".to_owned(),
            calendar_ref: "b:c".to_owned(),
            ..config()
        };
        let right = CalendarConnectorSeatConfig {
            system: "a:b".to_owned(),
            calendar_ref: "c".to_owned(),
            ..config()
        };
        assert_ne!(
            seat_identity("caldav", &left),
            seat_identity("caldav", &right)
        );
    }

    #[test]
    fn outbox_id_is_deterministic_and_write_scoped() {
        let first = derive_outbox_id("s", "c", "uid", CalendarWriteAction::Upsert);
        assert_eq!(
            first,
            derive_outbox_id("s", "c", "uid", CalendarWriteAction::Upsert)
        );
        assert_ne!(
            first,
            derive_outbox_id("s", "c", "other", CalendarWriteAction::Upsert)
        );
        assert_ne!(
            first,
            derive_outbox_id("s", "c", "uid", CalendarWriteAction::Delete)
        );
    }

    #[test]
    fn rendered_vevent_escapes_text_and_prints_utc_through_the_border() {
        assert_eq!(escape_ics_text("a,b;c\\d"), "a\\,b\\;c\\\\d");
        assert_eq!(
            format_utc(1_786_024_800).expect("in range"),
            "20260806T140000Z"
        );
    }
}
