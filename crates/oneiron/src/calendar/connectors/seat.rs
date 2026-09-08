//! Seat configs, cursors, kill switch, error type, and sync verbs.

use serde::{Deserialize, Serialize};

use crate::calendar::CalendarError;

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
            .field(
                "cadence_jitter_min_seconds",
                &self.cadence_jitter_min_seconds,
            )
            .field(
                "cadence_jitter_max_seconds",
                &self.cadence_jitter_max_seconds,
            )
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

/// One seat's injective poll-chain identity. Every segment is length-prefixed so
/// colon-bearing refs can never collide two seats into one chain.
pub(super) fn seat_identity(provider: &str, config: &CalendarConnectorSeatConfig) -> String {
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

fn bounded(value: &str, reason: &'static str) -> Result<(), CalendarConnectorError> {
    if value.is_empty() || value.len() > MAX_REF_BYTES || value.chars().any(char::is_control) {
        return Err(CalendarConnectorError::InvalidSeatConfig(reason));
    }
    Ok(())
}
