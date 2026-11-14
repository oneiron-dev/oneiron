//! A mailbox import paced within its provider's per-user quota (MAIL-GOOGLE
//! = A, ARCH-0027 #mail-drive): Gmail gives one user of a new project 6,000
//! quota units a minute, each call costs its own units, and downloads stop
//! at 2,500 MB a day, so a big copy can be byte-bound before it is
//! quota-bound.
//!
//! One step reads its provider through a [`MeteredMailWire`]: each provider
//! request is charged before it is made (a further request inside one call
//! as well, and the credential check a wire makes before its first), and
//! each answer's bytes are counted after, against windows kept on the
//! source, so the host's steps and the owner's own `vault.mail.sources.sync`
//! share them across restarts; one source's steps run one at a time. The change feed
//! may spend the whole minute; the copy (the listing, bodies, attachments)
//! spends at most three quarters of it, so new mail still reads while a big
//! mailbox copies. A call that does not fit ends the step cleanly: what
//! landed stays, no further call is made, and the source rests until its
//! window opens. A provider's rate-limit answer rests it a minute. A wire
//! that declares no quota is never charged.

use std::cell::Cell;

use serde::{Deserialize, Serialize};

use super::rest::{MAX_REST_RESPONSE_BYTES, refused};
use super::wire::{
    MailAddressHeaders, MailAttachmentRef, MailFull, MailHeaders, MailHistoryRead, MailIdPage,
    MailListQuery, MailProviderWire, MailSyncSource,
};
use crate::memory::MemoryResult;
use crate::{Error, Result};

/// What a wire answers for its provider's rate-limit answer (Gmail's 429,
/// or its 403 for a usage limit): the step rests the source a minute and
/// ends without a failure.
pub const MAIL_WIRE_RATE_LIMITED: &str = "mail_wire_rate_limited";

/// What a metered call answers once its source rests: the step reads it as
/// its pause, never as its failure.
const MAIL_WIRE_RESTING: &str = "mail_wire_quota_resting";

/// The minute window's length.
const MINUTE_SECS: u64 = 60;
/// The day window's length.
const DAY_SECS: u64 = 86_400;
/// How long a source rests after its provider's rate-limit answer: the
/// provider's minute refills in it.
const RATE_LIMIT_REST_SECS: u64 = 60;
/// The share of a minute's units the copy may spend, in percent: the rest
/// stays for the change feed (RESEARCH-1393 #backfill plans at 75%, to leave
/// room for live sync and retries).
const COPY_SHARE_PERCENT: u64 = 75;

/// One kind of provider call a mailbox step makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MailCall {
    /// The change anchor (Gmail `users.getProfile`).
    Anchor,
    /// One page of the newest-first listing (Gmail `messages.list`).
    ListPage,
    /// One message's headers (Gmail `messages.get`, metadata).
    Headers,
    /// One message whole (Gmail `messages.get`, full).
    Full,
    /// One page of the change feed (Gmail `history.list`).
    History,
    /// One attachment's bytes (Gmail `messages.attachments.get`).
    Attachment,
    /// The mailbox's own addresses (Gmail `settings.sendAs.list`).
    OwnAddresses,
    /// One message's raw header block (Gmail `messages.get`, raw).
    RawHeaders,
    /// One page of a search (Gmail `messages.list` with `q`).
    Search,
    /// Opening or renewing the mailbox's push channel (Gmail `users.watch`).
    Watch,
    /// Closing it (Gmail `users.stop`).
    StopWatch,
}

/// The quota units each kind of call costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MailCallCosts {
    pub anchor: u32,
    pub list_page: u32,
    pub headers: u32,
    pub full: u32,
    pub history: u32,
    pub attachment: u32,
    pub own_addresses: u32,
    pub raw_headers: u32,
    pub search: u32,
    pub watch: u32,
    pub stop_watch: u32,
}

impl MailCallCosts {
    /// The units `call` costs.
    #[must_use]
    pub const fn of(&self, call: MailCall) -> u32 {
        match call {
            MailCall::Anchor => self.anchor,
            MailCall::ListPage => self.list_page,
            MailCall::Headers => self.headers,
            MailCall::Full => self.full,
            MailCall::History => self.history,
            MailCall::Attachment => self.attachment,
            MailCall::OwnAddresses => self.own_addresses,
            MailCall::RawHeaders => self.raw_headers,
            MailCall::Search => self.search,
            MailCall::Watch => self.watch,
            MailCall::StopWatch => self.stop_watch,
        }
    }
}

/// A provider's limits for one user, and what each call costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailQuota {
    /// The quota units one user may spend in a minute.
    pub units_per_minute: u32,
    /// The bytes one user may download in a day.
    pub bytes_per_day: u64,
    /// The largest answer one call reads: a call runs only while the day
    /// has room for it, so a step never crosses the day's cap.
    pub largest_answer_bytes: u64,
    pub costs: MailCallCosts,
    /// The request a wire makes once, before its first call, to check that
    /// the credential it presents reads the mailbox the source names (Gmail
    /// reads the profile): charged with a step's first call, unless that
    /// call is the same request.
    pub first_call_check: Option<MailCall>,
}

/// Gmail's limits for one user of a new project and its calls' costs, as
/// ARCH-0027 #mail-drive rules them (from RESEARCH-1393 #quotas): 6,000
/// units a minute; a listing page 5, a metadata read 20, a full or raw read
/// 60, a history page 2, an attachment 20, a push channel's watch 100 and
/// its stop 50; 2,500 MB of downloads a day. The profile and the send-as
/// list are Google's 1. A text part Gmail keeps apart is read as an
/// attachment, an attachment that rides inline is read in its whole
/// message, and the credential check reads the profile.
pub const GMAIL_MAIL_QUOTA: MailQuota = MailQuota {
    units_per_minute: 6_000,
    bytes_per_day: 2_500 * 1_000_000,
    largest_answer_bytes: MAX_REST_RESPONSE_BYTES,
    costs: MailCallCosts {
        anchor: 1,
        list_page: 5,
        headers: 20,
        full: 60,
        history: 2,
        attachment: 20,
        own_addresses: 1,
        raw_headers: 60,
        search: 5,
        watch: 100,
        stop_watch: 50,
    },
    first_call_check: Some(MailCall::Anchor),
};

/// Where one source's quota windows stand. Each window opens at its first
/// charge after the last one closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(super) struct MailQuotaWindow {
    /// When the minute window opened, Unix seconds.
    pub(super) minute_start: u64,
    /// The units charged in it.
    pub(super) minute_units: u64,
    /// When the day window opened, Unix seconds.
    pub(super) day_start: u64,
    /// The bytes read in it.
    pub(super) day_bytes: u64,
    /// Until when the source rests: no provider call is made before it.
    #[serde(default)]
    pub(super) resting_until: Option<u64>,
}

impl MailQuotaWindow {
    /// When the source's rest ends, while it still rests at `now`.
    pub(super) fn resting_at(&self, now: u64) -> Option<u64> {
        self.resting_until.filter(|until| *until > now)
    }

    /// Opens a new window for each one closed at `now` (or one a clock set
    /// back left in the future).
    fn roll(&mut self, now: u64) {
        if now < self.minute_start || now >= self.minute_start.saturating_add(MINUTE_SECS) {
            self.minute_start = now;
            self.minute_units = 0;
        }
        if now < self.day_start || now >= self.day_start.saturating_add(DAY_SECS) {
            self.day_start = now;
            self.day_bytes = 0;
        }
    }
}

/// The refusal a metered call answers once its source rests.
fn resting() -> Error {
    refused(MAIL_WIRE_RESTING)
}

/// Whether `error` is a metered call's refusal: the step's pause.
pub(super) fn is_resting(error: &Error) -> bool {
    matches!(error, Error::InvalidConfig(code) if code == MAIL_WIRE_RESTING)
}

/// A step's outcome, a metered call's refusal read as no failure: a step
/// out of quota pauses, and what landed before it stays.
pub(super) fn pause_is_no_failure(outcome: MemoryResult<()>) -> MemoryResult<()> {
    match outcome {
        Err(error) if error.message == resting().to_string() => Ok(()),
        other => other,
    }
}

/// One step's wire, charged within its provider's quota: every provider
/// request is charged before it is made and each call's answer bytes counted
/// after, against the source's windows. Once a request does not fit, or the
/// provider answered that it is rate-limited, the source rests and every
/// later call is refused with no provider call.
pub(super) struct MeteredMailWire<'w> {
    inner: &'w dyn MailProviderWire,
    quota: Option<MailQuota>,
    window: Cell<MailQuotaWindow>,
    /// Whether the change feed reads now: it may spend the whole minute,
    /// the copy only [`COPY_SHARE_PERCENT`] of it.
    live: Cell<bool>,
    /// Whether a call was charged yet, and with it the wire's credential
    /// check ([`MailQuota::first_call_check`]).
    charged: Cell<bool>,
    /// The wire's [`MailProviderWire::bytes_read`] when the day's bytes
    /// were last counted.
    counted: Cell<u64>,
}

impl<'w> MeteredMailWire<'w> {
    pub(super) fn new(inner: &'w dyn MailProviderWire, window: MailQuotaWindow) -> Self {
        Self {
            quota: inner.quota(),
            inner,
            window: Cell::new(window),
            live: Cell::new(true),
            charged: Cell::new(false),
            counted: Cell::new(inner.bytes_read()),
        }
    }

    /// Marks what reads next: the change feed (`true`) or the copy.
    pub(super) fn set_live(&self, live: bool) {
        self.live.set(live);
    }

    /// The source's windows as this step leaves them.
    pub(super) fn window(&self) -> MailQuotaWindow {
        self.window.get()
    }

    /// When the source's rest ends, while it still rests at `now`.
    pub(super) fn resting_until(&self, now: u64) -> Option<u64> {
        self.window.get().resting_at(now)
    }

    /// Rests the source until `until` and answers the refusal.
    fn rest(&self, mut window: MailQuotaWindow, until: u64) -> Error {
        window.resting_until = Some(until);
        self.window.set(window);
        resting()
    }

    /// Adds the bytes the wire read since they were last counted to the
    /// day's.
    fn count_bytes(&self, window: &mut MailQuotaWindow) {
        let read = self.inner.bytes_read();
        window.day_bytes = window
            .day_bytes
            .saturating_add(read.saturating_sub(self.counted.get()));
        self.counted.set(read);
    }

    /// Charges one provider request of kind `call` before it is made: once
    /// it does not fit, the source rests and the request is refused. The
    /// step's first charge carries the wire's credential check, and the
    /// day counts the bytes of any request the call in flight made before.
    fn charge(&self, call: MailCall) -> Result<()> {
        let now = crate::unix_seconds_now();
        let mut window = self.window.get();
        if window.resting_at(now).is_some() {
            return Err(resting());
        }
        self.count_bytes(&mut window);
        window.roll(now);
        if let Some(quota) = &self.quota {
            let minute = u64::from(quota.units_per_minute);
            let ceiling = if self.live.get() {
                minute
            } else {
                minute * COPY_SHARE_PERCENT / 100
            };
            let check = quota
                .first_call_check
                .filter(|check| !self.charged.get() && *check != call)
                .map_or(0, |check| u64::from(quota.costs.of(check)));
            let units = window
                .minute_units
                .saturating_add(u64::from(quota.costs.of(call)))
                .saturating_add(check);
            if units > ceiling {
                return Err(self.rest(window, window.minute_start + MINUTE_SECS));
            }
            if window.day_bytes.saturating_add(quota.largest_answer_bytes) > quota.bytes_per_day {
                return Err(self.rest(window, window.day_start + DAY_SECS));
            }
            window.minute_units = units;
        }
        self.charged.set(true);
        self.window.set(window);
        Ok(())
    }

    /// Charges `call`, then makes it through `read` and counts its bytes.
    fn metered<A>(
        &self,
        call: MailCall,
        read: impl FnOnce(&dyn MailProviderWire) -> Result<A>,
    ) -> Result<A> {
        self.charge(call)?;
        self.settled(read(self.inner))
    }

    /// The answer of a call whose requests were charged: counts their bytes,
    /// and a rate-limit answer rests the source.
    fn settled<A>(&self, answer: Result<A>) -> Result<A> {
        let mut window = self.window.get();
        self.count_bytes(&mut window);
        if matches!(&answer, Err(Error::InvalidConfig(code)) if code == MAIL_WIRE_RATE_LIMITED) {
            let until = crate::unix_seconds_now() + RATE_LIMIT_REST_SECS;
            return Err(self.rest(window, until));
        }
        self.window.set(window);
        answer
    }
}

impl MailProviderWire for MeteredMailWire<'_> {
    fn current_anchor(&self, source: &MailSyncSource) -> Result<String> {
        self.metered(MailCall::Anchor, |wire| wire.current_anchor(source))
    }

    fn list_page(
        &self,
        source: &MailSyncSource,
        query: &MailListQuery,
        page: Option<&str>,
    ) -> Result<MailIdPage> {
        self.metered(MailCall::ListPage, |wire| {
            wire.list_page(source, query, page)
        })
    }

    fn headers(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>> {
        self.metered(MailCall::Headers, |wire| wire.headers(source, provider_id))
    }

    fn full(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>> {
        // A further request the read makes is charged before it is made.
        self.metered(MailCall::Full, |wire| {
            wire.full_charging(source, provider_id, &|call| self.charge(call))
        })
    }

    fn history(
        &self,
        source: &MailSyncSource,
        anchor: &str,
        page: Option<&str>,
    ) -> Result<MailHistoryRead> {
        self.metered(MailCall::History, |wire| wire.history(source, anchor, page))
    }

    fn listed_labels(&self, provider_id: &str) -> Option<Vec<String>> {
        self.inner.listed_labels(provider_id)
    }

    fn raw_address_headers(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
    ) -> Result<Option<MailAddressHeaders>> {
        self.metered(MailCall::RawHeaders, |wire| {
            wire.raw_address_headers(source, provider_id)
        })
    }

    fn own_addresses(&self, source: &MailSyncSource) -> Result<Option<Vec<String>>> {
        self.metered(MailCall::OwnAddresses, |wire| wire.own_addresses(source))
    }

    fn search_page(
        &self,
        source: &MailSyncSource,
        query: &str,
        limit: u32,
        page: Option<&str>,
    ) -> Result<MailIdPage> {
        self.metered(MailCall::Search, |wire| {
            wire.search_page(source, query, limit, page)
        })
    }

    fn search_escapes(&self) -> bool {
        self.inner.search_escapes()
    }

    fn attachment(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
        attachment: &MailAttachmentRef,
    ) -> Result<Option<Vec<u8>>> {
        // Each request the read makes is charged as what it is before it is
        // made: the first is not always the attachment read.
        let answer = self
            .inner
            .attachment_charging(source, provider_id, attachment, &|call| self.charge(call));
        self.settled(answer)
    }

    fn watch(&self, source: &MailSyncSource, topic: &str) -> Result<u64> {
        self.metered(MailCall::Watch, |wire| wire.watch(source, topic))
    }

    fn stop_watch(&self, source: &MailSyncSource) -> Result<()> {
        self.metered(MailCall::StopWatch, |wire| wire.stop_watch(source))
    }

    fn quota(&self) -> Option<MailQuota> {
        self.quota
    }

    fn bytes_read(&self) -> u64 {
        self.inner.bytes_read()
    }
}
