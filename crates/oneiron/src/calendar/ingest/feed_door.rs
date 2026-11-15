//! Owner-installed ICS feeds and public observations of completed polls.
use serde::{Deserialize, Serialize};

use super::{
    IcsFeedCursorSnapshot, IcsFeedFetcher, IcsFeedPollConfig, IcsPollRunState,
    IcsPropertyContinuationPayload, consent, enqueue_ics_feed_poll, ics_feed_cursor_snapshot,
};
use crate::calendar::safeguard::{CALENDAR_SAFEGUARD_CONFIG_KEY, CalendarBodyScreener};
use crate::consent::AuthenticatedOwner;
use crate::memory::{KeyValueAddress, Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, Vault};

const FEEDS: SideTable<String, CalendarIcsFeedRegistration, Named> =
    SideTable::new(&side_table::CALENDAR_ICS_FEED_CONFIG);

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarIcsFeedConfigureRequest {
    pub config: IcsFeedPollConfig,
}

#[doc(hidden)]
pub use oneiron_verb_wire::calendar::ingest::feed_door::{
    CalendarIcsFeedRequest, CalendarIcsPollCompletion, CalendarIcsPollResult,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarIcsFeedRegistration {
    pub config: IcsFeedPollConfig,
    pub last_poll: Option<CalendarIcsPollCompletion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarIcsFeedStatus {
    pub config: IcsFeedPollConfig,
    pub cursor: Option<IcsFeedCursorSnapshot>,
    pub last_poll: Option<CalendarIcsPollCompletion>,
    /// The feed's import consent (CAL-02): its first completed poll's review,
    /// or the owner's decision on it.
    pub consent: CalendarIcsFeedConsent,
}

pub use super::consent::CalendarIcsFeedConsent;

/// The owner's decision on an installed feed's first-poll review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CalendarIcsFeedReviewDecision {
    /// The feed's standing consent: the review's claims land Approved, and
    /// so does every later poll's.
    Approve,
    /// The review's claims are declined, and the feed polls no more.
    Decline,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarIcsFeedReviewRequest {
    pub system: String,
    /// The `review_ref` the feed's status showed; a review that moved since
    /// refuses.
    pub review_ref: String,
    pub decision: CalendarIcsFeedReviewDecision,
}

fn check_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<()> {
    if owner.revalidate_in_txn(memory.vault(), txn)? != memory.actor()
        || memory.actor_class() != EdgeActorClass::Human
    {
        return Err(MemoryError::bad_request(
            "ICS feed setup must act as its authenticated owner",
        ));
    }
    Ok(())
}

/// A system names exactly one complete feed: two feeds sharing a system would
/// otherwise cancel each other's absent UIDs. Reconfiguration cannot change it.
/// Installation starts the feed's poll chain, due at once; a chain already
/// pending for the feed is adopted, never forked.
pub fn configure(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarIcsFeedConfigureRequest,
) -> MemoryResult<CalendarIcsFeedRegistration> {
    input
        .config
        .validate()
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let row = memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        let vault = memory.vault();
        if let Some(row) = FEEDS.get(&vault.store, txn, &input.config.system)? {
            if row.config == input.config {
                return Ok(row);
            }
            return Err(MemoryError::bad_request(
                "an installed ICS feed is immutable; use a new system",
            ));
        }
        let row = CalendarIcsFeedRegistration {
            config: input.config.clone(),
            last_poll: None,
        };
        FEEDS.put(&vault.store, txn, &input.config.system, &row)?;
        Ok(row)
    })?;
    let vault = memory.vault();
    // A feed whose import waits on its owner, or was declined, starts no
    // chain: the owner's approval starts it.
    if consent::poll_hold(vault, &row.config)?.is_none() {
        enqueue_ics_feed_poll(vault, row.config.clone(), vault.now_recorded_at())
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    }
    Ok(row)
}

pub fn get(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarIcsFeedRequest,
) -> MemoryResult<Option<CalendarIcsFeedRegistration>> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    check_owner(memory, owner, &txn)?;
    Ok(FEEDS.get(&vault.store, &txn, &input.system)?)
}

pub fn status(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarIcsFeedRequest,
) -> MemoryResult<Option<CalendarIcsFeedStatus>> {
    get(memory, owner, input)?
        .map(|row| {
            let cursor = ics_feed_cursor_snapshot(memory.vault(), &row.config)
                .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            let consent = consent::consent_view(memory.vault(), &row.config)?;
            Ok(CalendarIcsFeedStatus {
                config: row.config,
                cursor,
                last_poll: row.last_poll,
                consent,
            })
        })
        .transpose()
}

/// Rechecked at the actual custody-bound GET, never an alternate principal.
pub fn check_installed_feed(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    config: &IcsFeedPollConfig,
) -> crate::Result<()> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    if FEEDS
        .get(&vault.store, &txn, &config.system)?
        .is_none_or(|row| row.config != *config)
    {
        return Err(crate::Error::InvalidConfig(
            "ICS feed is not installed".into(),
        ));
    }
    Ok(())
}

pub fn observe_poll(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    config: &IcsFeedPollConfig,
    poll_ref: String,
    outcome: IcsPollRunState,
) -> MemoryResult<CalendarIcsPollCompletion> {
    let cursor = ics_feed_cursor_snapshot(memory.vault(), config)
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let result = match outcome {
        IcsPollRunState::Reenqueued { next_not_before } => {
            CalendarIcsPollResult::Reenqueued { next_not_before }
        }
        IcsPollRunState::PausedNeedsInput {
            inbox_exception_ref,
        } => CalendarIcsPollResult::PausedNeedsInput {
            inbox_exception_ref: inbox_exception_ref.to_hex(),
        },
        IcsPollRunState::AwaitingReview { claims } => {
            CalendarIcsPollResult::AwaitingReview { claims }
        }
    };
    memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        let vault = memory.vault();
        let mut row = FEEDS
            .get(&vault.store, txn, &config.system)?
            .ok_or_else(|| MemoryError::not_found("ICS feed is not configured"))?;
        if row.config != *config {
            return Err(MemoryError::bad_request("ICS feed moved during poll"));
        }
        let completion = CalendarIcsPollCompletion {
            poll_ref,
            completed_at: vault.now_recorded_at(),
            result,
            cursor,
        };
        row.last_poll = Some(completion.clone());
        FEEDS.put(&vault.store, txn, &config.system, &row)?;
        Ok(completion)
    })
}

/// The owner's inbound-safeguard dial (CAL-09): the owner's own keyed value
/// at [`CALENDAR_SAFEGUARD_CONFIG_KEY`], its last dotted segment the key and
/// the rest its namespace. Absent, or anything but `true`, is off.
pub fn inbound_safeguard_enabled(memory: &Memory<'_>) -> MemoryResult<bool> {
    let mut segments: Vec<String> = CALENDAR_SAFEGUARD_CONFIG_KEY
        .split('.')
        .map(str::to_owned)
        .collect();
    let key = segments.pop().unwrap_or_default();
    let item = memory.key_value_get(&KeyValueAddress {
        namespace: segments,
        key,
    })?;
    Ok(item.is_some_and(|item| item.value == serde_json::Value::Bool(true)))
}

/// One poll of an installed feed as its owner, recorded on the feed: the
/// owner's safeguard dial decides whether `screener` (or its recorded
/// absence) screens each imported admission, the poll runs through
/// `fetcher`, and the completion lands as the feed's last poll. The manual
/// poll door and the host's queued-poll worker both run this.
///
/// # Errors
/// The owner no longer holds, the feed moved, or the poll failed.
pub fn run_installed_poll(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    fetcher: &dyn IcsFeedFetcher,
    screener: Option<&dyn CalendarBodyScreener>,
    config: &IcsFeedPollConfig,
    poll_ref: String,
) -> MemoryResult<CalendarIcsPollCompletion> {
    let safeguard_enabled = inbound_safeguard_enabled(memory)?;
    let vault = memory.vault();
    // A held feed is not fetched; the poll re-reads the hold under its turn.
    if let Some(hold) = consent::poll_hold(vault, config)? {
        return Err(MemoryError::bad_request(hold));
    }
    let now = vault.now_recorded_at();
    let outcome = super::poll::run_feed_poll(
        vault,
        fetcher,
        screener,
        safeguard_enabled,
        config,
        now,
        now,
        Some(owner),
    )
    .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    observe_poll(memory, owner, config, poll_ref, outcome)
}

/// Whether an installed feed's next poll waits on its owner (CAL-02): its
/// first poll's review is open, or the owner declined it. The host completes
/// such a queued poll unpolled; the owner's approval starts a new chain.
///
/// # Errors
/// The store's.
pub fn poll_waits_on_owner(vault: &Vault, config: &IcsFeedPollConfig) -> crate::Result<bool> {
    Ok(consent::poll_hold(vault, config)?.is_some())
}

/// The owner's one decision on an installed feed's first-poll review
/// (CAL-02-FEED-CONSENT = A): one consent receipt over the exact claim set,
/// every claim still waiting settled the same way in that transaction, and
/// the decision kept as the feed's consent. An approval is the feed's
/// standing consent and starts its poll chain again; a decline ends it.
///
/// # Errors
/// Not the authenticated owner, no installed feed, no open review, a review
/// that moved since `review_ref` was read, or a refused settlement.
pub fn review(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarIcsFeedReviewRequest,
) -> MemoryResult<CalendarIcsFeedConsent> {
    let vault = memory.vault();
    let now = vault.now_recorded_at();
    let approve = input.decision == CalendarIcsFeedReviewDecision::Approve;
    let (config, decided, metrics) = memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        let row = FEEDS
            .get(&vault.store, txn, &input.system)?
            .ok_or_else(|| MemoryError::not_found("ICS feed is not configured"))?;
        let (decided, metrics) = consent::decide_review_in_txn(
            vault,
            txn,
            owner,
            &row.config,
            &input.review_ref,
            approve,
            now,
        )?;
        Ok((row.config, decided, metrics))
    })?;
    consent::record_metrics(vault, metrics);
    if approve {
        enqueue_ics_feed_poll(vault, config, vault.now_recorded_at())
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    }
    Ok(decided)
}

/// One queued property continuation of a feed, run as the owner: the
/// imported claims it admits settle under the installed feed's consent
/// (CAL-02), as the feed's polls settle theirs. A continuation of a system
/// with no installed feed admits as it always has.
///
/// # Errors
/// The owner no longer holds, or the continuation or a settlement failed.
pub fn run_installed_continuation(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    screener: Option<&dyn CalendarBodyScreener>,
    payload: &IcsPropertyContinuationPayload,
) -> MemoryResult<()> {
    let safeguard_enabled = inbound_safeguard_enabled(memory)?;
    let vault = memory.vault();
    let admitted = super::admission::run_ics_property_continuation_admitting(
        vault,
        screener,
        safeguard_enabled,
        payload,
    )
    .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let installed = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        FEEDS.get(&vault.store, &txn, &payload.system)?
    };
    if let Some(row) = installed {
        consent::settle_continuation(
            vault,
            owner,
            &row.config,
            &admitted,
            vault.now_recorded_at(),
        )?;
    }
    Ok(())
}
