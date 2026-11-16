//! Owner-installed ICS feeds and public observations of completed polls. A feed's
//! configuration is the `calendar.ics_feed` setting, one item per system; this module keeps
//! each feed's last completed poll.
use serde::{Deserialize, Serialize};

use super::poll::enqueue_ics_feed_poll_in_txn;
use super::{
    IcsFeedCursorSnapshot, IcsFeedFetcher, IcsFeedPollConfig, IcsPollRunState,
    IcsPropertyContinuationPayload, consent, enqueue_ics_feed_poll, ics_feed_cursor_snapshot,
};
use crate::calendar::safeguard::{CALENDAR_SAFEGUARD_CONFIG_KEY, CalendarBodyScreener};
use crate::calendar::setting_keys::ICS_FEED;
use crate::consent::AuthenticatedOwner;
use crate::memory::{KeyValueAddress, Memory, MemoryError, MemoryResult};
use crate::setting::{Kind, SettingChange, SettingMode};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, Vault};
use oneiron_verb_wire::calendar::ingest::poll::MAX_SYSTEM_BYTES;

/// Each feed's last completed poll, by system. The configuration is the setting's.
const POLLS: SideTable<String, CalendarIcsPollCompletion, Named> =
    SideTable::new(&side_table::CALENDAR_ICS_FEED_POLL);

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

/// The systems `calendar.ics_feed` admits as items: the names a feed config itself admits.
pub(crate) fn is_feed_system(item: &str) -> bool {
    !item.is_empty() && item.len() <= MAX_SYSTEM_BYTES && !item.chars().any(char::is_control)
}

/// The installed feed of `system` with its last completed poll, or none when no feed is
/// installed there (or its configuration row does not read).
pub(crate) fn registration_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    system: &str,
) -> crate::Result<Option<CalendarIcsFeedRegistration>> {
    if !is_feed_system(system) {
        return Ok(None);
    }
    let Some(config) = ICS_FEED.read_in_txn(vault, txn, &[], Some(system))?.value else {
        return Ok(None);
    };
    let last_poll = POLLS.get(&vault.store, txn, &config.system)?;
    Ok(Some(CalendarIcsFeedRegistration { config, last_poll }))
}

/// The `calendar.ics_feed` hook, in the write that changes a feed's row. It keeps the rules the
/// configure door had: a system names exactly one complete feed (two feeds sharing a system
/// would otherwise cancel each other's absent UIDs), so a value row sits at its own system,
/// once; an installed feed is immutable (a change or a clear is refused; a new configuration
/// takes a new system), and a system an earlier feed polled under is never installed again.
/// Installing a feed starts its poll chain, due at once, in the same write; a chain already
/// pending for the feed is adopted, never forked. A feed whose import waits on its owner, or
/// was declined (CAL-02), starts no chain: the owner's approval starts it.
///
/// # Errors
///
/// `InvalidConfig` for a pin, a row with no system, a value naming another system, a change to
/// an installed feed, or a system used before; storage errors.
pub(crate) fn ics_feed_changed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> crate::Result<()> {
    if change.mode != SettingMode::Value {
        return Err(crate::Error::InvalidConfig(
            "an ICS feed takes no pin".into(),
        ));
    }
    let Some(system) = change.item.as_deref() else {
        return Err(crate::Error::InvalidConfig(
            "calendar.ics_feed is set per feed: name the system as the item".into(),
        ));
    };
    let decode = |value: Option<&crate::setting::EncodedValue>| {
        value
            .and_then(Kind::<Option<IcsFeedPollConfig>>::decode)
            .flatten()
    };
    if decode(change.prior.as_ref()).is_some() {
        return Err(crate::Error::InvalidConfig(
            "an installed ICS feed is immutable; use a new system".into(),
        ));
    }
    let config = decode(change.value.as_ref());
    let Some(config) = config else {
        return Ok(());
    };
    if config.system != system {
        return Err(crate::Error::InvalidConfig(
            "the feed's system must be the setting's item".into(),
        ));
    }
    if POLLS.contains(&vault.store, &*txn, &config.system)? {
        return Err(crate::Error::InvalidConfig(
            "this system named an earlier feed; use a new system".into(),
        ));
    }
    if consent::poll_hold_in_txn(vault, txn, &config)?.is_none() {
        enqueue_ics_feed_poll_in_txn(vault, txn, &config, change.at)?;
    }
    Ok(())
}

pub fn get(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarIcsFeedRequest,
) -> MemoryResult<Option<CalendarIcsFeedRegistration>> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    check_owner(memory, owner, &txn)?;
    Ok(registration_in_txn(vault, &txn, &input.system)?)
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
    if registration_in_txn(vault, &txn, &config.system)?.is_none_or(|row| row.config != *config) {
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
        let row = registration_in_txn(vault, txn, &config.system)?
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
        POLLS.put(&vault.store, txn, &config.system, &completion)?;
        Ok(completion)
    })
}

/// The owner's inbound-safeguard dial (CAL-09): the owner's own keyed value
/// at [`CALENDAR_SAFEGUARD_CONFIG_KEY`], its last dotted segment the key and
/// the rest its namespace. A keyed value is a JSON object, so the dial is on
/// when that object's field named by the key is `true` (`{"enabled": true}`).
/// Absent, or anything else, is off.
pub fn inbound_safeguard_enabled(memory: &Memory<'_>) -> MemoryResult<bool> {
    let mut segments: Vec<String> = CALENDAR_SAFEGUARD_CONFIG_KEY
        .split('.')
        .map(str::to_owned)
        .collect();
    let key = segments.pop().unwrap_or_default();
    let item = memory.key_value_get(&KeyValueAddress {
        namespace: segments,
        key: key.clone(),
    })?;
    Ok(item.is_some_and(|item| item.value.get(&key) == Some(&serde_json::Value::Bool(true))))
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
        let row = registration_in_txn(vault, txn, &input.system)?
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
/// with no installed feed, or of another source's admission under the
/// feed's system (a CalDAV connector's pull), admits as it always has.
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
        registration_in_txn(vault, &txn, &payload.system)?
    };
    let Some(row) = installed else {
        return Ok(());
    };
    if !continues_feed_poll(&row.config, payload)? {
        return Ok(());
    }
    consent::settle_continuation(
        vault,
        owner,
        &row.config,
        &admitted,
        vault.now_recorded_at(),
    )?;
    Ok(())
}

/// Whether `payload` continues one of `config`'s own polls: it reads a
/// version of the feed's own archive, and its claims cite that archive. A
/// connector admission under the same system reads its pulled resource and
/// cites its pull record, so the feed's consent never settles its claims.
fn continues_feed_poll(
    config: &IcsFeedPollConfig,
    payload: &IcsPropertyContinuationPayload,
) -> MemoryResult<bool> {
    let archive = super::fetch::ics_feed_archive(config)
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let prefix = format!("{}#v", archive.to_hex());
    let names_archive = |reference: &str| {
        reference
            .strip_prefix(prefix.as_str())
            .is_some_and(|version| version.parse::<u64>().is_ok())
    };
    Ok(names_archive(&payload.blob_ref) && names_archive(&payload.source_version))
}
