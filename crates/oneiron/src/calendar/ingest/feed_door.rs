//! Owner-installed ICS feeds and public observations of completed polls. A feed's
//! configuration is the `calendar.ics_feed` setting, one item per system; this module keeps
//! each feed's last completed poll.
use serde::{Deserialize, Serialize};

use super::poll::enqueue_ics_feed_poll_in_txn;
use super::{
    IcsFeedCursorSnapshot, IcsFeedFetcher, IcsFeedPollConfig, IcsPollRunState,
    ics_feed_cursor_snapshot, run_ics_feed_poll_with_screener,
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
/// pending for the feed is adopted, never forked.
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
    enqueue_ics_feed_poll_in_txn(vault, txn, &config, change.at)?;
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
            Ok(CalendarIcsFeedStatus {
                config: row.config,
                cursor,
                last_poll: row.last_poll,
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
    let now = vault.now_recorded_at();
    let outcome = run_ics_feed_poll_with_screener(
        vault,
        fetcher,
        screener,
        safeguard_enabled,
        config,
        now,
        now,
    )
    .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    observe_poll(memory, owner, config, poll_ref, outcome)
}
