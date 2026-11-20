//! The mail and calendar pack's Setting keys (owner ruling PACK-SETTINGS-ALL = B) move the
//! drafted reply's recipient ceiling and a Microsoft 365 calendar source's view.
//!
//! Proves the head's contract for `mail_calendar.reply.max_recipients` (default 50) and
//! `mail_calendar.microsoft365_calendar.view_before_secs` / `.view_after_secs` (defaults 31 and
//! 366 days): with no setting row each read behaves as the shipped constants do, once the owner
//! sets a row the next read follows it, a cursor written before the keys existed keeps the
//! shipped span, and values past each key's bounds fail their checks.
//!
//! Reaches the crate-private reads through the test door
//! `oneiron::test_doors::mail_pack_setting_keys`, so it runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test pack_keys_mail`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::mail_pack_setting_keys::{
    graph_calendar_cursor_covers, graph_calendar_opening, reply_recipient_count,
};
use oneiron::{TimeRange, Vault, VaultConfig};
use serde_json::json;

/// Seconds in a day.
const DAY_SECS: u64 = 86_400;
/// The shipped span before a view's opening: 31 days.
const SHIPPED_BEFORE_SECS: u64 = 31 * DAY_SECS;
/// The shipped span after a view's opening: 366 days.
const SHIPPED_AFTER_SECS: u64 = 366 * DAY_SECS;
/// The span an opening's far listing reads past the view's end: four leap years.
const FAR_AFTER_SECS: u64 = 4 * 366 * DAY_SECS;
/// A view's opening, 2025-08-05 13:20:00 UTC.
const OPENED_AT: u64 = 1_754_400_000;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn open_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    Fixture { _dir: dir, vault }
}

/// The vault's owner, authenticated: the proof the setting door revalidates in its write.
fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof")
}

/// The owner sets one vault-scope key; the door must apply it.
fn set_owner_setting(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    key: &str,
    value: serde_json::Value,
) {
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(owner),
            SetSetting::vault_value(key, value),
        )
        .expect("owner sets the key");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's set of {key} applies"
    );
}

/// `count` distinct bare Cc addresses.
fn cc_addresses(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("cc{index}@example.com"))
        .collect()
}

/// Unix seconds as the UTC time a Graph view takes.
fn graph_time(seconds: u64) -> String {
    chrono::DateTime::from_timestamp(i64::try_from(seconds).unwrap(), 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// The first link a view opened at `opened_at` reads over `before` and `after` seconds.
fn view_link(opened_at: u64, before: u64, after: u64) -> String {
    format!(
        "https://graph.microsoft.com/v1.0/me/calendarView/delta?startDateTime={}&endDateTime={}",
        graph_time(opened_at - before),
        graph_time(opened_at + after)
    )
}

/// The span an opening at `opened_at` over `before` and `after` seconds covers.
fn covers(opened_at: u64, before: u64, after: u64) -> TimeRange {
    TimeRange {
        start: opened_at - before,
        end: opened_at + after + FAR_AFTER_SECS,
    }
}

#[test]
fn a_reply_names_at_most_fifty_by_default_and_the_owners_ceiling_once_set() {
    let fixture = open_fixture();
    let vault = &fixture.vault;
    // The sender in To, then the Cc list: 1 + cc recipients.
    assert_eq!(
        reply_recipient_count(vault, &cc_addresses(49)).expect("read"),
        Ok(50),
        "by default a reply names 50 recipients"
    );
    let refused = reply_recipient_count(vault, &cc_addresses(50)).expect("read");
    assert!(
        refused
            .as_ref()
            .is_err_and(|message| message.contains("at most 50 recipients")),
        "by default a 51-recipient reply is refused, never cut: {refused:?}"
    );

    let owner = owner_proof(vault);
    set_owner_setting(
        vault,
        &owner,
        "mail_calendar.reply.max_recipients",
        json!(60),
    );
    assert_eq!(
        reply_recipient_count(vault, &cc_addresses(50)).expect("read"),
        Ok(51),
        "under the owner's ceiling of 60 a 51-recipient reply is drafted"
    );

    set_owner_setting(
        vault,
        &owner,
        "mail_calendar.reply.max_recipients",
        json!(2),
    );
    assert_eq!(
        reply_recipient_count(vault, &cc_addresses(1)).expect("read"),
        Ok(2),
        "under the owner's ceiling of 2 a 2-recipient reply is drafted"
    );
    let refused = reply_recipient_count(vault, &cc_addresses(2)).expect("read");
    assert!(
        refused
            .as_ref()
            .is_err_and(|message| message.contains("at most 2 recipients")),
        "under the owner's ceiling of 2 a 3-recipient reply is refused: {refused:?}"
    );
}

#[test]
fn a_calendar_view_spans_a_month_back_and_a_year_ahead_by_default_and_the_owners_span_once_set() {
    let fixture = open_fixture();
    let vault = &fixture.vault;
    let (link, covered) = graph_calendar_opening(vault, OPENED_AT).expect("default opening");
    assert_eq!(
        link,
        view_link(OPENED_AT, SHIPPED_BEFORE_SECS, SHIPPED_AFTER_SECS),
        "by default the view runs from 31 days before its opening to 366 days after"
    );
    assert_eq!(
        covered,
        covers(OPENED_AT, SHIPPED_BEFORE_SECS, SHIPPED_AFTER_SECS),
        "by default the listing covers the shipped view and its far listing"
    );

    let owner = owner_proof(vault);
    set_owner_setting(
        vault,
        &owner,
        "mail_calendar.microsoft365_calendar.view_before_secs",
        json!(0),
    );
    set_owner_setting(
        vault,
        &owner,
        "mail_calendar.microsoft365_calendar.view_after_secs",
        json!(60 * DAY_SECS),
    );
    let (link, covered) = graph_calendar_opening(vault, OPENED_AT).expect("owner's opening");
    assert_eq!(
        link,
        view_link(OPENED_AT, 0, 60 * DAY_SECS),
        "the next opening reads the owner's span"
    );
    assert_eq!(
        covered,
        covers(OPENED_AT, 0, 60 * DAY_SECS),
        "the next opening's listing covers the owner's span"
    );
}

#[test]
fn a_cursor_written_before_the_keys_keeps_the_shipped_span_and_a_new_one_keeps_its_own() {
    let fixture = open_fixture();
    let vault = &fixture.vault;
    let owner = owner_proof(vault);
    set_owner_setting(
        vault,
        &owner,
        "mail_calendar.microsoft365_calendar.view_after_secs",
        json!(90 * DAY_SECS),
    );
    // A cursor as the wire wrote it before the keys existed: no span of its own.
    let old = json!({
        "opened_at": OPENED_AT,
        "link": "https://graph.microsoft.com/v1.0/me/calendarView/delta?$deltatoken=old",
        "listing": false,
    })
    .to_string();
    assert_eq!(
        graph_calendar_cursor_covers(&old).expect("old cursor decodes"),
        covers(OPENED_AT, SHIPPED_BEFORE_SECS, SHIPPED_AFTER_SECS),
        "a view opened before the keys keeps the shipped span, whatever the owner sets later"
    );
    let own = json!({
        "opened_at": OPENED_AT,
        "link": "https://graph.microsoft.com/v1.0/me/calendarView/delta?$deltatoken=new",
        "listing": false,
        "view_before_secs": 7 * DAY_SECS,
        "view_after_secs": 45 * DAY_SECS,
    })
    .to_string();
    assert_eq!(
        graph_calendar_cursor_covers(&own).expect("new cursor decodes"),
        covers(OPENED_AT, 7 * DAY_SECS, 45 * DAY_SECS),
        "a view keeps the span it opened with until it opens again"
    );
}

#[test]
fn the_owner_cannot_set_an_empty_reply_ceiling_or_a_view_past_its_bounds() {
    let fixture = open_fixture();
    let vault = &fixture.vault;
    let owner = owner_proof(vault);
    for (key, value, why) in [
        (
            "mail_calendar.reply.max_recipients",
            json!(0),
            "a reply names at least one recipient",
        ),
        (
            "mail_calendar.microsoft365_calendar.view_before_secs",
            json!(366 * DAY_SECS + 1),
            "a view starts at most 366 days before its opening",
        ),
        (
            "mail_calendar.microsoft365_calendar.view_after_secs",
            json!(30 * DAY_SECS - 1),
            "a view ends at least the month it stands after its opening",
        ),
        (
            "mail_calendar.microsoft365_calendar.view_after_secs",
            json!(3 * 366 * DAY_SECS + 1),
            "a view ends at most three leap years after its opening",
        ),
    ] {
        let set = vault.set_setting(
            SettingCaller::Owner(&owner),
            SetSetting::vault_value(key, value),
        );
        assert!(
            matches!(set, Err(oneiron::Error::InvalidConfig(_))),
            "{why}: {set:?}"
        );
    }
}
