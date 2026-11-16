//! The LinkedIn pack's seat Setting keys (owner ruling PACK-SETTINGS-ALL = B; RULING
//! PACK-KEYS-LINKEDIN-SWEEPS = A) move whether a sweep may go and the day a seat's caps reset on.
//!
//! Proves the head's contract for `linkedin.sweeps_allowed` (default false) and
//! `linkedin.seat.cap_day_reset` (default utc_midnight): with no setting row a seat's policy is
//! judged as the base judges it, once the owner sets a row the next evaluation follows it, a
//! host's policy never carries the owner's sweep setting, and values of another shape fail.
//!
//! Reaches the settings as the outbound seat wall and the transport apply them through the test
//! door `oneiron::test_doors::linkedin_seat_settings`, so it runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test pack_keys_linkedin`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::commitment_wake::CommitmentReminderRoute;
use oneiron::consent::AuthenticatedOwner;
use oneiron::linkedin_connector::{
    LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB, LinkedInSandboxHostConfig, LinkedInSeatDispatchState,
    LinkedInSeatPolicyAction, LinkedInSeatSandboxPolicy,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::linkedin_seat_settings::seat_policy_under_settings;
use oneiron::{Vault, VaultConfig};
use serde_json::json;

/// 2025-08-05 13:20:00 UTC.
const NOW: u64 = 1_754_400_000;
/// 2025-08-06 00:00:00 UTC: the next UTC midnight after `NOW`.
const NEXT_UTC_MIDNIGHT: u64 = 1_754_438_400;
/// 2025-08-06 00:00:00 at UTC+09:00 (2025-08-05 15:00:00 UTC).
const NEXT_JST_MIDNIGHT: u64 = 1_754_406_000;
/// 2025-08-06 00:00:00 in New York, on daylight time UTC-04:00 (2025-08-06 04:00:00 UTC).
const NEXT_NEW_YORK_MIDNIGHT: u64 = 1_754_452_800;
/// The shipped daily DM cap.
const DAILY_DM_CAP: u16 = 15;

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

/// The owner's reminder route on a fixed offset, or on an IANA zone.
fn reminder_route(offset_minutes: Option<i16>, zone: Option<&str>) -> CommitmentReminderRoute {
    CommitmentReminderRoute {
        channel: "email".to_owned(),
        verb: "send".to_owned(),
        target: "owner@example.com".to_owned(),
        utc_offset_minutes: offset_minutes,
        iana_timezone: zone.map(str::to_owned),
        voice: None,
    }
}

fn seat(state: LinkedInSeatDispatchState) -> LinkedInSeatSandboxPolicy {
    LinkedInSeatSandboxPolicy::active(
        LinkedInSandboxHostConfig::new(
            "linkedin:seat:yuki",
            "sandbox:tokyo:yuki",
            "browser-profile:linkedin:yuki",
            "vault-secret:linkedin:yuki:session-cookie",
        )
        .expect("host config"),
    )
    .with_state(state)
}

#[test]
fn a_sweep_is_suppressed_by_default_and_goes_under_the_caps_once_the_owner_allows_sweeps() {
    let fixture = open_fixture();
    let vault = &fixture.vault;
    let sweep = LinkedInSeatDispatchState::active().as_sweep();

    let shipped = seat_policy_under_settings(vault, seat(sweep.clone()), NOW).expect("apply");
    assert!(!shipped.sweeps_allowed(), "by default no sweep is allowed");
    let decision = shipped.evaluate_outbound(LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB, NOW);
    assert_eq!(decision.action, LinkedInSeatPolicyAction::Suppress);
    assert_eq!(decision.reason_code.as_deref(), Some("linkedin.no_sweeps"));
    assert_eq!(
        decision
            .receipt_fields
            .get("linkedin_sweeps_allowed")
            .map(String::as_str),
        Some("false")
    );

    let owner = owner_proof(vault);
    set_owner_setting(vault, &owner, "linkedin.sweeps_allowed", json!(true));
    let allowed = seat_policy_under_settings(vault, seat(sweep.clone()), NOW).expect("apply");
    assert!(
        allowed.sweeps_allowed(),
        "the owner's setting reaches the seat"
    );
    let decision = allowed.evaluate_outbound(LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB, NOW);
    assert_eq!(
        decision.action,
        LinkedInSeatPolicyAction::Allow,
        "an allowed sweep goes: {decision:?}"
    );
    assert_eq!(
        decision
            .receipt_fields
            .get("linkedin_sweeps_allowed")
            .map(String::as_str),
        Some("true"),
        "the receipt names the owner's setting"
    );
    assert_eq!(
        allowed.evaluate_profile_read().action,
        LinkedInSeatPolicyAction::Allow
    );

    let full =
        seat_policy_under_settings(vault, seat(sweep.with_dm_sends_today(DAILY_DM_CAP)), NOW)
            .expect("apply");
    let decision = full.evaluate_outbound(LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB, NOW);
    assert_eq!(decision.action, LinkedInSeatPolicyAction::Hold);
    assert_eq!(
        decision.reason_code.as_deref(),
        Some("linkedin.daily_dm_cap"),
        "the daily cap still bounds an allowed sweep"
    );
    assert_eq!(
        decision.not_before,
        Some(NEXT_UTC_MIDNIGHT),
        "the held sweep waits for the cap day's reset"
    );
}

#[test]
fn the_caps_reset_on_the_utc_day_by_default_and_on_the_owners_day_once_set() {
    let fixture = open_fixture();
    let vault = &fixture.vault;
    let reset_at = |vault: &Vault| {
        seat_policy_under_settings(vault, seat(LinkedInSeatDispatchState::active()), NOW)
            .expect("apply")
            .state
            .caps_reset_at
    };
    assert_eq!(
        reset_at(vault),
        Some(NEXT_UTC_MIDNIGHT),
        "by default the caps reset at the next UTC midnight"
    );

    let owner = owner_proof(vault);
    set_owner_setting(
        vault,
        &owner,
        "linkedin.seat.cap_day_reset",
        json!("owner_local_midnight"),
    );
    assert_eq!(
        reset_at(vault),
        Some(NEXT_UTC_MIDNIGHT),
        "with no reminder route the owner's clock is UTC"
    );

    vault
        .set_commitment_reminder_route(&owner, Some(&reminder_route(Some(540), None)))
        .expect("route on +09:00");
    assert_eq!(
        reset_at(vault),
        Some(NEXT_JST_MIDNIGHT),
        "the caps reset at the owner's midnight on the route's offset"
    );

    vault
        .set_commitment_reminder_route(
            &owner,
            Some(&reminder_route(None, Some("America/New_York"))),
        )
        .expect("route in New York");
    assert_eq!(
        reset_at(vault),
        Some(NEXT_NEW_YORK_MIDNIGHT),
        "the caps reset at the owner's midnight in the route's zone"
    );

    let host_named = seat_policy_under_settings(
        vault,
        seat(LinkedInSeatDispatchState::active().with_caps_reset_at(NOW + 100)),
        NOW,
    )
    .expect("apply");
    assert_eq!(
        host_named.state.caps_reset_at,
        Some(NOW + 100),
        "a reset the host names while it is ahead wins over either day"
    );

    set_owner_setting(
        vault,
        &owner,
        "linkedin.seat.cap_day_reset",
        json!("utc_midnight"),
    );
    assert_eq!(
        reset_at(vault),
        Some(NEXT_UTC_MIDNIGHT),
        "back on the UTC day the route's zone no longer counts"
    );
}

#[test]
fn a_hosts_policy_never_carries_the_owners_sweep_setting() {
    let policy = seat(LinkedInSeatDispatchState::active().as_sweep()).with_sweeps_allowed(true);
    let mut encoded = serde_json::to_value(&policy).expect("encode");
    assert!(
        encoded.get("sweeps_allowed").is_none(),
        "the owner's sweep setting is never encoded: a policy's bytes stay as the base wrote them"
    );
    encoded["sweeps_allowed"] = json!(true);
    let decoded: LinkedInSeatSandboxPolicy = serde_json::from_value(encoded).expect("decode");
    assert!(
        !decoded.sweeps_allowed(),
        "a policy a host sends allows no sweep until the engine names the owner's setting"
    );
}

#[test]
fn the_owner_cannot_set_a_cap_day_or_a_sweep_switch_of_another_shape() {
    let fixture = open_fixture();
    let vault = &fixture.vault;
    let owner = owner_proof(vault);
    for (key, value) in [
        ("linkedin.seat.cap_day_reset", json!("owner_midnight")),
        ("linkedin.sweeps_allowed", json!("yes")),
    ] {
        let set = vault.set_setting(
            SettingCaller::Owner(&owner),
            SetSetting::vault_value(key, value),
        );
        assert!(
            matches!(set, Err(oneiron::Error::InvalidConfig(_))),
            "{key} refuses a value of another shape: {set:?}"
        );
    }
}
