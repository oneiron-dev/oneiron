//! The two owner settings a LinkedIn seat policy takes from the engine (owner ruling
//! PACK-SETTINGS-ALL = B; RULING PACK-KEYS-LINKEDIN-SWEEPS = A): whether a request its host flags
//! as a sweep may go, and the clock its daily caps reset on when its host names no reset.
//!
//! `cargo test --locked -p oneiron-linkedin-policy --test seat_owner_settings`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron_linkedin_policy::{
    LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB, LINKEDIN_DEFAULT_DAILY_DM_CAP,
    LINKEDIN_SEND_DM_VERB, LinkedInSandboxHostConfig, LinkedInSeatDispatchState,
    LinkedInSeatPolicyAction, LinkedInSeatSandboxPolicy,
};

/// 2025-08-05 13:20:00 UTC.
const NOW: u64 = 1_754_400_000;
/// 2025-08-06 00:00:00 UTC: the next UTC midnight after `NOW`.
const NEXT_UTC_MIDNIGHT: u64 = 1_754_438_400;
/// 2025-08-06 00:00:00 at UTC+09:00 (2025-08-05 15:00:00 UTC).
const NEXT_JST_MIDNIGHT: u64 = 1_754_406_000;
/// 2025-08-06 00:00:00 at UTC-04:00 (2025-08-06 04:00:00 UTC).
const NEXT_EDT_MIDNIGHT: u64 = 1_754_452_800;

fn host() -> LinkedInSandboxHostConfig {
    LinkedInSandboxHostConfig::new(
        "linkedin:seat:yuki",
        "sandbox:tokyo:yuki",
        "browser-profile:linkedin:yuki",
        "vault-secret:linkedin:yuki:session-cookie",
    )
    .expect("host config")
}

fn seat(state: LinkedInSeatDispatchState) -> LinkedInSeatSandboxPolicy {
    LinkedInSeatSandboxPolicy::active(host()).with_state(state)
}

#[test]
fn a_sweep_is_suppressed_unless_the_owner_allows_sweeps_and_the_caps_still_bound_it() {
    let sweep = LinkedInSeatDispatchState::active().as_sweep();
    let shipped = seat(sweep.clone());
    assert!(
        !shipped.sweeps_allowed(),
        "a policy allows no sweep until the engine names it"
    );
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
    let read = shipped.evaluate_profile_read();
    assert_eq!(read.action, LinkedInSeatPolicyAction::Suppress);
    assert_eq!(read.reason_code.as_deref(), Some("linkedin.no_sweeps"));

    let allowed = seat(sweep.clone()).with_sweeps_allowed(true);
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
        seat(sweep.with_dm_sends_today(LINKEDIN_DEFAULT_DAILY_DM_CAP)).with_sweeps_allowed(true);
    let decision = full.evaluate_outbound(LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB, NOW);
    assert_eq!(decision.action, LinkedInSeatPolicyAction::Hold);
    assert_eq!(
        decision.reason_code.as_deref(),
        Some("linkedin.daily_dm_cap"),
        "the daily cap still bounds an allowed sweep"
    );

    let killed = seat(LinkedInSeatDispatchState::active().as_sweep())
        .with_sweeps_allowed(true)
        .mark_killed(NOW, "reason:owner-stop")
        .expect("kill");
    let decision = killed.evaluate_outbound(LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB, NOW);
    assert_eq!(
        decision.reason_code.as_deref(),
        Some("linkedin.kill_switch_engaged"),
        "the kill switch still stops an allowed sweep"
    );

    let plain = seat(LinkedInSeatDispatchState::active()).with_sweeps_allowed(false);
    assert_eq!(
        plain
            .evaluate_outbound(LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB, NOW)
            .action,
        LinkedInSeatPolicyAction::Allow,
        "a request that is no sweep goes either way"
    );
}

#[test]
fn the_caps_reset_at_the_next_midnight_on_the_named_clock_unless_the_host_names_a_reset() {
    let utc = seat(LinkedInSeatDispatchState::active()).with_caps_reset_after(NOW);
    assert_eq!(utc.state.caps_reset_at, Some(NEXT_UTC_MIDNIGHT));
    let utc_on = seat(LinkedInSeatDispatchState::active()).with_caps_reset_after_on(NOW, |_| 0);
    assert_eq!(
        utc_on.state.caps_reset_at,
        Some(NEXT_UTC_MIDNIGHT),
        "the UTC clock is the zero offset"
    );
    let tokyo = seat(LinkedInSeatDispatchState::active()).with_caps_reset_after_on(NOW, |_| 540);
    assert_eq!(tokyo.state.caps_reset_at, Some(NEXT_JST_MIDNIGHT));
    let new_york =
        seat(LinkedInSeatDispatchState::active()).with_caps_reset_after_on(NOW, |_| -240);
    assert_eq!(new_york.state.caps_reset_at, Some(NEXT_EDT_MIDNIGHT));

    // The offset moves from +01:00 to +02:00 between now and the local midnight: the reset is
    // that midnight on the new offset (2025-08-05 22:00:00 UTC).
    let switch_at = 1_754_420_000;
    let moved = seat(LinkedInSeatDispatchState::active())
        .with_caps_reset_after_on(NOW, |at| if at < switch_at { 60 } else { 120 });
    assert_eq!(moved.state.caps_reset_at, Some(1_754_431_200));

    let host_named = seat(LinkedInSeatDispatchState::active().with_caps_reset_at(NOW + 100))
        .with_caps_reset_after_on(NOW, |_| 540);
    assert_eq!(
        host_named.state.caps_reset_at,
        Some(NOW + 100),
        "a reset the host names while it is ahead wins"
    );
    let host_passed = seat(LinkedInSeatDispatchState::active().with_caps_reset_at(NOW - 1))
        .with_caps_reset_after_on(NOW, |_| 540);
    assert_eq!(
        host_passed.state.caps_reset_at,
        Some(NEXT_JST_MIDNIGHT),
        "a reset the host named that has passed gives way to the next midnight"
    );
}
