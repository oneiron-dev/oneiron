//! Restriction wave 6 (owner 16 Nov 00:44: "we apply the optional freedom with good defaults
//! everywhere"): three hard-coded outbound waits become owner Setting keys whose default is
//! today's value.
//!
//! - `connectors.calls.pending_ttl_secs` (census C21): how long a held connector call waits for
//!   someone to allow it before it expires; seven days by default, a minute at the least.
//! - `outbound.grant.window_wait_hold_secs` (census C113): how long a channel-identity action
//!   that met a full envelope window keeps its place once its window opens; 15 minutes by
//!   default, and the window itself still bounds it.
//! - `outbound.dedupe.cooldown_secs` (census C64, RESTRICTION-WAVE-6-CANON-ROWS = A): how long a
//!   send suppresses a send with the same dedupe key; 24 hours by default, one hour at the least.
//!
//! Red on the helper base (main with the Setting primitive #8025/#8259 merged): none of the
//! three keys exists, so the owner's change is refused and each "owner moved it" test fails at
//! its set. The default tests pass there too: the default behaves exactly as today.
//!
//! Reaches the crate-private held-call table and the dedupe check through the test door
//! `oneiron::test_doors::outbound_wait_setting_keys`, so it runs only under
//! `RUSTFLAGS="--cfg oneiron_test_support"`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
    SelfHeldShape,
};
use oneiron::channel_identity_autonomy::{
    ChannelIdentityActionEnvelope, ChannelIdentityAutonomyRequest, ChannelIdentityAutonomyRung,
    ChannelIdentityEffectCandidate, MailboxReadEnvelope,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::outbound_grant::{ChannelIdentityGrantOutcome, ChannelIdentityWindowWait};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::outbound_wait_setting_keys::{
    held_connector_call_settled, put_held_connector_call, resend_blocked_after,
};
use oneiron::{EntityId, RelationshipContext, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const DAY_SECS: u64 = 86_400;
const DAY_MS: u64 = DAY_SECS * 1000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault on a manual clock at `T0`, its embedded owner bound and proved.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner,
        }
    }

    /// The owner's change of the vault-wide `key` to `value`.
    fn owner_sets(&self, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.vault.set_setting(
            SettingCaller::Owner(&self.owner),
            SetSetting {
                key: key.to_owned(),
                item: None,
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value: Some(value),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
    }

    /// The owner's change, which must apply.
    fn owner_moves(&self, key: &str, value: Value) {
        let outcome = self
            .owner_sets(key, value)
            .unwrap_or_else(|error| panic!("the owner's change of `{key}` was refused: {error}"));
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change of `{key}` did not apply: {outcome:?}"
        );
    }
}

// --- connectors.calls.pending_ttl_secs (C21) ---

#[test]
fn a_held_call_waits_the_longer_lifetime_the_owner_chose() {
    let fx = Fixture::rooted();
    let now_ms = T0 * 1000;
    let call = put_held_connector_call(&fx.vault, now_ms - 8 * DAY_MS).expect("held call");
    fx.owner_moves("connectors.calls.pending_ttl_secs", json!(14 * DAY_SECS));

    let expired = fx
        .vault
        .expire_connector_calls(now_ms)
        .expect("expiry pass");
    assert_eq!(
        expired, 0,
        "a call held 8 days ago expired although the owner keeps held calls 14 days"
    );
    assert_eq!(
        held_connector_call_settled(&fx.vault, &call).expect("call row"),
        Some(false),
        "the call held 8 days ago is not still waiting under a 14-day lifetime"
    );

    let expired = fx
        .vault
        .expire_connector_calls(now_ms + 7 * DAY_MS)
        .expect("expiry pass");
    assert_eq!(expired, 1, "the call did not expire once 14 days passed");
    assert_eq!(
        held_connector_call_settled(&fx.vault, &call).expect("call row"),
        Some(true)
    );
}

#[test]
fn a_held_call_expires_after_seven_days_by_default() {
    let fx = Fixture::rooted();
    let now_ms = T0 * 1000;
    let older = put_held_connector_call(&fx.vault, now_ms - 8 * DAY_MS).expect("held call");
    let newer = put_held_connector_call(&fx.vault, now_ms - 6 * DAY_MS).expect("held call");

    let expired = fx
        .vault
        .expire_connector_calls(now_ms)
        .expect("expiry pass");
    assert_eq!(
        expired, 1,
        "the default lifetime is not seven days from the first hold"
    );
    assert_eq!(
        held_connector_call_settled(&fx.vault, &older).expect("call row"),
        Some(true),
        "the call held 8 days ago did not expire by default"
    );
    assert_eq!(
        held_connector_call_settled(&fx.vault, &newer).expect("call row"),
        Some(false),
        "the call held 6 days ago expired by default"
    );
}

#[test]
fn a_held_call_lifetime_below_a_minute_is_refused() {
    let fx = Fixture::rooted();
    assert!(
        fx.owner_sets("connectors.calls.pending_ttl_secs", json!(30))
            .is_err(),
        "a 30-second lifetime was accepted"
    );
}

// --- outbound.grant.window_wait_hold_secs (C113) ---

/// A channel identity whose agent sends `mail.send` on its own inside an envelope of three
/// actions a day, minted by the owner; returns the envelope grant and a candidate maker.
fn envelope_of_three_a_day(
    fx: &Fixture,
) -> (EntityId, impl Fn(u8) -> ChannelIdentityEffectCandidate) {
    let identity_ref = EntityId::now();
    let actor_ref = EntityId::now();
    let identity = ChannelIdentity::requested(
        "email",
        "agent@example.test",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(actor_ref),
        1,
    )
    .step(
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Manual),
        2,
    )
    .expect("bind")
    .step(ChannelIdentityStep::Fulfill, 3)
    .expect("fulfil");
    fx.vault
        .create_channel_identity(&identity_ref, &identity)
        .expect("channel identity");
    let request = ChannelIdentityAutonomyRequest {
        actor_ref,
        relationship_context: RelationshipContext::WorkDeal,
        rung: ChannelIdentityAutonomyRung::AutonomousWithinEnvelope,
        read_envelope: MailboxReadEnvelope {
            identity_ref,
            label_allowlist: vec!["inbox".to_owned()],
            thread_allowlist: vec!["thread:1".to_owned()],
            full_mailbox: false,
            not_before: None,
            not_after: None,
        },
        action_envelope: Some(ChannelIdentityActionEnvelope {
            identity_ref,
            relationship_context: RelationshipContext::WorkDeal,
            counterparty_class: Some("known".to_owned()),
            max_actions: 3,
            window_secs: DAY_SECS,
        }),
    };
    let grant = fx
        .vault
        .apply_channel_identity_autonomy(&request, &fx.owner)
        .expect("autonomy")
        .mode
        .action_grant_ref
        .expect("an action grant");
    let candidate = move |n: u8| ChannelIdentityEffectCandidate {
        identity_ref,
        relationship_context: RelationshipContext::WorkDeal,
        verb_class: "mail.send".to_owned(),
        counterparty_class: Some("known".to_owned()),
        effect_key: [n; 32],
    };
    (grant, candidate)
}

/// Spends the envelope's three slots, then returns the wait the fourth action meets.
fn fourth_action_wait(fx: &Fixture) -> ChannelIdentityWindowWait {
    let (grant, candidate) = envelope_of_three_a_day(fx);
    for n in 1..=3 {
        assert_eq!(
            fx.vault
                .admit_channel_identity_grant(&grant, &candidate(n))
                .expect("admission"),
            ChannelIdentityGrantOutcome::Admitted,
            "FIXTURE: action {n} of three did not take a slot"
        );
    }
    match fx
        .vault
        .admit_channel_identity_grant(&grant, &candidate(4))
        .expect("admission")
    {
        ChannelIdentityGrantOutcome::WindowWait(wait) => wait,
        other => panic!("FIXTURE: the fourth action met {other:?}, not a full window"),
    }
}

#[test]
fn a_retained_action_keeps_its_place_as_long_as_the_owner_chose() {
    let fx = Fixture::rooted();
    fx.owner_moves("outbound.grant.window_wait_hold_secs", json!(3_600));

    let wait = fourth_action_wait(&fx);
    assert_eq!(
        wait.deadline,
        wait.next_eligible_at + 3_600,
        "the fourth action does not keep its place the hour the owner chose"
    );
}

#[test]
fn a_retained_action_keeps_its_place_15_minutes_by_default() {
    let fx = Fixture::rooted();

    let wait = fourth_action_wait(&fx);
    assert_eq!(
        wait.next_eligible_at,
        T0 + DAY_SECS,
        "FIXTURE: the next window does not open a day after the first slot"
    );
    assert_eq!(
        wait.deadline,
        wait.next_eligible_at + 15 * 60,
        "the default place hold is not 15 minutes"
    );
}

// --- outbound.dedupe.cooldown_secs (C64) ---

#[test]
fn a_resend_goes_once_the_owners_shorter_dedupe_window_passed() {
    let fx = Fixture::rooted();
    fx.owner_moves("outbound.dedupe.cooldown_secs", json!(2 * 3_600));

    assert!(
        !resend_blocked_after(&fx.vault, 3 * 3_600).expect("dedupe check"),
        "a re-send 3 hours later is suppressed although the owner's window is 2 hours"
    );
    assert!(
        resend_blocked_after(&fx.vault, 3_600).expect("dedupe check"),
        "a re-send 1 hour later goes although the owner's window is 2 hours"
    );
}

#[test]
fn a_resend_is_suppressed_for_24_hours_by_default() {
    let fx = Fixture::rooted();

    assert!(
        resend_blocked_after(&fx.vault, 23 * 3_600).expect("dedupe check"),
        "a re-send 23 hours later goes by default"
    );
    assert!(
        !resend_blocked_after(&fx.vault, DAY_SECS + 60).expect("dedupe check"),
        "a re-send a day and a minute later is still suppressed by default"
    );
}

#[test]
fn the_dedupe_window_cannot_go_below_an_hour() {
    let fx = Fixture::rooted();
    assert!(
        fx.owner_sets("outbound.dedupe.cooldown_secs", json!(600))
            .is_err(),
        "a 10-minute dedupe window was accepted: the key must never turn the dedupe off"
    );
}
