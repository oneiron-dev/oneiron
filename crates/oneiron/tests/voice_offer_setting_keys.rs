//! Restriction wave 5 (owner 16 Nov 00:44: "we apply the optional freedom with good defaults
//! everywhere"): three fixed voice limits become owner Setting keys whose default is today's value.
//! - `genui.voice.offer_lifetime_secs` (600): how long a voice grant offer may be confirmed;
//! - `voice.session.identity_ask_secs` (86400): how long a room speaker's "who is this?" ask
//!   stays open;
//! - `voice.session.room_candidates_max` (32): how many of the room's contacts that ask offers.
//!
//! Each key moved lets the formerly refused act stand; each default behaves as before.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test voice_offer_setting_keys`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::{
    AudienceBound, AuthenticatedOwner, DisclosureClass, DisclosureEnvelope, GrantBound,
};
use oneiron::genui::ConsentSurface;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::voice_cascade::VoiceContainerBinding;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const OFFER_LIFETIME: &str = "genui.voice.offer_lifetime_secs";
const IDENTITY_ASK: &str = "voice.session.identity_ask_secs";
const ROOM_CANDIDATES: &str = "voice.session.room_candidates_max";

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned, on a
    /// clock the test moves.
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
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        Self {
            vault,
            clock,
            _dir: dir,
            owner,
        }
    }

    /// The owner's proof as of now: its principal is the owner's own id.
    fn owner_proof(&self) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("owner proof")
    }

    /// The owner sets `key` vault-wide to `value`; the change applies at once.
    fn owner_sets(&self, key: &str, value: Value) {
        let proof = self.owner_proof();
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&proof),
                SetSetting::vault_value(key, value),
            )
            .unwrap_or_else(|error| panic!("the owner sets {key}: {error:?}"));
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change of {key} applies at once: {outcome:?}"
        );
    }

    /// A voice offer of `bound`, minted now for the owner, with no roster behind it (an offer the
    /// host displays unverified).
    fn offer(&self, bound: &GrantBound) -> String {
        self.vault
            .offer_voice_disclosure_grant(
                self.owner,
                &self.owner.to_hex(),
                "call-wave-5",
                "segment-1",
                bound,
            )
            .expect("voice offer")
            .grant_offer_nonce
    }

    /// The owner confirms the offer `nonce` from the dashboard, a device surface, now.
    fn confirm(&self, nonce: &str, bound: &GrantBound) -> oneiron::Result<()> {
        let proof = self.owner_proof();
        self.vault
            .confirm_voice_grant_offer(&proof, nonce, bound.clone(), ConsentSurface::Dashboard)
            .map(drop)
    }
}

fn bound() -> GrantBound {
    GrantBound::disclosure(
        AudienceBound::singleton("contact:friend").expect("audience"),
        DisclosureClass::new("private").expect("class"),
        DisclosureEnvelope::new(["named-set:friends".to_owned()]).expect("envelope"),
    )
    .expect("bound")
}

/// `n` distinct contacts, in order.
fn contacts(fx: &Fixture, n: usize) -> Vec<EntityId> {
    (0..n)
        .map(|_| fx.vault.new_entity_id().expect("contact id"))
        .collect()
}

#[test]
fn a_voice_offer_the_owner_gave_an_hour_is_still_confirmable_after_ten_minutes() {
    let fx = Fixture::rooted();
    fx.owner_sets(OFFER_LIFETIME, json!(3600));
    let bound = bound();
    let nonce = fx.offer(&bound);

    fx.clock.set(T0 + 700);
    fx.confirm(&nonce, &bound)
        .expect("an offer the owner gave an hour stands at 700 s");
}

#[test]
fn a_voice_offer_by_default_dies_ten_minutes_after_it_is_minted() {
    let fx = Fixture::rooted();
    let bound = bound();
    let late = fx.offer(&bound);
    let in_time = fx.offer(&bound);

    fx.clock.set(T0 + 599);
    fx.confirm(&in_time, &bound)
        .expect("a default offer stands until its tenth minute");
    fx.clock.set(T0 + 601);
    assert!(
        fx.confirm(&late, &bound).is_err(),
        "a default offer is gone after ten minutes"
    );
}

#[test]
fn a_room_offers_every_contact_up_to_the_owners_candidate_count() {
    let fx = Fixture::rooted();
    fx.owner_sets(ROOM_CANDIDATES, json!(40));
    let room = fx.vault.new_entity_id().expect("room id");
    let contacts = contacts(&fx, 45);

    let binding = VoiceContainerBinding::for_room(&fx.vault, room, fx.owner, contacts.clone())
        .expect("room binding");
    assert_eq!(
        binding.candidates,
        contacts[..40],
        "the first 40 contacts, in order"
    );
}

#[test]
fn a_who_is_this_ask_stays_open_as_long_as_the_owner_set() {
    let fx = Fixture::rooted();
    fx.owner_sets(IDENTITY_ASK, json!(172_800));
    let room = fx.vault.new_entity_id().expect("room id");

    let binding =
        VoiceContainerBinding::for_room(&fx.vault, room, fx.owner, Vec::new()).expect("binding");
    assert_eq!(binding.ask_seconds, 172_800);
}

#[test]
fn a_room_binding_by_default_offers_32_distinct_contacts_and_a_day_long_ask() {
    let fx = Fixture::rooted();
    let room = fx.vault.new_entity_id().expect("room id");
    let distinct = contacts(&fx, 40);
    let mut offered = vec![distinct[0]];
    offered.extend(distinct.iter().copied());

    let binding =
        VoiceContainerBinding::for_room(&fx.vault, room, fx.owner, offered).expect("room binding");
    assert_eq!(binding.container, room);
    assert_eq!(binding.writer, fx.owner);
    assert_eq!(
        binding.candidates,
        distinct[..32],
        "a repeated contact counts once, and 32 are offered"
    );
    assert_eq!(binding.ask_seconds, 24 * 60 * 60);
}
