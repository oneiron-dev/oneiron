//! DESIGN 15-setting-primitive, stage 4, lane SETTING-KEYED-A, PR K3a: two mixed calendar rows
//! split into a setting (the owner's choice) and a state table (what the engine wrote).
//! - `calendar.connector_seat` (the setup half of `CALENDAR_CONNECTOR_SEAT`), one item per seat
//!   ref: the owner installs a CalDAV seat with `vault.settings.set`; `calendar.connector.get`
//!   returns it joined with its cursor, kill switch and last sync; the kill switch stays a
//!   revocation the setting cannot undo; an installed seat is immutable, as the configure door
//!   made it.
//! - `calendar.ics_feed` (the configuration half of `CALENDAR_ICS_FEED_CONFIG`), one item per
//!   system: installing a feed starts its poll chain in the same write; the installed-feed check
//!   reads the setting; an installed feed is immutable.
//! - an agent's install waits on a check-in, and starts nothing.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_keyed_a_3`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::attempt_queue::EnqueueOutcome;
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::calendar::connectors::door::{
    CalendarConnectorKillRequest, CalendarConnectorRequest, check_installed_connector, get as seat,
    kill,
};
use oneiron::calendar::ingest::feed_door::{
    CalendarIcsFeedRequest, check_installed_feed, get as installed_feed,
};
use oneiron::calendar::{IcsFeedPollConfig, enqueue_ics_feed_poll};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const T0: u64 = 1_790_000_000;

const SEAT: &str = "calendar.connector_seat";
const FEED: &str = "calendar.ics_feed";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
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
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// An enabled, active agent the owner creates, with the owner's live Grant naming the
    /// setting verbs.
    fn granted_agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("keyed-a-calendar-agent-{}", id.to_hex()),
                    "desc": "setting keyed-a fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            ["read", GET, SET]
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent: id,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the Grant");
        assert!(minted.grant.confers, "the Grant confers");
        id
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> String {
    format!(
        "{:?}",
        invoke(memory, verb, input).expect_err("the call is refused")
    )
}

fn set(key: &str, item: &str, value: Value) -> Value {
    json!({ "key": key, "item": item, "scope": { "kind": "vault" }, "value": value })
}

fn get(memory: &Memory<'_>, key: &str, item: &str) -> Value {
    call(memory, GET, json!({ "key": key, "item": item }))
}

fn seat_config(calendar_ref: &str) -> Value {
    json!({
        "seat_ref": "work",
        "secret_ref": "caldav-work",
        "system": "caldav-work",
        "calendar_ref": calendar_ref,
        "cadence_jitter_min_seconds": 300,
        "cadence_jitter_max_seconds": 900,
    })
}

fn seat_setup(calendar_ref: &str) -> Value {
    json!({ "config": seat_config(calendar_ref), "endpoint": "https://dav.example.test/" })
}

fn feed(system: &str) -> Value {
    json!({
        "secret_ref": "ics-feed:work",
        "system": system,
        "cadence_min_seconds": 600,
        "cadence_max_seconds": 1200,
    })
}

fn feed_config(system: &str) -> IcsFeedPollConfig {
    serde_json::from_value(feed(system)).expect("a feed config")
}

#[test]
fn a_calendar_seat_is_a_setting_joined_with_its_sync_state() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let work = CalendarConnectorRequest {
        seat_ref: "work".to_owned(),
    };

    assert_eq!(get(&me, SEAT, "work")["value"], Value::Null);
    assert!(
        seat(&me, &fx.owner_proof, &work)
            .expect("seat read")
            .is_none()
    );

    let applied = call(&me, SET, set(SEAT, "work", seat_setup("Personal")));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(get(&me, SEAT, "work")["value"], seat_setup("Personal"));
    let row = seat(&me, &fx.owner_proof, &work)
        .expect("seat read")
        .expect("the installed seat");
    assert_eq!(row.endpoint, "https://dav.example.test/");
    assert_eq!(row.seat.config.calendar_ref, "Personal");
    assert_eq!(row.seat.cursor, None);
    assert!(row.seat.kill_switch.is_none());
    assert!(row.last_sync.is_none());
    check_installed_connector(&fx.vault, &fx.owner_proof, &row).expect("the seat is installed");

    let again = call(&me, SET, set(SEAT, "work", seat_setup("Personal")));
    assert_eq!(
        again["status"],
        json!("applied"),
        "an identical setup is idempotent: {again}"
    );
    let moved = refused(&me, SET, set(SEAT, "work", seat_setup("Shared")));
    assert!(moved.contains("immutable"), "{moved}");
    let cleared = refused(&me, SET, set(SEAT, "work", Value::Null));
    assert!(cleared.contains("immutable"), "{cleared}");
    let other_item = refused(&me, SET, set(SEAT, "home", seat_setup("Personal")));
    assert!(other_item.contains("seat_ref"), "{other_item}");
    let no_item = refused(
        &me,
        SET,
        json!({ "key": SEAT, "scope": { "kind": "vault" }, "value": seat_setup("Personal") }),
    );
    assert!(no_item.contains("item"), "{no_item}");
    let mut plain_http = seat_setup("Personal");
    plain_http["endpoint"] = json!("http://dav.example.test/");
    let plain_http = refused(&me, SET, set(SEAT, "work", plain_http));
    assert!(plain_http.contains("HTTPS"), "{plain_http}");

    let killed = kill(
        &me,
        &fx.owner_proof,
        &CalendarConnectorKillRequest {
            seat_ref: "work".to_owned(),
            reason_ref: "owner-stop".to_owned(),
        },
    )
    .expect("the owner kills the seat");
    assert!(killed.seat.kill_switch_engaged());
    assert!(
        check_installed_connector(&fx.vault, &fx.owner_proof, &row).is_err(),
        "the seat as it was before the kill no longer holds"
    );
    assert_eq!(
        seat(&me, &fx.owner_proof, &work).expect("seat read"),
        Some(killed.clone()),
        "the kill switch is stored beside the setup"
    );
    call(&me, SET, set(SEAT, "work", seat_setup("Personal")));
    assert!(
        seat(&me, &fx.owner_proof, &work)
            .expect("seat read")
            .expect("the seat")
            .seat
            .kill_switch_engaged(),
        "setting the same setup again does not lift the kill switch"
    );
}

#[test]
fn installing_an_ics_feed_starts_its_poll_chain_in_the_same_write() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let request = CalendarIcsFeedRequest {
        system: "work-ics".to_owned(),
    };

    assert!(
        installed_feed(&me, &fx.owner_proof, &request)
            .expect("feed read")
            .is_none()
    );
    assert!(check_installed_feed(&fx.vault, &fx.owner_proof, &feed_config("work-ics")).is_err());

    let applied = call(&me, SET, set(FEED, "work-ics", feed("work-ics")));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let row = installed_feed(&me, &fx.owner_proof, &request)
        .expect("feed read")
        .expect("the installed feed");
    assert!(
        row.config == feed_config("work-ics"),
        "the feed reads its configuration"
    );
    assert!(row.last_poll.is_none());
    check_installed_feed(&fx.vault, &fx.owner_proof, &feed_config("work-ics"))
        .expect("the feed is installed");
    let mut other = feed_config("work-ics");
    other.cadence_max_seconds = 1800;
    assert!(
        check_installed_feed(&fx.vault, &fx.owner_proof, &other).is_err(),
        "another configuration of the same system is not the installed feed"
    );
    assert!(
        matches!(
            enqueue_ics_feed_poll(&fx.vault, feed_config("work-ics"), T0).expect("enqueue"),
            EnqueueOutcome::Existing(_)
        ),
        "the install already started the feed's poll chain"
    );

    let moved = refused(
        &me,
        SET,
        set(
            FEED,
            "work-ics",
            json!({
                "secret_ref": "ics-feed:work",
                "system": "work-ics",
                "cadence_min_seconds": 600,
                "cadence_max_seconds": 1800,
            }),
        ),
    );
    assert!(moved.contains("immutable"), "{moved}");
    let other_item = refused(&me, SET, set(FEED, "home-ics", feed("work-ics")));
    assert!(other_item.contains("system"), "{other_item}");
    let mut unordered = feed("home-ics");
    unordered["cadence_min_seconds"] = json!(2000);
    let unordered = refused(&me, SET, set(FEED, "home-ics", unordered));
    assert!(unordered.contains("cadence"), "{unordered}");
}

#[test]
fn an_agents_install_waits_on_a_check_in_and_starts_nothing() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let agent = fx.granted_agent();
    let them = fx.vault.memory(agent, EdgeActorClass::Agent);

    for (key, item, value) in [
        (SEAT, "work", seat_setup("Personal")),
        (FEED, "work-ics", feed("work-ics")),
    ] {
        let pending = call(&them, SET, set(key, item, value));
        assert_eq!(pending["status"], json!("pending"), "{key}: {pending}");
        assert_eq!(
            get(&me, key, item)["source"],
            json!({ "from": "default" }),
            "{key}: nothing applied"
        );
    }
    assert!(
        seat(
            &me,
            &fx.owner_proof,
            &CalendarConnectorRequest {
                seat_ref: "work".to_owned()
            }
        )
        .expect("seat read")
        .is_none()
    );
    assert!(
        matches!(
            enqueue_ics_feed_poll(&fx.vault, feed_config("work-ics"), T0).expect("enqueue"),
            EnqueueOutcome::Enqueued(_)
        ),
        "a pending install started no poll chain"
    );
}
