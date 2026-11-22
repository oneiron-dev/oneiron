//! Five owner policy doors read the value in force before they ask (row OWNER-CONFIRM-SHEET, PR 4b-3c1).
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::authority::{ActAuthority, ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    FreeTimeCadence, FreeTimePolicy, FreeTimePolicyInput, FreeTimeSchedule, FreeTimeSplit,
};
use oneiron::error::{
    DevicePinRefusal, GateError, OwnerPresenceRefusal, RecordError, RegistryError, SecretError,
};
use oneiron::recovery::PassphraseCost;
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_WORLD};
use oneiron::settings::RoomThreadAdminSettings;
use oneiron::settings::agent_world_access::{
    AgentWorldAccess, AgentWorldAccessChange, AgentWorldAccessRequest, AgentWorldAccessSetRequest,
    Worlds,
};
use oneiron::settings::default_facet::DefaultFacet;
use oneiron::settings::undo_send::{UndoSendChannelLength, UndoSendSetting};
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::policy_doors_between::{
    set_agent_world_access_as_owner_between, set_default_facet_as_owner_between,
    set_free_time_policy_between, set_room_thread_admin_settings_between, set_undo_send_between,
};
use oneiron::test_support::provision_engine_machines;
use oneiron::world_keys::DevicePin;
use oneiron::{EntityId, Error, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PRESENCE_WINDOW_SECS, PresenceClock, PresenceError,
    PresenceGate, PresenceInstant, PresenceWindow, ScriptedPresence,
};
use oneiron_store::ports::manual_clock::ManualClock;

/// The reason lines the doors show, as the engine's constants hold them:
/// the test asserts them literally, since those constants are crate-private.
const ROOM_THREAD_ADMIN_REASON: &str = "change admin access to private conversations";
const DEFAULT_FACET_REASON: &str = "change where new memories are saved by default";
const UNDO_SEND_REASON: &str = "change how long you can undo sending a message";
const AGENT_WORLD_ACCESS_REASON: &str = "change which worlds an agent can access";
const FREE_TIME_POLICY_REASON: &str = "change how an agent uses its free time";
/// When the fixture's stored rows were learned.
const LEARNED_AT: u64 = 1_780_000_000;
const OCCURRED: TimeRange = TimeRange {
    start: LEARNED_AT,
    end: LEARNED_AT,
};
/// The free-time fixture's IANA zone.
const ZONE: &str = "Asia/Tokyo";
/// When the owner was shown the fixture's recurring cap, in host milliseconds.
const CAP_SHOWN_AT_MS: u64 = 1_000;

/// The device PIN: a passphrase, since nothing counts wrong tries but this
/// process.
const PIN: &[u8] = b"quiet harbour lantern";
const SURFACE: Option<ActSurface> = Some(ActSurface::ThisInstall);

/// A hosted vault with its serving install profiled and its owner authenticated.
/// The vault drops before its directory.
struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn hosted() -> Self {
        Self::with_keystore(Arc::new(MemoryKeystore::default()))
    }

    fn with_keystore(keystore: Arc<MemoryKeystore>) -> Self {
        let (vault, dir) = open_vault();
        vault.install_device_keystore(keystore);
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let owner = embedded_owner(&vault)
            .expect("authenticated embedded owner")
            .1;
        Self {
            vault,
            owner,
            _dir: dir,
        }
    }

    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
    }

    fn set_room(
        &self,
        admin_walk_in: Option<bool>,
        admin_delete: Option<bool>,
    ) -> oneiron::Result<RoomThreadAdminSettings> {
        self.vault
            .set_room_thread_admin_settings(&self.owner, SURFACE, admin_walk_in, admin_delete)
    }

    fn room(&self) -> RoomThreadAdminSettings {
        self.vault
            .room_thread_admin_settings()
            .expect("the switches read")
    }

    fn set_facet(&self, facet: EntityId) -> oneiron::Result<DefaultFacet> {
        self.vault
            .set_default_facet_as_owner(&self.owner, SURFACE, DefaultFacet { facet })
    }

    fn facet(&self) -> EntityId {
        self.vault
            .default_facet_as_owner(&self.owner)
            .expect("the default reads")
            .facet
    }

    fn set_undo(&self, setting: &UndoSendSetting) -> oneiron::Result<UndoSendSetting> {
        self.vault.set_undo_send(&self.owner, SURFACE, setting)
    }

    fn undo(&self) -> UndoSendSetting {
        let read = self
            .vault
            .undo_send_settings_as_owner(&self.owner)
            .expect("the window reads");
        UndoSendSetting {
            all_channels_secs: read.all_channels_secs,
            channels: read.channels,
        }
    }

    fn set_access(
        &self,
        request: AgentWorldAccessSetRequest,
    ) -> oneiron::Result<AgentWorldAccessChange> {
        self.vault
            .set_agent_world_access_as_owner(&self.owner, SURFACE, request)
    }

    fn access(&self, agent: EntityId) -> AgentWorldAccess {
        self.vault
            .agent_world_access_as_owner(&self.owner, AgentWorldAccessRequest { agent })
            .expect("the agent's access reads")
    }

    fn set_free(
        &self,
        agent: EntityId,
        expected_revision: u64,
        input: FreeTimePolicyInput,
    ) -> oneiron::Result<FreeTimePolicy> {
        self.vault
            .set_free_time_policy(&self.owner, SURFACE, agent, expected_revision, input)
    }

    fn clear_free(&self, agent: EntityId, expected_revision: u64) -> oneiron::Result<()> {
        self.vault
            .clear_free_time_policy(&self.owner, SURFACE, agent, expected_revision)
    }

    fn free_time(&self, agent: EntityId) -> Option<FreeTimePolicy> {
        self.vault
            .free_time_policy(agent)
            .expect("the policy reads")
    }
}

fn open_vault() -> (Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config.store_clock = ManualClock::new(1_790_000_000).bundle();
    let vault = Vault::open(dir.path(), config).expect("vault");
    (vault, dir)
}

struct ExpiresAtOnce {
    next_ms: AtomicU64,
}

impl PresenceClock for ExpiresAtOnce {
    fn now(&self) -> PresenceInstant {
        let ms = self
            .next_ms
            .fetch_add(PRESENCE_WINDOW_SECS * 1_000 + 1, Ordering::SeqCst);
        PresenceInstant {
            wall_ms: ms,
            monotonic_ms: ms,
        }
    }
}

fn scripted_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let clock = Arc::new(ExpiresAtOnce {
        next_ms: AtomicU64::new(1_000_000),
    });
    let window = PresenceWindow::new(clock);
    let gate = PresenceGate::new(presence.clone(), window);
    vault.install_presence_gate(Arc::new(gate));
    presence
}

fn assert_declined_without_change<T: std::fmt::Debug, S: std::fmt::Debug + PartialEq>(
    served: &ServedVault,
    reason: &str,
    read: impl Fn() -> S,
    set: impl FnOnce() -> oneiron::Result<T>,
) {
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let before = read();
    let history = served.history();
    let refused = set();
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "{reason}: {refused:?}"
    );
    assert_eq!(presence.reasons(), [reason]);
    assert_eq!(read(), before, "the setting stays in force");
    assert_eq!(
        served.history(),
        history,
        "the authority log keeps the same entries"
    );
}

fn assert_foreign<T: std::fmt::Debug>(refused: &oneiron::Result<T>, what: &str) {
    assert!(
        matches!(
            refused,
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
        ),
        "another vault's owner proof is refused as no owner of this vault at {what}: {refused:?}"
    );
}

fn assert_conflict<T: std::fmt::Debug>(result: oneiron::Result<T>) {
    assert!(
        matches!(result, Err(Error::ConcurrentWrite(_))),
        "expected ConcurrentWrite: {result:?}"
    );
}

fn fixture_id(byte: u8) -> EntityId {
    EntityId::from_bytes(u128::from(byte).to_be_bytes()).expect("a fixture id")
}

/// A stored FACET named `name`.
fn put_facet(vault: &Vault, byte: u8, name: &str) -> EntityId {
    let id = fixture_id(byte);
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("a facet body");
    vault
        .put_entity(&id, ENTITY_TYPE_FACET, OCCURRED, LEARNED_AT, &body)
        .expect("a stored FACET");
    id
}

/// A stored live WORLD.
fn put_world(vault: &Vault) -> EntityId {
    let world = fixture_id(3);
    vault
        .put_entity(&world, ENTITY_TYPE_WORLD, OCCURRED, LEARNED_AT, b"world")
        .expect("a live WORLD");
    world
}

/// A worlds value as the doors spell it: base reality, and world ids ascending.
fn worlds(include_base: bool, ids: &[EntityId]) -> Worlds {
    let mut worlds = ids.to_vec();
    worlds.sort();
    Worlds {
        include_base,
        worlds,
    }
}

/// A world-access set of `allowed`, and of `default_on` when one is named.
fn access_request(
    agent: EntityId,
    allowed: Worlds,
    default_on: Option<Worlds>,
) -> AgentWorldAccessSetRequest {
    AgentWorldAccessSetRequest {
        agent,
        allowed,
        default_on,
    }
}

/// An undo-send window of `all_channels_secs`, with one lane length per named channel.
fn undo_setting(all_channels_secs: u32, channels: &[(&str, u32)]) -> UndoSendSetting {
    UndoSendSetting {
        all_channels_secs,
        channels: channels
            .iter()
            .map(|(channel, secs)| UndoSendChannelLength {
                channel: channel.to_string(),
                secs: *secs,
            })
            .collect(),
    }
}

/// A free-time policy input of `total_units`, with the pinned split when one
/// is named, on the nightly clock at `hour` o'clock.
fn policy_input(total_units: u64, split: Option<(u64, u64)>, hour: u8) -> FreeTimePolicyInput {
    FreeTimePolicyInput {
        total_units,
        schedule: FreeTimeSchedule {
            cadence: FreeTimeCadence::Nightly,
            hour,
            minute: 0,
            zone: ZONE.to_owned(),
        },
        pinned_split: split.map(|(for_human_units, own_time_units)| FreeTimeSplit {
            for_human_units,
            own_time_units,
        }),
        cap_shown_at_ms: CAP_SHOWN_AT_MS,
    }
}

/// One vault with a device PIN set, over a process-memory keystore, on a
/// clock the test moves. The vault drops first.
struct PinDevice {
    served: ServedVault,
    pin: Arc<DevicePin>,
}

impl PinDevice {
    fn with_pin_set() -> Self {
        let keystore = Arc::new(MemoryKeystore::new());
        let served = ServedVault::with_keystore(keystore.clone());
        let pin = DevicePin::with_clock_and_cost(
            keystore,
            ManualPresenceClock::new(1_000_000, 1_000_000),
            PassphraseCost::FLOOR,
        )
        .expect("device PIN over the vault's keystore");
        served
            .vault
            .install_device_pin(pin.clone())
            .expect("install device PIN");
        let authority = ActAuthority::Owner(served.owner.clone(), ActSurface::ThisInstall);
        served
            .vault
            .set_device_pin_as(&authority, PIN, false)
            .expect("set the device PIN");
        Self { served, pin }
    }
}

/// An admin switch asks only when it is turned on.
#[test]
fn an_admin_switch_asks_only_when_it_is_turned_on() {
    let served = ServedVault::hosted();
    assert!(served.room().admin_walk_in && served.room().admin_delete);
    let presence = scripted_gate(&served.vault, [Ok(()), Ok(())]);
    for (walk_in, delete, prompts) in [
        (Some(false), None, 0),
        (None, Some(false), 0),
        (Some(false), Some(false), 0),
        (Some(true), None, 1),
        (None, Some(true), 2),
    ] {
        let prior = served.room();
        let history = served.history();
        let written = served
            .set_room(walk_in, delete)
            .expect("the switch set lands");
        assert_eq!(
            written.admin_walk_in,
            walk_in.unwrap_or(prior.admin_walk_in)
        );
        assert_eq!(written.admin_delete, delete.unwrap_or(prior.admin_delete));
        assert_eq!(served.room(), written);
        assert_eq!(
            presence.prompts(),
            prompts,
            "switches {walk_in:?}, {delete:?}"
        );
        if prior == written {
            assert_eq!(served.history(), history);
        }
    }
}

/// An undo-send window asks only when a send waits less.
#[test]
fn an_undo_send_window_asks_only_when_a_send_waits_less() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Ok(()), Ok(()), Ok(())]);
    for (setting, prompts) in [
        (undo_setting(30, &[]), 0),
        (undo_setting(10, &[]), 1),
        (undo_setting(10, &[("email", 60)]), 1),
        (undo_setting(10, &[("email", 5)]), 2),
        (undo_setting(10, &[]), 2),
        (undo_setting(0, &[]), 3),
    ] {
        served.set_undo(&setting).expect("the window lands");
        assert_eq!(served.undo(), setting);
        assert_eq!(presence.prompts(), prompts, "window {setting:?}");
    }
}

/// A free-time policy asks only when a cap rises or its schedule moves.
#[test]
fn a_free_time_policy_asks_only_when_a_cap_rises_or_its_schedule_moves() {
    let served = ServedVault::hosted();
    let agent = define_agent(&served.vault).expect("an agent definition");
    let presence = scripted_gate(&served.vault, (0..6).map(|_| Ok(())));
    let mut revision = 0;
    for (input, prompts) in [
        (policy_input(100, None, 3), 1),
        (policy_input(100, None, 3), 1),
        (policy_input(80, None, 3), 1),
        (policy_input(120, None, 3), 2),
        (policy_input(120, Some((70, 50)), 3), 2),
        (policy_input(120, Some((90, 30)), 3), 3),
        (policy_input(120, None, 3), 4),
        (policy_input(120, None, 4), 5),
    ] {
        let policy = served
            .set_free(agent, revision, input)
            .expect("the policy lands");
        assert_eq!(presence.prompts(), prompts, "set at revision {revision}");
        revision = policy.revision;
    }
    served.clear_free(agent, revision).expect("the clear lands");
    assert_eq!(presence.prompts(), 5, "the clear shows no prompt");
    assert_eq!(served.free_time(agent), None);

    // Here only the total rises: each pinned share is below the previous unpinned cap.
    let starting = served
        .set_free(agent, 0, policy_input(80, None, 3))
        .expect("the first set lands again");
    let presence = scripted_gate(&served.vault, [Ok(())]);
    served
        .set_free(
            agent,
            starting.revision,
            policy_input(120, Some((70, 50)), 3),
        )
        .expect("the total-only raise lands");
    assert_eq!(presence.prompts(), 1, "only the total rises");
}

/// A world-access set asks only when the agent reads more.
#[test]
fn a_world_access_set_asks_only_when_the_agent_reads_more() {
    let served = ServedVault::hosted();
    let agent = define_agent(&served.vault).expect("an agent definition");
    let world = put_world(&served.vault);
    let presence = scripted_gate(&served.vault, (0..5).map(|_| Ok(())));
    let base = worlds(true, &[]);
    let both = worlds(true, &[world]);
    let empty = worlds(false, &[]);
    assert!(!served.access(agent).governed);
    let first = served
        .set_access(access_request(agent, base.clone(), None))
        .expect("base alone lands");
    assert!(first.changed, "the first grant is a change");
    assert_eq!(
        presence.prompts(),
        1,
        "a retrieval turn of an agent no grant governs read nothing"
    );
    for (allowed, default_on, prompts) in [
        (&both, None, 2),
        (&base, None, 2),
        // No default row stands, so a retrieval turn's default was empty.
        (&base, Some(&base), 3),
        (&both, None, 4),
        (&both, Some(&both), 5),
        (&both, Some(&base), 5),
        (&empty, None, 5),
    ] {
        let change = served
            .set_access(access_request(agent, allowed.clone(), default_on.cloned()))
            .expect("the world access lands");
        assert_eq!(&change.access.allowed, allowed);
        assert_eq!(
            presence.prompts(),
            prompts,
            "grant {allowed:?}, default {default_on:?}"
        );
    }
    assert_eq!(served.access(agent).allowed, empty);
}

/// A default facet asks only when it changes.
#[test]
fn a_default_facet_asks_only_when_it_changes() {
    let served = ServedVault::hosted();
    let work = put_facet(&served.vault, 11, "work");
    let presence = scripted_gate(&served.vault, [Ok(())]);
    served.set_facet(work).expect("another stored FACET lands");
    assert_eq!(presence.prompts(), 1);
    let history = served.history();
    served.set_facet(work).expect("that facet again lands");
    assert_eq!(
        presence.prompts(),
        1,
        "the facet in force again shows no prompt"
    );
    assert_eq!(served.facet(), work);
    assert_eq!(served.history(), history);
}

/// A declined confirm refuses each widening policy set and stores nothing.
#[test]
fn a_declined_confirm_refuses_each_widening_policy_set_and_stores_nothing() {
    let served = ServedVault::hosted();
    let agent = define_agent(&served.vault).expect("an agent definition");
    let world = put_world(&served.vault);
    let work = put_facet(&served.vault, 11, "work");
    served.set_room(Some(false), None).expect("walk-in off");
    served
        .set_undo(&undo_setting(30, &[]))
        .expect("all channels 30");
    served
        .set_access(access_request(agent, worlds(true, &[]), None))
        .expect("base reality alone");
    assert_declined_without_change(
        &served,
        ROOM_THREAD_ADMIN_REASON,
        || served.room(),
        || served.set_room(Some(true), None),
    );
    assert_declined_without_change(
        &served,
        DEFAULT_FACET_REASON,
        || served.facet(),
        || served.set_facet(work),
    );
    assert_declined_without_change(
        &served,
        UNDO_SEND_REASON,
        || served.undo(),
        || served.set_undo(&undo_setting(10, &[])),
    );
    assert_declined_without_change(
        &served,
        AGENT_WORLD_ACCESS_REASON,
        || served.access(agent),
        || served.set_access(access_request(agent, worlds(true, &[world]), None)),
    );
    assert_declined_without_change(
        &served,
        FREE_TIME_POLICY_REASON,
        || served.free_time(agent),
        || served.set_free(agent, 0, policy_input(100, None, 3)),
    );
}

/// A policy set refused on its read never raises the prompt.
#[test]
fn a_policy_set_refused_on_its_read_never_raises_the_prompt() {
    let served = ServedVault::hosted();
    let agent = define_agent(&served.vault).expect("an agent definition");
    let world = put_world(&served.vault);
    let missing = fixture_id(4);
    let live = served
        .set_free(agent, 0, policy_input(100, None, 3))
        .expect("the owner's policy");
    let presence = scripted_gate(&served.vault, []);
    let history = served.history();
    let no_facet = served.set_facet(missing);
    assert!(matches!(
        no_facet,
        Err(Error::Registry(RegistryError::InvalidFacet { .. }))
    ));
    for request in [
        access_request(missing, worlds(true, &[]), None),
        access_request(agent, worlds(true, &[missing]), None),
        access_request(agent, worlds(true, &[]), Some(worlds(true, &[world]))),
    ] {
        let refused = served.set_access(request);
        assert!(matches!(refused, Err(Error::InvalidConfig(_))));
    }
    let stale = served.set_free(agent, live.revision + 1, policy_input(80, None, 3));
    assert!(matches!(stale, Err(Error::ConcurrentWrite(_))));
    let unknown = served.set_free(missing, 0, policy_input(80, None, 3));
    assert!(matches!(unknown, Err(Error::EntityNotFound)));
    assert_eq!(presence.prompts(), 0);
    assert_eq!(served.history(), history);
}

/// An owner proof of another vault never raises the prompt at a policy door.
#[test]
fn an_owner_proof_of_another_vault_never_raises_the_prompt_at_a_policy_door() {
    let mut served = ServedVault::hosted();
    let other = ServedVault::hosted();
    let agent = define_agent(&served.vault).expect("an agent definition");
    let world = put_world(&served.vault);
    let work = put_facet(&served.vault, 11, "work");
    served.set_room(Some(false), None).expect("walk-in off");
    served
        .set_undo(&undo_setting(30, &[]))
        .expect("all channels 30");
    served
        .set_access(access_request(agent, worlds(true, &[]), None))
        .expect("base reality alone");
    let presence = scripted_gate(&served.vault, []);
    let history = served.history();
    served.owner = other.owner;
    assert_foreign(&served.set_room(Some(true), None), "the room-thread set");
    assert_foreign(&served.set_facet(work), "the default-facet set");
    assert_foreign(
        &served.set_undo(&undo_setting(10, &[])),
        "the undo-send set",
    );
    let access = access_request(agent, worlds(true, &[world]), None);
    assert_foreign(&served.set_access(access), "the world-access set");
    assert_foreign(
        &served.set_free(agent, 0, policy_input(100, None, 3)),
        "the free-time set",
    );
    assert_eq!(presence.prompts(), 0, "no refusal showed a prompt");
    assert_eq!(served.history(), history);
}

/// An admin switch set that became a turn-on since the door asked is a conflict.
#[test]
fn an_admin_switch_set_that_widens_since_the_door_asked_is_a_conflict() {
    let served = ServedVault::hosted();
    assert!(served.room().admin_walk_in);
    let presence = scripted_gate(&served.vault, []);
    let conflict = set_room_thread_admin_settings_between(
        &served.vault,
        &served.owner,
        SURFACE,
        Some(true),
        None,
        || {
            served
                .set_room(Some(false), None)
                .expect("walk-in off lands between");
        },
    );
    assert_conflict(conflict);
    assert_eq!(presence.prompts(), 0, "neither act showed a prompt");
    assert!(!served.room().admin_walk_in, "walk-in reads off");
}

/// An undo-send set that became a shortening since the door asked is a conflict.
#[test]
fn an_undo_send_set_that_widens_since_the_door_asked_is_a_conflict() {
    let served = ServedVault::hosted();
    served
        .set_undo(&undo_setting(30, &[]))
        .expect("all channels 30 in force");
    let presence = scripted_gate(&served.vault, []);
    let conflict = set_undo_send_between(
        &served.vault,
        &served.owner,
        SURFACE,
        &undo_setting(30, &[]),
        || {
            served
                .set_undo(&undo_setting(60, &[]))
                .expect("all channels 60 lands between");
        },
    );
    assert_conflict(conflict);
    assert_eq!(presence.prompts(), 0, "neither act showed a prompt");
    assert_eq!(served.undo().all_channels_secs, 60, "the window reads 60");
}

/// A world-access set that became a wider read since the door asked is a conflict.
#[test]
fn a_world_access_set_that_widens_since_the_door_asked_is_a_conflict() {
    let served = ServedVault::hosted();
    let agent = define_agent(&served.vault).expect("an agent definition");
    let world = put_world(&served.vault);
    let base = worlds(true, &[]);
    let both = worlds(true, &[world]);
    served
        .set_access(access_request(agent, both.clone(), None))
        .expect("base and the world in force");
    let presence = scripted_gate(&served.vault, []);
    let conflict = set_agent_world_access_as_owner_between(
        &served.vault,
        &served.owner,
        SURFACE,
        access_request(agent, both, None),
        || {
            served
                .set_access(access_request(agent, base.clone(), None))
                .expect("base alone lands between");
        },
    );
    assert_conflict(conflict);
    assert_eq!(presence.prompts(), 0, "neither act showed a prompt");
    assert_eq!(served.access(agent).allowed, base);
}

/// A default-facet set that became a change since the door asked is a conflict.
#[test]
fn a_default_facet_set_that_widens_since_the_door_asked_is_a_conflict() {
    let served = ServedVault::hosted();
    let first = put_facet(&served.vault, 11, "first");
    let second = put_facet(&served.vault, 12, "second");
    served.set_facet(first).expect("facet A in force");
    let presence = scripted_gate(&served.vault, [Ok(())]);
    let conflict = set_default_facet_as_owner_between(
        &served.vault,
        &served.owner,
        SURFACE,
        DefaultFacet { facet: first },
        || {
            served.set_facet(second).expect("facet B lands between");
        },
    );
    assert_conflict(conflict);
    assert_eq!(presence.prompts(), 1, "only facet B showed a prompt");
    assert_eq!(served.facet(), second, "the default reads B");
}

/// A free-time set that became a raise since the door asked is a conflict.
#[test]
fn a_free_time_set_that_widens_since_the_door_asked_is_a_conflict() {
    let served = ServedVault::hosted();
    let agent = define_agent(&served.vault).expect("an agent definition");
    let standing = served
        .set_free(agent, 0, policy_input(100, None, 3))
        .expect("total 100 in force");
    let presence = scripted_gate(&served.vault, [Ok(())]);
    let conflict = set_free_time_policy_between(
        &served.vault,
        &served.owner,
        SURFACE,
        agent,
        standing.revision,
        policy_input(80, None, 3),
        || {
            served
                .clear_free(agent, standing.revision)
                .expect("the clear lands between");
            served
                .set_free(agent, 0, policy_input(50, None, 3))
                .expect("total 50 lands between");
        },
    );
    assert_conflict(conflict);
    assert_eq!(presence.prompts(), 1, "only between's set showed a prompt");
    let policy = served.free_time(agent).expect("a policy stands");
    assert_eq!((policy.total_units, policy.revision), (50, 1));
}

/// A policy set with no surface asks nothing.
#[test]
fn a_policy_set_with_no_surface_asks_nothing() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    for on in [false, true] {
        let setting = served
            .vault
            .set_room_thread_admin_settings(&served.owner, None, Some(on), None)
            .expect("the set with no surface lands");
        assert_eq!(setting.admin_walk_in, on);
    }
    assert_eq!(presence.prompts(), 0, "no surface shows no prompt");
    assert!(served.room().admin_walk_in, "walk-in reads on");
}

/// A device with a PIN set asks for it only for a widening policy set.
#[test]
fn a_device_with_a_pin_set_asks_for_it_only_for_a_widening_policy_set() {
    let device = PinDevice::with_pin_set();
    device.pin.end_window();
    device
        .served
        .set_room(Some(false), None)
        .expect("walk-in off lands");
    let refused = device.served.set_room(Some(true), None);
    assert!(
        matches!(
            refused,
            Err(Error::Secret(SecretError::DevicePin(
                DevicePinRefusal::Required
            )))
        ),
        "the widening set asks for the PIN: {refused:?}"
    );
    assert!(!device.served.room().admin_walk_in, "walk-in reads off");
}
