//! Turn programs on timer, idle and feed triggers (untangle slice 6.8c, B-3), on the public
//! crate surface only: `Memory::arm_program`, the release doors and `Vault::wake_turn_programs`,
//! the one drain that admits each wake. Run with
//! `cargo test -p oneiron --all-features --test turn_program_triggers`.

use oneiron::claim::ScopedReadActorKey;
use oneiron::dreamer_runner::{ArmTurnProgram, ProgramTrigger, TurnProgramDrain};
use oneiron::dreamer_wake::WakeIdleState;
use oneiron::feeds::{
    FeedAckRequest, FeedRead, FeedReadRequest, FeedSelector, FeedSource, FeedStart,
    FeedSubscribeRequest,
};
use oneiron::registry::{ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_PERSON};
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// A due time well past any clock the vault records in a test.
const T0: u64 = 4_000_000_000;

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

/// An active callable SKILL, enough to arm: arming pins the record and never loads its source.
fn active_callable_skill(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let files: [(&str, &[u8]); 2] = [
        (
            "SKILL.md",
            b"---\nname: fixture.callable\ndescription: Increment a number\nversion: 1\nrole: callable\ncall:\n  reference: scripts/call.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n---\nAn executable fixture.\n",
        ),
        (
            "scripts/call.js",
            b"finish(JSON.stringify({result:skillArgs.value + 1}));",
        ),
    ];
    let hash = canonical_skill_tree_hash(files).expect("hash the fixture tree");
    let mut record = SkillRecord::new(
        "fixture.callable",
        "Increment a number",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: "scripts/call.js".into(),
            arguments: serde_json::json!({"value": "integer"}),
            returns: serde_json::json!({"result": "integer"}),
        }),
    )
    .with_content_hash(hash);
    vault
        .put_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)
        .expect("put the callable candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &record, TimeRange { start: 2, end: 2 }, 2)
        .expect("activate the callable");
    id
}

/// The vault's owner, its active callable, and arming on `trigger` for that owner.
struct Fixture {
    owner: EntityId,
    skill: EntityId,
}

impl Fixture {
    fn new(vault: &Vault) -> Self {
        Self {
            owner: vault.ensure_embedded_owner_actor().expect("owner"),
            skill: active_callable_skill(vault),
        }
    }

    fn input(&self, conversation: Option<EntityId>) -> ArmTurnProgram {
        ArmTurnProgram {
            skill: self.skill,
            executor: "fixture.executor@1".into(),
            args: serde_json::json!({"value": 41}),
            conversation,
        }
    }

    fn arm(&self, vault: &Vault, trigger: ProgramTrigger) -> EntityId {
        vault
            .memory(self.owner, EdgeActorClass::Human)
            .arm_program(&self.input(None), trigger)
            .expect("arm")
            .registration
    }

    fn reader_key(&self) -> ScopedReadActorKey {
        ScopedReadActorKey::with_actor_class(self.owner.to_hex(), "human").expect("owner key")
    }
}

fn drain(vault: &Vault, now: u64) -> TurnProgramDrain {
    vault.wake_turn_programs(now).expect("drain")
}

fn put_person(vault: &Vault) {
    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("person");
}

/// A timer wakes its program once per due time, however many releases see it; a due time
/// missed while nothing released wakes it once, and the next due time follows the release.
#[test]
fn a_timer_program_wakes_once_per_due_time() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    fixture.arm(
        &vault,
        ProgramTrigger::Timer {
            first_at: T0,
            every_secs: 3_600,
        },
    );

    assert_eq!(
        vault.release_timer_program_wakes(T0 - 1).expect("release"),
        0
    );
    assert_eq!(vault.release_timer_program_wakes(T0).expect("release"), 1);
    assert_eq!(
        vault.release_timer_program_wakes(T0).expect("release"),
        0,
        "a replayed release records nothing new"
    );
    let first = drain(&vault, T0);
    assert_eq!((first.admitted, first.refused), (1, 0), "{first:?}");

    assert_eq!(
        vault
            .release_timer_program_wakes(T0 + 3_599)
            .expect("release"),
        0
    );
    let late = T0 + 3 * 3_600 + 5;
    assert_eq!(
        vault.release_timer_program_wakes(late).expect("release"),
        1,
        "three missed due times wake it once"
    );
    assert_eq!(vault.release_timer_program_wakes(late).expect("release"), 0);
    assert_eq!(
        vault
            .release_timer_program_wakes(T0 + 4 * 3_600)
            .expect("release"),
        1,
        "the next due time follows the late release"
    );
    let rest = drain(&vault, T0 + 4 * 3_600);
    assert_eq!((rest.admitted, rest.refused), (2, 0), "{rest:?}");
}

/// The wake an occurrence records is judged again at admission: a program disarmed after its
/// timer released is refused, and a timer that wakes once never wakes again.
#[test]
fn an_occurrence_is_judged_again_at_admission() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let registration = fixture.arm(
        &vault,
        ProgramTrigger::Timer {
            first_at: T0,
            every_secs: 0,
        },
    );
    assert_eq!(vault.release_timer_program_wakes(T0).expect("release"), 1);
    assert!(
        vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .disarm_turn_program(registration)
            .expect("disarm")
    );
    let judged = drain(&vault, T0);
    assert_eq!((judged.admitted, judged.refused), (0, 1), "{judged:?}");
    assert_eq!(
        vault
            .release_timer_program_wakes(T0 + 1_000_000)
            .expect("release"),
        0
    );
}

/// A feed program wakes once per set of entries its lane is shown past its subscription's
/// cursor, not while the cursor stands past every one; once its subscription is gone, a wake it
/// still owes is refused.
#[test]
fn a_feed_program_wakes_once_per_head() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let lane = vault.scoped_read(fixture.reader_key());
    let subscription = vault
        .feed_subscribe(
            &lane,
            &FeedSubscribeRequest {
                selector: FeedSelector {
                    sources: vec![FeedSource::Changes],
                    kinds: Vec::new(),
                    entity_types: Vec::new(),
                    predicates: Vec::new(),
                },
                start: FeedStart::Head,
            },
        )
        .expect("subscribe")
        .subscription;
    fixture.arm(&vault, ProgramTrigger::Feed { subscription });
    // Whatever arming wrote is settled first, so each count below is this test's own.
    vault.release_feed_program_wakes(T0).expect("release");
    drain(&vault, T0);

    put_person(&vault);
    assert_eq!(vault.release_feed_program_wakes(T0).expect("release"), 1);
    assert_eq!(
        vault.release_feed_program_wakes(T0).expect("release"),
        0,
        "a head that has not moved wakes it once"
    );
    let woken = drain(&vault, T0);
    assert_eq!((woken.admitted, woken.refused), (1, 0), "{woken:?}");

    let FeedRead::Page(page) = vault
        .feed_read(
            &lane,
            &FeedReadRequest {
                subscription,
                limit: None,
            },
        )
        .expect("read")
    else {
        panic!("a page");
    };
    assert!(!page.more, "{page:?}");
    vault
        .feed_ack(
            &lane,
            &FeedAckRequest {
                subscription,
                through: page.through,
            },
        )
        .expect("ack");
    assert_eq!(
        vault.release_feed_program_wakes(T0).expect("release"),
        0,
        "a cursor at the head owes no wake"
    );

    put_person(&vault);
    assert_eq!(vault.release_feed_program_wakes(T0).expect("release"), 1);
    assert!(
        vault
            .feed_unsubscribe(&lane, subscription)
            .expect("unsubscribe")
    );
    let refused = drain(&vault, T0);
    assert_eq!((refused.admitted, refused.refused), (0, 1), "{refused:?}");
}

/// Lead call K: a feed program's wake is judged as its own read would be, at delivery, so a
/// change it would not be shown never wakes it. Here the subscription's selector takes PERSONs
/// alone: a CODE_SYMBOL written past the cursor wakes nothing, a PERSON wakes it once.
#[test]
fn a_feed_program_is_not_woken_by_a_change_it_would_not_be_shown() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let lane = vault.scoped_read(fixture.reader_key());
    let subscription = vault
        .feed_subscribe(
            &lane,
            &FeedSubscribeRequest {
                selector: FeedSelector {
                    sources: vec![FeedSource::Changes],
                    kinds: Vec::new(),
                    entity_types: vec![ENTITY_TYPE_PERSON],
                    predicates: Vec::new(),
                },
                start: FeedStart::Head,
            },
        )
        .expect("subscribe")
        .subscription;
    fixture.arm(&vault, ProgramTrigger::Feed { subscription });
    vault.release_feed_program_wakes(T0).expect("release");
    drain(&vault, T0);

    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_CODE_SYMBOL,
            TimeRange { start: 1, end: 1 },
            1,
            b"symbol",
        )
        .expect("code symbol");
    assert_eq!(
        vault.release_feed_program_wakes(T0).expect("release"),
        0,
        "a change it would not be shown wakes nothing"
    );
    put_person(&vault);
    assert_eq!(vault.release_feed_program_wakes(T0).expect("release"), 1);
}

/// An idle program wakes once per idle stretch, after its quiet time, and never while a turn
/// or background work runs.
#[test]
fn an_idle_program_wakes_once_per_idle_stretch() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    fixture.arm(&vault, ProgramTrigger::Idle { quiet_secs: 600 });
    let idle = |last_inbound_at| WakeIdleState {
        running_turns: false,
        live_background_work: false,
        compute_available: true,
        last_inbound_at,
    };

    assert_eq!(
        vault
            .release_idle_program_wakes(idle(T0), T0 + 599)
            .expect("release"),
        0
    );
    assert_eq!(
        vault
            .release_idle_program_wakes(idle(T0), T0 + 600)
            .expect("release"),
        1
    );
    assert_eq!(
        vault
            .release_idle_program_wakes(idle(T0), T0 + 5_000)
            .expect("release"),
        0,
        "one stretch wakes it once"
    );
    let busy = WakeIdleState {
        running_turns: true,
        ..idle(T0 + 6_000)
    };
    assert_eq!(
        vault
            .release_idle_program_wakes(busy, T0 + 9_000)
            .expect("release"),
        0
    );
    assert_eq!(
        vault
            .release_idle_program_wakes(idle(T0 + 6_000), T0 + 9_000)
            .expect("release"),
        1,
        "a new stretch wakes it again"
    );
    let woken = drain(&vault, T0 + 9_000);
    assert_eq!((woken.admitted, woken.refused), (2, 0), "{woken:?}");
}

/// A trigger other than a turn names no conversation, a timer repeats at most once a minute,
/// an idle program waits some quiet time, and a feed program follows its own actor's
/// subscription.
#[test]
fn a_trigger_is_refused_outside_its_bounds() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let memory = vault.memory(fixture.owner, EdgeActorClass::Human);
    let timer = ProgramTrigger::Timer {
        first_at: T0,
        every_secs: 3_600,
    };
    assert!(
        memory
            .arm_program(&fixture.input(Some(EntityId::now())), timer)
            .is_err()
    );
    for trigger in [
        ProgramTrigger::Timer {
            first_at: T0,
            every_secs: 30,
        },
        ProgramTrigger::Idle { quiet_secs: 0 },
        ProgramTrigger::Feed {
            subscription: EntityId::now(),
        },
    ] {
        assert!(
            memory.arm_program(&fixture.input(None), trigger).is_err(),
            "{trigger:?}"
        );
    }
    let first = memory
        .arm_program(&fixture.input(None), timer)
        .expect("arm");
    let again = memory
        .arm_program(&fixture.input(None), timer)
        .expect("arm again");
    assert!(first.newly_armed && !again.newly_armed);
    assert_eq!(first.registration, again.registration);
}

/// Authority is sealed at arm and judged again at each admission (B-3): a timer armed under a
/// live slip whose slip then expires is held for a rebind, as a turn's wake is (FIX 12058), and
/// runs nothing. Expiry is not a withdrawal, so the wake is held, not refused. The authority
/// clock moves through the `test-hooks` door, which `--all-features` builds.
#[cfg(feature = "test-hooks")]
#[test]
fn a_program_whose_sealed_slip_lapsed_holds_and_does_not_run() {
    use oneiron::authority::HostSlipIssuer;

    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let issuer = HostSlipIssuer::from_seed(&[0x37; 32]).expect("issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");

    const SLIP_TTL_SECS: u64 = 3_600;
    let issued_at = vault.capability_slip_now().expect("authority clock");
    let expires_at = issued_at + SLIP_TTL_SECS;
    let mut claims = root.claims.clone();
    claims.slip_id = [0x69; 32];
    claims.holder_ref = fixture.owner.to_hex();
    claims.actor_class = Some("human".into());
    claims.issued_at = issued_at;
    claims.expires_at = expires_at;
    claims.ttl_secs = SLIP_TTL_SECS;
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("the owner's slip");
    let challenge = b"turn-program-slip-lapse";
    let signature = issuer
        .binding_proof(&slip, challenge)
        .expect("holder proof");
    let binding = vault
        .bind_invocation_slip(&slip, challenge, &signature)
        .expect("bind the slip");
    let proof = vault.verify_invocation_slip(&binding).expect("live proof");

    vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof)
        .with_invocation_slip(&binding)
        .arm_program(
            &fixture.input(None),
            ProgramTrigger::Timer {
                first_at: expires_at,
                every_secs: 0,
            },
        )
        .expect("arm under the live slip");

    vault
        .advance_authority_clock_for_test(expires_at)
        .expect("expire the slip");
    assert!(vault.verify_invocation_slip(&binding).is_err());
    assert!(
        !vault
            .capability_slip_is_explicitly_revoked(&proof)
            .expect("revocation read"),
        "expiry is not a withdrawal"
    );

    assert_eq!(
        vault
            .release_timer_program_wakes(expires_at)
            .expect("release"),
        1
    );
    let drain = drain(&vault, expires_at);
    assert_eq!(
        (drain.admitted, drain.refused, drain.held),
        (0, 0, 1),
        "{drain:?}"
    );
}
