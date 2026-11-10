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
use oneiron::housekeeping::HousekeepingBudget;
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

/// Review #6982: a feed program's wake scan goes on from where the last release stopped, so a
/// run of changes its subscription does not take, longer than one release scans, delays the
/// wake and never hides the change it is shown behind them. 4,097 CODE_SYMBOLs (one more than a
/// release scans) stand before the PERSON.
#[test]
fn a_feed_program_wakes_for_a_change_behind_a_long_run_it_is_not_shown() {
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

    for chunk in 0..9 {
        let mut batch = vault.batch();
        for _ in 0..(if chunk < 8 { 512 } else { 1 }) {
            batch = batch.put(
                &EntityId::now(),
                ENTITY_TYPE_CODE_SYMBOL,
                TimeRange { start: 1, end: 1 },
                1,
                b"symbol",
            );
        }
        batch.commit().expect("symbols");
    }
    put_person(&vault);

    let mut woken = Vec::new();
    for _ in 0..4 {
        woken.push(vault.release_feed_program_wakes(T0).expect("release"));
    }
    assert_eq!(
        woken.iter().sum::<usize>(),
        1,
        "the PERSON wakes it once, after the run: {woken:?}"
    );
}

/// Review #6982: a pass admits a bounded number of owed wakes, and a later pass admits the rest
/// even when it records no new wake. 257 one-shot timers, all due, are one more than a pass
/// admits; two housekeeping passes leave none owed.
#[test]
fn a_later_pass_admits_the_wakes_an_earlier_pass_left_owed() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    for due in 0..257 {
        fixture.arm(
            &vault,
            ProgramTrigger::Timer {
                first_at: 1_000 + due,
                every_secs: 0,
            },
        );
    }
    for _ in 0..2 {
        vault
            .housekeeping(HousekeepingBudget::unbounded())
            .expect("housekeeping");
    }
    let left = drain(&vault, T0);
    assert_eq!(
        (left.admitted, left.refused, left.held),
        (0, 0, 0),
        "no wake is left owed: {left:?}"
    );
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

/// Review #6982 round 2 (F1): a Proposed CLAIM served by the recorded lane wakes its feed
/// program once, even though the default Surfaceable lane would withhold it.
#[test]
fn a_feed_program_wakes_for_a_proposed_claim_it_is_shown() {
    use oneiron::registry::ENTITY_TYPE_CLAIM;
    use oneiron::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};

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
                    entity_types: vec![ENTITY_TYPE_CLAIM],
                    predicates: Vec::new(),
                },
                start: FeedStart::Head,
            },
        )
        .expect("subscribe to claim changes")
        .subscription;
    fixture.arm(&vault, ProgramTrigger::Feed { subscription });
    vault.release_feed_program_wakes(T0).expect("settle arming");
    drain(&vault, T0);

    let claim = EntityId::now();
    let body = ClaimBody::new(
        "fixture.proposed",
        ClaimSubject::Entity(fixture.owner),
        rmpv::Value::from("a proposed claim"),
        0.8,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .expect("build the proposed claim");
    vault
        .put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("put the proposed claim");

    let recorded = lane.recorded_lane().expect("the owner's recorded lane");
    let FeedRead::Page(page) = vault
        .feed_read(
            &recorded,
            &FeedReadRequest {
                subscription,
                limit: None,
            },
        )
        .expect("read proposed claim changes")
    else {
        panic!("the claim subscription returns a page");
    };
    assert!(
        page.entries.iter().any(|entry| entry.entity == claim),
        "the recorded lane is shown the proposed claim: {page:?}"
    );
    assert_eq!(
        vault.release_feed_program_wakes(T0).expect("release"),
        1,
        "a proposed claim the recorded lane is shown wakes its program"
    );
    assert_eq!(
        vault.release_feed_program_wakes(T0).expect("release again"),
        0,
        "the same proposed claim wakes its program only once"
    );
}

fn put_diary(vault: &Vault, author: EntityId, markdown: &str) -> EntityId {
    use oneiron::note::{NoteKind, NoteScope, NoteWriteEnvelope};

    let receipt = vault
        .memory(author, EdgeActorClass::Human)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: author },
            markdown: markdown.into(),
            source_revision_ref: [0x7a; 16],
            mask: None,
        })
        .expect("author a private diary note");
    EntityId::from_hex(&receipt.id_hex).expect("the diary receipt's note id")
}

// Both endpoints are readable through a different, consented pair. That pair must not
// authorize the edge this test will add between the owner's other diary and the foreign one.
fn readable_diary_pair(vault: &Vault, fixture: &Fixture) -> (EntityId, EntityId, EntityId) {
    let other_author = EntityId::now();
    vault
        .put_entity(
            &other_author,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"other diary author",
        )
        .expect("put the other diary author");
    let owner_diary = put_diary(vault, fixture.owner, "the owner's separate private thought");
    let other_diary = put_diary(vault, other_author, "the other author's private thought");
    let consented_diary = put_diary(vault, fixture.owner, "the owner's consented private thought");
    let owner = vault.memory(fixture.owner, EdgeActorClass::Human);
    let other = vault.memory(other_author, EdgeActorClass::Human);
    owner
        .link_diary_coreference(consented_diary, other_diary)
        .expect("link the separate consented diary pair");
    owner
        .grant_diary_coreference(consented_diary, other_diary)
        .expect("the owner's consent for the separate pair");
    other
        .grant_diary_coreference(consented_diary, other_diary)
        .expect("the other author's consent for the separate pair");
    (other_author, owner_diary, other_diary)
}

fn read_feed_page(
    vault: &Vault,
    lane: &oneiron::claim::ScopedRead<'_>,
    subscription: EntityId,
) -> oneiron::feeds::FeedPage {
    let FeedRead::Page(page) = vault
        .feed_read(
            lane,
            &FeedReadRequest {
                subscription,
                limit: None,
            },
        )
        .expect("read the feed page")
    else {
        panic!("the live subscription returns a page");
    };
    page
}

fn feed_has_diary_pair(page: &oneiron::feeds::FeedPage, a: EntityId, b: EntityId) -> bool {
    page.entries.iter().any(|entry| {
        entry.edge.as_ref().is_some_and(|edge| {
            edge.kind == oneiron::EdgeKind::SameAs.name()
                && ((edge.source == a && edge.target == b)
                    || (edge.source == b && edge.target == a))
        })
    })
}

/// Review #6981 round 1, finding 1 (F2): a SameAs edge between different authors' diaries
/// is withheld in both directions without that pair's consent, even when both ends are readable.
#[test]
fn an_edge_between_diaries_without_their_consent_is_not_in_the_feed() {
    use oneiron::registry::ENTITY_TYPE_NOTE;

    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let (_other_author, note_a, note_b) = readable_diary_pair(&vault, &fixture);
    let owner = vault.memory(fixture.owner, EdgeActorClass::Human);
    let lane = vault.scoped_read(owner.read_key().expect("the owner's read key"));
    assert!(
        lane.is_entity_readable(&note_a)
            .expect("read the owner's diary"),
        "the owner is shown the first endpoint before the unconsented link"
    );
    assert!(
        lane.is_entity_readable(&note_b)
            .expect("read the other diary"),
        "the separate consented pair makes the second endpoint readable"
    );
    let subscription = vault
        .feed_subscribe(
            &lane,
            &FeedSubscribeRequest {
                selector: FeedSelector {
                    sources: vec![FeedSource::Edges],
                    kinds: Vec::new(),
                    entity_types: vec![ENTITY_TYPE_NOTE],
                    predicates: Vec::new(),
                },
                start: FeedStart::Head,
            },
        )
        .expect("subscribe to diary edges")
        .subscription;
    fixture.arm(&vault, ProgramTrigger::Feed { subscription });
    vault.release_feed_program_wakes(T0).expect("settle arming");
    drain(&vault, T0);

    owner
        .link_diary_coreference(note_a, note_b)
        .expect("link the diary pair without its consent");
    let (left, right) = if note_a < note_b {
        (note_a, note_b)
    } else {
        (note_b, note_a)
    };
    assert!(
        vault
            .edge_exists(&left, oneiron::EdgeKind::SameAs, &right)
            .expect("read the stored diary link"),
        "the opaque link acknowledgement really stored the unconsented pair"
    );
    let page = read_feed_page(&vault, &lane, subscription);
    assert!(
        !feed_has_diary_pair(&page, note_a, note_b),
        "neither direction of the unconsented diary pair is in the feed: {page:?}"
    );
    assert_eq!(
        vault.release_feed_program_wakes(T0).expect("release"),
        0,
        "the unconsented pair wakes no program despite readable endpoints"
    );
}

/// Review #6981 round 1, findings 1 and 2 (F2/F3): exact mutual consent reveals a diary
/// edge already scanned while hidden, and wakes it once within four releases with no new edge.
#[test]
fn an_edge_between_diaries_is_shown_once_they_consent_and_wakes_the_program() {
    use oneiron::registry::ENTITY_TYPE_NOTE;

    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let (other_author, note_a, note_b) = readable_diary_pair(&vault, &fixture);
    let owner = vault.memory(fixture.owner, EdgeActorClass::Human);
    let other = vault.memory(other_author, EdgeActorClass::Human);
    let lane = vault.scoped_read(owner.read_key().expect("the owner's read key"));
    assert!(
        lane.is_entity_readable(&note_a)
            .expect("read the owner's diary"),
        "the owner is shown the first endpoint before the unconsented link"
    );
    assert!(
        lane.is_entity_readable(&note_b)
            .expect("read the other diary"),
        "the separate consented pair makes the second endpoint readable"
    );
    let request = FeedSubscribeRequest {
        selector: FeedSelector {
            sources: vec![FeedSource::Edges],
            kinds: Vec::new(),
            entity_types: vec![ENTITY_TYPE_NOTE],
            predicates: Vec::new(),
        },
        start: FeedStart::Head,
    };
    let subscription = vault
        .feed_subscribe(&lane, &request)
        .expect("subscribe to diary edges")
        .subscription;
    fixture.arm(&vault, ProgramTrigger::Feed { subscription });
    vault.release_feed_program_wakes(T0).expect("settle arming");
    drain(&vault, T0);

    owner
        .link_diary_coreference(note_a, note_b)
        .expect("link the diary pair before its consent");
    let (left, right) = if note_a < note_b {
        (note_a, note_b)
    } else {
        (note_b, note_a)
    };
    assert!(
        vault
            .edge_exists(&left, oneiron::EdgeKind::SameAs, &right)
            .expect("read the stored diary link"),
        "the row exists before the wake scan passes it"
    );
    let hidden = read_feed_page(&vault, &lane, subscription);
    assert!(
        !feed_has_diary_pair(&hidden, note_a, note_b),
        "the pair is hidden before consent despite readable endpoints: {hidden:?}"
    );
    assert_eq!(
        vault
            .release_feed_program_wakes(T0)
            .expect("scan the hidden edge"),
        0,
        "the program scans past the hidden edge without a wake"
    );

    let after_link = vault
        .feed_subscribe(&lane, &request)
        .expect("watch for any new diary edge after the link")
        .subscription;
    owner
        .grant_diary_coreference(note_a, note_b)
        .expect("the owner's consent for this exact pair");
    let unilateral = read_feed_page(&vault, &lane, subscription);
    assert!(
        !feed_has_diary_pair(&unilateral, note_a, note_b),
        "one author's consent does not reveal the pair: {unilateral:?}"
    );
    assert_eq!(
        vault
            .release_feed_program_wakes(T0)
            .expect("release after one consent"),
        0,
        "one author's consent wakes nothing"
    );
    other
        .grant_diary_coreference(note_b, note_a)
        .expect("the other author's consent for this exact pair");
    let new_edges = read_feed_page(&vault, &lane, after_link);
    assert!(
        new_edges.entries.is_empty(),
        "consent writes no new edge the selector takes: {new_edges:?}"
    );
    let shown = read_feed_page(&vault, &lane, subscription);
    assert!(
        feed_has_diary_pair(&shown, note_a, note_b),
        "both consents reveal the original edge without acknowledging it: {shown:?}"
    );

    let mut woken = Vec::new();
    for _ in 0..4 {
        woken.push(
            vault
                .release_feed_program_wakes(T0)
                .expect("rejudge the scanned edge"),
        );
    }
    assert_eq!(
        woken.iter().sum::<usize>(),
        1,
        "the newly shown, already scanned edge wakes its program once: {woken:?}"
    );
}
