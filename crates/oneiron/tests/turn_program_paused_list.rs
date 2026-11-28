//! The paused programs a vault copy holds (FIX TURNPROGRAM-OCCURRENCE-ARMINGS-LIVE-ON-A-VAULT-COPY,
//! lead ruling 21 Nov): `vault.turn_programs.paused` lists them, one page at a time.
//!
//! The fixture arms, for the vault's owner, the three programs of `turn_program_copy_pause.rs`: a
//! timer that wakes once, a feed program and an idle program, all pinned to one active callable
//! SKILL, and one repeating timer for a second actor of class agent. It takes a checkpoint before
//! any release and restores it beside its source, so the copy holds all four paused at the
//! restore's time while the source holds none.
//!
//! - the verified owner reads every paused program of the copy, each with the registration, the
//!   actor, the trigger, a timer's next due time as it stood, when it was paused, and the pinned
//!   SKILL with its current name and description; the store's count reads beside the list;
//! - the SKILL's name and description are the record's current ones, while each row's pin is the
//!   revision armed;
//! - any other caller reads only its own paused programs, and the SKILL's fields are withheld
//!   unless the SKILL reads on its own lane;
//! - the list pages by cursor, and refuses a zero limit and a bad cursor.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turn_program_paused_list`.

#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::dreamer_runner::{
    ArmTurnProgram, PausedTurnProgramItem, PausedTurnProgramsRequest, PausedTurnProgramsView,
    ProgramTrigger, paused_turn_programs,
};
use oneiron::feeds::{FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest};
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::recovery::checkpoint::CheckpointKey;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::test_doors::steward::open_owner_carrier_vault;
use oneiron::test_support::{restore_tempdir, test_host_issuer};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// The fixture timer's due time.
const TIMER_DUE: u64 = 1_000;

/// The agent's repeating timer: its first due time.
const AGENT_FIRST_AT: u64 = 9_000;

/// The agent's repeating timer: its interval, a minute many times over, so the arming is valid.
const AGENT_EVERY_SECS: u64 = 3_600;

/// The `created_at` the checkpoint below is taken with.
const SNAPSHOT_AT: u64 = 100;

/// The `restored_at` the restore below passes: a copy the restore pauses names it.
const RESTORED_AT: u64 = 200;

/// The idle program's quiet time.
const QUIET_SECS: u64 = 600;

/// The SKILL's revised description in the current-fields test.
const REVISED_DESCRIPTION: &str = "Increment a number twice";

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

/// An owner vault a checkpoint can be taken of: rooted under the test host, with its data key
/// minted.
fn open_live(path: &Path) -> Vault {
    let vault = open_owner_carrier_vault(path).expect("an owner vault");
    vault.ensure_vault_key().expect("mint the vault data key");
    vault
}

/// The vault's owner and the callable its programs pin.
struct Armer {
    owner: EntityId,
    skill: EntityId,
}

impl Armer {
    /// The embedded owner of `vault` and a fresh active callable there.
    fn new(vault: &Vault) -> Self {
        Self {
            owner: vault.ensure_embedded_owner_actor().expect("the owner"),
            skill: active_callable_skill(vault),
        }
    }

    /// Arms the owner's program on `trigger` through the public door, as the in-process host's
    /// own caller; answers its registration.
    fn arm(&self, vault: &Vault, trigger: ProgramTrigger) -> EntityId {
        vault
            .memory(self.owner, EdgeActorClass::Human)
            .arm_turn_program(&ArmTurnProgram {
                skill: self.skill,
                executor: "fixture.executor@1".into(),
                args: serde_json::json!({"value": 41}),
                conversation: None,
                trigger,
                expected: None,
                project: None,
            })
            .expect("arm the program")
            .registration
    }

    /// Arms a timer that wakes once, at `due`.
    fn arm_timer(&self, vault: &Vault, due: u64) -> EntityId {
        self.arm(
            vault,
            ProgramTrigger::Timer {
                first_at: due,
                every_secs: 0,
            },
        )
    }
}

/// The owner's three programs on a vault: each registration, and the feed program's subscription.
struct Seeded {
    timer: EntityId,
    feed: EntityId,
    idle: EntityId,
    subscription: EntityId,
}

/// Arms the owner's three programs on `vault`: a timer due at [`TIMER_DUE`], a feed program on a
/// change subscription of the owner's own taken at the head, and an idle program that waits
/// [`QUIET_SECS`]. Then writes a PERSON, an entry past the subscription's cursor that the owner's
/// lane is shown. Answers each registration with the subscription.
fn seed_owner_programs(vault: &Vault, armer: &Armer) -> Seeded {
    let lane = vault.scoped_read(
        ScopedReadActorKey::with_actor_class(armer.owner.to_hex(), "human")
            .expect("the owner's lane key"),
    );
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
        .expect("subscribe to the change feed")
        .subscription;
    let timer = armer.arm_timer(vault, TIMER_DUE);
    let feed = armer.arm(vault, ProgramTrigger::Feed { subscription });
    let idle = armer.arm(
        vault,
        ProgramTrigger::Idle {
            quiet_secs: QUIET_SECS,
        },
    );
    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("the feed's entry");
    Seeded {
        timer,
        feed,
        idle,
        subscription,
    }
}

/// Arms the agent's repeating timer on `vault` through the public door, as the in-process host's
/// own caller, pinned to the fixture SKILL: first at [`AGENT_FIRST_AT`], then every
/// [`AGENT_EVERY_SECS`]. Answers its registration.
fn arm_agent_timer(vault: &Vault, agent: EntityId, skill: EntityId) -> EntityId {
    vault
        .memory(agent, EdgeActorClass::Agent)
        .arm_turn_program(&ArmTurnProgram {
            skill,
            executor: "fixture.executor@1".into(),
            args: serde_json::json!({"value": 41}),
            conversation: None,
            trigger: ProgramTrigger::Timer {
                first_at: AGENT_FIRST_AT,
                every_secs: AGENT_EVERY_SECS,
            },
            expected: None,
            project: None,
        })
        .expect("arm the agent's timer")
        .registration
}

/// Takes `live`'s checkpoint at `image`, with the programs armed and none released; answers
/// the key the image opens with.
fn snapshot_live(live: &Vault, image: &Path) -> CheckpointKey {
    let key = live.checkpoint_key().expect("derive the checkpoint key");
    live.snapshot_checkpoint(image, SNAPSHOT_AT)
        .expect("the checkpoint, with the programs armed");
    key
}

/// Gives a restored or reopened vault what a serving host holds: a device keystore and the
/// test host's root, as `restored_machine_join_guards.rs` gives its copies.
fn serve(vault: &Vault) {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
}

/// The paused-list fixture: the source vault, the copy restored beside it, and every id the
/// tests name. The copy holds all four programs paused at [`RESTORED_AT`]; the source holds none.
struct Fixture {
    _dir: tempfile::TempDir,
    live: Vault,
    copy: Vault,
    owner: EntityId,
    agent: EntityId,
    other: EntityId,
    skill: EntityId,
    timer: EntityId,
    feed: EntityId,
    idle: EntityId,
    agent_timer: EntityId,
    feed_subscription: EntityId,
}

/// Builds the paused-list fixture: the owner's three programs and the agent's repeating timer on
/// a live vault (with a third actor that arms nothing), a checkpoint of it, and the copy restored
/// beside it at [`RESTORED_AT`], served as a host serves it.
fn fixture() -> Fixture {
    let dir = restore_tempdir();
    let live = open_live(&dir.path().join("vault"));
    let armer = Armer::new(&live);
    let agent = live
        .ensure_agent_principal("paused-list-agent")
        .expect("the agent principal");
    let other = live
        .ensure_agent_principal("paused-list-other")
        .expect("the third actor");
    let seeded = seed_owner_programs(&live, &armer);
    let agent_timer = arm_agent_timer(&live, agent, armer.skill);
    let image = dir.path().join("image");
    let key = snapshot_live(&live, &image);
    let (copy, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &dir.path().join("copy"),
        VaultConfig::device(),
        &live.side_restore_source().expect("the restore's source"),
        RESTORED_AT,
    )
    .expect("restore the checkpoint beside its source");
    serve(&copy);
    Fixture {
        _dir: dir,
        live,
        copy,
        owner: armer.owner,
        agent,
        other,
        skill: armer.skill,
        timer: seeded.timer,
        feed: seeded.feed,
        idle: seeded.idle,
        agent_timer,
        feed_subscription: seeded.subscription,
    }
}

/// The paused programs `actor` reads on `vault` with `request`.
fn paused(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    request: &PausedTurnProgramsRequest,
) -> PausedTurnProgramsView {
    let memory = vault.memory(actor, class);
    paused_turn_programs(&memory, request).expect("list the paused programs")
}

/// The withheld fields of a row, as text.
fn withheld(row: &PausedTurnProgramItem) -> Vec<&str> {
    row.withheld.iter().map(String::as_str).collect()
}

/// The verified owner reads every paused program of the copy: the count, the rows in actor then
/// registration order, each with its armer, its trigger, its timer's due time as it stood, when
/// it was paused, and the pinned SKILL with its current name and description. The store's count
/// reads beside the list; the source vault holds none paused and lists none.
#[test]
fn the_owner_reads_every_paused_program_of_the_copy() {
    let fixture = fixture();
    let view = paused(
        &fixture.copy,
        fixture.owner,
        EdgeActorClass::Human,
        &PausedTurnProgramsRequest::default(),
    );
    assert_eq!(view.paused, 4, "the owner reads all four paused programs");
    assert_eq!(view.programs.len(), 4, "one page holds all four");
    assert_eq!(view.next_cursor, None, "no page follows");

    let keys: Vec<(EntityId, EntityId)> = view
        .programs
        .iter()
        .map(|row| (row.actor, row.registration))
        .collect();
    let mut ordered = keys.clone();
    ordered.sort();
    assert_eq!(
        keys, ordered,
        "rows come in actor order, then registration order"
    );
    let registrations: BTreeSet<EntityId> =
        view.programs.iter().map(|row| row.registration).collect();
    assert_eq!(
        registrations,
        BTreeSet::from([
            fixture.timer,
            fixture.feed,
            fixture.idle,
            fixture.agent_timer,
        ]),
        "the rows are the four armed, neither more nor fewer"
    );

    for row in &view.programs {
        assert_eq!(
            row.paused_at, RESTORED_AT,
            "the restore's time paused each row"
        );
        let (actor, class, trigger, next_due) = if row.registration == fixture.timer {
            (
                fixture.owner,
                "human",
                ProgramTrigger::Timer {
                    first_at: TIMER_DUE,
                    every_secs: 0,
                },
                Some(TIMER_DUE),
            )
        } else if row.registration == fixture.feed {
            (
                fixture.owner,
                "human",
                ProgramTrigger::Feed {
                    subscription: fixture.feed_subscription,
                },
                None,
            )
        } else if row.registration == fixture.idle {
            (
                fixture.owner,
                "human",
                ProgramTrigger::Idle {
                    quiet_secs: QUIET_SECS,
                },
                None,
            )
        } else {
            assert_eq!(
                row.registration, fixture.agent_timer,
                "every row is one of the four armed"
            );
            (
                fixture.agent,
                "agent",
                ProgramTrigger::Timer {
                    first_at: AGENT_FIRST_AT,
                    every_secs: AGENT_EVERY_SECS,
                },
                Some(AGENT_FIRST_AT),
            )
        };
        assert_eq!(row.actor, actor, "the row names its armer");
        assert_eq!(row.actor_class, class, "the row names its armer's class");
        assert_eq!(row.trigger, trigger, "the row names what wakes it");
        assert_eq!(
            row.next_due, next_due,
            "a timer keeps the due time it had; no other trigger names one"
        );
    }

    for row in &view.programs {
        let definition = row
            .definition
            .as_ref()
            .expect("the owner reads the pinned SKILL");
        assert_eq!(
            definition.skill, fixture.skill,
            "the pin names the fixture SKILL"
        );
        assert_eq!(definition.version, "1", "the pin names the revision armed");
        assert_eq!(
            row.skill_name.as_deref(),
            Some("fixture.callable"),
            "the SKILL's name now"
        );
        assert_eq!(
            row.skill_description.as_deref(),
            Some("Increment a number"),
            "the SKILL's description now"
        );
        assert!(
            row.withheld.is_empty(),
            "the owner is withheld nothing: {:?}",
            row.withheld
        );
    }

    assert_eq!(
        fixture
            .copy
            .paused_turn_program_count()
            .expect("count the copy's paused programs"),
        4,
        "the copy holds four paused"
    );
    assert_eq!(
        fixture
            .live
            .paused_turn_program_count()
            .expect("count the source's paused programs"),
        0,
        "the source holds none paused"
    );
    let live = paused(
        &fixture.live,
        fixture.owner,
        EdgeActorClass::Human,
        &PausedTurnProgramsRequest::default(),
    );
    assert_eq!(live.paused, 0, "the source lists none paused");
    assert!(live.programs.is_empty(), "the source lists no row");
    assert_eq!(live.next_cursor, None, "no page follows on the source");
}

/// The paused list shows the SKILL's name and description as they read now: after the SKILL's
/// record is revised, every row carries the new description, while each row's pin is still the
/// revision armed.
#[test]
fn the_paused_list_shows_the_skills_current_description_beside_its_pinned_revision() {
    let fixture = fixture();
    let before = paused(
        &fixture.copy,
        fixture.owner,
        EdgeActorClass::Human,
        &PausedTurnProgramsRequest::default(),
    );
    assert_eq!(
        before.programs.len(),
        4,
        "the owner reads all four before the revision"
    );
    for row in &before.programs {
        assert_eq!(
            row.skill_description.as_deref(),
            Some("Increment a number"),
            "the SKILL's description before the revision"
        );
    }
    let pins: Vec<(String, String)> = before
        .programs
        .iter()
        .map(|row| {
            let definition = row
                .definition
                .as_ref()
                .expect("the owner reads the pinned SKILL");
            (definition.version.clone(), definition.content_hash.clone())
        })
        .collect();

    let mut record = fixture
        .copy
        .get_skill_record(&fixture.skill)
        .expect("read the SKILL record")
        .expect("the fixture SKILL");
    record.desc = REVISED_DESCRIPTION.into();
    record.version = "2".into();
    fixture
        .copy
        .update_skill_record(&fixture.skill, &record, TimeRange { start: 3, end: 3 }, 3)
        .expect("revise the SKILL's description");

    let after = paused(
        &fixture.copy,
        fixture.owner,
        EdgeActorClass::Human,
        &PausedTurnProgramsRequest::default(),
    );
    assert_eq!(after.paused, 4, "the revision pauses and resumes nothing");
    assert_eq!(after.programs.len(), 4, "the owner still reads all four");
    for (row, (version, content_hash)) in after.programs.iter().zip(&pins) {
        assert_eq!(
            row.skill_description.as_deref(),
            Some(REVISED_DESCRIPTION),
            "every row carries the description as it reads now"
        );
        assert_eq!(
            row.skill_name.as_deref(),
            Some("fixture.callable"),
            "the name reads as it reads now"
        );
        let definition = row
            .definition
            .as_ref()
            .expect("the owner reads the pinned SKILL");
        assert_eq!(
            &definition.version, version,
            "the pin keeps the revision armed"
        );
        assert_eq!(
            &definition.content_hash, content_hash,
            "the pin keeps the content hash armed"
        );
    }
}

/// Any other caller reads only its own paused programs: the agent reads its timer alone, with the
/// SKILL's fields withheld, since the SKILL does not read on its lane; a third actor reads none.
#[test]
fn an_actor_reads_only_its_own_paused_programs() {
    let fixture = fixture();
    let view = paused(
        &fixture.copy,
        fixture.agent,
        EdgeActorClass::Agent,
        &PausedTurnProgramsRequest::default(),
    );
    assert_eq!(view.paused, 1, "the agent reads one paused program");
    assert_eq!(view.programs.len(), 1, "the agent reads one row");
    assert_eq!(view.next_cursor, None, "no page follows");
    let row = &view.programs[0];
    assert_eq!(
        row.registration, fixture.agent_timer,
        "the row is the agent's timer"
    );
    assert_eq!(row.actor, fixture.agent, "the row names the agent");
    assert_eq!(row.actor_class, "agent", "the row names the agent's class");
    assert_eq!(
        row.paused_at, RESTORED_AT,
        "the restore's time paused the row"
    );
    assert_eq!(
        row.trigger,
        ProgramTrigger::Timer {
            first_at: AGENT_FIRST_AT,
            every_secs: AGENT_EVERY_SECS,
        },
        "the row names what wakes it"
    );
    assert_eq!(
        row.next_due,
        Some(AGENT_FIRST_AT),
        "the timer keeps the due time it had"
    );
    assert!(
        row.definition.is_none(),
        "the pin is withheld from the agent"
    );
    assert!(
        row.skill_name.is_none(),
        "the name is withheld from the agent"
    );
    assert!(
        row.skill_description.is_none(),
        "the description is withheld from the agent"
    );
    assert_eq!(
        withheld(row),
        ["definition", "skill_name", "skill_description"],
        "the row names what it withholds"
    );

    let view = paused(
        &fixture.copy,
        fixture.other,
        EdgeActorClass::Agent,
        &PausedTurnProgramsRequest::default(),
    );
    assert_eq!(view.paused, 0, "a third actor reads none paused");
    assert!(view.programs.is_empty(), "a third actor reads no row");
    assert_eq!(view.next_cursor, None, "no page follows for a third actor");
}

/// The paused list pages by cursor: pages of one walk the whole list in order, each carrying the
/// whole count and naming its last row; a zero limit and a bad cursor are refused.
#[test]
fn the_paused_list_pages_by_cursor() {
    let fixture = fixture();
    let unpaged = paused(
        &fixture.copy,
        fixture.owner,
        EdgeActorClass::Human,
        &PausedTurnProgramsRequest::default(),
    );
    assert_eq!(unpaged.programs.len(), 4, "the unpaged list holds all four");
    let unpaged_keys: Vec<(EntityId, EntityId)> = unpaged
        .programs
        .iter()
        .map(|row| (row.actor, row.registration))
        .collect();

    let mut cursor: Option<String> = None;
    let mut paged: Vec<(EntityId, EntityId)> = Vec::new();
    let mut pages = 0;
    loop {
        let view = paused(
            &fixture.copy,
            fixture.owner,
            EdgeActorClass::Human,
            &PausedTurnProgramsRequest {
                cursor: cursor.clone(),
                limit: Some(1),
            },
        );
        assert_eq!(view.paused, 4, "every page carries the whole count");
        assert_eq!(view.programs.len(), 1, "a page holds one row");
        pages += 1;
        let row = view.programs[0].clone();
        paged.push((row.actor, row.registration));
        match view.next_cursor {
            Some(next) => {
                assert_eq!(next.len(), 64, "a cursor is 64 hex characters");
                assert!(
                    next.chars().all(|digit| digit.is_ascii_hexdigit()),
                    "a cursor is 64 hex characters: {next}"
                );
                assert_eq!(
                    next,
                    format!("{}{}", row.actor.to_hex(), row.registration.to_hex()),
                    "the cursor names the page's last row"
                );
                cursor = Some(next);
            }
            None => break,
        }
    }
    assert_eq!(pages, 4, "four rows in pages of one");
    assert_eq!(paged, unpaged_keys, "page order is the list's order");

    let first = paused(
        &fixture.copy,
        fixture.owner,
        EdgeActorClass::Human,
        &PausedTurnProgramsRequest {
            cursor: None,
            limit: Some(3),
        },
    );
    assert_eq!(first.paused, 4, "every page carries the whole count");
    assert_eq!(first.programs.len(), 3, "the first page holds three rows");
    let cursor = first
        .next_cursor
        .clone()
        .expect("more rows follow the first page");
    let second = paused(
        &fixture.copy,
        fixture.owner,
        EdgeActorClass::Human,
        &PausedTurnProgramsRequest {
            cursor: Some(cursor),
            limit: Some(3),
        },
    );
    assert_eq!(second.paused, 4, "every page carries the whole count");
    assert_eq!(
        second.programs.len(),
        1,
        "the second page holds the last row"
    );
    assert_eq!(second.next_cursor, None, "no page follows the last row");

    let memory = fixture.copy.memory(fixture.owner, EdgeActorClass::Human);
    let error = paused_turn_programs(
        &memory,
        &PausedTurnProgramsRequest {
            cursor: None,
            limit: Some(0),
        },
    )
    .expect_err("a zero limit is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    for cursor in ["zz".to_owned(), "zz".repeat(32)] {
        let error = paused_turn_programs(
            &memory,
            &PausedTurnProgramsRequest {
                cursor: Some(cursor),
                limit: None,
            },
        )
        .expect_err("a bad cursor is refused");
        assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
        assert_eq!(error.message, "cursor must be 64 hex characters");
    }
}
