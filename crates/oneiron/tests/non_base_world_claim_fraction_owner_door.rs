//! ARCH-0004 #world-scope: "The non-base fraction is a budget knob, and the
//! vault owner sets it" (FIX WORLD-SHARE-FRACTION-NO-OWNER-DOOR). The owner
//! sets the fraction through `vault.settings.non_base_world_claim_fraction.set`
//! and reads it back through `vault.settings.non_base_world_claim_fraction`;
//! the next context pack that names no fraction of its own holds its
//! non-base claims to it. A fraction outside 0 to 1, and a caller other than
//! the owner, are refused with nothing written. A change records the owner's
//! act, and a set that changes nothing records none. The fraction survives a
//! reopen. An agent reads it only while it holds an `engine.controls` class,
//! and never sets it.
//!
//! Every door is reached by its verb name and every read through a public
//! door that main already has, so this file builds on a tree without the
//! doors and fails there at the first verb call.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test non_base_world_claim_fraction_owner_door`.
#![cfg(oneiron_test_support)]

use std::path::Path;

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::pipeline::WorldScope;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERBS, coach, define_agent};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, open_owner_carrier_vault, stand_steward_grant,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use serde_json::{Value, json};

const READ: &str = "vault.settings.non_base_world_claim_fraction";
const SET: &str = "vault.settings.non_base_world_claim_fraction.set";
/// The owner act's setting name (`PolicySetting::as_str`).
const SETTING: &str = "settings.non_base_world_claim_fraction";
const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

fn config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = QUERY.len();
    config.embedding_model = Some("test/model@v1".to_owned());
    config
}

/// Opens the vault this process owns (the writer lease), as an embedded
/// host does at each start, so the owner's handle carries the owner's proof.
fn open_owned(path: &Path) -> (Vault, EntityId) {
    let vault = Vault::open_owned(path, config()).expect("an owned vault");
    oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    (vault, owner)
}

fn call(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    input: Value,
) -> MemoryResult<Value> {
    invoke(&vault.memory(actor, class), verb, input)
}

/// The owner's acts on this setting, as this install recorded them.
fn fraction_acts(vault: &Vault) -> usize {
    vault
        .policy_setting_acts()
        .expect("the owner's setting acts")
        .iter()
        .filter(|receipt| receipt.setting.as_str() == SETTING)
        .count()
}

/// Two base claims below three story-world claims, by cosine to [`QUERY`].
struct Claims {
    story: [EntityId; 3],
    base: [EntityId; 2],
}

fn seed_claims(vault: &Vault) -> Claims {
    let occurred = TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    };
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            occurred,
            LEARNED_AT,
            b"subject",
        )
        .expect("subject entity");
    let story_world = EntityId::now();
    let claims = Claims {
        story: [EntityId::now(), EntityId::now(), EntityId::now()],
        base: [EntityId::now(), EntityId::now()],
    };
    let rows: [(EntityId, Option<EntityId>, [f32; 4]); 5] = [
        (claims.story[0], Some(story_world), [0.99, 0.141, 0.0, 0.0]),
        (claims.story[1], Some(story_world), [0.98, 0.199, 0.0, 0.0]),
        (claims.story[2], Some(story_world), [0.97, 0.243, 0.0, 0.0]),
        (claims.base[0], None, [0.9, 0.436, 0.0, 0.0]),
        (claims.base[1], None, [0.8, 0.6, 0.0, 0.0]),
    ];
    for &(id, world, _) in &rows {
        let mut body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            rmpv::Value::from(format!("harbor note {}", id.to_hex())),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        body.source = Some(ClaimSource::UserStated);
        body.world = world;
        vault
            .put_claim(&id, &body, occurred, LEARNED_AT)
            .expect("seed claim");
    }
    let mut vectors = vault.batch();
    for (id, _, vector) in &rows {
        vectors = vectors.vector(id, vector);
    }
    vectors.commit().expect("seed vectors");
    claims
}

impl Claims {
    /// The seeded claim ids of one `All`-scope pack, in pack order; with
    /// `fraction`, the caller names the pack's own share.
    fn pack(&self, vault: &Vault, fraction: Option<f32>) -> Vec<EntityId> {
        let mut builder = vault
            .context_pack()
            .search_vector(&QUERY, 10)
            .world(WorldScope::All)
            .limit(10);
        if let Some(fraction) = fraction {
            builder = builder.non_base_world_claim_fraction(fraction);
        }
        let pack = builder.run().expect("context pack");
        let seeded: Vec<EntityId> = self.story.iter().chain(&self.base).copied().collect();
        pack.results
            .iter()
            .map(|entity| entity.id)
            .filter(|id| seeded.contains(id))
            .collect()
    }
}

/// The owner reads the default, sets 1 and then 0, and each next pack holds
/// its story claims to the owner's fraction; refused sets write and record
/// nothing; the fraction and the owner's acts survive a reopen.
#[test]
fn the_owner_sets_the_fraction_and_the_next_pack_reads_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = open_owned(dir.path());
    let human = EdgeActorClass::Human;
    let claims = seed_claims(&vault);
    let [story_1, story_2, story_3] = claims.story;
    let [base_1, base_2] = claims.base;

    // Unset: the default share. On a tree without the door, the test fails
    // here.
    let read = call(&vault, owner, human, READ, json!({})).expect("the owner reads the fraction");
    assert_eq!(
        read,
        json!({ "fraction": 0.5 }),
        "unset reads as the default"
    );
    assert_eq!(
        claims.pack(&vault, None),
        [base_1, base_2, story_1, story_2],
        "the default share keeps two story claims beside two base claims"
    );
    assert_eq!(fraction_acts(&vault), 0);

    // The owner lifts the cap: the next pack keeps every story claim.
    let set =
        call(&vault, owner, human, SET, json!({ "fraction": 1.0 })).expect("the owner sets 1");
    assert_eq!(set, json!({ "fraction": 1.0 }));
    let read = call(&vault, owner, human, READ, json!({})).expect("the owner reads it back");
    assert_eq!(read, json!({ "fraction": 1.0 }));
    assert_eq!(
        claims.pack(&vault, None),
        [base_1, base_2, story_1, story_2, story_3],
        "the owner's fraction 1 keeps every story claim"
    );
    assert_eq!(
        claims.pack(&vault, Some(0.5)),
        [base_1, base_2, story_1, story_2],
        "a caller that names its own share keeps it"
    );
    assert_eq!(
        fraction_acts(&vault),
        1,
        "the change records the owner's act"
    );

    // Refused: out of range, and a caller that is not the owner. Nothing is
    // written or recorded.
    for fraction in [1.5, -0.25] {
        let refused = call(&vault, owner, human, SET, json!({ "fraction": fraction }))
            .expect_err("a fraction outside 0 to 1");
        assert_eq!(
            refused.code, MEMORY_CODE_BAD_REQUEST,
            "{fraction}: {refused:?}"
        );
    }
    let agent = define_agent(&vault).expect("an agent");
    let refused = call(
        &vault,
        agent,
        EdgeActorClass::Agent,
        SET,
        json!({ "fraction": 0.0 }),
    )
    .expect_err("an agent never sets the owner's fraction");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    let refused = call(&vault, agent, EdgeActorClass::Agent, READ, json!({}))
        .expect_err("an agent with no engine.controls class reads nothing");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    let read = call(&vault, owner, human, READ, json!({})).expect("the owner reads");
    assert_eq!(
        read,
        json!({ "fraction": 1.0 }),
        "a refused set changes nothing"
    );
    assert_eq!(fraction_acts(&vault), 1, "a refused set records nothing");

    // The same fraction again changes nothing and records nothing.
    let set =
        call(&vault, owner, human, SET, json!({ "fraction": 1.0 })).expect("the same fraction");
    assert_eq!(set, json!({ "fraction": 1.0 }));
    assert_eq!(
        fraction_acts(&vault),
        1,
        "an unchanged fraction records no act"
    );

    // Fraction 0: base reality alone.
    let set =
        call(&vault, owner, human, SET, json!({ "fraction": 0.0 })).expect("the owner sets 0");
    assert_eq!(set, json!({ "fraction": 0.0 }));
    assert_eq!(
        claims.pack(&vault, None),
        [base_1, base_2],
        "the owner's fraction 0 keeps base reality alone"
    );
    assert_eq!(fraction_acts(&vault), 2);

    // A reopen reads the owner's fraction and keeps both acts.
    drop(vault);
    let (vault, owner) = open_owned(dir.path());
    let read = call(&vault, owner, human, READ, json!({})).expect("the owner reads after a reopen");
    assert_eq!(
        read,
        json!({ "fraction": 0.0 }),
        "the fraction survives a reopen"
    );
    assert_eq!(fraction_acts(&vault), 2, "the acts survive a reopen");
}

/// A holder of any `engine.controls` class reads the fraction, as every dial
/// read is (S66F-READ = C), and is refused once the class is gone. No holder
/// ever sets it: the set is the owner's alone.
#[test]
fn a_holder_of_an_engine_controls_class_reads_the_fraction_and_never_sets_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let agent = define_agent(&vault).expect("an agent");
    let class = EdgeActorClass::Agent;

    // No grant: refused.
    let refused = call(&vault, agent, class, READ, json!({})).expect_err("no grant");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");

    // One engine.controls class reads the fraction in force.
    stand_steward_grant(&vault, agent, &[ENGINE_CONTROLS_VERBS[0]]).expect("a class grant");
    let read = call(&vault, agent, class, READ, json!({})).expect("a class holder reads");
    assert_eq!(read, json!({ "fraction": 0.5 }));

    // The holder never sets it.
    let refused = call(&vault, agent, class, SET, json!({ "fraction": 1.0 }))
        .expect_err("the set is the owner's");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert_eq!(fraction_acts(&vault), 0, "a refused set records nothing");

    // The grant that replaces it names `read` alone: refused at the next read.
    stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB]).expect("a read grant");
    let refused = call(&vault, agent, class, READ, json!({}))
        .expect_err("`read` is not an engine.controls class");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
}
