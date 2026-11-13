//! OPUS-T0-F gate pins, PR 2 (Engine task 12 Nov 19:38): green pins for
//! eleven write gates of OPUS-GATECENSUS's DEEP list (census/GATE-CENSUS.md,
//! class GAP-PASSES: real callers pass the gate today, and no running test
//! drove it from a door). Each test drives the door a real caller uses, with
//! that caller's input, through the gate, and reads the write back. A pin
//! that goes red is a live refusal of a real caller (GAP-BROKEN).
//!
//! Each test name starts with its census ids, so `-- g380_` runs the pin of
//! G380 alone.
//!
//! - G171 `normalize_lexical_query_hints`, G380 `lexical_query_hint_target`
//!   and G434 `validate_lexical_query_hint`: a claim written with its
//!   prospective queries lands with one hint claim per normalized query.
//! - G422 `BatchBuilder::apply_with_gate_mode`: the same write applied in
//!   the caller's write transaction, as the Dreamer promotion writer does.
//! - G116 `validate_public_entity_type`: the owner's child project, a kind
//!   the vault registers at run time, lands through the public put door.
//! - G79 `typed_body::validate_actor`: a MACHINE births a typed body and
//!   edits it.
//! - G289 `stamp_replicated_row_birth_in_txn`: an own-device replay of a row
//!   keeps the birth it carries.
//! - G320 `stage_core_put`: the owner's core batch rewrites a PERSON.
//! - G78 `CommHeadWrites::before`: a bound raw put of a `comm.last_touch`
//!   claim lands its comm head.
//! - G392 `supersede_claim_for_code_run_trap` and G393
//!   `put_edge_for_code_run_trap`: the owner's code run supersedes its own
//!   claim and puts an edge.
//!
//! `cargo test --locked -p oneiron --all-features --test gate_pins_claim_producers`
//! (the lane's runner also sets `RUSTFLAGS="--cfg oneiron_test_support"`).
#![cfg(all(feature = "test-support", feature = "sync"))]

use oneiron::code_run::{
    HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfMemoryEdgeWriteResult,
    SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySupersedeClaimCall,
    SelfMemoryWriteResult,
};
use oneiron::comm::{
    CommClaimValue, PREDICATE_COMM_LAST_TOUCH, count_active_comm_claims,
    resolve_or_create_comm_party,
};
use oneiron::core_write::{CoreBatchEntityInput, CoreBatchWriteInput};
use oneiron::provenance::birth::RowBirth;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity_with_birth};
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, put_policy_manifest_bytes, test_host_issuer,
};
use oneiron::typed_body::TypedBodyWriter;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::write_envelope::claim_body::lexical_query_hint::{
    PREDICATE_LEXICAL_QUERY_HINT, decode_lexical_query_hint_value, lexical_query_hint_claim_id,
};
use oneiron::write_envelope::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, RawEntityPut, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed, so a red
/// pin names its door and the refusal's own words.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A PERSON row at a fresh id, as the claim and code-run fixtures seed one.
fn person(vault: &Vault) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
        .map_err(at("put a PERSON"))?;
    Ok(id)
}

/// A seeded vault, opened as most hosts and tests open one.
fn open_seeded() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
    Ok((dir, vault))
}

/// A vault with no policy manifest yet: the shipped default has no `comm.`
/// or `self.memory.` rule, so there those writes pend at the criticality
/// floor before the gate under test is read.
fn open_unseeded() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).map_err(at("open unseeded"))?;
    Ok((dir, vault))
}

/// The prospective queries a Dreamer extraction attaches to a claim: one
/// duplicate and one padded with spaces, which normalization folds away.
const HINTS: [&str; 3] = [
    "green tea preferences",
    "  matcha order history  ",
    "green tea preferences",
];

/// A claim about a fresh PERSON, stated by a PERSON, approved at write.
fn hinted_claim(vault: &Vault) -> TestResult<(ClaimCandidate, WriteEnvelope)> {
    let actor = WriteActor::new(person(vault)?, EdgeActorClass::Human);
    let subject = person(vault)?;
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("gate pin fixture")).map_err(at("provenance"))?,
        ClaimApprovalStatus::Auto,
    );
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    Ok((candidate, envelope))
}

/// The source claim holds one hint claim per normalized query, each at the
/// id its target and query derive.
fn assert_hint_claims_landed(vault: &Vault, claim: &EntityId) -> TestResult {
    let hints = vault
        .claims_for_subject(claim)
        .map_err(at("read the hint claims"))?;
    assert_eq!(hints.len(), 2, "one hint claim per normalized query");
    let mut queries = Vec::new();
    for hint in &hints {
        let stored = vault
            .get_claim(hint)
            .map_err(at("read a hint claim"))?
            .ok_or("a hint claim id reads nothing")?;
        assert_eq!(stored.predicate, PREDICATE_LEXICAL_QUERY_HINT);
        let value = decode_lexical_query_hint_value(&stored.value).map_err(at("decode a hint"))?;
        assert_eq!(value.target, *claim, "a hint names its source claim");
        assert_eq!(
            *hint,
            lexical_query_hint_claim_id(claim, &value.query).map_err(at("derive a hint id"))?,
            "a hint's id is derived from its target and query"
        );
        queries.push(value.query);
    }
    queries.sort();
    assert_eq!(queries, ["green tea preferences", "matcha order history"]);
    Ok(())
}

/// G171, G380 and G434: a claim written with its prospective queries
/// through the batch door's commit. The batch normalizes the hints (G171),
/// and each hint claim put is checked for its target (G380) and its derived
/// id (G434).
#[test]
fn g171_g380_g434_a_hinted_claim_lands_with_its_query_hints() -> TestResult {
    let (_dir, vault) = open_seeded()?;
    let (candidate, envelope) = hinted_claim(&vault)?;
    let claim = EntityId::now();
    vault
        .batch()
        .claim_candidate_with_lexical_hints(&claim, candidate, &envelope, range(10), 11, &HINTS)
        .commit()
        .map_err(at("the hinted claim's commit"))?;
    assert!(
        vault
            .get_claim(&claim)
            .map_err(at("read the claim"))?
            .is_some(),
        "the source claim landed"
    );
    assert_hint_claims_landed(&vault, &claim)
}

/// G422: the same hinted claim applied in the caller's own write
/// transaction, as the Dreamer promotion writer applies its batch
/// (`dreamer_promotion/writer.rs`). Only this terminal runs the batch's
/// apply gate.
#[test]
fn g422_a_hinted_claim_applied_in_a_write_txn_lands() -> TestResult {
    let (_dir, vault) = open_seeded()?;
    let (candidate, envelope) = hinted_claim(&vault)?;
    let claim = EntityId::now();
    vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .claim_candidate_with_lexical_hints(
                    &claim,
                    candidate,
                    &envelope,
                    range(10),
                    11,
                    &HINTS,
                )
                .apply(wtxn)
        })
        .map_err(at("the batch's apply"))?;
    assert!(
        vault
            .get_claim(&claim)
            .map_err(at("read the claim"))?
            .is_some(),
        "the source claim landed"
    );
    assert_hint_claims_landed(&vault, &claim)
}

/// G116: the owner puts a child project of the root, led by the owner. A
/// PROJECT is a kind the vault registers at run time, so its put takes the
/// gate's runtime-kind arm, which refuses only a project revision.
#[test]
fn g116_the_owners_child_project_lands() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).map_err(at("open owned"))?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let root = vault.root_project().map_err(at("root project"))?;
    let child = EntityId::now();
    let record =
        ProjectRecord::new(child, Some(root), root, owner).map_err(at("the project record"))?;
    vault
        .put_project(child, &record, 1)
        .map_err(at("the owner's project put"))?;
    assert!(
        vault
            .project(child)
            .map_err(at("read the project"))?
            .is_some(),
        "the child project reads back"
    );
    assert_eq!(
        vault.get_entity_type(&child).map_err(at("read the kind"))?,
        Some(vault.project_type_byte().map_err(at("the PROJECT byte"))?),
        "the row is a PROJECT"
    );
    Ok(())
}

/// The typed-body writer of `actor`, under one pin schema.
fn typed_writer(actor: WriteActor, made_by: &MadeBy) -> TypedBodyWriter<'_> {
    TypedBodyWriter {
        schema: "gate-pin.typed-body.v1",
        actor,
        made_by,
    }
}

/// G79: the Dreamer MACHINE births a typed body on an ASSET and then edits
/// it. Each commit checks that the writing actor is live and of its stored
/// class.
#[test]
fn g79_a_machine_births_and_edits_a_typed_body() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device()).map_err(at("open"))?;
    provision_engine_machines(&vault);
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    bind_host_owner(&vault, &test_host_issuer(), owner).map_err(at("owner host binding"))?;
    let dreamer = vault.dreamer_authority().map_err(at("Dreamer authority"))?;
    let entity = EntityId::now();
    vault
        .put_entity(&entity, ENTITY_TYPE_ASSET, range(7), 9, b"typed body pin")
        .map_err(at("put the ASSET"))?;
    let made_by = MadeBy {
        inputs: Vec::new(),
        process: MadeByProcess {
            actor: dreamer.entity_ref(),
            class: MadeByClass::Concluded,
            identity: "gate-pin-typed-body".to_owned(),
            version: "1".to_owned(),
            params_hash: "gate-pin".to_owned(),
        },
        at: 7,
        trigger: None,
    };
    vault
        .birth_typed_body(&entity, typed_writer(dreamer, &made_by), |document| {
            document
                .get_map("body")
                .insert("text", "born")
                .map_err(|_| oneiron::Error::InvariantViolation("typed body birth edit"))?;
            Ok(())
        })
        .map_err(at("the MACHINE's birth"))?;
    let born = vault
        .typed_body_head(&entity)
        .map_err(at("read the head"))?
        .ok_or("no typed body head after the birth")?;
    assert_eq!(born.commits, 1, "the birth is the body's first commit");
    vault
        .edit_typed_body(&entity, None, typed_writer(dreamer, &made_by), |document| {
            document
                .get_map("body")
                .insert("text", "edited")
                .map_err(|_| oneiron::Error::InvariantViolation("typed body edit"))?;
            Ok(())
        })
        .map_err(at("the MACHINE's edit"))?;
    let edited = vault
        .typed_body_head(&entity)
        .map_err(at("read the head"))?
        .ok_or("no typed body head after the edit")?;
    assert_eq!(edited.commits, 2, "the edit is the body's second commit");
    Ok(())
}

/// A PERSON body: a MessagePack map with its name.
fn person_body(name: &str) -> TestResult<Vec<u8>> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )?;
    Ok(body)
}

/// G289: an own-device sync replay of a PERSON row with the birth the row
/// carries, as the window ingest replays a row and its birth. The carried
/// birth is stamped in the transaction that admits the row. Its callers log
/// a refused birth and keep the row, so the pin reads the birth back.
#[test]
fn g289_a_replayed_row_keeps_its_carried_birth() -> TestResult {
    const T0: u64 = 1_773_532_800;
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open(dir.path(), config).map_err(at("open"))?;
    // A sync host installs its keystore and loads its signing keys before
    // replay enters a transaction.
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    vault
        .prepare_install_signing()
        .map_err(at("install signing"))?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let row = EntityId::now();
    let body = person_body("replayed pin person")?;
    let birth = RowBirth {
        made_by: MadeBy {
            inputs: Vec::new(),
            process: MadeByProcess {
                actor: WriteActor::new(owner, EdgeActorClass::Human).entity_ref(),
                class: MadeByClass::Stated,
                identity: "gate-pin-replay".to_owned(),
                version: "1".to_owned(),
                params_hash: "gate-pin".to_owned(),
            },
            at: T0,
            trigger: None,
        },
        content_hash: String::new(),
        withheld: Vec::new(),
        room_evidence: None,
    };
    replay_entity_with_birth(
        &vault,
        ReplicatedEntity {
            id: row,
            entity_type: ENTITY_TYPE_PERSON,
            occurred: range(T0),
            learned_at: T0,
            row_version: 0,
            body: &body,
        },
        Some(&birth),
        ImportTier::OwnDevice,
    )
    .map_err(at("the own-device replay"))?;
    assert_eq!(
        vault.get_entity_type(&row).map_err(at("read the row"))?,
        Some(ENTITY_TYPE_PERSON),
        "the replayed row landed"
    );
    assert_eq!(
        vault.row_birth(&row).map_err(at("read the row birth"))?,
        Some(birth),
        "G289: the carried birth is stamped on the replayed row"
    );
    Ok(())
}

/// G320: the owner rewrites a PERSON through the core batch door
/// (`vault.batch`, POST /v1/core/batch). Each put is staged by the core
/// batch's put stager, which refuses only a scope summary.
#[test]
fn g320_the_owners_core_batch_rewrites_a_person() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).map_err(at("open owned"))?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let id = person(&vault)?;
    let before = vault.get_raw(&id).map_err(at("read before"))?;
    vault
        .memory(owner, EdgeActorClass::Human)
        .core_batch_write(&CoreBatchWriteInput {
            entities: vec![CoreBatchEntityInput {
                id: Some(id.to_hex()),
                entity_type: ENTITY_TYPE_PERSON,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body: serde_json::json!({ "name": "Gate Pin" }),
                text: None,
            }],
        })
        .map_err(at("the owner's core batch"))?;
    let after = vault.get_raw(&id).map_err(at("read after"))?;
    assert!(after.is_some(), "the PERSON still reads");
    assert_ne!(after, before, "the core batch rewrote the PERSON's body");
    assert_eq!(
        vault.get_entity_type(&id).map_err(at("read the kind"))?,
        Some(ENTITY_TYPE_PERSON)
    );
    Ok(())
}

/// G78: the owner puts a `comm.last_touch` CLAIM through the bound raw put
/// door, the door a host app's raw writes take. The commit routes the comm
/// claim to the comm projector, whose head writes check that the bound
/// reader can read each head they name. A raw CLAIM body names no source
/// (the raw door refuses one that does: the source belongs to the write
/// envelope), so the pin drops the typed builder's `Observed` stamp.
#[test]
fn g78_a_bound_comm_claim_put_lands_its_comm_head() -> TestResult {
    const PARTY: &str = "pin@example.com";
    const CHANNEL: &str = "email";
    let (_dir, vault) = open_unseeded()?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let party_ref = resolve_or_create_comm_party(&vault, PARTY).map_err(at("the comm party"))?;
    let mut body = CommClaimValue::LastTouch {
        party_ref,
        channel_class: CHANNEL.to_owned(),
        occurred_at: 10,
    }
    .claim_body()
    .map_err(at("the comm claim body"))?;
    body.source = None;
    let data = encode_claim_body(&body).map_err(at("encode the comm claim"))?;
    vault
        .memory(owner, EdgeActorClass::Human)
        .raw_put_entity(RawEntityPut {
            id: EntityId::now(),
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: range(10),
            learned_at: 10,
            data: &data,
        })
        .map_err(at("the owner's raw comm put"))?;
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, PARTY, CHANNEL)
            .map_err(at("count the comm heads"))?,
        1,
        "the last-touch head landed"
    );
    Ok(())
}

/// A policy manifest that lets `actor`, a human, write `self.memory.*`
/// at Auto from the code run's Generated source, as the code-run unit
/// fixture installs for its agent (`code_run/tests.rs`).
fn self_memory_policy(actor: EntityId) -> TestResult<Vec<u8>> {
    let axes = || {
        Value::Map(vec![
            (Value::from("criticality"), Value::from("normal")),
            (Value::from("sensitivity"), Value::from("normal")),
        ])
    };
    let manifest = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
        ),
        (Value::from("pack_id"), Value::from("gate-pin-code-run")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (Value::from("defaults"), axes()),
        (
            Value::from("rules"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("prefix"), Value::from("self.memory.")),
                (Value::from("axes"), axes()),
            ])]),
        ),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("human")),
                (Value::from("actor_ref"), Value::from(actor.to_hex())),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (
            Value::from("source_trust"),
            Value::Map(vec![(
                Value::from(ClaimSource::Generated.as_str()),
                Value::Map(vec![
                    (Value::from("max_auto_sensitivity"), Value::from(2_u64)),
                    (Value::from("receipted"), Value::Boolean(true)),
                    (Value::from("warned"), Value::Boolean(true)),
                ]),
            )]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest)?;
    Ok(data)
}

/// G392 and G393: the owner's code run writes two claims, supersedes the
/// first with the second (`self.memory.supersede_claim`, G392) and puts an
/// edge (`self.memory.put_edge`, G393) through the host dispatcher. Each
/// trap checks its write against the vault policy before it lands. Before
/// each trap the run's rows meet the record-reference check under the
/// actor's own read key (FIX 1214); the owner reads every record it names,
/// where a bare agent with no Grant reads none (INVENTED_REFERENCE).
#[test]
fn g392_g393_a_code_run_supersedes_its_claim_and_puts_an_edge() -> TestResult {
    let (_dir, vault) = open_unseeded()?;
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    put_policy_manifest_bytes(&vault, EntityId::now(), &self_memory_policy(actor)?)
        .map_err(at("install the policy"))?;
    let subject = person(&vault)?;
    let edge_target = person(&vault)?;
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Human),
        "gate-pin-run",
    )
    .map_err(at("the dispatcher"))?;
    let old = EntityId::now();
    let new = EntityId::now();
    for (id, drink, confidence, at_time) in [(old, "sencha", 0.8, 10), (new, "matcha", 0.9, 12)] {
        dispatcher
            .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                id,
                ClaimCandidate::new(
                    "profile.favorite_drink",
                    ClaimSubject::Entity(subject),
                    Value::from(drink),
                    confidence,
                ),
                range(at_time),
                at_time + 1,
            )))
            .map_err(at("the run's claim put"))?;
    }

    let superseded = dispatcher
        .dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall::new(new, old, 20),
        ))
        .map_err(at("the run's supersede"))?;
    assert_eq!(
        superseded,
        SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: new })
    );
    let old_claim = vault
        .get_claim(&old)
        .map_err(at("read the old claim"))?
        .ok_or("the superseded claim reads nothing")?;
    assert_eq!(old_claim.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_claim.valid_to, Some(20));
    assert_eq!(
        vault
            .targets(&new, EdgeKind::Supersedes, None)
            .map_err(at("read the supersedes edge"))?,
        vec![old]
    );

    let put_edge = dispatcher
        .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            subject,
            EdgeKind::Mentions,
            edge_target,
            0.7,
        )))
        .map_err(at("the run's edge put"))?;
    assert_eq!(
        put_edge,
        SelfDispatchOutcome::MemoryEdgeWrite(SelfMemoryEdgeWriteResult {
            src: subject,
            kind: EdgeKind::Mentions,
            tgt: edge_target,
        })
    );
    assert_eq!(
        vault
            .targets(&subject, EdgeKind::Mentions, None)
            .map_err(at("read the edge"))?,
        vec![edge_target]
    );
    Ok(())
}
