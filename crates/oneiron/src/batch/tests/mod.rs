//! White-box tests for the batch apply pipeline, split by topic across child files.

use super::*;
use crate::Vault;
use crate::affect::Vad;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::edge::{
    EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, EDGE_VALUE_STRUCTURAL_LEN,
    EdgeKind,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, ErrorKind, GateError, RecordError, Result};
use crate::habit::TaskRole;
use crate::off_record::OffRecordBackendClass;
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
#[cfg(feature = "sync")]
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::test_util::{assert_secret_scan_rejected, embedding_test_config, entity};
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;
use core::assert_matches;
#[cfg(feature = "sync")]
use ed25519_dalek::{Signer, SigningKey};
use rmpv::Value;
use std::str;

#[cfg(feature = "sync")]
mod authority_log;
mod facet_taint_session;
mod habit_streak;
mod lexical_hints_lifecycle;
mod lexical_hints_policy;
mod provenance_edges;
mod secret_policy_claim;
mod seeded_actors;
mod support;
mod tree_child_of;
mod vectors_embeddings;

use self::support::*;

/// A vault whose store clock and id source are fixed, so the rows a batch
/// changes are the same bytes on every open. (What the open itself seeds
/// still carries fresh ids; the pins compare changed rows, not whole stores.)
fn deterministic_vault() -> (tempfile::TempDir, Vault) {
    let clock = crate::ports::ManualClock::new(1_000);
    let mut config = embedding_test_config();
    config.store_clock = clock.bundle();
    crate::test_util::open_test_vault_with(config)
}

/// One fixture batch, written once through the committing terminal and once
/// through the caller-transaction terminal on a twin vault.
struct BatchFixture {
    name: &'static str,
    seed: fn(&Vault) -> Result<()>,
    committing: fn(&Vault) -> Result<()>,
    in_txn: fn(&Vault) -> Result<()>,
}

/// Builds a [`BatchFixture`] from ONE builder chain, so both terminals queue
/// exactly the same ops.
macro_rules! batch_fixture {
    ($name:literal, $seed:expr, |$b:ident| $chain:expr) => {
        BatchFixture {
            name: $name,
            seed: $seed,
            committing: |vault: &Vault| {
                let $b = vault.batch();
                $chain.commit()
            },
            in_txn: |vault: &Vault| {
                vault.with_write_txn(|txn| {
                    let $b = vault.batch_in();
                    $chain.apply(txn)
                })
            },
        }
    };
}

/// Seeds nothing: the batch writes into a freshly opened vault.
const SEED_NOTHING: fn(&Vault) -> Result<()> = |_| Ok(());

fn seed_people(vault: &Vault) -> Result<()> {
    for seed in [0x31, 0x32, 0x33] {
        vault.put_entity(
            &entity(seed),
            ENTITY_TYPE_PERSON,
            test_time_range(5, 5),
            6,
            b"person",
        )?;
    }
    Ok(())
}

fn seed_people_and_edges(vault: &Vault) -> Result<()> {
    seed_people(vault)?;
    vault.put_edge(&entity(0x31), EdgeKind::Mentions, &entity(0x32), 0.5)?;
    vault.put_edge(&entity(0x32), EdgeKind::Mentions, &entity(0x33), 0.5)?;
    Ok(())
}

fn seed_habit(vault: &Vault) -> Result<()> {
    vault.put_entity(
        &entity(0x34),
        ENTITY_TYPE_TASK,
        test_time_range(5, 5),
        6,
        &crate::habit::task_body_for_test(TaskRole::Habit),
    )
}

fn seed_task_and_people(vault: &Vault) -> Result<()> {
    seed_people(vault)?;
    vault.put_entity(
        &entity(0x35),
        ENTITY_TYPE_TASK,
        test_time_range(5, 5),
        6,
        &crate::habit::task_body_for_test(TaskRole::Task),
    )
}

fn seed_people_and_mask(vault: &Vault) -> Result<()> {
    seed_people(vault)?;
    vault.put_entity(
        &entity(0x36),
        ENTITY_TYPE_FACET,
        test_time_range(5, 5),
        6,
        b"facet",
    )
}

fn fixture_envelope() -> WriteEnvelope {
    test_write_envelope(entity(0x31)).expect("fixture envelope")
}

fn fixture_candidate() -> ClaimCandidate {
    ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(entity(0x32)),
        Value::from("Ada"),
        0.9,
    )
}

fn fixture_task_fact() -> Vec<u8> {
    crate::task_authority::encode_task_authority_fact_body(
        &crate::task_authority::TaskAuthorityFact {
            task_ref: entity(0x35),
            kind: crate::task_authority::TaskAuthorityFactKind::Owner,
            actor_ref: entity(0x31),
            occurred_at: 40,
        },
    )
}

fn fixture_note() -> Vec<u8> {
    crate::note::encode_note_body(&crate::note::NoteBody {
        kind: crate::note::NoteKind::parse("diary").expect("shipped kind"),
        author_ref: entity(0x31),
        markdown: "harbor lights at dusk".to_owned(),
        source_revision_ref: [1; 16],
    })
    .expect("note body")
}

fn batch_fixtures() -> Vec<BatchFixture> {
    vec![
        batch_fixture!("put", SEED_NOTHING, |b| b
            .put(
                &entity(0x51),
                ENTITY_TYPE_PERSON,
                test_time_range(10, 10),
                11,
                b"ada"
            )
            .put(
                &entity(0x52),
                ENTITY_TYPE_EVENT,
                test_time_range(12, 14),
                15,
                b"launch"
            )),
        batch_fixture!("put_habit_checkin", seed_habit, |b| b.put_habit_checkin(
            &entity(0x34),
            &entity(0x53),
            test_time_range(20, 20),
            21,
            &crate::habit::task_body_for_test(TaskRole::HabitCheckin),
        )),
        batch_fixture!("edges", seed_people_and_edges, |b| b
            .edge(&entity(0x31), EdgeKind::About, &entity(0x33), 0.75)
            .edge_with_created_at(&entity(0x33), EdgeKind::Supports, &entity(0x31), 0.25, 500)
            .set_edge_vad(
                &entity(0x31),
                EdgeKind::Mentions,
                &entity(0x32),
                Vad {
                    valence: -0.5,
                    arousal: 0.25,
                    dominance: 0.75,
                },
            )
            .delete_edge(&entity(0x32), EdgeKind::Mentions, &entity(0x33))),
        batch_fixture!("text", seed_people, |b| b.text(
            &entity(0x31),
            &[("name", "Ada Lovelace"), ("bio", "harbor lights at dusk")],
        )),
        batch_fixture!("phonetic", seed_people, |b| b
            .phonetic(&entity(0x31), &["ATLF", "LFLS"])),
        batch_fixture!("vector", seed_people, |b| b
            .vector(&entity(0x31), &[0.1, 0.2, 0.3, 0.4])
            .vector(&entity(0x32), &[0.4, 0.3, 0.2, 0.1])),
        batch_fixture!("delete", seed_people_and_edges, |b| b.delete(&entity(0x32))),
        batch_fixture!("claim_candidate", seed_people, |b| b.claim_candidate(
            &entity(0x54),
            fixture_candidate(),
            &fixture_envelope(),
            test_time_range(30, 30),
            31,
        )),
        batch_fixture!("put_internal", SEED_NOTHING, |b| b.put_internal(
            &entity(0x55),
            ENTITY_TYPE_TASK,
            test_time_range(1, 1),
            2,
            &crate::habit::task_body_for_test(TaskRole::Task),
        )),
        batch_fixture!("put_task_fact", seed_task_and_people, |b| b
            .put_task_fact(&entity(0x56), &fixture_task_fact(), 40)
            .edge(&entity(0x56), EdgeKind::ScopedTo, &entity(0x35), 1.0)),
        batch_fixture!("put_authored_note", seed_people_and_mask, |b| b
            .mask(Some(entity(0x36)))
            .put_authored_note(
                &entity(0x57),
                &entity(0x31),
                test_time_range(50, 50),
                51,
                &fixture_note(),
            )
            .edge(&entity(0x57), EdgeKind::AuthoredBy, &entity(0x31), 1.0)
            .edge(&entity(0x57), EdgeKind::About, &entity(0x32), 1.0)),
    ]
}

/// Per fixture: the blake3 digest of the rows its batch changed, pinned on
/// the two-builder code before the fold (T48) and re-pinned at storage ABI 21,
/// where the derived ids those rows carry moved onto `EntityId::derive` (T50).
const PINNED_BATCH_DIGESTS: &[(&str, &str)] = &[
    (
        "put",
        "7ead77bf6ddab70220cce8c59eb8352cdda48a5df9be686e1a03a76c99ea648c",
    ),
    (
        "put_habit_checkin",
        "8b936130be9eb44d754196d954ddca88a49f93bb4a891a093939876c5d1fc8d2",
    ),
    (
        "edges",
        "bfc5eb1422faa31e263861b987b38b42c080706637e0094c4b2ae4f05f24684e",
    ),
    (
        "text",
        "66bbb27b7e3113e19204371ff096fe5154d3acced275ff5df33b1d46da97bdf9",
    ),
    (
        "phonetic",
        "6d2859364867f6150b8ae939448cdefa658b79ceeab0d4ac77a9f6058550c4da",
    ),
    (
        "vector",
        "bcffaa6b0aa3ea3647810cb8527cc09f1a0910540c6141bf599030d9594bed3e",
    ),
    (
        "delete",
        "f57afee9939ad92b59b75b3c91890b9bba0c3cda2b28d334b19da422bf2f2cee",
    ),
    ("claim_candidate", CLAIM_CANDIDATE_DIGEST),
    (
        "put_internal",
        "e4d242c9b3e6483ce43a753acbe117ca97681a9e57ff203544350336eb7be66d",
    ),
    (
        "put_task_fact",
        "6fb47fae60c34fc0929c466e5d3656f6e19482ed39a1c341be4e6c5a63a9f5d8",
    ),
    (
        "put_authored_note",
        "1548ea94abad9200e9c8717162f1fb4a276fd7fcec56b106001b2935af86cc65",
    ),
];

/// A `sync` build also queues the claim's embed job in the same batch.
#[cfg(feature = "sync")]
const CLAIM_CANDIDATE_DIGEST: &str =
    "1fc461e743033c2b51add72fde31f8789b72e5b16fca44df69168de6dd17990f";
#[cfg(not(feature = "sync"))]
const CLAIM_CANDIDATE_DIGEST: &str =
    "2ea5b9f3ef12c7a5bc16e456fadd2008a08c2433abce11f68ba0881e04306396";

#[test]
fn one_builder_writes_what_both_builders_wrote() -> Result<()> {
    use crate::test_util::row_dump::{changed_rows, digest_changes, dump_rows};

    let mut digests = Vec::new();
    for fixture in batch_fixtures() {
        let mut stored = Vec::new();
        for write in [fixture.committing, fixture.in_txn] {
            let (_dir, vault) = deterministic_vault();
            (fixture.seed)(&vault)?;
            let before = dump_rows(&vault);
            write(&vault)?;
            stored.push(changed_rows(&before, &dump_rows(&vault)));
        }
        let [committed, applied] = stored.as_slice() else {
            unreachable!("two terminals");
        };
        assert_eq!(
            committed, applied,
            "{}: both terminals store the same rows",
            fixture.name
        );
        assert!(
            !applied.is_empty(),
            "{}: the batch stores rows",
            fixture.name
        );
        digests.push((fixture.name, digest_changes(applied)));
    }
    let pinned: Vec<(&str, String)> = PINNED_BATCH_DIGESTS
        .iter()
        .map(|(name, digest)| (*name, (*digest).to_owned()))
        .collect();
    assert_eq!(digests, pinned);
    Ok(())
}

#[test]
fn one_builder_applies_in_the_callers_transaction_and_commits_on_its_own() -> Result<()> {
    use crate::test_util::row_dump::{changed_rows, dump_rows};

    let (ada, launch) = (entity(0x58), entity(0x59));
    let occurred = test_time_range(60, 60);

    let (_committed_dir, committed) = deterministic_vault();
    let before = dump_rows(&committed);
    committed
        .batch()
        .put(&ada, ENTITY_TYPE_PERSON, occurred, 61, b"ada")
        .put(&launch, ENTITY_TYPE_EVENT, occurred, 61, b"launch")
        .commit()?;
    let committed_rows = changed_rows(&before, &dump_rows(&committed));

    let (_applied_dir, applied) = deterministic_vault();
    let before = dump_rows(&applied);
    applied.with_write_txn(|txn| {
        applied
            .batch_in()
            .put(&ada, ENTITY_TYPE_PERSON, occurred, 61, b"ada")
            .put(&launch, ENTITY_TYPE_EVENT, occurred, 61, b"launch")
            .apply(txn)
    })?;
    let applied_rows = changed_rows(&before, &dump_rows(&applied));

    assert!(applied.get(&ada)?.is_some() && applied.get(&launch)?.is_some());
    assert_eq!(committed_rows, applied_rows);

    let (_aborted_dir, aborted) = deterministic_vault();
    let before = dump_rows(&aborted);
    let outcome: Result<()> = aborted.try_with_write_txn(|txn| {
        aborted
            .batch_in()
            .put(&ada, ENTITY_TYPE_PERSON, occurred, 61, b"ada")
            .put(&launch, ENTITY_TYPE_EVENT, occurred, 61, b"launch")
            .apply(txn)?;
        Err(Error::InvariantViolation("the caller aborts after apply"))
    });
    assert_matches!(outcome, Err(Error::InvariantViolation(_)));
    assert!(changed_rows(&before, &dump_rows(&aborted)).is_empty());
    assert!(aborted.get(&ada)?.is_none() && aborted.get(&launch)?.is_none());
    Ok(())
}

#[test]
fn apply_put_request_defaults_match_the_old_positional_call() {
    // The op the plain `put_entity` path queues, under the gate mode it
    // applies with.
    let plain_put = BatchOp::Put {
        id: entity(0x5a),
        entity_type: ENTITY_TYPE_PERSON,
        occurred: test_time_range(1, 1),
        learned_at: 1,
        data: b"ada".to_vec(),
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    };
    let built = PutOptions::for_batch_op(&plain_put, &ApplyOpsGateMode::new(false, true));
    assert_eq!(built, PutOptions::default());
    // What that path passed positionally: allow_reserved_predicate,
    // replicated, hub_sync_imported, has_later_covering_text_op,
    // internal_lexical_query_hint, record_gate_decisions,
    // persist_gate_pending_consent, can_resolve_pending_consent,
    // include_source_in_gate_input, claim_gate_prechecked,
    // preflight_gate_decision_id.
    assert_eq!(
        PutOptions::default(),
        PutOptions {
            replication: Replication {
                replicated: false,
                reserved_predicate: false,
            },
            hub: HubImport {
                sync_imported: false,
            },
            decision: DecisionRecording {
                record: false,
                prechecked: false,
                include_source_in_gate_input: false,
                internal_lexical_query_hint: false,
                preflight: None,
            },
            consent: ConsentHandling {
                persist_pending: true,
                can_resolve_pending: false,
            },
            indexing: TextIndexing {
                later_text_op_covers: false,
            },
        }
    );
}

/// Runs ONE `apply_put` in its own write transaction against the vault's
/// resolved policy, then commits whatever the put staged, a refusal's
/// receipts included, so the caller reads what it left behind. `prepare`
/// runs first in the same transaction and returns the options.
fn put_in_own_txn(
    vault: &Vault,
    (id, entity_type, data): (EntityId, u8, &[u8]),
    envelope: Option<&WriteEnvelope>,
    prepare: impl FnOnce(
        &mut heed::RwTxn<'_>,
        &crate::gate::PolicyManifestResolution,
    ) -> Result<PutOptions>,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    let options = prepare(&mut wtxn, &policy)?;
    let outcome = apply_put(
        &vault.store,
        &mut wtxn,
        PutRequest {
            row: PutRow {
                id,
                entity_type,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data,
            },
            options,
            context: PutContext {
                origin: BaseWriteOrigin::Ordinary,
                write_policy: Some(&policy),
                write_envelope: envelope,
                hub_admission: None,
                companion_retired_histories: None,
            },
        },
    )
    .map(drop);
    wtxn.commit()?;
    outcome
}

fn put_with(
    vault: &Vault,
    row: (EntityId, u8, &[u8]),
    envelope: Option<&WriteEnvelope>,
    options: PutOptions,
) -> Result<()> {
    put_in_own_txn(vault, row, envelope, |_, _| Ok(options))
}

fn gate_decisions_for(vault: &Vault, id: &EntityId) -> Result<usize> {
    Ok(vault
        .store
        .gate_decisions(1_000)?
        .iter()
        .filter(|decision| decision.claim_id == Some(*id.as_bytes()))
        .count())
}

fn pending_consent_for(
    vault: &Vault,
    id: &EntityId,
) -> Result<Option<crate::store::PendingGateConsentRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    vault.store.pending_gate_consent_in_txn(&rtxn, id)
}

/// A `profile.preference` claim the first-party connector agent authors
/// from unstamped tool output. Its envelope's source always joins the gate
/// input, and the gate holds it for source trust: a proposal waits for
/// consent, an approval or an Auto write is refused. Seeds the actor and the
/// subject.
fn agent_tool_output_claim(
    vault: &Vault,
    approval: ClaimApprovalStatus,
) -> Result<(WriteEnvelope, Vec<u8>)> {
    let actor = EntityId::from_bytes(crate::gate::FIRST_PARTY_CONNECTOR_ACTOR_ID)
        .map_err(|_| Error::InvariantViolation("first-party actor id"))?;
    let subject = entity(0x61);
    for (id, body) in [(actor, b"connector".as_slice()), (subject, b"subject")] {
        if vault.get(&id)?.is_none() {
            vault.put_entity(&id, ENTITY_TYPE_PERSON, test_time_range(1, 1), 1, body)?;
        }
    }
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::ToolOutput,
        WriteProvenance::new(Value::from("fixture"))?,
        approval,
    );
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    let rtxn = vault.store.env.read_txn()?;
    let facet = crate::claim::default_facet_in(&vault.store, &rtxn)?;
    let body = crate::claim::encode_claim_body(&candidate.into_claim_body(&envelope, facet)?)?;
    Ok((envelope, body))
}

/// An envelope-less local claim on a seeded subject, as a raw body carries it.
fn local_claim(
    vault: &Vault,
    source: Option<ClaimSource>,
    approval: ClaimApprovalStatus,
) -> Result<Vec<u8>> {
    let subject = entity(0x61);
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    let mut body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        approval,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = source;
    crate::claim::encode_claim_body(&body)
}

#[test]
fn every_put_option_reaches_apply_put() -> Result<()> {
    let defaults = PutOptions::default();

    // replication.replicated: the replicated road has no actor binding for a
    // MESSAGE author, so it fails closed where the local road stores it.
    {
        let (_dir, vault) = open_test_vault();
        let body =
            crate::gate::canonical_witness_message_body_for_test("user", "text", "hi", true, 0)?;
        let local = put_with(
            &vault,
            (entity(0x62), crate::registry::ENTITY_TYPE_MESSAGE, &body),
            None,
            defaults,
        );
        let mut replicated = defaults;
        replicated.replication.replicated = true;
        let remote = put_with(
            &vault,
            (entity(0x63), crate::registry::ENTITY_TYPE_MESSAGE, &body),
            None,
            replicated,
        );
        assert!(
            local.is_ok()
                && matches!(
                    remote,
                    Err(Error::Record(RecordError::InvalidWitnessMessageBody(_)))
                ),
            "replicated: local {local:?}, replicated {remote:?}"
        );
    }

    // replication.reserved_predicate: an `edge.provenance` body is admitted
    // instead of refused as a reserved predicate.
    {
        let (_dir, vault) = open_test_vault();
        seed_people(&vault)?;
        let mut body = ClaimBody::new(
            "edge.provenance",
            ClaimSubject::Edge {
                source: entity(0x31),
                kind: EdgeKind::Mentions,
                target: entity(0x32),
            },
            crate::provenance::encode_edge_provenance_value(&EdgeProvenanceClaimBody::new(
                entity(0x31),
                0.9,
                SupersessionStatus::Confirmed,
            )),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.evidence = Some(crate::provenance::encode_actor_class_evidence(
            EdgeActorClass::Human,
        ));
        let bytes = crate::claim::encode_claim_body(&body)?;
        let public = put_with(
            &vault,
            (entity(0x64), ENTITY_TYPE_CLAIM, &bytes),
            None,
            defaults,
        );
        let mut reserved = defaults;
        reserved.replication.reserved_predicate = true;
        let door = put_with(
            &vault,
            (entity(0x64), ENTITY_TYPE_CLAIM, &bytes),
            None,
            reserved,
        );
        assert!(
            public
                .as_ref()
                .is_err_and(|e| e.kind() == ErrorKind::ReservedPredicate)
                && door.is_ok(),
            "reserved_predicate: public {public:?}, door {door:?}"
        );
    }

    // hub.sync_imported: a SKILL overwrite is judged by the hub-sync update
    // rule, which only updates imported skills.
    {
        let (_dir, vault) = open_test_vault();
        let prior = crate::skill::SkillRecord::new(
            "fixture-skill",
            "before",
            "1.0.0",
            ClaimApprovalStatus::Approved,
            crate::skill::SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            0.5,
            false,
            true,
            Vec::new(),
            Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
        );
        vault.put_skill_record(&entity(0x65), &prior, test_time_range(1, 1), 1)?;
        let mut updated = prior;
        updated.desc = "after".to_owned();
        updated.version = "1.0.1".to_owned();
        let bytes = crate::skill::encode_skill_record(&updated)?;
        let skill = crate::registry::ENTITY_TYPE_SKILL;
        let mut hub = defaults;
        hub.hub.sync_imported = true;
        let hub_import = put_with(&vault, (entity(0x65), skill, &bytes), None, hub);
        let local = put_with(&vault, (entity(0x65), skill, &bytes), None, defaults);
        assert!(
            hub_import
                .as_ref()
                .is_err_and(|e| e.kind() == ErrorKind::InvalidSkillBody)
                && local.is_ok(),
            "sync_imported: hub {hub_import:?}, local {local:?}"
        );
    }

    // decision.record: the gate appends its decision from inside apply.
    {
        let (_dir, vault) = open_raw_test_vault();
        let body = local_claim(&vault, None, ClaimApprovalStatus::Approved)?;
        put_with(
            &vault,
            (entity(0x66), ENTITY_TYPE_CLAIM, &body),
            None,
            defaults,
        )?;
        let mut record = defaults;
        record.decision.record = true;
        put_with(
            &vault,
            (entity(0x67), ENTITY_TYPE_CLAIM, &body),
            None,
            record,
        )?;
        assert_eq!(
            (
                gate_decisions_for(&vault, &entity(0x66))?,
                gate_decisions_for(&vault, &entity(0x67))?
            ),
            (0, 1),
            "record"
        );
    }

    // decision.prechecked: a claim the gate holds lands when the gate already
    // authorized it in this transaction.
    {
        let (_dir, vault) = open_raw_test_vault();
        let (envelope, body) = agent_tool_output_claim(&vault, ClaimApprovalStatus::Auto)?;
        let gated = put_with(
            &vault,
            (entity(0x68), ENTITY_TYPE_CLAIM, &body),
            Some(&envelope),
            defaults,
        );
        let mut prechecked = defaults;
        prechecked.decision.prechecked = true;
        put_with(
            &vault,
            (entity(0x69), ENTITY_TYPE_CLAIM, &body),
            Some(&envelope),
            prechecked,
        )?;
        assert!(
            matches!(gated, Err(Error::Gate(GateError::GateWriteRejected { .. })))
                && vault.get_claim(&entity(0x69))?.is_some(),
            "prechecked: gated {gated:?}"
        );
    }

    // decision.include_source_in_gate_input: the claim's source joins the
    // gate input, and approved unstamped tool output is held for consent.
    {
        let (_dir, vault) = open_raw_test_vault();
        let body = local_claim(
            &vault,
            Some(ClaimSource::ToolOutput),
            ClaimApprovalStatus::Approved,
        )?;
        let without = put_with(
            &vault,
            (entity(0x6a), ENTITY_TYPE_CLAIM, &body),
            None,
            defaults,
        );
        let mut sourced = defaults;
        sourced.decision.include_source_in_gate_input = true;
        let with = put_with(
            &vault,
            (entity(0x6b), ENTITY_TYPE_CLAIM, &body),
            None,
            sourced,
        );
        assert!(
            without.is_ok()
                && matches!(with, Err(Error::Gate(GateError::GateWriteRejected { .. }))),
            "include_source_in_gate_input: without {without:?}, with {with:?}"
        );
    }

    // decision.internal_lexical_query_hint: the gate does not judge an
    // engine-internal hint, so recording leaves no decision for it.
    {
        let (_dir, vault) = open_raw_test_vault();
        let target = entity(0x6c);
        let target_body = local_claim(&vault, None, ClaimApprovalStatus::Approved)?;
        vault.put_entity(
            &target,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &target_body,
        )?;
        let hint_id = lexical_query_hint_claim_id(&target, "tea")?;
        let envelope = test_write_envelope(entity(0x31))?;
        vault.put_entity(
            &entity(0x31),
            ENTITY_TYPE_PERSON,
            test_time_range(1, 1),
            1,
            b"actor",
        )?;
        let rtxn = vault.store.env.read_txn()?;
        let facet = crate::claim::default_facet_in(&vault.store, &rtxn)?;
        drop(rtxn);
        let hint = ClaimCandidate::new(
            crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
            ClaimSubject::Entity(target),
            crate::claim::encode_lexical_query_hint_value(&target, "tea"),
            1.0,
        )
        .with_stale(true)
        .into_claim_body(&envelope, facet)?;
        let bytes = crate::claim::encode_claim_body(&hint)?;
        let mut recorded = defaults;
        recorded.decision.record = true;
        let mut internal = recorded;
        internal.decision.internal_lexical_query_hint = true;
        put_with(
            &vault,
            (hint_id, ENTITY_TYPE_CLAIM, &bytes),
            Some(&envelope),
            internal,
        )?;
        let internal_decisions = gate_decisions_for(&vault, &hint_id)?;
        // The gate's verdict on the judged put is beside the point; that it
        // judged, and recorded, is the observable.
        let judged = put_with(
            &vault,
            (hint_id, ENTITY_TYPE_CLAIM, &bytes),
            Some(&envelope),
            recorded,
        );
        assert_eq!(
            (internal_decisions, gate_decisions_for(&vault, &hint_id)?),
            (0, 1),
            "internal_lexical_query_hint: judged {judged:?}"
        );
    }

    // decision.preflight: a held claim binds its pending consent to the
    // receipt a same-transaction preflight recorded instead of minting one.
    {
        let (_dir, vault) = open_raw_test_vault();
        let (envelope, body) = agent_tool_output_claim(&vault, ClaimApprovalStatus::Proposed)?;
        let decoded = crate::claim::decode_claim_body(&body, false)?;
        let mut receipts = Vec::new();
        for (id, bind) in [(entity(0x6d), false), (entity(0x6e), true)] {
            put_in_own_txn(
                &vault,
                (id, ENTITY_TYPE_CLAIM, &body),
                Some(&envelope),
                |wtxn, policy| {
                    let mut recorded = None;
                    crate::gate::check_claim_policy_for_write_with_record(
                        &vault.store,
                        wtxn,
                        &id,
                        crate::gate::ClaimGateWrite {
                            body: &decoded,
                            envelope: Some(&envelope),
                            auto_checker: None,
                            defer_metrics_until_commit: true,
                        },
                        policy,
                        crate::gate::GateWriteMode {
                            record_decision: true,
                            persist_pending_consent: false,
                            resolve_pending: false,
                            can_resolve_pending_consent: true,
                            include_source_in_gate_input: false,
                        },
                        &mut recorded,
                    )?;
                    let preflight = recorded.map(|decision| decision.decision_id());
                    receipts.push(preflight);
                    let mut options = defaults;
                    options.decision.preflight = preflight.filter(|_| bind);
                    Ok(options)
                },
            )?;
        }
        let bound = |id: EntityId, receipt: Option<crate::store::GateDecisionId>| -> Result<bool> {
            Ok(pending_consent_for(&vault, &id)?.map(|pending| pending.decision_id) == receipt)
        };
        assert_eq!(
            (
                bound(entity(0x6d), receipts[0])?,
                bound(entity(0x6e), receipts[1])?
            ),
            (false, true),
            "preflight"
        );
    }

    // consent.persist_pending: a held proposal persists its pending consent.
    {
        let (_dir, vault) = open_raw_test_vault();
        let (envelope, body) = agent_tool_output_claim(&vault, ClaimApprovalStatus::Proposed)?;
        let mut unpersisted = defaults;
        unpersisted.consent.persist_pending = false;
        put_with(
            &vault,
            (entity(0x6f), ENTITY_TYPE_CLAIM, &body),
            Some(&envelope),
            unpersisted,
        )?;
        put_with(
            &vault,
            (entity(0x70), ENTITY_TYPE_CLAIM, &body),
            Some(&envelope),
            defaults,
        )?;
        assert_eq!(
            (
                pending_consent_for(&vault, &entity(0x6f))?.is_some(),
                pending_consent_for(&vault, &entity(0x70))?.is_some()
            ),
            (false, true),
            "persist_pending"
        );
    }

    // consent.can_resolve_pending: an approval of a held proposal lands only
    // when its consent was already pending when the batch began.
    {
        let (_dir, vault) = open_raw_test_vault();
        let (envelope, proposed) = agent_tool_output_claim(&vault, ClaimApprovalStatus::Proposed)?;
        let (approving, approved) = agent_tool_output_claim(&vault, ClaimApprovalStatus::Approved)?;
        let mut outcomes = Vec::new();
        for (id, can_resolve) in [(entity(0x71), false), (entity(0x72), true)] {
            put_with(
                &vault,
                (id, ENTITY_TYPE_CLAIM, &proposed),
                Some(&envelope),
                defaults,
            )?;
            let mut options = defaults;
            options.consent.can_resolve_pending = can_resolve;
            outcomes.push(put_with(
                &vault,
                (id, ENTITY_TYPE_CLAIM, &approved),
                Some(&approving),
                options,
            ));
        }
        assert!(
            matches!(
                outcomes[0],
                Err(Error::Gate(GateError::GateWriteRejected { .. }))
            ) && outcomes[1].is_ok(),
            "can_resolve_pending: {outcomes:?}"
        );
    }

    // indexing.later_text_op_covers: a body-changing overwrite leaves the
    // old text postings to the later text op instead of deindexing them.
    {
        let (_dir, vault) = open_test_vault();
        let mut forward_rows = Vec::new();
        for (id, covered) in [(entity(0x73), false), (entity(0x74), true)] {
            // Seeded raw, so no revision state owns the row's text and the
            // put itself decides whether its postings go stale.
            let old = crate::test_util::entity_record(
                ENTITY_TYPE_EVENT,
                test_time_range(1, 1),
                1,
                b"old",
            );
            vault.with_write_txn(|wtxn| {
                vault.store.entities.put(wtxn, id.as_bytes(), &old)?;
                crate::bm25::index_text(
                    &vault.store,
                    wtxn,
                    &vault.analyzer,
                    &id,
                    &[("body".to_owned(), "harbor lights".to_owned())],
                )
            })?;
            let mut options = defaults;
            options.indexing.later_text_op_covers = covered;
            put_with(&vault, (id, ENTITY_TYPE_EVENT, b"new"), None, options)?;
            let rtxn = vault.store.env.read_txn()?;
            forward_rows.push(
                vault
                    .store
                    .text_forward
                    .get(&rtxn, id.as_bytes())?
                    .is_some(),
            );
        }
        assert_eq!(forward_rows, [false, true], "later_text_op_covers");
    }
    Ok(())
}
