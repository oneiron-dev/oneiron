//! The `vault.embedding_spaces.*` doors keep the embedding-space promises
//! (ruling L4-23 = A: each test proves a promise at its public door). Every
//! verb call enters through `oneiron_testkit::door::invoke`, the generated
//! verb dispatch every transport shares. All thirteen rows are the owner's;
//! twelve run here on a vault opened with the process writer lease, and
//! `move_check` runs a server's own probe towers and answers the host-only
//! refusal on an embedded vault.
//!
//! - P1 `oneiron/retrieval/oneiron-arch-0004-retrieval-graph.md:135`:
//!   "`begin_embedding_migration(new_model)` flips model_id, clears
//!   vectors/graph, and re-marks all claims priority 3 without mixing
//!   spaces". No row starts a migration (the server's `reembed` command
//!   does), so the test calls the public `Vault::begin_embedding_migration`
//!   and reads the flip at the door: `list` serves the text index under the
//!   new model. The re-mark is read from the worker queue, and the reconciler
//!   refuses the old model's fills and lands the new one's. The crate's own
//!   test of this (`src/tests/embedding.rs:282`) sits in the lib test module
//!   that `#[cfg(any())]` turns off (FIX [LIBTEST-QUARANTINE-TESTS-EMBEDDING]).
//! - P2 `oneiron/core/oneiron-arch-0019-oneiron-db-v1.md:39`: "HNSW/NSW
//!   index structures remain node-local and never sync". No row reads a
//!   vector or the sync queue: the test writes a vector with the public
//!   `Vault::put_vector`, finds the sync queue unchanged, and finds the row
//!   through the local graph (`Vault::search_vector`). The crate's own
//!   replica and checkpoint tests (`embed/tests/device.rs:171, :214`) are
//!   turned off the same way.
//! - Owner: every row refuses an agent; the owner declares and lists.
//!
//! Not in this file: arch-0004:32 "Re-embedding fires at the same moment,
//! never on every op" is idle publication (`Vault::refresh_indexed_at_idle`),
//! which no `vault.embedding_spaces` row starts or reads; the live lib test
//! `vault/entity_revision/tests.rs:46` pins it.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_embedding_spaces_doors`.
#![cfg(all(oneiron_test_support, feature = "sync", feature = "test-support"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::embed::{
    EMBED_PRIORITY_BACKFILL, Embedder, EmbedderLocality, PendingEmbeddingInput,
    PendingEmbeddingReconciler,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError};
use oneiron::sync::{QueuedEmbedJob, SyncQueue};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    ErrorKind, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use oneiron_testkit::door;
use serde_json::{Value, json};

const OLD_MODEL: &str = "test/old@v1";
const NEW_MODEL: &str = "test/new@v2";

/// A device vault this process owns (the writer lease), embedding at width
/// 4 under `OLD_MODEL`, as `tests/gate_pins_turn_retry_model_routing.rs`
/// (G187) opens one; the owner's door works on it unrooted.
fn owned_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("a tempdir");
    let mut config = VaultConfig::device();
    config.embedding_model = Some(OLD_MODEL.to_owned());
    config.dimensions = 4;
    let vault = Vault::open_owned(dir.path(), config).expect("an owned open");
    (dir, vault)
}

/// One live, UserStated claim by a human writer about a person, as
/// `tests/claim_decay_transition.rs` writes it.
fn put_claim(vault: &Vault) -> EntityId {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let subject = EntityId::now();
    for id in [actor.entity_ref(), subject] {
        vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"",
            )
            .expect("put person");
    }
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("embedding spaces doors")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    let claim = EntityId::now();
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.embedding_doors",
                ClaimSubject::Entity(subject),
                rmpv::Value::from("fact"),
                1.0,
            ),
            &envelope,
            TimeRange { start: 10, end: 99 },
            10,
        )
        .commit()
        .expect("write the claim");
    claim
}

/// The worker jobs queued for `id`.
fn jobs_for(vault: &Arc<Vault>, id: EntityId) -> Vec<QueuedEmbedJob> {
    SyncQueue::new(Arc::clone(vault))
        .expect("a queue")
        .drain_embed_jobs()
        .expect("the jobs")
        .into_iter()
        .filter(|job| job.entity_id == id)
        .collect()
}

/// An on-device embedder under a fixed model id answering one fixed vector.
struct FixedEmbedder {
    model: &'static str,
    vector: [f32; 4],
}

impl Embedder for FixedEmbedder {
    fn model_id(&self) -> &str {
        self.model
    }

    fn dimensions(&self) -> usize {
        self.vector.len()
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        Ok(inputs.iter().map(|_| self.vector.to_vec()).collect())
    }
}

#[track_caller]
fn refused(result: Result<Value, MemoryError>, what: &str) -> MemoryError {
    match result {
        Err(error) => error,
        Ok(value) => panic!("{what} was answered, want a refusal: {value}"),
    }
}

/// P1. A migration flips the model the door serves, clears the old vector,
/// re-marks the claim at priority 3, refuses the old model's fills and lands
/// the new model's.
/// Red proof: `oneiron/src/vault/transactions.rs:420` re-marks at the device
/// priority (2) (`-red1`).
#[test]
fn a_migration_remarks_claims_at_backfill_without_mixing_spaces() {
    let (_dir, mut vault) = owned_vault();
    let claim = put_claim(&vault);
    vault
        .put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .expect("the old vector");

    vault
        .begin_embedding_migration(NEW_MODEL)
        .expect("the migration");
    {
        let owner = door::owner(&vault).expect("the owner");
        let view = door::invoke(&owner, "vault.embedding_spaces.list", json!({}))
            .expect("the owner lists");
        assert_eq!(
            view["text_index"]["id"],
            json!(NEW_MODEL),
            "the flip is served: {view}"
        );
    }
    assert_eq!(
        vault.get_vector(&claim).expect("a read"),
        None,
        "the old vector is cleared"
    );

    let vault = Arc::new(vault);
    let jobs = jobs_for(&vault, claim);
    assert_eq!(jobs.len(), 1, "one job for the claim: {jobs:?}");
    assert_eq!(
        jobs[0].priority, EMBED_PRIORITY_BACKFILL,
        "re-marked at backfill"
    );
    assert_eq!(EMBED_PRIORITY_BACKFILL, 3, "canon's priority 3");

    let old = Arc::new(FixedEmbedder {
        model: OLD_MODEL,
        vector: [9.0, 9.0, 9.0, 9.0],
    });
    let error = PendingEmbeddingReconciler::new(Arc::clone(&vault), old)
        .with_batch_size(4096)
        .reconcile_once()
        .expect_err("the old model's fills are refused");
    assert_eq!(error.kind(), ErrorKind::EmbeddingModelChanged, "{error}");
    assert_eq!(
        vault.get_vector(&claim).expect("a read"),
        None,
        "nothing old landed"
    );

    let new = Arc::new(FixedEmbedder {
        model: NEW_MODEL,
        vector: [0.0, 1.0, 0.0, 0.0],
    });
    let report = PendingEmbeddingReconciler::new(Arc::clone(&vault), new)
        .with_batch_size(4096)
        .reconcile_once()
        .expect("the new model fills");
    assert!(report.filled >= 1, "the claim is filled: {report:?}");
    assert_eq!(
        vault.get_vector(&claim).expect("a read"),
        Some(vec![0.0, 1.0, 0.0, 0.0]),
        "the new space holds the new vector"
    );
}

/// P2. A vector write adds nothing to the sync queue and queues no worker
/// job, and the local graph serves the row.
/// Red proof: `oneiron/src/batch/base_apply/ops_vector.rs:35` the vector arm
/// skips the graph insert (`-red2`). The "never sync" half pins an absence:
/// no one-line change on main makes a vector write enqueue a sync row.
#[test]
fn a_vector_index_stays_local_and_never_enters_the_sync_queue() {
    let (_dir, vault) = owned_vault();
    let claim = put_claim(&vault);
    let vault = Arc::new(vault);
    assert_eq!(
        jobs_for(&vault, claim).len(),
        1,
        "the claim queues one worker job"
    );
    let rows_before = vault
        .sync_queue_rows_with_prefix(b"")
        .expect("the sync rows");

    vault
        .put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .expect("a local vector");

    let rows_after = vault
        .sync_queue_rows_with_prefix(b"")
        .expect("the sync rows");
    assert_eq!(
        rows_after, rows_before,
        "a vector write puts nothing on the sync queue"
    );
    assert_eq!(jobs_for(&vault, claim).len(), 1, "and queues no second job");
    assert_eq!(
        vault.get_vector(&claim).expect("a read"),
        Some(vec![1.0, 0.0, 0.0, 0.0]),
        "the row lands on this node"
    );
    let hits = vault
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .expect("a search");
    assert!(
        hits.iter().any(|hit| hit.id == claim),
        "this node's graph serves the row: {:?}",
        hits.iter().map(|hit| hit.id).collect::<Vec<_>>()
    );
}

/// Owner. The owner declares and lists a space; an agent is refused all
/// twelve owner rows, and the host row refuses it as it refuses the owner.
/// Red proof: `oneiron/src/memory/owner_door.rs:85` the embedded owner door's
/// refusal answers NOT_FOUND (`-red2`).
#[test]
fn an_agent_is_refused_every_embedding_space_row() {
    let (_dir, vault) = owned_vault();
    let agent = oneiron::test_doors::coach::define_agent(&vault).expect("an agent");
    let _issuer = oneiron::test_support::provision_engine_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let agent = vault.memory(agent, EdgeActorClass::Agent);

    let space = "doors-table@r1@own_server";
    let declare =
        json!({"id": space, "dimensions": 4, "accepts": ["text"], "query_towers": ["text"]});
    let view = door::invoke(&owner, "vault.embedding_spaces.declare", declare.clone())
        .expect("the owner declares");
    assert!(
        view["spaces"]
            .as_array()
            .expect("spaces")
            .iter()
            .any(|row| row["id"] == json!(space)),
        "the declared space is listed: {view}"
    );

    let some_id = EntityId::now().to_hex();
    let rows = [
        (
            "vault.embedding_spaces.bind",
            json!({"kind": "text", "space": space}),
        ),
        ("vault.embedding_spaces.declare", declare),
        ("vault.embedding_spaces.list", json!({})),
        ("vault.embedding_spaces.move", json!({"candidate": space})),
        (
            "vault.embedding_spaces.move_abandon",
            json!({"candidate": space}),
        ),
        (
            "vault.embedding_spaces.move_approve",
            json!({"candidate": space}),
        ),
        (
            "vault.embedding_spaces.move_undo",
            json!({"candidate": space}),
        ),
        ("vault.embedding_spaces.one_space", json!({"space": space})),
        (
            "vault.embedding_spaces.probes.delete",
            json!({"id": some_id}),
        ),
        ("vault.embedding_spaces.probes.list", json!({})),
        (
            "vault.embedding_spaces.probes.put",
            json!({"kind": "text", "query": "tide clock", "family": some_id, "author": "owner"}),
        ),
        ("vault.embedding_spaces.retire", json!({"space": space})),
    ];
    for (verb, body) in rows {
        let error = refused(door::invoke(&agent, verb, body), verb);
        assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{verb}: {error:?}");
        assert!(
            error.message.contains("is the vault owner's"),
            "{verb}: {error:?}"
        );
    }
    let check = json!({"candidate": space});
    for caller in [&agent, &owner] {
        let error = refused(
            door::invoke(caller, "vault.embedding_spaces.move_check", check.clone()),
            "move_check",
        );
        assert_eq!(error.code, MEMORY_CODE_MODEL_UNAVAILABLE, "{error:?}");
    }
    let view =
        door::invoke(&owner, "vault.embedding_spaces.list", json!({})).expect("the owner lists");
    assert!(
        view["spaces"]
            .as_array()
            .expect("spaces")
            .iter()
            .any(|row| row["id"] == json!(space)),
        "the agent's acts changed nothing: {view}"
    );
}
