//! The `vault.sync.*` doors keep the sync promises (ruling L4-23 = A: each
//! test proves a promise at its public door). Every verb call enters through
//! `oneiron_testkit::door::invoke`, the generated verb dispatch every
//! transport shares. Four of the seven rows are the owner's and run here on a
//! vault opened with the process writer lease, as an embedded host's are:
//! `quarantine.held_edits`, `repo_manifests.conflict.review`,
//! `repo_manifests.conflict.discard` and `retained_work.wait.set`. The other
//! three (`documents.copy_edit.review`, `documents.copy_edit.settle`,
//! `outbox`) act on a server's own state and answer the host-only refusal on
//! an embedded vault.
//!
//! - P1 `oneiron/sync/oneiron-arch-0023b-crdt-sync-implementation-v1`
//!   #artifact-body-quarantine-built: "a malformed artifact body is
//!   quarantined, and replay goes on"; "The `x:` row keeps hashes, a key
//!   length and the typed reason, never the rejected bytes". No `vault.sync`
//!   row replays a window, so the test runs the public forward
//!   rematerialization a peer's window takes, reads the `x:` rows with the
//!   public `quarantined_records`, and asks the owner's held-edits door,
//!   which lists held-edit evidence only. Canon's own tests for this
//!   (`sync/quarantine/tests.rs:1681, :1691`) sit in the lib test module that
//!   `#[cfg(any())]` turns off (FIX [LIBTEST-QUARANTINE-SYNC-QUARANTINE-TESTS]).
//! - P2 the same page, #facet-stamp-federation-built: "`maintain` retires a
//!   held stamp after 30 days", and the row's own words ("The owner sets one
//!   retained-work queue's wait in seconds, or resets it to its existing
//!   default, and receives the effective wait").
//! - Refusals: an agent is refused every owner row and a host row refuses it
//!   as it refuses the owner; malformed bodies are refused.
//!
//! Not in this file: arch-0023b:84 "The receiver never merges it" (a
//! replacement snapshot) runs inside the sync client, and no `vault.sync`
//! row reads a replacement install; a held repo-manifest conflict, which the
//! review and discard rows act on, has no seed a test can reach (only the
//! sync ingest writes the held row), so these two rows are pinned here on an
//! empty vault and on malformed bindings only.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_sync_doors`.
#![cfg(all(oneiron_test_support, feature = "sync", feature = "test-support"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::{Memory, MemoryError};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CODE_ARTIFACT};
use oneiron::sync::WindowKey;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::federation_burst::{FEDERATION_BURST_WAIT_SECS, RetainedWorkQueue};
use oneiron::sync::quarantine::{QuarantineContainer, quarantined_records};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::forward_rematerialize;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_store::loro_document::map_insert_bytes;
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The window the replay fills; `LEARNED_AT` falls inside it.
const WINDOW: &str = "2026-03";
/// A `learned_at` inside `WINDOW`, as `sync/quarantine/tests.rs` uses.
const LEARNED_AT: u64 = 1_772_400_000;
/// Canon's facet stamp hold: 30 days.
const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;
/// A 32-hex id for the host rows' bodies (nothing is stored under it).
const SOME_ID: &str = "019a7218240070008000000000000001";
/// A 64-hex portable repo id (nothing is stored under it).
const PORTABLE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// A seeded vault this process owns (the writer lease), as an embedded host
/// opens it, with the engine's MACHINE writers provisioned
/// (`tests/gate_pins_authority_rechecks.rs` opens it the same way).
fn owned_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("a tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("an owned open");
    (dir, vault)
}

fn provision_machines(vault: &Vault) {
    let _issuer = oneiron::test_support::provision_engine_machines(vault);
}

/// The 25-byte entity envelope (type, occurred start and end, learned_at,
/// all big-endian) and the body, as a peer's window row carries it.
fn window_row(entity_type: u8, data: &[u8]) -> Vec<u8> {
    let occurred = TimeRange { start: 1, end: 2 };
    let mut row = Vec::with_capacity(25 + data.len());
    row.push(entity_type);
    row.extend_from_slice(&occurred.start.to_be_bytes());
    row.extend_from_slice(&occurred.end.to_be_bytes());
    row.extend_from_slice(&LEARNED_AT.to_be_bytes());
    row.extend_from_slice(data);
    row
}

#[track_caller]
fn refused(result: Result<Value, MemoryError>, what: &str) -> MemoryError {
    match result {
        Err(error) => error,
        Ok(value) => panic!("{what} was answered, want a refusal: {value}"),
    }
}

fn wait_set(owner: &Memory<'_>, body: Value) -> Result<Value, MemoryError> {
    door::invoke(owner, "vault.sync.retained_work.wait.set", body)
}

/// P1. A peer's window carries a malformed CODE_ARTIFACT row, a malformed
/// BLOB_ARTIFACT row and a valid ASSET sibling. The replay finishes, the
/// sibling lands, the two bad rows do not, and each leaves one `x:` row with
/// its typed reason and its key's length, not its bytes. The owner's
/// held-edits door does not list them: it lists held edits only.
/// Red proof: `sync/quarantine/keys_classifier.rs:120` no longer lists
/// `InvalidBlobArtifactBody` as a remote rejection (`-red1`).
#[test]
fn a_malformed_artifact_body_is_quarantined_and_replay_goes_on() {
    let (_dir, vault) = owned_vault();
    provision_machines(&vault);
    let window = WindowKey::new(WINDOW);
    let doc = create_window_doc("vault-sync-doors", &window);
    let entities = doc.get_map("entities");
    let (code, blob, good) = (EntityId::now(), EntityId::now(), EntityId::now());
    for (id, entity_type) in [
        (code, ENTITY_TYPE_CODE_ARTIFACT),
        (blob, ENTITY_TYPE_BLOB_ARTIFACT),
    ] {
        // 0xc1 is MessagePack's reserved marker: never a valid body.
        map_insert_bytes(&entities, &id.to_hex(), &window_row(entity_type, &[0xc1]))
            .expect("a malformed artifact row");
    }
    map_insert_bytes(
        &entities,
        &good.to_hex(),
        &window_row(ENTITY_TYPE_ASSET, b"unrelated valid asset"),
    )
    .expect("a valid sibling row");
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window)
        .expect("the replay goes on past the malformed rows");

    assert_eq!(
        vault.get(&good).expect("read the sibling").as_deref(),
        Some(b"unrelated valid asset".as_slice()),
        "the valid sibling lands"
    );
    assert_eq!(vault.get_raw(&code).expect("read the code row"), None);
    assert_eq!(vault.get_raw(&blob).expect("read the blob row"), None);

    let mut records: Vec<_> = quarantined_records(&vault)
        .expect("read the quarantine")
        .into_iter()
        .map(|(_, record)| record)
        .collect();
    records.sort_by(|a, b| a.reason_code.cmp(&b.reason_code));
    let reasons: Vec<&str> = records.iter().map(|r| r.reason_code.as_str()).collect();
    assert_eq!(
        reasons,
        ["InvalidBlobArtifactBody", "InvalidCodeArtifactBody"],
        "each malformed row is quarantined under its typed reason"
    );
    for record in &records {
        assert_eq!(record.window_key, WINDOW, "{record:?}");
        assert_eq!(
            record.container,
            QuarantineContainer::Entities,
            "{record:?}"
        );
        assert_eq!(
            record.crdt_key_len, 32,
            "the key's length, not the key: {record:?}"
        );
    }

    let owner = door::owner(&vault).expect("the owner");
    assert_eq!(
        door::invoke(&owner, "vault.sync.quarantine.held_edits", json!({}))
            .expect("the held edits"),
        json!([]),
        "a rejected artifact row is not a held edit"
    );
}

/// P2. A queue's wait is its default until the owner sets one; the owner's
/// wait is answered and read back, moves no other queue, is never zero, and
/// an absent or null `secs` restores the default. The facet stamp default
/// is canon's 30 days.
/// Red proof: `sync/federation_burst/schedule.rs:248` keeps the owner's
/// wait on a reset (`-red1`).
#[test]
fn the_owner_sets_a_retained_work_wait_and_a_reset_restores_the_default() {
    let (_dir, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let facet = || {
        vault
            .retained_work_wait_secs(RetainedWorkQueue::FacetStamp)
            .expect("read the facet stamp wait")
    };
    assert_eq!(facet(), THIRTY_DAYS, "a held facet stamp waits 30 days");

    let set = wait_set(&owner, json!({"queue": "facet_stamp", "secs": 3600})).expect("set");
    assert_eq!(set, json!(3600), "the wait in force is answered");
    assert_eq!(facet(), 3600, "and read back");
    assert_eq!(
        vault
            .retained_work_wait_secs(RetainedWorkQueue::FederationBurst)
            .expect("read the federation wait"),
        FEDERATION_BURST_WAIT_SECS,
        "one queue's wait moves no other queue"
    );

    let zero = refused(
        wait_set(&owner, json!({"queue": "facet_stamp", "secs": 0})),
        "a zero wait",
    );
    assert_eq!(zero.code, "BAD_REQUEST", "{zero:?}");
    assert_eq!(facet(), 3600, "a refused wait changes nothing");

    let reset = wait_set(&owner, json!({"queue": "facet_stamp"})).expect("reset");
    assert_eq!(
        reset,
        json!(THIRTY_DAYS),
        "an absent secs restores the default"
    );
    assert_eq!(facet(), THIRTY_DAYS);

    wait_set(&owner, json!({"queue": "facet_stamp", "secs": 60})).expect("set again");
    let reset = wait_set(&owner, json!({"queue": "facet_stamp", "secs": null})).expect("reset");
    assert_eq!(
        reset,
        json!(THIRTY_DAYS),
        "a null secs restores the default"
    );
    assert_eq!(facet(), THIRTY_DAYS);
}

/// Refusals by caller. An agent is refused each owner row with a well-formed
/// body, and its call changes nothing; each host row refuses the owner and
/// the agent alike, as an embedded vault reaches no server state.
/// Red proof: `memory/owner_door.rs:77` admits any handle in the lease's
/// process (`-red2`).
#[test]
fn an_agent_is_refused_every_owner_sync_row() {
    let (_dir, vault) = owned_vault();
    let agent = oneiron::test_doors::coach::define_agent(&vault).expect("an agent");
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let agent = vault.memory(agent, EdgeActorClass::Agent);

    for (verb, body) in [
        ("vault.sync.quarantine.held_edits", json!({})),
        (
            "vault.sync.repo_manifests.conflict.review",
            json!({"window": WINDOW, "portable_repo": PORTABLE}),
        ),
        (
            "vault.sync.repo_manifests.conflict.discard",
            json!({"binding": "e30="}),
        ),
        (
            "vault.sync.retained_work.wait.set",
            json!({"queue": "facet_stamp", "secs": 60}),
        ),
    ] {
        let error = refused(door::invoke(&agent, verb, body), verb);
        assert_eq!(error.code, "FORBIDDEN", "an agent on {verb}: {error:?}");
    }
    assert_eq!(
        vault
            .retained_work_wait_secs(RetainedWorkQueue::FacetStamp)
            .expect("read the facet stamp wait"),
        THIRTY_DAYS,
        "the agent's wait was not set"
    );

    let revision = "ab".repeat(32);
    for (verb, body) in [
        (
            "vault.sync.documents.copy_edit.review",
            json!({"source": SOME_ID}),
        ),
        (
            "vault.sync.documents.copy_edit.settle",
            json!({"source": SOME_ID, "revision": revision, "replacement": "text"}),
        ),
        ("vault.sync.outbox", json!({"machine": SOME_ID})),
    ] {
        for (who, caller) in [("the owner", &owner), ("an agent", &agent)] {
            let error = refused(door::invoke(caller, verb, body.clone()), verb);
            assert_eq!(
                error.code, "MODEL_UNAVAILABLE",
                "{who} on {verb}: {error:?}"
            );
        }
    }
}

/// Refusals by body. Each row refuses an unknown field; the review refuses a
/// bad window or portable id, the discard a binding that is not one, the
/// wait an unknown queue or a mistyped `secs`, the host rows a bad id. The
/// owner's well-formed review of a window with no durable state answers
/// null, so each malformed review row differs from an answered one by its
/// fault alone.
/// Red proof: `verbs/repo_manifest_conflict.rs:40` reads a bad window as
/// `2026-03` (`-red2`).
#[test]
fn a_malformed_sync_body_is_refused() {
    let (_dir, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let review =
        |body: Value| door::invoke(&owner, "vault.sync.repo_manifests.conflict.review", body);
    assert_eq!(
        review(json!({"window": WINDOW, "portable_repo": PORTABLE})).expect("a review"),
        Value::Null,
        "no conflict is held, so none is reviewed"
    );

    let revision = "ab".repeat(32);
    for (case, verb, body) in [
        (
            "an unknown field",
            "vault.sync.quarantine.held_edits",
            json!({"zzz": 1}),
        ),
        (
            "an unknown field",
            "vault.sync.repo_manifests.conflict.review",
            json!({"window": WINDOW, "portable_repo": PORTABLE, "zzz": 1}),
        ),
        (
            "a window not YYYY-MM",
            "vault.sync.repo_manifests.conflict.review",
            json!({"window": "03-2026", "portable_repo": PORTABLE}),
        ),
        (
            "month 13",
            "vault.sync.repo_manifests.conflict.review",
            json!({"window": "2026-13", "portable_repo": PORTABLE}),
        ),
        (
            "a portable id not 64 hex",
            "vault.sync.repo_manifests.conflict.review",
            json!({"window": WINDOW, "portable_repo": "abcd"}),
        ),
        (
            "no portable id",
            "vault.sync.repo_manifests.conflict.review",
            json!({"window": WINDOW}),
        ),
        (
            "an unknown field",
            "vault.sync.repo_manifests.conflict.discard",
            json!({"binding": "e30=", "zzz": 1}),
        ),
        (
            "a binding not base64",
            "vault.sync.repo_manifests.conflict.discard",
            json!({"binding": "!!!"}),
        ),
        (
            "base64 that is no binding",
            "vault.sync.repo_manifests.conflict.discard",
            json!({"binding": "e30="}),
        ),
        (
            "an unknown field",
            "vault.sync.retained_work.wait.set",
            json!({"queue": "facet_stamp", "zzz": 1}),
        ),
        (
            "an unknown queue",
            "vault.sync.retained_work.wait.set",
            json!({"queue": "no_such_queue"}),
        ),
        (
            "secs as text",
            "vault.sync.retained_work.wait.set",
            json!({"queue": "facet_stamp", "secs": "an hour"}),
        ),
        (
            "negative secs",
            "vault.sync.retained_work.wait.set",
            json!({"queue": "facet_stamp", "secs": -1}),
        ),
        (
            "an unknown field",
            "vault.sync.documents.copy_edit.review",
            json!({"source": SOME_ID, "zzz": 1}),
        ),
        (
            "no source",
            "vault.sync.documents.copy_edit.review",
            json!({}),
        ),
        (
            "an unknown field",
            "vault.sync.documents.copy_edit.settle",
            json!({"source": SOME_ID, "revision": revision, "replacement": "text", "zzz": 1}),
        ),
        (
            "no replacement",
            "vault.sync.documents.copy_edit.settle",
            json!({"source": SOME_ID, "revision": revision}),
        ),
        (
            "an unknown field",
            "vault.sync.outbox",
            json!({"machine": SOME_ID, "zzz": 1}),
        ),
        (
            "a machine id not hex",
            "vault.sync.outbox",
            json!({"machine": "not-hex"}),
        ),
        ("no machine", "vault.sync.outbox", json!({})),
    ] {
        let error = refused(door::invoke(&owner, verb, body), case);
        assert_eq!(error.code, "BAD_REQUEST", "{case} on {verb}: {error:?}");
    }
    assert_eq!(
        vault
            .retained_work_wait_secs(RetainedWorkQueue::FacetStamp)
            .expect("read the facet stamp wait"),
        THIRTY_DAYS,
        "no refused wait was set"
    );
}
