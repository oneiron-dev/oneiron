//! NO-DOOR REPO-LFS-PATH-POLICY (tests/e2e/code-custody.test.ts
//! CODE-CUSTODY-06; Engine CODECUSTODY-LFS Q1 = A), on the catalogue key
//! `origin.lfs_path_rules` (DESIGN 15-setting-primitive stage 4,
//! SETTING-KEYED-A K2a): the owner reads and replaces one served origin's
//! ordered LFS path rules through `vault.settings.get` and `vault.settings.set`
//! at the repository's scope. A fresh origin is at revision 0 with no rules; a
//! set names the revision it read, and a stale one is refused with nothing
//! written. Rules are exact paths or directory prefixes, first match wins, and
//! an unmatched path is repository-large. A path that is not normalized is
//! refused, a caller that is not the owner changes nothing, and the rules
//! survive a reopen.
//!
//! `cargo test --locked -p oneiron --all-features --test origin_lfs_path_policy`.

use std::path::Path;

use oneiron::memory::origin_doors::OriginRegisterRequest;
use oneiron::origin::lfs::{LfsAssetClass, LfsPathPolicy, OriginLfsPathPolicy};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const KEY: &str = "origin.lfs_path_rules";
const REPO: &str = "assets";

/// Opens the vault this process owns (the writer lease), as an embedded host
/// does at each start, so the owner's handle carries the owner's proof.
fn open_owned(path: &Path) -> (Vault, EntityId) {
    let vault = Vault::open_owned(path, VaultConfig::device()).expect("an owned vault");
    oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    (vault, owner)
}

/// A change of the rules at `repo_id`, naming the revision the caller read.
fn set(repo_id: EntityId, expected_revision: u64, rules: Value) -> Value {
    json!({
        "key": KEY,
        "scope": { "kind": "repo", "id": repo_id.to_hex() },
        "value": rules,
        "expected_revision": expected_revision,
    })
}

/// The rules and their revision as `vault.settings.get` reads them at `repo_id`.
fn read(vault: &Vault, owner: EntityId, repo_id: EntityId) -> OriginLfsPathPolicy {
    let read = invoke(
        &vault.memory(owner, EdgeActorClass::Human),
        GET,
        json!({ "key": KEY, "at": [{ "kind": "repo", "id": repo_id.to_hex() }] }),
    )
    .unwrap_or_else(|error| panic!("{GET} answers: {error:?}"));
    OriginLfsPathPolicy {
        revision: read["revision"].as_u64().expect("a revision"),
        rules: serde_json::from_value(read["value"].clone()).expect("the rules"),
    }
}

#[test]
fn the_owner_sets_and_reads_an_origins_lfs_path_rules() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = open_owned(dir.path());
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let me = vault.memory(owner, EdgeActorClass::Human);
    let repo_id = me
        .origin_register_as(
            &proof,
            OriginRegisterRequest {
                repo: REPO.to_owned(),
                default_branch: "main".to_owned(),
            },
        )
        .expect("the owner registers the origin")
        .repo_id;

    let fresh = read(&vault, owner, repo_id);
    assert_eq!((fresh.revision, fresh.rules.is_empty()), (0, true));
    assert_eq!(
        fresh
            .classify(repo_id, b"docs/manual.pdf")
            .expect("classify"),
        LfsAssetClass::RepositoryLarge
    );

    // An exact override before the broader prefix wins: first match.
    let rules = json!([
        { "match": { "exact": "vendor/keep-large.bin" }, "class": "repository-large" },
        { "match": { "prefix": "vendor" }, "class": "build-required" },
        { "match": { "exact": "assets/logo.bin" }, "class": "build-required" },
    ]);
    let applied = invoke(&me, SET, set(repo_id, 0, rules.clone())).expect("the owner's set");
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let first = read(&vault, owner, repo_id);
    assert_eq!(first.revision, 1);
    assert_eq!(
        serde_json::to_value(&first.rules).expect("rules as JSON"),
        rules
    );

    // A set at a revision the rules moved past is refused; nothing changes.
    invoke(&me, SET, set(repo_id, 0, json!([]))).expect_err("a stale revision is refused");
    // A path that is not a normalized repository-relative path is refused.
    for bad in ["/abs.bin", "a/../b.bin", "dir/", ""] {
        invoke(
            &me,
            SET,
            set(
                repo_id,
                1,
                json!([{ "match": { "exact": bad }, "class": "build-required" }]),
            ),
        )
        .expect_err("an unnormalized path is refused");
    }
    // A caller that is not the owner changes nothing.
    let stranger = invoke(
        &vault.memory(EntityId::now(), EdgeActorClass::Human),
        SET,
        set(repo_id, 1, json!([])),
    );
    assert!(
        !stranger
            .as_ref()
            .is_ok_and(|answer| answer["status"] == json!("applied")),
        "{stranger:?}"
    );
    assert_eq!(read(&vault, owner, repo_id), first, "nothing was written");

    // The rules as read classify: exact, prefix at a `/` boundary, first
    // match, and repository-large for every other path.
    for (path, class) in [
        ("assets/logo.bin", LfsAssetClass::BuildRequired),
        ("vendor/lib/model.bin", LfsAssetClass::BuildRequired),
        ("vendor/keep-large.bin", LfsAssetClass::RepositoryLarge),
        ("vendor-other/lib.bin", LfsAssetClass::RepositoryLarge),
        ("vendor", LfsAssetClass::RepositoryLarge),
        ("docs/manual.pdf", LfsAssetClass::RepositoryLarge),
    ] {
        assert_eq!(
            first.classify(repo_id, path.as_bytes()).expect("classify"),
            class,
            "{path}"
        );
    }

    // The rules survive a reopen; an empty set restores the default and still
    // advances the revision.
    drop(me);
    drop(vault);
    let (vault, owner) = open_owned(dir.path());
    assert_eq!(read(&vault, owner, repo_id), first, "the rules survive");
    let cleared = invoke(
        &vault.memory(owner, EdgeActorClass::Human),
        SET,
        set(repo_id, 1, json!([])),
    )
    .expect("the owner clears the rules");
    assert_eq!(cleared["status"], json!("applied"), "{cleared}");
    let after = read(&vault, owner, repo_id);
    assert_eq!((after.revision, after.rules.is_empty()), (2, true));
}
