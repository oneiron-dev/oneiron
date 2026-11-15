//! The skill library's doors (ARCH-0053), entered as the SDK enters them:
//! HTTP `POST /v1/core/facade/<verb>` through the in-process router
//! (`oneshot`, no TCP ports, no sleeps). The doors are `vault.skills.list`,
//! `.get`, `.archive`, `.restore`, `.fork`, `.governance.get`,
//! `.governance.set`, and `vault.delete` on a skill.
//!
//! The promises: archive is a soft tombstone that restore undoes; restore
//! refuses a skill that is not archived; a fork is a new identity that pins
//! its parent; a governance mark changes no content or version; the owner's
//! doors refuse a person on their own credential and change nothing; delete is
//! the owner's explicit act with a receipt; and the owner's get answers the
//! skill as a clean folder whose tree hashes back to its content hash.
//!
//! Each test owns a fresh vault whose bootstrap skills seed Active at open.
//! The skill under test is the first `active` row of the owner's
//! `vault.skills.list` page, or a fresh fork of it where the promise needs a
//! skill that is not a bootstrap skill.
//!
//! The vault's keystore is a `MemoryKeystore`, which `oneiron/test-support`
//! forwards (`oneiron-keystore/test-keystore`); no cfg door is used.
//! Run: `cargo test --locked -p oneiron-server --all-features --features
//! oneiron/test-support --test vault_skills_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill::canonical_skill_tree_hash;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tower::ServiceExt;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person: EntityId,
    person_slip: CapabilitySlip,
    person_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every person credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
}

/// A live PERSON entity, as `graduation_demote_holder_door.rs` places one.
fn seed_person(vault: &Vault) -> EntityId {
    let who = EntityId::now();
    vault
        .put_entity(
            &who,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    who
}

/// A human credential this host mints `who`, holding `read` and `write`:
/// a person's own slip, not owner-grade.
fn mint_person_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential")
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-skills-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let who = seed_person(&vault);
    let person_slip = mint_person_credential(&owner_slip, &vault, &issuer, who);
    let person_token = person_slip.to_token().expect("person slip token");
    let app = build_app(server);
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        person: who,
        person_slip,
        person_token,
    }
}

fn owner_binding(fixture: &Fixture) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&fixture
        .issuer
        .binding_proof(&fixture.owner_slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

fn person_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.person_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("holder proof")
    .to_string()
}

async fn post(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

async fn post_as_owner(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.owner_token.clone();
    post(fixture, path, &token, owner_binding(fixture), body).await
}

async fn post_as_person(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.person_token.clone();
    post(fixture, path, &token, person_binding(fixture), body).await
}

async fn list_skills(fixture: &Fixture) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.list",
        json!({"limit": 50}),
    )
    .await
}

async fn get_skill(fixture: &Fixture, entity_hex: &str) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.get",
        json!({"entity": entity_hex}),
    )
    .await
}

async fn archive_skill(fixture: &Fixture, entity_hex: &str) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.archive",
        json!({"entity": entity_hex}),
    )
    .await
}

async fn restore_skill(fixture: &Fixture, entity_hex: &str) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.restore",
        json!({"entity": entity_hex}),
    )
    .await
}

async fn fork_skill(fixture: &Fixture, parent_hex: &str, skill_id: &str) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.fork",
        json!({"parent": parent_hex, "skill_id": skill_id}),
    )
    .await
}

async fn governance_get(fixture: &Fixture, entity_hex: &str) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.governance.get",
        json!({"entity": entity_hex}),
    )
    .await
}

async fn governance_set(fixture: &Fixture, entity_hex: &str, tier: Value) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.governance.set",
        json!({"entity": entity_hex, "tier": tier}),
    )
    .await
}

async fn delete_skill(fixture: &Fixture, entity_hex: &str) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.delete",
        json!({"entity_ref": entity_hex, "reason": "user_delete"}),
    )
    .await
}

/// The first skill of an owner's list page whose `lifecycle` is `"active"`.
fn first_active_skill(page: &Value) -> String {
    page["skills"]
        .as_array()
        .expect("skills page lists skills")
        .iter()
        .find(|skill| skill["lifecycle"].as_str() == Some("active"))
        .unwrap_or_else(|| panic!("a fresh vault seeds an active skill: {page}"))["entity"]
        .as_str()
        .expect("skill entity")
        .to_owned()
}

/// One skill row of an owner's list page, by entity hex.
fn listed_skill<'a>(page: &'a Value, entity_hex: &str) -> &'a Value {
    page["skills"]
        .as_array()
        .expect("skills page lists skills")
        .iter()
        .find(|skill| skill["entity"].as_str() == Some(entity_hex))
        .unwrap_or_else(|| panic!("the list still shows the skill: {page}"))
}

/// Archive is the soft tombstone with a restorable view: archiving keeps the
/// body and restore brings it back.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:273`
/// "Archive is the soft tombstone with a restorable view".
#[test]
fn archive_keeps_the_body_and_restore_brings_it_back() {
    run_on_engine_stack("skills-archive-restore", || async {
        let fixture = setup().await;
        let (status, page) = list_skills(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner lists the library: {page}");
        let entity_hex = first_active_skill(&page);

        let (status, before) = get_skill(&fixture, &entity_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads the skill: {before}");
        assert_eq!(
            before["lifecycle"].as_str(),
            Some("active"),
            "the seed stands active: {before}"
        );

        let (status, archived) = archive_skill(&fixture, &entity_hex).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner archives the skill: {archived}"
        );
        assert_eq!(
            archived["entity"].as_str(),
            Some(entity_hex.as_str()),
            "the archive answers the same entity: {archived}"
        );
        assert_eq!(
            archived["lifecycle"].as_str(),
            Some("archived"),
            "the archive answers archived: {archived}"
        );
        assert_eq!(
            archived["loadable"].as_bool(),
            Some(false),
            "an archived skill does not load: {archived}"
        );
        assert_eq!(
            archived["content_hash"], before["content_hash"],
            "the archive keeps the content hash: {archived}"
        );
        assert_eq!(
            archived["version"], before["version"],
            "the archive keeps the version: {archived}"
        );
        assert_eq!(
            archived["files"], before["files"],
            "the archive keeps the files: {archived}"
        );
        assert_eq!(
            archived["receipts"], before["receipts"],
            "the archive keeps the receipts: {archived}"
        );

        let (status, again) = get_skill(&fixture, &entity_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads it back: {again}");
        assert_eq!(
            again["lifecycle"].as_str(),
            Some("archived"),
            "get still shows it archived: {again}"
        );
        assert_eq!(
            again["content_hash"], before["content_hash"],
            "get keeps the content hash: {again}"
        );
        assert_eq!(
            again["version"], before["version"],
            "get keeps the version: {again}"
        );
        assert_eq!(
            again["files"], before["files"],
            "get keeps the files: {again}"
        );

        let (status, page) = list_skills(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner lists again: {page}");
        let row = listed_skill(&page, &entity_hex);
        assert_eq!(
            row["lifecycle"].as_str(),
            Some("archived"),
            "the list still shows it archived: {page}"
        );
        assert_eq!(
            row["content_hash"], before["content_hash"],
            "the list keeps the content hash: {page}"
        );
        assert_eq!(
            row["version"], before["version"],
            "the list keeps the version: {page}"
        );

        let (status, restored) = restore_skill(&fixture, &entity_hex).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner restores the skill: {restored}"
        );
        assert_eq!(
            restored["outcome"].as_str(),
            Some("restored"),
            "the restore lands: {restored}"
        );
        assert_eq!(
            restored["skill"]["lifecycle"].as_str(),
            Some("active"),
            "the restore reactivates: {restored}"
        );
        assert_eq!(
            restored["skill"]["content_hash"], before["content_hash"],
            "the restore keeps the content hash: {restored}"
        );
        assert_eq!(
            restored["skill"]["version"], before["version"],
            "the restore keeps the version: {restored}"
        );
        assert_eq!(
            restored["skill"]["files"], before["files"],
            "the restore keeps the files: {restored}"
        );
    });
}

/// Restore is archive's undo only: on an active skill it is refused, and the
/// skill is unchanged.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:273`
/// "Archive is the soft tombstone with a restorable view".
#[test]
fn restore_refuses_a_skill_that_is_not_archived() {
    run_on_engine_stack("skills-restore-refused", || async {
        let fixture = setup().await;
        let (status, page) = list_skills(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner lists the library: {page}");
        let entity_hex = first_active_skill(&page);

        let (status, before) = get_skill(&fixture, &entity_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads the skill: {before}");
        assert_eq!(
            before["lifecycle"].as_str(),
            Some("active"),
            "the seed stands active: {before}"
        );

        let (status, refused) = restore_skill(&fixture, &entity_hex).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "restore of an active skill is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("restore requires an archived skill"),
            "the refusal names its reason: {refused}"
        );

        let (status, again) = get_skill(&fixture, &entity_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads it back: {again}");
        assert_eq!(
            again["lifecycle"], before["lifecycle"],
            "the refused restore keeps the lifecycle: {again}"
        );
        assert_eq!(
            again["version"], before["version"],
            "the refused restore keeps the version: {again}"
        );
        assert_eq!(
            again["content_hash"], before["content_hash"],
            "the refused restore keeps the content hash: {again}"
        );
    });
}

/// A fork takes a new identity and pins its parent: the fork is a new entity
/// whose first lineage hop names the parent and its version, and the parent
/// is unchanged.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:236`
/// "Local edit = fork (one fork law). ... a document off a frontier that
/// remembers its parent."
#[test]
fn fork_takes_a_new_identity_and_pins_its_parent() {
    run_on_engine_stack("skills-fork", || async {
        let fixture = setup().await;
        let (status, page) = list_skills(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner lists the library: {page}");
        let parent_hex = first_active_skill(&page);

        let (status, parent) = get_skill(&fixture, &parent_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads the parent: {parent}");
        let parent_skill_id = parent["skill_id"]
            .as_str()
            .expect("parent skill id")
            .to_owned();
        let parent_version = parent["version"]
            .as_str()
            .expect("parent version")
            .to_owned();
        let fork_skill_id = format!("{parent_skill_id}-fork");

        let (status, forked) = fork_skill(&fixture, &parent_hex, &fork_skill_id).await;
        assert_eq!(status, StatusCode::OK, "owner forks the skill: {forked}");
        let fork_hex = forked["entity"].as_str().expect("fork entity").to_owned();
        assert_ne!(fork_hex, parent_hex, "the fork is a new entity: {forked}");
        assert_eq!(
            forked["skill_id"].as_str(),
            Some(fork_skill_id.as_str()),
            "the fork takes its own skill id: {forked}"
        );

        let (status, fork_view) = get_skill(&fixture, &fork_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads the fork: {fork_view}");
        assert_eq!(
            fork_view["lineage"][0]["parent"].as_str(),
            Some(parent_hex.as_str()),
            "the fork pins its parent: {fork_view}"
        );
        assert_eq!(
            fork_view["lineage"][0]["parent_version"].as_str(),
            Some(parent_version.as_str()),
            "the fork pins its parent's version: {fork_view}"
        );

        let (status, parent_again) = get_skill(&fixture, &parent_hex).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the parent back: {parent_again}"
        );
        assert_eq!(
            parent_again["version"], parent["version"],
            "the fork keeps the parent's version: {parent_again}"
        );
        assert_eq!(
            parent_again["content_hash"], parent["content_hash"],
            "the fork keeps the parent's content hash: {parent_again}"
        );
        assert_eq!(
            parent_again["lifecycle"], parent["lifecycle"],
            "the fork keeps the parent's lifecycle: {parent_again}"
        );
    });
}

/// A governance mark changes no content or version: set shows on
/// governance.get and skills.get beside the same version and content hash,
/// and clearing returns governance.get to none.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:216`
/// "identity/alignment-tier: never enters auto-edit at all": the tier is a
/// mark on the skill, never an edit of it.
#[test]
fn governance_mark_changes_no_content_or_version() {
    run_on_engine_stack("skills-governance", || async {
        let fixture = setup().await;
        let (status, page) = list_skills(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner lists the library: {page}");
        let parent_hex = first_active_skill(&page);
        let (status, parent) = get_skill(&fixture, &parent_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads the parent: {parent}");
        let parent_skill_id = parent["skill_id"]
            .as_str()
            .expect("parent skill id")
            .to_owned();
        // A fork, not a bootstrap skill: only an unmarked record whose road
        // no provenance explains resolves to no tier once cleared.
        let governed_skill_id = format!("{parent_skill_id}-governed");
        let (status, forked) = fork_skill(&fixture, &parent_hex, &governed_skill_id).await;
        assert_eq!(status, StatusCode::OK, "owner forks the skill: {forked}");
        let fork_hex = forked["entity"].as_str().expect("fork entity").to_owned();

        let (status, before) = get_skill(&fixture, &fork_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads the fork: {before}");

        let (status, marked) = governance_set(&fixture, &fork_hex, json!("identity")).await;
        assert_eq!(status, StatusCode::OK, "owner marks the tier: {marked}");
        assert_eq!(
            marked["entity"].as_str(),
            Some(fork_hex.as_str()),
            "the mark answers the same entity: {marked}"
        );
        assert_eq!(
            marked["tier"].as_str(),
            Some("identity"),
            "the mark lands: {marked}"
        );

        let (status, view) = governance_get(&fixture, &fork_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads the mark: {view}");
        assert_eq!(
            view["tier"].as_str(),
            Some("identity"),
            "governance.get shows the mark: {view}"
        );
        assert_eq!(
            view["verdict"].as_str(),
            Some("marked"),
            "an explicit mark reads marked: {view}"
        );

        let (status, again) = get_skill(&fixture, &fork_hex).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the skill back: {again}"
        );
        assert_eq!(
            again["version"], before["version"],
            "the mark keeps the version: {again}"
        );
        assert_eq!(
            again["content_hash"], before["content_hash"],
            "the mark keeps the content hash: {again}"
        );
        assert_eq!(
            again["governance_tier"].as_str(),
            Some("identity"),
            "skills.get shows the mark: {again}"
        );

        let (status, cleared) = governance_set(&fixture, &fork_hex, Value::Null).await;
        assert_eq!(status, StatusCode::OK, "owner clears the mark: {cleared}");
        let (status, view) = governance_get(&fixture, &fork_hex).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the cleared mark: {view}"
        );
        assert!(
            view["tier"].is_null(),
            "governance.get shows none after the clear: {view}"
        );
    });
}

/// The owner-only doors refuse a person on its own credential and change
/// nothing: one table test over archive, restore, governance.set and
/// governance.get.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:273`
/// "A shipped skill is archived, deleted or replaced with the vault's own
/// verbs."
#[test]
fn owner_only_doors_refuse_a_person_and_change_nothing() {
    run_on_engine_stack("skills-owner-only", || async {
        let fixture = setup().await;
        let (status, page) = list_skills(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner lists the library: {page}");
        let entity_hex = first_active_skill(&page);

        let (status, before) = get_skill(&fixture, &entity_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads the skill: {before}");

        assert_eq!(
            fixture.person_slip.claims.holder_ref,
            fixture.person.to_hex(),
            "the person's credential binds the person"
        );
        let rows: Vec<(&str, Value)> = vec![
            (
                "vault.skills.archive",
                json!({"entity": entity_hex.clone()}),
            ),
            (
                "vault.skills.restore",
                json!({"entity": entity_hex.clone()}),
            ),
            (
                "vault.skills.governance.set",
                json!({"entity": entity_hex.clone(), "tier": "standard"}),
            ),
            (
                "vault.skills.governance.get",
                json!({"entity": entity_hex.clone()}),
            ),
        ];
        for (verb, input) in rows {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post_as_person(&fixture, &path, input).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a person is refused {verb}: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {refused}"
            );
            assert_eq!(
                refused["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "the refusal names the owner: {refused}"
            );
        }

        let (status, again) = get_skill(&fixture, &entity_hex).await;
        assert_eq!(status, StatusCode::OK, "owner reads it back: {again}");
        assert_eq!(
            again["lifecycle"], before["lifecycle"],
            "the refusals keep the lifecycle: {again}"
        );
        assert_eq!(
            again["version"], before["version"],
            "the refusals keep the version: {again}"
        );
        assert_eq!(
            again["content_hash"], before["content_hash"],
            "the refusals keep the content hash: {again}"
        );
        assert_eq!(
            again["governance_tier"], before["governance_tier"],
            "the refusals keep the governance tier: {again}"
        );
    });
}

/// Delete is erasure through the person's own path with a receipt, never
/// automatic: the owner archives a bootstrap skill, deletes it with a reason,
/// and reads it back gone.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:273`
/// "Delete is erasure through the person's own path with a receipt, never automatic".
#[test]
fn delete_is_the_owners_explicit_act_with_a_receipt() {
    run_on_engine_stack("skills-delete", || async {
        let fixture = setup().await;
        let (status, page) = list_skills(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner lists the library: {page}");
        let entity_hex = first_active_skill(&page);

        let (status, archived) = archive_skill(&fixture, &entity_hex).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner archives the skill: {archived}"
        );
        assert_eq!(
            archived["lifecycle"].as_str(),
            Some("archived"),
            "the skill stands archived: {archived}"
        );

        let (status, receipt) = delete_skill(&fixture, &entity_hex).await;
        assert_eq!(status, StatusCode::OK, "owner deletes the skill: {receipt}");
        assert_eq!(
            receipt["existed"].as_bool(),
            Some(true),
            "the receipt names that the skill existed: {receipt}"
        );
        assert_eq!(
            receipt["reason"].as_str(),
            Some("user_delete"),
            "the receipt names the reason: {receipt}"
        );
        assert!(
            receipt["receipt_ref"].is_null(),
            "a tombstone delete writes no redaction receipt: {receipt}"
        );
        assert_eq!(
            receipt["state"].as_str(),
            Some("applied"),
            "the delete applies: {receipt}"
        );

        let (status, gone) = get_skill(&fixture, &entity_hex).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "the deleted skill reads back gone: {gone}"
        );
        assert_eq!(
            gone["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {gone}"
        );
    });
}

/// Every skill exports as a clean folder: for each active skill, the owner's
/// get answers its files path-sorted with a `SKILL.md`, and that tree hashes
/// back to the skill's own content hash. Export is get's exact files
/// (`HubPackage::export_files`); main has no separate export verb.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:270`
/// "Export always. Every skill — authored, distilled, forked — exports as a
/// clean agentskills.io folder."
#[test]
fn get_returns_the_skill_as_a_clean_folder() {
    run_on_engine_stack("skills-clean-folder", || async {
        let fixture = setup().await;
        let (status, page) = list_skills(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner lists the library: {page}");
        let active: Vec<String> = page["skills"]
            .as_array()
            .expect("skills page lists skills")
            .iter()
            .filter(|skill| skill["lifecycle"].as_str() == Some("active"))
            .map(|skill| skill["entity"].as_str().expect("skill entity").to_owned())
            .collect();
        assert!(
            !active.is_empty(),
            "a fresh vault seeds an active skill: {page}"
        );

        for entity_hex in &active {
            let (status, skill) = get_skill(&fixture, entity_hex).await;
            assert_eq!(status, StatusCode::OK, "owner reads the skill: {skill}");
            let folder: Vec<(String, Vec<u8>)> = skill["files"]
                .as_array()
                .unwrap_or_else(|| panic!("the owner's get carries the files: {skill}"))
                .iter()
                .map(|file| {
                    let path = file["path"].as_str().expect("file path").to_owned();
                    let content: Vec<u8> = serde_json::from_value(file["content"].clone())
                        .expect("file content bytes");
                    (path, content)
                })
                .collect();
            let paths: Vec<&str> = folder.iter().map(|(path, _)| path.as_str()).collect();
            assert!(
                paths.contains(&"SKILL.md"),
                "the folder holds SKILL.md: {paths:?} in {skill}"
            );
            assert!(
                paths
                    .windows(2)
                    .all(|pair| pair[0].as_bytes() < pair[1].as_bytes()),
                "the folder is path-sorted with no duplicate path: {paths:?}"
            );
            let tree_hash = canonical_skill_tree_hash(
                folder
                    .iter()
                    .map(|(path, content)| (path.as_str(), content.as_slice())),
            )
            .expect("the folder is a valid skill tree");
            assert_eq!(
                skill["content_hash"].as_str(),
                Some(tree_hash.to_hex().as_str()),
                "the folder hashes back to the skill's content hash: {paths:?}"
            );
        }
    });
}
