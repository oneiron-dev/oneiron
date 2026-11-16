//! The graph-FS memory fork (L3-39 PR 2, PLAN-L3-39 Tests PR 2): a mount
//! that reads the vault's memory as it stood at a frontier the engine handed
//! out. Each test mounts a live head, takes its frontier, moves the live rows,
//! then mounts the fork and proves the fork still reads the old revisions, the
//! old worlds, and only the links recorded before the frontier's instant, while
//! the live head reads the new ones.
//!
//! Run line:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test graph_fs_memory_fork`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine as _;
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::graph_fs_doors::{
    GraphFsDirectoryView, GraphFsEncoding, GraphFsGrepRequest, GraphFsMountRequest, GraphFsOutput,
    GraphFsPathRequest, GraphFsPlan,
};
use oneiron::memory::{MEMORY_CODE_NOT_FOUND, Memory, SafeDeleteReason};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::memory_frontier::{MemoryFrontier, forget_retained_revision, revision_at};
use oneiron::test_support::provision_engine_machines;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, TimeRange, Vault, VaultConfig,
};
use serde_json::json;

/// A fresh device vault and the directory that holds it.
fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("create a fresh vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open a fresh vault");
    (dir, vault)
}

/// The vault's embedded owner.
fn owner_id(vault: &Vault) -> EntityId {
    vault
        .ensure_embedded_owner_actor()
        .expect("ensure the embedded owner")
}

/// A claim timestamp used for every put in these tests.
const fn claim_time() -> TimeRange {
    TimeRange { start: 1, end: 1 }
}

/// A fresh WORLD row.
fn put_world(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_WORLD, claim_time(), 1, b"world")
        .expect("put a WORLD row");
    id
}

/// A fresh PERSON row.
fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, claim_time(), 1, b"person")
        .expect("put a PERSON row");
    id
}

/// The claim `id` about `subject` in `world` with the string `value`.
fn put_claim_in_world(
    vault: &Vault,
    id: &EntityId,
    subject: &EntityId,
    world: Option<EntityId>,
    value: &str,
) {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(*subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("build a claim body");
    body.world = world;
    vault
        .put_claim(id, &body, claim_time(), 1)
        .expect("put the claim");
}

/// The lowercase hex of the UTF-8 bytes of `text`.
fn utf8_hex(text: &str) -> String {
    text.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A live-head mount request.
fn live_mount_request() -> GraphFsMountRequest {
    serde_json::from_value(json!({"ref": {"kind": "live_head"}}))
        .expect("a live-head mount request decodes")
}

/// A live-head mount request that pages one entry at a time.
fn live_mount_request_paged() -> GraphFsMountRequest {
    serde_json::from_value(json!({"ref": {"kind": "live_head"}, "max_entries": 1}))
        .expect("a paged live-head mount request decodes")
}

/// A memory-fork mount request for the frontier hex `frontier`.
fn fork_mount_request(frontier: &str) -> GraphFsMountRequest {
    serde_json::from_value(json!({"ref": {"kind": "fork_hash", "hash": frontier}}))
        .expect("a memory-fork mount request decodes")
}

/// A memory-fork mount request for `frontier` that pages one entry at a time.
fn fork_mount_request_paged(frontier: &str) -> GraphFsMountRequest {
    serde_json::from_value(
        json!({"ref": {"kind": "fork_hash", "hash": frontier}, "max_entries": 1}),
    )
    .expect("a paged memory-fork mount request decodes")
}

/// The frontier hex the mount `mount` reports when `memory` mounts it.
fn mount_frontier_hex(memory: &Memory<'_>, mount: GraphFsMountRequest) -> String {
    let mounted = memory
        .graph_fs_mount(mount)
        .expect("mount the graph file face");
    let value = serde_json::to_value(&mounted).expect("the mount answer encodes");
    let frontier = value
        .get("frontier")
        .and_then(serde_json::Value::as_str)
        .expect("the mount reports its frontier hex")
        .to_owned();
    assert_eq!(
        frontier.len(),
        32,
        "a frontier is 32 hex characters: {frontier}"
    );
    assert!(
        frontier
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "a frontier is lowercase hex: {frontier}"
    );
    frontier
}

/// The frontier the 32 hex characters `frontier` name: `sequence` then
/// `recorded_at`, each eight bytes big-endian, as a mount answer spells it.
fn parse_frontier(frontier: &str) -> MemoryFrontier {
    assert_eq!(
        frontier.len(),
        32,
        "a frontier is 32 hex characters: {frontier}"
    );
    let word = |range: std::ops::Range<usize>| {
        u64::from_str_radix(&frontier[range], 16).expect("a frontier word is hex")
    };
    MemoryFrontier {
        sequence: word(0..16),
        recorded_at: word(16..32),
    }
}

/// A path request for `path` on `mount`.
fn path_request(mount: &GraphFsMountRequest, path: &str) -> GraphFsPathRequest {
    let mount_value = serde_json::to_value(mount).expect("the mount request encodes");
    serde_json::from_value(json!({"mount": mount_value, "path": path}))
        .expect("a graph file path request decodes")
}

/// A path request for `path` on `mount` resumed at `cursor`.
fn path_request_at(mount: &GraphFsMountRequest, path: &str, cursor: &str) -> GraphFsPathRequest {
    let mount_value = serde_json::to_value(mount).expect("the mount request encodes");
    serde_json::from_value(json!({"mount": mount_value, "path": path, "cursor": cursor}))
        .expect("a graph file path request with a cursor decodes")
}

/// A grep request for `pattern` under `path` on `mount`.
fn grep_request(mount: &GraphFsMountRequest, path: &str, pattern: &str) -> GraphFsGrepRequest {
    let mount_value = serde_json::to_value(mount).expect("the mount request encodes");
    serde_json::from_value(
        json!({"mount": mount_value, "path": path, "pattern": pattern, "recursive": true}),
    )
    .expect("a graph file grep request decodes")
}

/// The decoded text of a coreutils answer.
fn decoded_output_text(output: &GraphFsOutput) -> String {
    match output.encoding {
        GraphFsEncoding::Utf8 => output.output.clone(),
        GraphFsEncoding::Base64 => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(output.output.as_bytes())
                .expect("the base64 coreutils output decodes");
            String::from_utf8(bytes).expect("the decoded coreutils output is text")
        }
    }
}

/// The text of the file at `path` on `mount` as `memory` cats it.
fn cat_text(memory: &Memory<'_>, mount: &GraphFsMountRequest, path: &str) -> String {
    let output = memory
        .graph_fs_cat(path_request(mount, path))
        .expect("cat the graph file");
    decoded_output_text(&output)
}

/// The entry names of the directory at `path` on `mount`.
fn readdir_names(memory: &Memory<'_>, mount: &GraphFsMountRequest, path: &str) -> Vec<String> {
    let view = memory
        .graph_fs_readdir(path_request(mount, path))
        .expect("list the graph directory");
    view.entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect()
}

/// The directory view at `path` on `mount`.
fn readdir_view(
    memory: &Memory<'_>,
    mount: &GraphFsMountRequest,
    path: &str,
) -> GraphFsDirectoryView {
    memory
        .graph_fs_readdir(path_request(mount, path))
        .expect("list the graph directory")
}

/// The grep answer for `pattern` under `path` on `mount`.
fn grep_output(
    memory: &Memory<'_>,
    mount: &GraphFsMountRequest,
    path: &str,
    pattern: &str,
) -> GraphFsOutput {
    memory
        .graph_fs_grep(grep_request(mount, path, pattern))
        .expect("grep the graph tree")
}

/// The fork answer names plan walk. (The memory door's answer carries the
/// plan alone; the fork walk reason lives on the engine's command output.)
fn assert_fork_walk_plan(output: &GraphFsOutput) {
    match output.plan {
        GraphFsPlan::Walk => {}
        GraphFsPlan::Pushdown => {
            panic!("a memory-fork coreutils answer walks, never pushes down: {output:?}")
        }
    }
    let value = serde_json::to_value(output).expect("the coreutils answer encodes");
    assert_eq!(
        value.get("plan").and_then(serde_json::Value::as_str),
        Some("walk"),
        "a memory-fork coreutils answer names its plan walk: {value}"
    );
}

/// Delete `id_hex` as the owner through the named `safe_delete` door, as
/// `delete_authority.rs` deletes.
fn delete_as_owner(vault: &Vault, owner: EntityId, id_hex: &str) {
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .safe_delete(id_hex, SafeDeleteReason::UserDelete)
        .expect("the owner's named delete runs");
    assert!(receipt.existed, "the deleted row existed");
}

#[test]
fn a_memory_fork_reads_a_claim_as_it_stood() {
    let (_dir, vault) = open_vault();
    let owner = owner_id(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let subject = put_person(&vault);
    let claim = EntityId::now();
    put_claim_in_world(&vault, &claim, &subject, None, "before");
    let frontier = mount_frontier_hex(&memory, live_mount_request());
    put_claim_in_world(&vault, &claim, &subject, None, "after");

    let fork = fork_mount_request(&frontier);
    let live = live_mount_request();
    let path = format!("/claims/by-id/{}", claim.to_hex());
    let fork_text = cat_text(&memory, &fork, &path);
    assert!(
        fork_text.contains(&utf8_hex("before")),
        "the fork reads the value the claim held at the frontier: {fork_text}"
    );
    assert!(
        !fork_text.contains(&utf8_hex("after")),
        "the fork reads none of the later value: {fork_text}"
    );
    assert!(
        fork_text.contains(&format!("mount\tmemoryFork:{frontier}")),
        "the fork file names its mount: {fork_text}"
    );
    let live_text = cat_text(&memory, &live, &path);
    assert!(
        live_text.contains(&utf8_hex("after")),
        "the live head reads the later value: {live_text}"
    );
}

#[test]
fn a_claim_born_after_the_fork_is_absent_there() {
    let (_dir, vault) = open_vault();
    let owner = owner_id(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let subject = put_person(&vault);
    let frontier = mount_frontier_hex(&memory, live_mount_request());
    let claim = EntityId::now();
    put_claim_in_world(&vault, &claim, &subject, None, "born late");

    let fork = fork_mount_request(&frontier);
    let live = live_mount_request();
    let listed_fork = readdir_names(&memory, &fork, "/claims/by-id");
    assert!(
        !listed_fork.contains(&claim.to_hex()),
        "a claim born after the frontier is not listed at the fork: {listed_fork:?}"
    );
    let path = format!("/claims/by-id/{}", claim.to_hex());
    let fork_text = cat_text(&memory, &fork, &path);
    assert!(
        fork_text.is_empty(),
        "a claim born after the frontier is no file at the fork: {fork_text}"
    );
    let listed_live = readdir_names(&memory, &live, "/claims/by-id");
    assert!(
        listed_live.contains(&claim.to_hex()),
        "the live head lists the later claim: {listed_live:?}"
    );
}

#[test]
fn a_claim_lists_in_the_world_it_stood_in_at_the_fork() {
    let (_dir, vault) = open_vault();
    let owner = owner_id(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let world_a = put_world(&vault);
    let world_b = put_world(&vault);
    let subject = put_person(&vault);
    let claim = EntityId::now();
    put_claim_in_world(&vault, &claim, &subject, Some(world_a), "world move");
    let frontier = mount_frontier_hex(&memory, live_mount_request());
    put_claim_in_world(&vault, &claim, &subject, Some(world_b), "world move");

    let fork = fork_mount_request(&frontier);
    let live = live_mount_request();
    let path_a = format!("/worlds/{}/claims", world_a.to_hex());
    let path_b = format!("/worlds/{}/claims", world_b.to_hex());
    let fork_a = readdir_names(&memory, &fork, &path_a);
    assert!(
        fork_a.contains(&claim.to_hex()),
        "at the fork the claim lists in the world it stood in: {fork_a:?}"
    );
    let fork_b = readdir_names(&memory, &fork, &path_b);
    assert!(
        !fork_b.contains(&claim.to_hex()),
        "at the fork the claim lists in no later world: {fork_b:?}"
    );
    let live_a = readdir_names(&memory, &live, &path_a);
    assert!(
        !live_a.contains(&claim.to_hex()),
        "the live head lists the claim in no former world: {live_a:?}"
    );
    let live_b = readdir_names(&memory, &live, &path_b);
    assert!(
        live_b.contains(&claim.to_hex()),
        "the live head lists the claim in its later world: {live_b:?}"
    );
}

#[test]
fn grep_at_a_fork_finds_the_old_words_and_walks() {
    let (_dir, vault) = open_vault();
    let owner = owner_id(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let subject = put_person(&vault);
    let claim = EntityId::now();
    put_claim_in_world(&vault, &claim, &subject, None, "before");
    let frontier = mount_frontier_hex(&memory, live_mount_request());
    put_claim_in_world(&vault, &claim, &subject, None, "after");

    let fork = fork_mount_request(&frontier);
    let before = grep_output(&memory, &fork, "/claims", &utf8_hex("before"));
    assert_fork_walk_plan(&before);
    let before_text = decoded_output_text(&before);
    assert!(
        before_text.contains(&claim.to_hex()),
        "the fork grep for the old words matches the claim: {before_text}"
    );
    let after = grep_output(&memory, &fork, "/claims", &utf8_hex("after"));
    assert_fork_walk_plan(&after);
    let after_text = decoded_output_text(&after);
    assert!(
        !after_text.contains(&claim.to_hex()),
        "the fork grep for the later words matches nothing: {after_text}"
    );
}

#[test]
fn a_link_made_after_the_fork_is_absent_there() {
    let (_dir, vault) = open_vault();
    let owner = owner_id(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let source = put_person(&vault);
    let target = put_person(&vault);
    let frontier_hex = mount_frontier_hex(&memory, live_mount_request());
    let frontier = parse_frontier(&frontier_hex);
    vault
        .batch()
        .edge_with_created_at(
            &source,
            EdgeKind::Mentions,
            &target,
            0.5,
            frontier.recorded_at.saturating_add(1),
        )
        .commit()
        .expect("link the two rows after the frontier");

    let fork = fork_mount_request(&frontier_hex);
    let live = live_mount_request();
    let path = format!("/backlinks/{}", target.to_hex());
    let expected = format!("{}-{}", EdgeKind::Mentions as u8, source.to_hex());
    let fork_links = readdir_names(&memory, &fork, &path);
    assert!(
        !fork_links.contains(&expected),
        "a link made after the frontier is absent at the fork: {fork_links:?}"
    );
    let live_links = readdir_names(&memory, &live, &path);
    assert!(
        live_links.contains(&expected),
        "the live head lists the later link: {live_links:?}"
    );
}

#[test]
fn a_row_deleted_since_the_fork_is_absent_there() {
    let (_dir, vault) = open_vault();
    let owner = owner_id(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let subject = put_person(&vault);
    let claim = EntityId::now();
    put_claim_in_world(&vault, &claim, &subject, None, "doomed");
    let frontier = mount_frontier_hex(&memory, live_mount_request());
    delete_as_owner(&vault, owner, &claim.to_hex());

    let fork = fork_mount_request(&frontier);
    let path = format!("/claims/by-id/{}", claim.to_hex());
    let fork_text = cat_text(&memory, &fork, &path);
    assert!(
        fork_text.is_empty(),
        "a row deleted since the frontier is no file at the fork: {fork_text}"
    );
}

#[test]
fn a_reader_who_cannot_read_a_row_now_reads_nothing_of_it_at_the_fork() {
    let dir = tempfile::tempdir().expect("create a fresh vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open a fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install carries the owner's grant act");
    let (owner, owner_proof) = embedded_owner(&vault).expect("the authenticated embedded owner");
    let world_a = put_world(&vault);
    let world_b = put_world(&vault);
    let subject = put_person(&vault);
    let agent = define_agent(&vault, "fork-world-reader").expect("define the agent reader");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world_a)]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner grants the agent world A to read");
    assert!(minted.grant.confers, "the one-world read grant confers");

    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let claim = EntityId::now();
    put_claim_in_world(&vault, &claim, &subject, Some(world_a), "sealed words");
    let frontier = mount_frontier_hex(&owner_memory, live_mount_request());
    put_claim_in_world(&vault, &claim, &subject, Some(world_b), "sealed words");

    let owner_fork = fork_mount_request(&frontier);
    let agent_fork = fork_mount_request(&frontier);
    let file = format!("/claims/by-id/{}", claim.to_hex());
    let agent_text = cat_text(&agent_memory, &agent_fork, &file);
    assert!(
        agent_text.is_empty(),
        "the agent reads none of the row it cannot read now: {agent_text}"
    );
    let world_path = format!("/worlds/{}/claims", world_a.to_hex());
    let agent_listed = readdir_names(&agent_memory, &agent_fork, &world_path);
    assert!(
        !agent_listed.contains(&claim.to_hex()),
        "the agent's fork listing omits the row it cannot read now: {agent_listed:?}"
    );
    let owner_listed = readdir_names(&owner_memory, &owner_fork, &world_path);
    assert!(
        owner_listed.contains(&claim.to_hex()),
        "the owner's fork listing shows the row as it stood: {owner_listed:?}"
    );
}

#[test]
fn a_fork_cursor_does_not_open_on_the_live_head() {
    let (_dir, vault) = open_vault();
    let owner = owner_id(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let subject = put_person(&vault);
    let first = EntityId::now();
    put_claim_in_world(&vault, &first, &subject, None, "first");
    let second = EntityId::now();
    put_claim_in_world(&vault, &second, &subject, None, "second");
    let frontier = mount_frontier_hex(&memory, live_mount_request());

    let fork = fork_mount_request_paged(&frontier);
    let first_page = readdir_view(&memory, &fork, "/claims/by-id");
    let cursor = first_page
        .next_cursor
        .expect("one entry of two leaves a fork cursor");
    let live = live_mount_request_paged();
    let request = path_request_at(&live, "/claims/by-id", &cursor);
    memory
        .graph_fs_readdir(request)
        .expect_err("a fork cursor does not open on the live head");
}

#[test]
fn a_frontier_past_the_head_is_not_found() {
    let (_dir, vault) = open_vault();
    let owner = owner_id(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    put_person(&vault);
    let frontier_hex = mount_frontier_hex(&memory, live_mount_request());
    let frontier = parse_frontier(&frontier_hex);
    let past = MemoryFrontier {
        sequence: frontier.sequence.saturating_add(1),
        recorded_at: frontier.recorded_at,
    }
    .to_hex();

    let refused = memory
        .graph_fs_mount(fork_mount_request(&past))
        .expect_err("a frontier past the head is refused");
    assert_eq!(
        refused.code, MEMORY_CODE_NOT_FOUND,
        "a frontier past the head is not found: {refused:?}"
    );
}

#[test]
fn a_row_this_machine_holds_no_bytes_of_at_the_fork_says_so() {
    let (_dir, vault) = open_vault();
    let owner = owner_id(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let subject = put_person(&vault);
    let claim = EntityId::now();
    put_claim_in_world(&vault, &claim, &subject, None, "before");
    let frontier_hex = mount_frontier_hex(&memory, live_mount_request());
    let frontier = parse_frontier(&frontier_hex);
    put_claim_in_world(&vault, &claim, &subject, None, "after");
    let revision = revision_at(&vault, &claim, frontier)
        .expect("read the revision the frontier names")
        .expect("the row held a revision at the frontier");
    forget_retained_revision(&vault, &claim, revision).expect("forget the retained bytes");

    let fork = fork_mount_request(&frontier_hex);
    let live = live_mount_request();
    let path = format!("/claims/by-id/{}", claim.to_hex());
    let refused = memory
        .graph_fs_cat(path_request(&fork, &path))
        .expect_err("a direct fork read without bytes is refused");
    assert_eq!(
        refused.code, "HISTORY_NOT_HELD",
        "a fork read without bytes says so: {refused:?}"
    );
    let listed = readdir_names(&memory, &fork, "/claims/by-id");
    assert!(
        !listed.contains(&claim.to_hex()),
        "the fork listing omits the row without bytes: {listed:?}"
    );
    let live_text = cat_text(&memory, &live, &path);
    assert!(
        live_text.contains(&utf8_hex("after")),
        "the live head still reads the later value: {live_text}"
    );
}
