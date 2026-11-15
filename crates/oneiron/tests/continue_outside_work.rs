//! An outside session continues on this node from its pushed commit
//! (census L10-17, PR 1: the engine door; no verb).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron --test continue_outside_work`
#![cfg(oneiron_test_support)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own git subprocesses; the rule covers the server's crates"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use oneiron::attempt_queue::AttemptQueue;
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::checkout::lease::{
    CheckoutFactMutation, CheckoutFactSink, CheckoutId, CheckoutLeaseService, CheckoutLiveness,
    CheckoutLivenessPulse, CheckoutResult,
};
use oneiron::codebase::RepoRef;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dispatch_byoa::{
    BYOA_ATTEMPT_KIND, ByoEndpointBackendFactory, ByoEndpointSpec, ByoaDispatcher, ByoaEgressLease,
    ByoaEgressPort, ByoaError, ByoaResult, ContinueOutsideWorkCheckRequest,
    ContinueOutsideWorkCheckView, ContinueOutsideWorkRequest, ContinueOutsideWorkView,
    DrySeatFallback, OfficialDreamerSeat, OfficialSeatRegistry, OfficialSeatRoute,
    OfficialSeatSpec, OnSeatSpent, ProviderAdapterRegistry, RunnerContinueCaller, RunnerSeat,
    RunnerSeatPolicy, SeatAuth, SeatIdentity, SeatPassedOver, SeatPlacementApproval,
    hosted_seat_bound, register_official_dreamer_providers,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::habit::TaskRole;
use oneiron::ingest::history::{
    HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistorySource,
    HistoryThreadKind,
};
use oneiron::memory::checkout_doors::{
    CheckoutGetInput, CheckoutRetention, CheckoutState, CheckoutTeardownInput, CheckoutTornDown,
};
use oneiron::origin::smart_http::{ORIGIN_REPO_DIR_SUFFIX, origin_serving_root};
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::history_import_rows::imported_message_rows;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, LlmBackend, Vault, VaultConfig};
use serde_json::json;

const IMPORTED_AT: u64 = 1_700_100_000;
const CONTINUE_REF: &str = "refs/heads/oneiron/continue/s1";

fn git_output(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Oneiron")
        .env("GIT_AUTHOR_EMAIL", "oneiron@example.invalid")
        .env("GIT_COMMITTER_NAME", "Oneiron")
        .env("GIT_COMMITTER_EMAIL", "oneiron@example.invalid")
        .args(args)
        .output()
        .expect("run git")
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = git_output(cwd, args);
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A vault with an embedded owner, a host root slip, a keystore, a serving
/// install profile and the owner's proof.
fn owner_vault() -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer =
        HostSlipIssuer::from_secret(b"continue-outside-work").expect("fixture host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("live install profile to carry owner acts");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner");
    (dir, vault, owner_proof)
}

/// A vault in the hosted posture, as custody_will_over_substrate.rs builds
/// one: the test host's cloud root, this install's profile under it, the
/// owner bound there.
fn hosted_vault() -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open(dir.path(), config).expect("hosted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile under the host root");
    let (_owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    (dir, vault, owner_proof)
}

/// The agent `agent_id`, defined by the owner.
fn ensure_agent(vault: &Vault, owner_proof: &AuthenticatedOwner, agent_id: &str) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Continue-outside-work agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates the agent");
    agent
}

/// The owner's Grant naming `vault.runners.continue` (and `read`, which a
/// conferring Grant carries) for `agent`.
fn mint_continue_grant(vault: &Vault, owner_proof: &AuthenticatedOwner, agent: EntityId) {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "vault.runners.continue".to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        vault,
        owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a continue Grant");
    assert!(minted.grant.confers, "precondition: the Grant is live");
}

/// A custody repo `demo` with two commits; the bare store holds the
/// hand-off push of the second (`commit_c`) on [`CONTINUE_REF`]. Answers
/// the bare path, the first commit and the hand-off commit.
fn seed_custody_repo(vault: &Vault) -> (PathBuf, String, String) {
    let root = origin_serving_root(vault).expect("serving root");
    let bare_name = format!("demo{ORIGIN_REPO_DIR_SUFFIX}");
    git(
        &root,
        &["init", "--bare", "--initial-branch=main", &bare_name],
    );
    let bare = root.join(&bare_name);
    let source = tempfile::tempdir().expect("source repo directory");
    git(source.path(), &["init", "--initial-branch=main"]);
    std::fs::write(source.path().join("README.md"), "outside work\n").expect("write readme");
    git(source.path(), &["add", "--", "README.md"]);
    git(source.path(), &["commit", "-m", "first"]);
    let commit_p = git(source.path(), &["rev-parse", "--verify", "HEAD"]);
    std::fs::write(source.path().join("WORK.md"), "hand-off\n").expect("write hand-off");
    git(source.path(), &["add", "--", "WORK.md"]);
    git(source.path(), &["commit", "-m", "hand-off"]);
    let commit_c = git(source.path(), &["rev-parse", "--verify", "HEAD"]);
    git(
        source.path(),
        &[
            "push",
            bare.to_str().expect("bare path is UTF-8"),
            &format!("HEAD:{CONTINUE_REF}"),
        ],
    );
    (bare, commit_p, commit_c)
}

/// A two-message conversation imported for the owner. Answers its id.
fn import_conversation(vault: &Vault, owner_proof: &AuthenticatedOwner) -> EntityId {
    let conversation = HistoryConversation {
        native_id: "continue-s1".to_owned(),
        kind: HistoryThreadKind::Main,
        parent: None,
        title: Some("outside session".to_owned()),
        started_at_ms: Some(1_699_990_000_000),
        own_started_at_ms: Some(1_699_990_000_000),
        cwd: None,
        messages: vec![
            HistoryMessage {
                native_id: "m1".to_owned(),
                parent_id: None,
                role: HistoryRole::User,
                text: "continue this work on the node".to_owned(),
                at_ms: Some(1_700_000_000_000),
                said_by: None,
                tools: Vec::new(),
                alias: None,
            },
            HistoryMessage {
                native_id: "m2".to_owned(),
                parent_id: None,
                role: HistoryRole::Assistant,
                text: "handing off to the node".to_owned(),
                at_ms: Some(1_700_000_060_000),
                said_by: None,
                tools: Vec::new(),
                alias: None,
            },
        ],
        skipped: HistorySkips::default(),
        sharing: None,
    };
    let report = vault
        .import_history(
            owner_proof,
            HistorySource::ClaudeCode,
            &conversation,
            IMPORTED_AT,
        )
        .expect("import");
    assert_eq!(
        report.new, 2,
        "precondition: both messages land: {report:?}"
    );
    imported_message_rows(vault, HistorySource::ClaudeCode, "m1")
        .expect("landed rows read")
        .expect("message m1 landed")
        .conversation
}

/// The owner's one-seat policy for `runner` under its vendor login.
fn login_policy(runner: &str) -> RunnerSeatPolicy {
    RunnerSeatPolicy {
        seats: vec![RunnerSeat {
            runner: runner.to_owned(),
            auth: SeatAuth::VendorLogin,
            egress_profile_ref: "egress/test-default".to_owned(),
            credential_handles: Vec::new(),
        }],
        on_spent: OnSeatSpent::NextSeat,
    }
}

/// The `role` byte a TASK-typed row's body names.
fn task_row_role(vault: &Vault, id: &EntityId) -> Option<u64> {
    let body = vault.get(id).expect("TASK row reads")?;
    let value = rmpv::decode::read_value(&mut &body[..]).expect("TASK row decodes");
    value
        .as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some("role"))
        .and_then(|(_, role)| role.as_u64())
}

/// The TASK and attempt counts: how much the doors wrote. A TASK mint also
/// writes its Owner authority fact as a TASK-typed row with the
/// AuthorityFact role, so only rows with the Task role count as TASKs.
fn counts(vault: &Vault) -> (usize, usize) {
    let task_role = u64::from(TaskRole::Task.role_byte());
    let tasks = vault
        .entities_by_type(ENTITY_TYPE_TASK)
        .expect("TASK ids")
        .iter()
        .filter(|id| task_row_role(vault, id) == Some(task_role))
        .count();
    let attempts = AttemptQueue::new(vault).list().expect("attempt rows").len();
    (tasks, attempts)
}

fn hex_bytes(hex: &str) -> [u8; 16] {
    assert_eq!(hex.len(), 32, "an id is 32 hex chars: {hex}");
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex id");
    }
    bytes
}

struct Facts;

impl CheckoutFactSink for Facts {
    fn apply_checkout_fact(&mut self, _: CheckoutFactMutation) -> CheckoutResult<()> {
        Ok(())
    }
}

struct NoLiveness;

impl CheckoutLiveness for NoLiveness {
    fn publish(&mut self, _: CheckoutLivenessPulse) -> CheckoutResult<()> {
        Ok(())
    }

    fn current(&self, _: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        Ok(None)
    }

    fn clear(&mut self, _: CheckoutId, _: u64) -> CheckoutResult<()> {
        Ok(())
    }
}

/// A seat run reaches no endpoint (the seat host's own stub).
struct NoEndpoints;

impl ByoEndpointBackendFactory for NoEndpoints {
    fn resolve_backend(&self, _spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        Err(ByoaError::Backend("the test serves no endpoint".to_owned()))
    }
}

/// A seat run takes no egress lease (the seat host's own stub).
struct NoEgress;

impl ByoaEgressPort for NoEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "the test leases no egress".to_owned(),
        })
    }
}

/// The node's registry when its settings name an official Codex seat on
/// a ChatGPT plan, OpenAI's hosted approval recorded, whose login lives on
/// `machine`: the seat settings' registry, as the seat host builds it.
fn official_codex_registry(machine: &str) -> ProviderAdapterRegistry {
    let mut registry = ProviderAdapterRegistry::default();
    let seat = OfficialDreamerSeat {
        spec: OfficialSeatSpec {
            route: OfficialSeatRoute::CodexAppServerChatGptPlan,
            account_ref: "acct-codex".to_owned(),
            machine_ref: Some(machine.to_owned()),
            login_store_ref: None,
            credential_ref: None,
            unmodified_binary: true,
            approvals: SeatPlacementApproval {
                anthropic_agent_sdk: false,
                openai_hosted_plan: true,
            },
            dry_fallback: DrySeatFallback::default(),
            plan_window: None,
        },
        model_slug_map: BTreeMap::new(),
        base_url: None,
    };
    register_official_dreamer_providers(&mut registry, &OfficialSeatRegistry::standard(), [seat])
        .expect("the official Codex seat registers");
    registry
}

fn leases(vault: &Vault) -> CheckoutLeaseService<'_, Facts, NoLiveness> {
    CheckoutLeaseService::new(vault, Facts, NoLiveness)
}

/// The TASK body's `spec.runner_continue` map, decoded from its row.
fn task_handover(task_body: &[u8]) -> (String, String, String, String) {
    let value = rmpv::decode::read_value(&mut &task_body[..]).expect("TASK body decodes");
    let body = value.as_map().expect("TASK body is a map");
    let field = |map: &[(rmpv::Value, rmpv::Value)], key: &str| -> rmpv::Value {
        map.iter()
            .find_map(|(field, value)| (field.as_str() == Some(key)).then(|| value.clone()))
            .expect("TASK body names the field")
    };
    let spec = field(body, "spec");
    let handover = field(spec.as_map().expect("spec is a map"), "runner_continue");
    let map = handover.as_map().expect("runner_continue is a map");
    let text =
        |key: &str| -> String { field(map, key).as_str().expect("handover text").to_owned() };
    (
        text("conversation"),
        text("repo"),
        text("git_ref"),
        text("commit"),
    )
}

#[test]
fn an_outside_session_continues_on_this_node_from_its_pushed_commit() {
    let (_dir, vault, owner_proof) = owner_vault();
    let (_bare, _commit_p, commit_c) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let conversation_hex = conversation.to_hex();
    let policy = login_policy("claude-code");
    let registry = ProviderAdapterRegistry::standard();
    let check = ContinueOutsideWorkCheckRequest {
        repo: "demo".to_owned(),
        runner: "claude-code".to_owned(),
    };
    let before = counts(&vault);
    let ready = vault
        .continue_outside_work_check(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &check,
        )
        .expect("the check answers");
    assert!(
        matches!(ready, ContinueOutsideWorkCheckView::Ready { seat: 0, .. }),
        "the check is ready on seat 0: {ready:?}"
    );
    assert_eq!(counts(&vault), before, "the check writes nothing");
    let input = ContinueOutsideWorkRequest {
        repo: "demo".to_owned(),
        git_ref: CONTINUE_REF.to_owned(),
        commit: commit_c.clone(),
        conversation: conversation_hex.clone(),
        runner: "claude-code".to_owned(),
        note: None,
    };
    let first = vault
        .continue_outside_work(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &input,
        )
        .expect("the door answers");
    let ContinueOutsideWorkView::Bound {
        binding,
        seat,
        attempt,
        task,
        checkout,
        existing,
    } = first
    else {
        panic!("the door binds the work: {first:?}");
    };
    assert_eq!(seat, 0, "the work binds on seat 0");
    assert!(!existing, "the first call is new");
    let rows = AttemptQueue::new(&vault).list().expect("attempt rows");
    assert!(
        rows.iter().any(|row| row.kind == BYOA_ATTEMPT_KIND),
        "the attempt is in the queue with kind {BYOA_ATTEMPT_KIND}"
    );
    let lease = leases(&vault)
        .get(CheckoutId::from_bytes(hex_bytes(&checkout)).expect("checkout id"))
        .expect("lease reads")
        .expect("the checkout lease is claimed");
    assert_eq!(lease.task_ref.to_hex(), task, "the lease is for the TASK");
    let RepoRef::LocalFolder { commit, .. } = &lease.repo_ref else {
        panic!("the lease pins a local folder: {:?}", lease.repo_ref);
    };
    assert_eq!(commit, &commit_c, "the lease is pinned at the hand-off");
    let task_body = vault
        .get(&EntityId::from_hex(&task).expect("TASK id"))
        .expect("TASK reads")
        .expect("the TASK row is there");
    let (kept_conversation, kept_repo, kept_ref, kept_commit) = task_handover(&task_body);
    assert_eq!(
        kept_conversation, conversation_hex,
        "the TASK names the conversation"
    );
    assert_eq!(kept_repo, "demo", "the TASK names the repo");
    assert_eq!(kept_ref, CONTINUE_REF, "the TASK names the ref");
    assert_eq!(kept_commit, commit_c, "the TASK names the hand-off");
    let (tasks_after, attempts_after) = counts(&vault);
    assert_eq!(tasks_after, before.0 + 1, "one TASK lands");
    assert_eq!(attempts_after, before.1 + 1, "one attempt lands");
    let second = vault
        .continue_outside_work(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &input,
        )
        .expect("the repeat answers");
    let ContinueOutsideWorkView::Bound {
        binding: again_binding,
        seat: again_seat,
        attempt: again_attempt,
        task: again_task,
        checkout: again_checkout,
        existing: again_existing,
    } = second
    else {
        panic!("the repeat binds the same work: {second:?}");
    };
    assert!(again_existing, "the repeat is existing");
    assert_eq!(again_binding, binding, "the same binding");
    assert_eq!(again_seat, seat, "the same seat");
    assert_eq!(again_attempt, attempt, "the same attempt");
    assert_eq!(again_task, task, "the same TASK");
    assert_eq!(again_checkout, checkout, "the same checkout");
    assert_eq!(
        counts(&vault),
        (tasks_after, attempts_after),
        "the repeat writes nothing"
    );
}

#[test]
fn a_commit_the_push_never_landed_starts_nothing() {
    let (_dir, vault, owner_proof) = owner_vault();
    let (_bare, commit_p, _commit_c) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let policy = login_policy("claude-code");
    let registry = ProviderAdapterRegistry::standard();
    let before = counts(&vault);
    let input = ContinueOutsideWorkRequest {
        repo: "demo".to_owned(),
        git_ref: CONTINUE_REF.to_owned(),
        commit: commit_p,
        conversation: conversation.to_hex(),
        runner: "claude-code".to_owned(),
        note: None,
    };
    let refused = vault
        .continue_outside_work(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &input,
        )
        .expect_err("a commit past the tip starts nothing");
    assert_eq!(refused.code, oneiron::memory::MEMORY_CODE_INVALID_STATE);
    assert_eq!(counts(&vault), before, "nothing is written");
}

#[test]
fn a_hosted_node_keeps_a_login_its_vendor_keeps_off_hosted() {
    let (_dir, vault, owner_proof) = hosted_vault();
    let (_bare, _commit_p, commit_c) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let policy = login_policy("codex");
    let registry = ProviderAdapterRegistry::standard();
    let before = counts(&vault);
    let expected = hosted_seat_bound(
        Some(SeatIdentity::CliProgram("codex")),
        true,
        HostingPrivacyPosture::Hosted,
        None,
    )
    .expect("codex login is bound off hosted");
    let expected_reason = SeatPassedOver::Hosted(expected).to_string();
    let check = ContinueOutsideWorkCheckRequest {
        repo: "demo".to_owned(),
        runner: "codex".to_owned(),
    };
    let checked = vault
        .continue_outside_work_check(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &check,
        )
        .expect("the check answers");
    let ContinueOutsideWorkCheckView::NoSeat { skipped } = checked else {
        panic!("the check finds no seat: {checked:?}");
    };
    assert_eq!(skipped.len(), 1, "one seat is skipped: {skipped:?}");
    assert_eq!(skipped[0].seat, 0, "seat 0 is skipped");
    assert_eq!(skipped[0].reason, expected_reason, "the hosted reason");
    let input = ContinueOutsideWorkRequest {
        repo: "demo".to_owned(),
        git_ref: CONTINUE_REF.to_owned(),
        commit: commit_c,
        conversation: conversation.to_hex(),
        runner: "codex".to_owned(),
        note: None,
    };
    let answered = vault
        .continue_outside_work(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &input,
        )
        .expect("the door answers");
    let ContinueOutsideWorkView::NoSeat { skipped } = answered else {
        panic!("the door finds no seat: {answered:?}");
    };
    assert_eq!(skipped.len(), 1, "one seat is skipped: {skipped:?}");
    assert_eq!(skipped[0].seat, 0, "seat 0 is skipped");
    assert_eq!(skipped[0].reason, expected_reason, "the hosted reason");
    assert_eq!(counts(&vault), before, "nothing is written");
}

#[test]
fn a_continue_keeps_to_the_runner_it_names() {
    // Seat 0 is Codex on its ChatGPT login, which a hosted node keeps off;
    // seat 1 is Claude Code, which runs here. The caller asked for Codex, so
    // neither door hands the work to Claude Code, whatever the spend rule.
    let (_dir, vault, owner_proof) = hosted_vault();
    let (_bare, _commit_p, commit_c) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let mut policy = login_policy("codex");
    let registry = ProviderAdapterRegistry::standard();
    policy.seats.extend(login_policy("claude-code").seats);
    policy.on_spent = OnSeatSpent::Stop;
    let before = counts(&vault);
    let check = ContinueOutsideWorkCheckRequest {
        repo: "demo".to_owned(),
        runner: "codex".to_owned(),
    };
    let checked = vault
        .continue_outside_work_check(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &check,
        )
        .expect("the check answers");
    let ContinueOutsideWorkCheckView::NoSeat { skipped } = checked else {
        panic!("the check offers no seat of another runner: {checked:?}");
    };
    assert_eq!(
        skipped.len(),
        1,
        "only the Codex seat is named: {skipped:?}"
    );
    assert_eq!(skipped[0].seat, 0, "seat 0 is skipped");
    assert_eq!(skipped[0].runner, "codex", "the skipped seat is Codex");
    let input = ContinueOutsideWorkRequest {
        repo: "demo".to_owned(),
        git_ref: CONTINUE_REF.to_owned(),
        commit: commit_c,
        conversation: conversation.to_hex(),
        runner: "codex".to_owned(),
        note: None,
    };
    let answered = vault
        .continue_outside_work(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &input,
        )
        .expect("the door answers");
    let ContinueOutsideWorkView::NoSeat { skipped } = answered else {
        panic!("the door binds no seat of another runner: {answered:?}");
    };
    assert_eq!(
        skipped.len(),
        1,
        "only the Codex seat is named: {skipped:?}"
    );
    assert_eq!(skipped[0].seat, 0, "seat 0 is skipped");
    assert_eq!(skipped[0].runner, "codex", "the skipped seat is Codex");
    assert_eq!(counts(&vault), before, "nothing is written");
}

#[test]
fn a_continue_runs_the_seat_the_node_registry_names() {
    // The node's settings name an official Codex seat whose login lives on
    // machine-b. The door runs the seat under that registry, so the login's
    // machine rides the attempt: a host on machine-a never claims it.
    let (_dir, vault, owner_proof) = owner_vault();
    let (_bare, _commit_p, commit_c) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let policy = login_policy("codex");
    let registry = official_codex_registry("machine-b");
    let input = ContinueOutsideWorkRequest {
        repo: "demo".to_owned(),
        git_ref: CONTINUE_REF.to_owned(),
        commit: commit_c,
        conversation: conversation.to_hex(),
        runner: "codex".to_owned(),
        note: None,
    };
    let bound = vault
        .continue_outside_work(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &input,
        )
        .expect("the door answers");
    let ContinueOutsideWorkView::Bound { seat, attempt, .. } = bound else {
        panic!("the door binds the work: {bound:?}");
    };
    assert_eq!(seat, 0, "the work binds on the Codex seat");
    let attempt = hex_bytes(&attempt);
    let dispatcher = ByoaDispatcher::new(&vault, NoEndpoints, NoEgress);
    let ready_on = |machine: &str| {
        dispatcher
            .ready_host_cli_attempts(u64::MAX, &[machine.to_owned()], |_| true)
            .expect("the queue reads")
            .iter()
            .any(|id| id.as_bytes() == &attempt)
    };
    assert!(
        !ready_on("machine-a"),
        "a host on another machine never claims the login seat's run"
    );
    assert!(ready_on("machine-b"), "the login's own machine claims it");
}

#[test]
fn only_an_agent_whose_grant_names_the_verb_may_continue() {
    let (_dir, vault, owner_proof) = owner_vault();
    let (_bare, _commit_p, commit_c) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let agent = ensure_agent(&vault, &owner_proof, "continue_outside_work_agent");
    let policy = login_policy("claude-code");
    let registry = ProviderAdapterRegistry::standard();
    let before = counts(&vault);
    let input = ContinueOutsideWorkRequest {
        repo: "demo".to_owned(),
        git_ref: CONTINUE_REF.to_owned(),
        commit: commit_c,
        conversation: conversation.to_hex(),
        runner: "claude-code".to_owned(),
        note: None,
    };
    vault
        .continue_outside_work(
            RunnerContinueCaller::GrantedAgent(agent),
            &registry,
            &policy,
            &input,
        )
        .expect_err("an agent with no Grant is refused");
    let check = ContinueOutsideWorkCheckRequest {
        repo: "demo".to_owned(),
        runner: "claude-code".to_owned(),
    };
    vault
        .continue_outside_work_check(
            RunnerContinueCaller::GrantedAgent(agent),
            &registry,
            &policy,
            &check,
        )
        .expect_err("the check refuses an agent with no Grant");
    assert_eq!(counts(&vault), before, "nothing is written");
    mint_continue_grant(&vault, &owner_proof, agent);
    let bound = vault
        .continue_outside_work(
            RunnerContinueCaller::GrantedAgent(agent),
            &registry,
            &policy,
            &input,
        )
        .expect("the granted agent continues");
    assert!(
        matches!(
            bound,
            ContinueOutsideWorkView::Bound {
                existing: false,
                ..
            }
        ),
        "the granted agent binds the work: {bound:?}"
    );
}

#[test]
fn an_agent_with_no_grant_learns_nothing_of_the_repo() {
    // The Grant refusal is the whole answer an agent with no Grant gets:
    // a repo this node does not serve, a commit that is not the ref's tip
    // and a commit the store does not hold each answer that refusal, as
    // the right hand-off does. The door judges the caller before it reads
    // the served store or the pushed ref.
    let (_dir, vault, owner_proof) = owner_vault();
    let (_bare, commit_p, commit_c) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let agent = ensure_agent(&vault, &owner_proof, "continue_outside_work_agent");
    let policy = login_policy("claude-code");
    let registry = ProviderAdapterRegistry::standard();
    let caller = RunnerContinueCaller::GrantedAgent(agent);
    let before = counts(&vault);
    let check = |repo: &str| {
        vault
            .continue_outside_work_check(
                caller,
                &registry,
                &policy,
                &ContinueOutsideWorkCheckRequest {
                    repo: repo.to_owned(),
                    runner: "claude-code".to_owned(),
                },
            )
            .expect_err("the check refuses an agent with no Grant")
    };
    let refusal = check("demo");
    assert!(
        refusal
            .message
            .contains("no live Grant of this agent names this act"),
        "precondition: the check answers the Grant refusal: {refusal:?}"
    );
    assert_eq!(
        check("absent"),
        refusal,
        "a repo this node does not serve answers the Grant refusal"
    );
    let hand_off = |repo: &str, commit: &str| {
        vault
            .continue_outside_work(
                caller,
                &registry,
                &policy,
                &ContinueOutsideWorkRequest {
                    repo: repo.to_owned(),
                    git_ref: CONTINUE_REF.to_owned(),
                    commit: commit.to_owned(),
                    conversation: conversation.to_hex(),
                    runner: "claude-code".to_owned(),
                    note: None,
                },
            )
            .expect_err("the door refuses an agent with no Grant")
    };
    let refusal = hand_off("demo", &commit_c);
    assert!(
        refusal
            .message
            .contains("no live Grant of this agent names this act"),
        "precondition: the door answers the Grant refusal: {refusal:?}"
    );
    assert_eq!(
        hand_off("absent", &commit_c),
        refusal,
        "a repo this node does not serve answers the Grant refusal"
    );
    assert_eq!(
        hand_off("demo", &commit_p),
        refusal,
        "a commit that is not the ref's tip answers the Grant refusal"
    );
    assert_eq!(
        hand_off("demo", &"0".repeat(40)),
        refusal,
        "a commit the store does not hold answers the Grant refusal"
    );
    assert_eq!(counts(&vault), before, "nothing is written");
}

#[test]
fn the_owner_reads_and_tears_down_the_continued_checkout() {
    // The continued checkout is the owner's custody: the owner reads it
    // through the checkout door and tears it down under the owner's own
    // credential, as for a checkout the owner claimed by hand. With no
    // pushed-head receipt the shipped teardown keeps the tree.
    let (_dir, vault, owner_proof) = owner_vault();
    let (_bare, _commit_p, commit_c) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let policy = login_policy("claude-code");
    let registry = ProviderAdapterRegistry::standard();
    let bound = vault
        .continue_outside_work(
            RunnerContinueCaller::Owner(&owner_proof),
            &registry,
            &policy,
            &ContinueOutsideWorkRequest {
                repo: "demo".to_owned(),
                git_ref: CONTINUE_REF.to_owned(),
                commit: commit_c,
                conversation: conversation.to_hex(),
                runner: "claude-code".to_owned(),
                note: None,
            },
        )
        .expect("the door answers");
    let ContinueOutsideWorkView::Bound { task, checkout, .. } = bound else {
        panic!("the door binds the work: {bound:?}");
    };
    let owner = owner_proof.actor_for_read(&vault).expect("the owner's id");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let lease = memory
        .checkout_get(CheckoutGetInput {
            checkout: checkout.clone(),
        })
        .expect("the owner reads the continued checkout");
    assert_eq!(
        lease.holder, owner,
        "the owner holds the continued checkout"
    );
    assert_eq!(
        lease.task.to_hex(),
        task,
        "the checkout is the continued TASK's"
    );
    assert!(
        matches!(lease.state, CheckoutState::Active),
        "the continued checkout is active: {lease:?}"
    );
    let torn = memory
        .checkout_teardown_through(
            CheckoutTeardownInput {
                checkout,
                epoch: lease.epoch,
                pushed_head_receipt: None,
            },
            &mut NoLiveness,
        )
        .expect("the owner's teardown passes the holder fence");
    assert!(
        matches!(
            torn,
            CheckoutTornDown::Retained {
                epoch,
                reason: CheckoutRetention::MissingPushedHeadReceipt,
                ..
            } if epoch == lease.epoch
        ),
        "with no pushed-head receipt the teardown keeps the tree: {torn:?}"
    );
}

#[test]
fn a_second_runner_never_answers_the_first_runners_work() {
    // One hand-off continued under two runner names: the second never
    // answers the first runner's work as its own, and the same request
    // again still answers the work it bound.
    let (_dir, vault, owner_proof) = owner_vault();
    let (_bare, _commit_p, commit_c) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let mut policy = login_policy("claude-code");
    policy.seats.extend(login_policy("codex").seats);
    let registry = ProviderAdapterRegistry::standard();
    let request = |runner: &str| ContinueOutsideWorkRequest {
        repo: "demo".to_owned(),
        git_ref: CONTINUE_REF.to_owned(),
        commit: commit_c.clone(),
        conversation: conversation.to_hex(),
        runner: runner.to_owned(),
        note: None,
    };
    let continue_as = |runner: &str| {
        vault
            .continue_outside_work(
                RunnerContinueCaller::Owner(&owner_proof),
                &registry,
                &policy,
                &request(runner),
            )
            .expect("the door answers")
    };
    let first = continue_as("claude-code");
    let ContinueOutsideWorkView::Bound {
        seat: 0,
        attempt: first_attempt,
        existing: false,
        ..
    } = first
    else {
        panic!("precondition: Claude Code binds the work on seat 0: {first:?}");
    };
    let second = continue_as("codex");
    match &second {
        ContinueOutsideWorkView::Bound {
            seat,
            attempt,
            existing,
            ..
        } => {
            assert!(
                !existing,
                "a Codex continue is not the Claude Code work: {second:?}"
            );
            assert_eq!(*seat, 1, "a Codex continue binds the Codex seat");
            assert_ne!(
                attempt, &first_attempt,
                "a Codex continue runs its own attempt"
            );
        }
        ContinueOutsideWorkView::NoSeat { .. } | ContinueOutsideWorkView::Exhausted { .. } => {}
        other => panic!("a Codex continue answers its own seats: {other:?}"),
    }
    let again = continue_as("claude-code");
    assert!(
        matches!(
            &again,
            ContinueOutsideWorkView::Bound {
                seat: 0,
                attempt,
                existing: true,
                ..
            } if attempt == &first_attempt
        ),
        "the same request again answers the work it bound: {again:?}"
    );
}
