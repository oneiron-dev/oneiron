//! A continued outside session's spent seat hands its work on only to a CLI
//! seat of the runner the continue asked for (census L10-17, FIX-LIST
//! [RUNNER-CONTINUE-SPILL-TO-NON-CLI-SEAT]). Each run is claimed and its end
//! routed as the seat host does: `claim_host_cli_attempt`, then
//! `host_attempt_seat`, then `route_runner_terminal` with the run's spend.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron --all-features --test continue_work_spill`
#![cfg(oneiron_test_support)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own git subprocesses; the rule covers the server's crates"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::attempt_queue::{AttemptId, AttemptQueue};
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::code_sandbox::SandboxCredentialHandle;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dispatch_byoa::{
    ByoEndpointBackendFactory, ByoEndpointSpec, ByoaDispatcher, ByoaEgressLease, ByoaEgressPort,
    ByoaError, ByoaExhaust, ByoaResult, ByoaTerminalDisposition, CaptureByoaExhaust,
    ContinueOutsideWorkRequest, ContinueOutsideWorkView, DrySeatFallback, OfficialDreamerSeat,
    OfficialSeatRegistry, OfficialSeatRoute, OfficialSeatSpec, OnSeatSpent,
    ProviderAdapterRegistry, ResumeRunnerWork, RunnerContinueCaller, RunnerSeat, RunnerSeatChoice,
    RunnerSeatPolicy, RunnerWorkBindingId, RunnerWorkResume, SeatAuth, SeatPlacementApproval,
    SeatRoute, SeatSpent, SkippedRunnerSeat, register_official_dreamer_providers,
};
use oneiron::ingest::history::{
    HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistorySource,
    HistoryThreadKind,
};
use oneiron::llm::ModelId;
use oneiron::origin::smart_http::{ORIGIN_REPO_DIR_SUFFIX, origin_serving_root};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::history_import_rows::imported_message_rows;
use oneiron::{EntityId, LlmBackend, Vault, VaultConfig};

const IMPORTED_AT: u64 = 1_700_100_000;
const CONTINUE_REF: &str = "refs/heads/oneiron/continue/s1";

/// The lease owner the test's seat host claims runs as.
const HOST_LEASE_OWNER: &str = "seat-host-continue-spill";

/// Why a spill passes over a seat naming another runner.
const OTHER_RUNNER_REASON: &str = "this seat names another runner, and a continued session's work keeps to the runner it asked for";

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
    let issuer = HostSlipIssuer::from_secret(b"continue-work-spill").expect("fixture host issuer");
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

/// The served custody repo `demo`, its ref holding the hand-off commit.
/// Answers that commit.
fn seed_custody_repo(vault: &Vault) -> String {
    let root = origin_serving_root(vault).expect("serving root");
    let bare_name = format!("demo{ORIGIN_REPO_DIR_SUFFIX}");
    git(
        &root,
        &["init", "--bare", "--initial-branch=main", &bare_name],
    );
    let bare: PathBuf = root.join(&bare_name);
    let source = tempfile::tempdir().expect("source repo directory");
    git(source.path(), &["init", "--initial-branch=main"]);
    std::fs::write(source.path().join("WORK.md"), "hand-off\n").expect("write hand-off");
    git(source.path(), &["add", "--", "WORK.md"]);
    git(source.path(), &["commit", "-m", "hand-off"]);
    let commit = git(source.path(), &["rev-parse", "--verify", "HEAD"]);
    git(
        source.path(),
        &[
            "push",
            bare.to_str().expect("bare path is UTF-8"),
            &format!("HEAD:{CONTINUE_REF}"),
        ],
    );
    commit
}

/// A two-message conversation imported for the owner. Answers its id.
fn import_conversation(vault: &Vault, owner_proof: &AuthenticatedOwner) -> EntityId {
    let message = |native_id: &str, role: HistoryRole, text: &str, at_ms: u64| HistoryMessage {
        native_id: native_id.to_owned(),
        parent_id: None,
        role,
        text: text.to_owned(),
        at_ms: Some(at_ms),
        said_by: None,
        tools: Vec::new(),
        alias: None,
    };
    let conversation = HistoryConversation {
        native_id: "continue-spill-s1".to_owned(),
        kind: HistoryThreadKind::Main,
        parent: None,
        title: Some("outside session".to_owned()),
        started_at_ms: Some(1_699_990_000_000),
        own_started_at_ms: Some(1_699_990_000_000),
        cwd: None,
        messages: vec![
            message(
                "m1",
                HistoryRole::User,
                "continue this work on the node",
                1_700_000_000_000,
            ),
            message(
                "m2",
                HistoryRole::Assistant,
                "handing off to the node",
                1_700_000_060_000,
            ),
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

/// A seat of `runner` under its vendor login.
fn login_seat(runner: &str) -> RunnerSeat {
    RunnerSeat {
        runner: runner.to_owned(),
        auth: SeatAuth::VendorLogin,
        egress_profile_ref: "egress/test-default".to_owned(),
        credential_handles: Vec::new(),
    }
}

/// A Claude Code seat on an API key: the same runner as a login seat, under
/// a quota of its own.
fn claude_code_key_seat() -> RunnerSeat {
    RunnerSeat {
        runner: "claude-code".to_owned(),
        auth: SeatAuth::ApiKey,
        egress_profile_ref: "egress/test-default".to_owned(),
        credential_handles: vec![
            SandboxCredentialHandle::new("custody://byoa/anthropic-key")
                .expect("credential handle"),
        ],
    }
}

fn policy(seats: Vec<RunnerSeat>, on_spent: OnSeatSpent) -> RunnerSeatPolicy {
    RunnerSeatPolicy { seats, on_spent }
}

/// The standard runners plus a valid official Sign in with ChatGPT seat,
/// whose adapter shapes an endpoint connector no host runner claims.
fn registry_with_sign_in_with_chatgpt() -> ProviderAdapterRegistry {
    let mut registry = ProviderAdapterRegistry::standard();
    let seat = OfficialDreamerSeat {
        spec: OfficialSeatSpec {
            route: OfficialSeatRoute::SignInWithChatGpt,
            account_ref: "acct-chatgpt".to_owned(),
            machine_ref: None,
            login_store_ref: None,
            credential_ref: Some(
                SandboxCredentialHandle::new("custody://byoa/chatgpt-signin")
                    .expect("credential handle"),
            ),
            unmodified_binary: false,
            approvals: SeatPlacementApproval {
                anthropic_agent_sdk: false,
                openai_hosted_plan: false,
            },
            dry_fallback: DrySeatFallback::default(),
            plan_window: None,
        },
        model_slug_map: BTreeMap::from([(
            "fast".to_owned(),
            ModelId::new("openai/chatgpt-fast@1").expect("model id"),
        )]),
        base_url: None,
    };
    register_official_dreamer_providers(&mut registry, &OfficialSeatRegistry::standard(), [seat])
        .expect("the official Sign in with ChatGPT seat registers");
    registry
}

fn hex_bytes(hex: &str) -> [u8; 16] {
    assert_eq!(hex.len(), 32, "an id is 32 hex chars: {hex}");
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex id");
    }
    bytes
}

fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
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

/// A continued outside session, bound on its first seat.
struct Continued {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_proof: AuthenticatedOwner,
    binding: RunnerWorkBindingId,
    attempt: AttemptId,
}

/// Continues an outside session for `runner` under `policy` and `registry`;
/// the door binds it on seat 0.
fn continue_on_seat_zero(
    registry: &ProviderAdapterRegistry,
    policy: &RunnerSeatPolicy,
    runner: &str,
) -> Continued {
    let (dir, vault, owner_proof) = owner_vault();
    let commit = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let input = ContinueOutsideWorkRequest {
        repo: "demo".to_owned(),
        git_ref: CONTINUE_REF.to_owned(),
        commit,
        conversation: conversation.to_hex(),
        runner: runner.to_owned(),
        note: None,
    };
    let bound = vault
        .continue_outside_work(
            RunnerContinueCaller::Owner(&owner_proof),
            registry,
            policy,
            &input,
        )
        .expect("the door answers");
    let ContinueOutsideWorkView::Bound {
        binding,
        seat,
        attempt,
        ..
    } = bound
    else {
        panic!("precondition: the door binds the work: {bound:?}");
    };
    assert_eq!(seat, 0, "precondition: the work binds on seat 0");
    Continued {
        _dir: dir,
        vault,
        owner_proof,
        binding: RunnerWorkBindingId::from_bytes(hex_bytes(&binding)).expect("binding id"),
        attempt: AttemptId::from_bytes(&hex_bytes(&attempt)).expect("attempt id"),
    }
}

/// The seat's usage window, spent for an hour.
fn spent_for_an_hour() -> SeatSpent {
    SeatSpent {
        kind: None,
        retry_after: Some(3600),
        resets_at: Vec::new(),
    }
}

/// Claims the continued run as the seat host does and routes its end as
/// spent: the host's claim by id, the seat its work's head hop names, and
/// the policy's atomic route door with the run's typed spend.
fn spend_on_the_seat_host(
    continued: &Continued,
    registry: &ProviderAdapterRegistry,
    policy: &RunnerSeatPolicy,
) -> SeatRoute {
    let mut dispatcher = ByoaDispatcher::new(&continued.vault, NoEndpoints, NoEgress);
    let now = wall_now();
    let fence = dispatcher
        .claim_host_cli_attempt(continued.attempt, HOST_LEASE_OWNER, now, &[], |_| true)
        .expect("the claim reads")
        .expect("precondition: the host claims the continued run");
    let seat = dispatcher
        .host_attempt_seat(fence.attempt_id)
        .expect("the run's work reads")
        .expect("precondition: the run carries its bound work");
    assert_eq!(seat, 0, "precondition: the run is on seat 0");
    let capture = CaptureByoaExhaust {
        attempt_id: fence.attempt_id,
        lease_owner: fence.lease_owner.clone(),
        attempt_count: fence.attempt_count,
        disposition: ByoaTerminalDisposition::Failed,
        // The capture door refuses an empty exhaust, so the spent run leaves
        // a line of stdout behind.
        exhaust: ByoaExhaust {
            stdout: b"the seat ran out of quota\n".to_vec().into(),
            ..ByoaExhaust::default()
        },
        reason: None,
        now: now + 1,
    };
    dispatcher
        .route_runner_terminal(registry, policy, seat, capture, Some(spent_for_an_hour()))
        .expect("the spend routes")
}

/// Where a route left the work, in words a failure prints.
fn route_shape(route: &SeatRoute) -> String {
    match route {
        SeatRoute::Settled(_) => "settled".to_owned(),
        SeatRoute::Park { until, .. } => format!("parked until {until:?}"),
        SeatRoute::NextSeat { seat, .. } => format!("handed to seat {seat}"),
        SeatRoute::InternalModels { .. } => "back to the internal models".to_owned(),
        _ => "another route".to_owned(),
    }
}

/// Each passed-over seat as (seat, runner, reason in words).
fn skipped_words(skipped: &[SkippedRunnerSeat]) -> Vec<(usize, String, String)> {
    skipped
        .iter()
        .map(|skip| (skip.seat, skip.runner.clone(), skip.reason.to_string()))
        .collect()
}

fn attempt_count(vault: &Vault) -> usize {
    AttemptQueue::new(vault).list().expect("attempt rows").len()
}

#[test]
fn a_spent_continue_never_goes_to_another_runners_seat() {
    // Seat 0 is Claude Code, the runner the continue asked for; seat 1 is
    // Codex. When seat 0's window is spent, the owner's NextSeat rule hands
    // spent work on, but a continued session keeps to its runner: the work
    // parks, and the Codex seat is named as passed over.
    let registry = ProviderAdapterRegistry::standard();
    let policy = policy(
        vec![login_seat("claude-code"), login_seat("codex")],
        OnSeatSpent::NextSeat,
    );
    let continued = continue_on_seat_zero(&registry, &policy, "claude-code");
    let before = attempt_count(&continued.vault);
    let route = spend_on_the_seat_host(&continued, &registry, &policy);
    let SeatRoute::Park { receipt, .. } = &route else {
        panic!(
            "the spent continue parks rather than go to another runner: {}",
            route_shape(&route)
        );
    };
    assert_eq!(
        skipped_words(&receipt.skipped_seats),
        vec![(1, "codex".to_owned(), OTHER_RUNNER_REASON.to_owned())],
        "the Codex seat is named as passed over"
    );
    assert_eq!(
        attempt_count(&continued.vault),
        before,
        "no successor attempt is minted"
    );
}

#[test]
fn a_spent_continue_never_goes_to_a_seat_no_host_runner_claims() {
    // Seat 0 is Claude Code; seat 1 is a valid official Sign in with
    // ChatGPT seat, whose connector is an endpoint one. The hand-over job
    // rides only a CLI connector and a host claims only CLI work, so the
    // continue asks for Claude Code and the spent work parks.
    let registry = registry_with_sign_in_with_chatgpt();
    let policy = policy(
        vec![login_seat("claude-code"), login_seat("chatgpt-signin")],
        OnSeatSpent::NextSeat,
    );
    let continued = continue_on_seat_zero(&registry, &policy, "claude-code");
    let before = attempt_count(&continued.vault);
    let route = spend_on_the_seat_host(&continued, &registry, &policy);
    let SeatRoute::Park { receipt, .. } = &route else {
        panic!(
            "the spent continue parks rather than go to an endpoint seat: {}",
            route_shape(&route)
        );
    };
    assert_eq!(
        skipped_words(&receipt.skipped_seats),
        vec![(
            1,
            "chatgpt-signin".to_owned(),
            OTHER_RUNNER_REASON.to_owned()
        )],
        "the endpoint seat names another runner, so it is passed over first"
    );
    assert_eq!(
        attempt_count(&continued.vault),
        before,
        "no successor attempt is minted"
    );
}

#[test]
fn a_spent_continue_goes_to_its_own_runners_next_cli_seat() {
    // Seat 0 is Claude Code on its login, seat 1 Codex, seat 2 Claude Code
    // on an API key (a quota of its own). The spent work passes Codex over
    // and goes to seat 2, a fresh CLI attempt a host claims.
    let registry = ProviderAdapterRegistry::standard();
    let policy = policy(
        vec![
            login_seat("claude-code"),
            login_seat("codex"),
            claude_code_key_seat(),
        ],
        OnSeatSpent::NextSeat,
    );
    let continued = continue_on_seat_zero(&registry, &policy, "claude-code");
    let route = spend_on_the_seat_host(&continued, &registry, &policy);
    let SeatRoute::NextSeat {
        receipt,
        seat,
        outcome,
        ..
    } = &route
    else {
        panic!(
            "the spent continue goes to its runner's next seat: {}",
            route_shape(&route)
        );
    };
    assert_eq!(*seat, 2, "the Claude Code key seat takes the work");
    assert_eq!(
        skipped_words(&receipt.skipped_seats),
        vec![(1, "codex".to_owned(), OTHER_RUNNER_REASON.to_owned())],
        "the Codex seat is named as passed over"
    );
    let successor = outcome.status().attempt.id;
    let dispatcher = ByoaDispatcher::new(&continued.vault, NoEndpoints, NoEgress);
    let ready = dispatcher
        .ready_host_cli_attempts(u64::MAX, &[], |_| true)
        .expect("the queue reads");
    assert!(
        ready.contains(&successor),
        "a host claims the successor: {ready:?}"
    );
}

#[test]
fn a_resume_of_a_continue_never_takes_another_runners_seat() {
    // The owner's rule is Stop, so the spent work parks on seat 0. The
    // owner then resumes it on the Codex seat by index: a continued session
    // keeps to its runner, so the resume answers that no seat takes it and
    // mints nothing.
    let registry = ProviderAdapterRegistry::standard();
    let policy = policy(
        vec![login_seat("claude-code"), login_seat("codex")],
        OnSeatSpent::Stop,
    );
    let continued = continue_on_seat_zero(&registry, &policy, "claude-code");
    let route = spend_on_the_seat_host(&continued, &registry, &policy);
    assert!(
        matches!(route, SeatRoute::Park { .. }),
        "precondition: the Stop rule parks the work: {}",
        route_shape(&route)
    );
    let before = attempt_count(&continued.vault);
    let dispatcher = ByoaDispatcher::new(&continued.vault, NoEndpoints, NoEgress);
    let resumed = dispatcher
        .resume_runner_work_as_owner(
            &continued.owner_proof,
            &registry,
            &policy,
            ResumeRunnerWork {
                binding: continued.binding,
                expected_attempt: continued.attempt,
                choice: Some(RunnerSeatChoice::Seat(1)),
                now: wall_now() + 2,
            },
        )
        .expect("the resume answers");
    let RunnerWorkResume::NoSeat { skipped } = &resumed else {
        panic!("the resume takes no seat of another runner: {resumed:?}");
    };
    assert_eq!(
        skipped_words(skipped),
        vec![(1, "codex".to_owned(), OTHER_RUNNER_REASON.to_owned())],
        "the Codex seat is named as passed over"
    );
    assert_eq!(
        attempt_count(&continued.vault),
        before,
        "no successor attempt is minted"
    );
}
