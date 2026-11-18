//! Restriction wave 11 on the in-process call line (FIX
//! WAVE11-INPROCESS-OWNER-DOORS): the eight owner doors that also admit the
//! owner's delegate admit it in process too (SDK invoke, a host's typed verb
//! fns), as the facade does (`oneiron-server/tests/
//! restriction_wave11_owner_delegates.rs`). An agent handle bound to its own
//! live credential (`Memory::with_read_proof`, as a host binds a paired
//! agent's) reaches each row's delegate door, which reads the owner's
//! Setting key and the agent's live Grant in the act's own transaction:
//! with the key off, every row gives the owner refusal with the suggestion
//! naming its key; with it on and a Grant listing the verb, the act runs and
//! its record names the agent and its Grant. The embedded owner's call is
//! unchanged. An agent handle with no credential, another holder's, a
//! revoked one or one short of the row's core scope takes no delegate door.
//! Every call enters through `oneiron_testkit::door::invoke`, the generated
//! verb dispatch every transport shares.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test restriction_wave11_inprocess_owner_delegates`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip,
    pairing_binding_transcript,
};
use oneiron::campaign::compliance::{
    COMPLIANCE_INSTALL_VERB, COMPLIANCE_REJECT_VERB, embedded_seed_pack,
};
use oneiron::dispatch_byoa::{
    RUNNER_SEAT_QUOTAS_VERB, RUNNER_SEAT_TOP_UP_VERB, RUNNER_WORK_RESUME_VERB, RunnerSeat, SeatAuth,
};
use oneiron::dreamer_runner::PROGRAM_HOLD_RELEASE_VERB;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::run_doors::CANCEL_FORCE_VERB;
use oneiron::task_verb::sdk::REPO_ANCHOR_BIND_VERB;
use oneiron::test_doors::spent_seat::{plant_spent_seat_credit_for_test, topped_up_by_for_test};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The four owner keys that open the doors below.
const FORCE_CANCEL_KEY: &str = "attempt_queue.agent_may_force_cancel";
const RUNNER_SEATS_KEY: &str = "dispatch_byoa.runner_seats.agent_may_manage";
const REGISTRATION_KEY: &str = "codebase.registration.agent_may_register";
const COMPLIANCE_KEY: &str = "campaign.compliance.agent_may_decide";

/// The challenge each agent proves its credential on, as a host verifies a
/// paired agent's request.
const CHALLENGE: &[u8] = b"oneiron-request:restriction-wave11-inprocess";

/// The eight owner-delegate rows, in the order `delegate_rows` builds them.
const DELEGATE_VERBS: [&str; 8] = [
    CANCEL_FORCE_VERB,
    PROGRAM_HOLD_RELEASE_VERB,
    RUNNER_SEAT_QUOTAS_VERB,
    RUNNER_SEAT_TOP_UP_VERB,
    RUNNER_WORK_RESUME_VERB,
    REPO_ANCHOR_BIND_VERB,
    COMPLIANCE_INSTALL_VERB,
    COMPLIANCE_REJECT_VERB,
];

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
}

/// One agent paired the way `token agent` pairs it, and the credential a
/// host binds to its handle once the agent proves it.
struct Agent {
    principal: EntityId,
    slip: CapabilitySlip,
    credential: VerifiedSlip,
}

impl Agent {
    /// The agent's in-process handle, bound to its own credential.
    fn bound<'v>(&self, fixture: &'v Fixture) -> Memory<'v> {
        self.unbound(fixture).with_read_proof(&self.credential)
    }

    /// The agent's in-process handle with no credential.
    fn unbound<'v>(&self, fixture: &'v Fixture) -> Memory<'v> {
        fixture.vault.memory(self.principal, EdgeActorClass::Agent)
    }
}

/// A process-owned vault, as an embedded host opens it: it holds the writer
/// lease, so the embedded owner's doors admit the owner. Rooted by its host
/// issuer and serving this install, as the facade test's vault is.
fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault =
        Vault::open_owned(dir.path(), VaultConfig::device()).expect("open the process-owned vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    Fixture {
        _dir: dir,
        vault,
        issuer,
    }
}

fn owner(fixture: &Fixture) -> Memory<'_> {
    door::owner(&fixture.vault).expect("the embedded owner")
}

/// Pairs one agent as `token agent` does: a named agent principal, a
/// principal-bound link narrowed to `verbs`, redeemed with the
/// holder-signed binding transcript. The holder then proves the slip, and
/// the host verifies that proof into the credential it binds.
fn pair_agent(fixture: &Fixture, name: &str, seed: [u8; 32], verbs: &[&str]) -> Agent {
    let vault = &fixture.vault;
    let principal = vault.ensure_agent_principal(name).expect("agent principal");
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let link = vault
        .issue_pairing_link_for_principal(
            &fixture.issuer,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(principal.to_hex()),
                actor_class: Some("agent".to_owned()),
                org_ref: None,
                write_facet: None,
                ..Default::default()
            },
        )
        .expect("pairing link");
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .expect("pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            &fixture.issuer,
            &link.code,
            &principal.to_hex(),
            binding_key,
            &holder.sign(&transcript).to_bytes(),
        )
        .expect("the agent redeems its link");
    let proof = holder
        .sign(
            &slip
                .binding_transcript(CHALLENGE)
                .expect("request transcript"),
        )
        .to_bytes();
    let credential = vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, CHALLENGE, &proof)
        .expect("the agent proves its credential");
    Agent {
        principal,
        slip,
        credential,
    }
}

/// An agent paired with `core:read` and `core:write`, as `token agent` pairs it.
fn pair_writer(fixture: &Fixture, name: &str, seed: [u8; 32]) -> Agent {
    pair_agent(fixture, name, seed, &["core:read", "core:write"])
}

/// The owner mints `agent` a conferring Grant listing `verbs` (and `read`),
/// in process; answers its grant ref.
fn mint_grant(fixture: &Fixture, agent: EntityId, verbs: &[&str]) -> String {
    let mut values = vec!["read".to_owned()];
    values.extend(verbs.iter().map(|verb| (*verb).to_owned()));
    let minted = door::invoke(
        &owner(fixture),
        "vault.agents.grants.mint",
        json!({
            "agent": agent.to_hex(),
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "all"},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": values},
                "sensitivity": {"kind": "at_most", "value": "restricted"},
            },
        }),
    )
    .expect("the owner mints the grant");
    assert_eq!(minted["grant"]["confers"], json!(true), "{minted}");
    minted["grant"]["grant_ref"]
        .as_str()
        .expect("minted grant ref")
        .to_owned()
}

/// The owner sets one Setting row at `agent` engine-direct: setup, never the
/// act under test. Asserts the row applied.
fn owner_turns_on(fixture: &Fixture, key: &str, item: Option<&str>, agent: EntityId) {
    let vault = &fixture.vault;
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner actor");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let outcomes = oneiron::test_doors::setting::set_settings_in_one_write(
        vault,
        &proof,
        &[SetSetting {
            key: key.to_owned(),
            item: item.map(str::to_owned),
            scope: SettingScope::Agent(agent),
            mode: SettingMode::Value,
            value: Some(json!(true)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
            weight_runs: None,
            surface: None,
        }],
        false,
    )
    .expect("set the row");
    assert!(
        matches!(outcomes[..], [SetSettingOutcome::Applied { .. }]),
        "the row applied: {outcomes:?}"
    );
}

/// One owner-chosen seat that requests and planters name alike.
fn seat() -> RunnerSeat {
    RunnerSeat {
        runner: "claude-code".to_owned(),
        auth: SeatAuth::VendorLogin,
        egress_profile_ref: "delegate-test".to_owned(),
        credential_handles: Vec::new(),
    }
}

fn seat_json() -> Value {
    json!({
        "runner": "claude-code",
        "auth": "vendor_login",
        "egress_profile_ref": "delegate-test",
        "credential_handles": [],
    })
}

fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A committed local Git repository; answers its canonical folder.
fn git_repo() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("temporary repo directory");
    git(dir.path(), &["init", "--quiet"]);
    git(dir.path(), &["symbolic-ref", "HEAD", "refs/heads/main"]);
    std::fs::write(
        dir.path().join("math.rs"),
        "pub fn add_one(value: u32) -> u32 {\n    value + 1\n}\n",
    )
    .expect("write a file");
    git(dir.path(), &["add", "--", "math.rs"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "one file",
        ],
    );
    let folder = dir
        .path()
        .canonicalize()
        .expect("canonical folder")
        .to_str()
        .expect("UTF-8 repo path")
        .to_owned();
    (dir, folder)
}

/// One call of each owner-delegate row, in [`DELEGATE_VERBS`] order, with
/// the key that opens it: a body the row decodes and its door reads up to
/// its admission. `folder` is a local Git repository.
fn delegate_rows(fixture: &Fixture, folder: &str) -> Vec<(&'static str, &'static str, Value)> {
    let project = fixture.vault.root_project().expect("root project");
    let seed = embedded_seed_pack().expect("seed pack");
    let id = || EntityId::now().to_hex();
    vec![
        (
            CANCEL_FORCE_VERB,
            FORCE_CANCEL_KEY,
            json!({"task_ref": id()}),
        ),
        (
            PROGRAM_HOLD_RELEASE_VERB,
            FORCE_CANCEL_KEY,
            json!({"attempt": id(), "reason": "authority_lapsed", "parked_at": 1, "action": "stop"}),
        ),
        (
            RUNNER_SEAT_QUOTAS_VERB,
            RUNNER_SEATS_KEY,
            json!({"seats": [seat_json()]}),
        ),
        (
            RUNNER_SEAT_TOP_UP_VERB,
            RUNNER_SEATS_KEY,
            json!({"seat": seat_json(), "expected_spent_attempt": id()}),
        ),
        (
            RUNNER_WORK_RESUME_VERB,
            RUNNER_SEATS_KEY,
            json!({
                "binding": id(),
                "expected_attempt": id(),
                "policy": {"seats": [seat_json()], "on_spent": "stop"},
            }),
        ),
        (
            REPO_ANCHOR_BIND_VERB,
            REGISTRATION_KEY,
            json!({"local_folder": folder, "project": project.to_hex()}),
        ),
        (
            COMPLIANCE_INSTALL_VERB,
            COMPLIANCE_KEY,
            json!({"prior_version": seed.pack_version, "pack": seed}),
        ),
        (
            COMPLIANCE_REJECT_VERB,
            COMPLIANCE_KEY,
            json!({"prior_version": seed.pack_version, "proposal_hash": "0".repeat(64)}),
        ),
    ]
}

/// What one call answered, in the parts an owner-door refusal pins: its
/// code, its message, and whether a suggestion names `key` (only a delegate
/// door's refusal does).
fn answered(answer: MemoryResult<Value>, key: &str) -> (String, String, bool) {
    let named = format!("The owner lets an agent do this with the setting `{key}`.");
    match answer {
        Ok(value) => ("answered".to_owned(), value.to_string(), false),
        Err(MemoryError {
            code,
            message,
            suggestions,
            ..
        }) => (code, message, suggestions.contains(&named)),
    }
}

/// A refusal of `verb` with the code `FORBIDDEN`: the owner's message, and
/// whether it names the key.
fn owner_refusal(verb: &str, names_key: bool) -> (String, String, bool) {
    (
        "FORBIDDEN".to_owned(),
        format!("{verb} is the vault owner's"),
        names_key,
    )
}

/// A refusal of the agent's credential with the code `FORBIDDEN`.
fn credential_refusal(message: &str) -> (String, String, bool) {
    ("FORBIDDEN".to_owned(), message.to_owned(), false)
}

/// With the agent's own live credential and a Grant listing all eight
/// verbs but no key on, each row's in-process call reaches its delegate
/// door: the owner refusal, with the suggestion naming the row's key, as
/// the facade answers. Before the fix each gave the embedded owner's
/// refusal, which names no key.
#[test]
fn every_row_sends_an_agent_on_its_own_credential_to_its_delegate_door() {
    let fixture = setup();
    let agent = pair_writer(&fixture, "inprocess-off", [0xA1; 32]);
    let _grant = mint_grant(&fixture, agent.principal, &DELEGATE_VERBS);
    let (_repo, folder) = git_repo();
    let bound = agent.bound(&fixture);

    let rows = delegate_rows(&fixture, &folder);
    let seen: Vec<(&str, (String, String, bool))> = rows
        .iter()
        .map(|(verb, key, input)| {
            (
                *verb,
                answered(door::invoke(&bound, verb, input.clone()), key),
            )
        })
        .collect();
    let expected: Vec<(&str, (String, String, bool))> = rows
        .iter()
        .map(|(verb, _, _)| (*verb, owner_refusal(verb, true)))
        .collect();
    assert_eq!(
        seen, expected,
        "each row's in-process call reaches its delegate door"
    );
}

/// With its `quotas` and `top_up` rows on and a Grant listing both verbs,
/// the agent reads the seat's quota and tops up its spent credit in
/// process, and the top-up's record names the agent and its Grant, as the
/// facade's delegate top-up does.
#[test]
fn an_agent_the_owner_lets_through_tops_up_a_seat_in_process() {
    let fixture = setup();
    let agent = pair_writer(&fixture, "inprocess-topup", [0xA2; 32]);
    let grant = mint_grant(
        &fixture,
        agent.principal,
        &[RUNNER_SEAT_QUOTAS_VERB, RUNNER_SEAT_TOP_UP_VERB],
    );
    owner_turns_on(&fixture, RUNNER_SEATS_KEY, Some("quotas"), agent.principal);
    owner_turns_on(&fixture, RUNNER_SEATS_KEY, Some("top_up"), agent.principal);
    let spent = EntityId::now().to_hex();
    plant_spent_seat_credit_for_test(
        &fixture.vault,
        &seat(),
        *EntityId::from_hex(&spent).expect("spent id").as_bytes(),
    )
    .expect("plant a spent credit");
    let bound = agent.bound(&fixture);

    let quotas = door::invoke(
        &bound,
        RUNNER_SEAT_QUOTAS_VERB,
        json!({"seats": [seat_json()]}),
    )
    .expect("the delegate reads the seat's quota in process");
    assert_eq!(
        quotas["quotas"][0]["runner"],
        json!("claude-code"),
        "{quotas}"
    );

    let topped = door::invoke(
        &bound,
        RUNNER_SEAT_TOP_UP_VERB,
        json!({"seat": seat_json(), "expected_spent_attempt": spent}),
    )
    .expect("the delegate tops up the seat in process");
    assert_eq!(topped["effect"], json!("cleared"), "{topped}");
    assert!(
        topped["quota"]["topped_up_at"].is_number(),
        "the quota shows the top-up: {topped}"
    );
    let (_owner, decision, _at, delegate) = topped_up_by_for_test(&fixture.vault, &seat())
        .expect("read the top-up")
        .expect("a top-up stands");
    assert_eq!(
        delegate.as_deref(),
        Some(agent.principal.to_hex().as_str()),
        "the record names the agent"
    );
    assert_eq!(decision, grant, "the record names the delegate's Grant");
}

/// The embedded owner's in-process calls answer as before: it reads the
/// seat's quota and tops up the spent credit, and the record names no
/// delegate.
#[test]
fn the_embedded_owner_call_is_unchanged() {
    let fixture = setup();
    let spent = EntityId::now().to_hex();
    plant_spent_seat_credit_for_test(
        &fixture.vault,
        &seat(),
        *EntityId::from_hex(&spent).expect("spent id").as_bytes(),
    )
    .expect("plant a spent credit");
    let caller = owner(&fixture);

    let quotas = door::invoke(
        &caller,
        RUNNER_SEAT_QUOTAS_VERB,
        json!({"seats": [seat_json()]}),
    )
    .expect("the owner reads the seat's quota");
    assert_eq!(
        quotas["quotas"][0]["runner"],
        json!("claude-code"),
        "{quotas}"
    );

    let topped = door::invoke(
        &caller,
        RUNNER_SEAT_TOP_UP_VERB,
        json!({"seat": seat_json(), "expected_spent_attempt": spent}),
    )
    .expect("the owner tops up the seat");
    assert_eq!(topped["effect"], json!("cleared"), "{topped}");
    let (_owner, _decision, _at, delegate) = topped_up_by_for_test(&fixture.vault, &seat())
        .expect("read the top-up")
        .expect("a top-up stands");
    assert_eq!(delegate, None, "the owner's top-up names no delegate");
}

/// With the key on and a Grant listing the verb, an agent handle still
/// takes no delegate door without its own live credential of the row's
/// scope: with no credential, or another agent's, it gets the embedded
/// owner's refusal; with its own revoked one, the facade's refusal of a
/// credential that no longer holds; with a read-only one on a write row,
/// the refusal naming the scope it lacks.
#[test]
fn an_agent_without_its_own_live_credential_takes_no_delegate_door() {
    let fixture = setup();
    let agent = pair_writer(&fixture, "inprocess-holder", [0xA3; 32]);
    let other = pair_writer(&fixture, "inprocess-other", [0xA4; 32]);
    let reader = pair_agent(&fixture, "inprocess-reader", [0xA5; 32], &["core:read"]);
    for paired in [&agent, &reader] {
        let _grant = mint_grant(&fixture, paired.principal, &[RUNNER_SEAT_TOP_UP_VERB]);
        owner_turns_on(&fixture, RUNNER_SEATS_KEY, Some("top_up"), paired.principal);
    }
    let top_up =
        || json!({"seat": seat_json(), "expected_spent_attempt": EntityId::now().to_hex()});

    let call = |caller: &Memory<'_>| {
        answered(
            door::invoke(caller, RUNNER_SEAT_TOP_UP_VERB, top_up()),
            RUNNER_SEATS_KEY,
        )
    };

    assert_eq!(
        call(&agent.unbound(&fixture)),
        owner_refusal(RUNNER_SEAT_TOP_UP_VERB, false),
        "no credential: the embedded owner's refusal"
    );
    assert_eq!(
        call(&agent.unbound(&fixture).with_read_proof(&other.credential)),
        owner_refusal(RUNNER_SEAT_TOP_UP_VERB, false),
        "another agent's credential: the embedded owner's refusal"
    );
    assert_eq!(
        call(&reader.bound(&fixture)),
        credential_refusal("the credential does not have the required scope core:write"),
        "a read-only credential on a write row"
    );

    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, agent.slip.claims.slip_id)
        .expect("revoke the agent's credential");
    assert_eq!(
        call(&agent.bound(&fixture)),
        credential_refusal("the credential is no longer live"),
        "a revoked credential"
    );
}
