//! Self hook regen doors: an agent reads and adopts the regen of the hooks it authored.
//!
//! Proves `self.hooks.regen.get` reads only the caller's own hook record and
//! `self.hooks.regen.adopt` enacts only an identical fingerprint through the
//! agent's own `local` put, while a changed regen waits for the owner.
//!
//! It uses no cfg door. Run: `cargo test --locked -p oneiron --all-features --test
//! self_hooks_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::{
    FactHookRunner, HookBodyRun, HookBodyRuntime, HookRegenFailure, HookRegenOutcome,
    HookRegenRequest, HookRegenerator, HookRunContext,
};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{HookAuthor, PackInstallDisposition};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, WriteActor,
};
use oneiron_testkit::{TestVault, door};
use serde_json::{Value, json};

/// One test's vault: the copy owns its temp dir, the open vault borrows it.
struct SelfFixture {
    test_vault: TestVault,
    vault: Vault,
}

impl SelfFixture {
    /// An empty vault, opened owned so every door can run, with its embedded
    /// owner present so an agent's `local` put has a live owner to name.
    fn open(seed_name: &str) -> Self {
        let test_vault = TestVault::seeded(seed_name, |_, _| Ok(())).expect("seed an empty vault");
        let vault = test_vault.open_owned().expect("open the vault owned");
        vault
            .ensure_embedded_owner_actor()
            .expect("ensure the embedded owner");
        Self { test_vault, vault }
    }

    /// The agent principal `name` acts as.
    fn agent_id(&self, name: &str) -> EntityId {
        self.vault
            .ensure_agent_principal(name)
            .expect("ensure the agent principal")
    }
}

/// A `local` pack folder carrying one fact hook.
fn local_files_for_hook(
    hook: &str,
    verbs_json: &str,
    outcomes_json: &str,
    intent: &str,
    body: &str,
) -> Vec<HubFile> {
    let pack_md = format!(
        "---\nname: local\ndescription: Agent local pack for self hook regen tests.\nversion: 1\nkind: capability\nhooks: [\"{hook}\"]\n---\nLocal pack.\n"
    );
    let hook_md = format!(
        "---\nname: {hook}\nversion: 1.0.0\nverbs: {verbs_json}\nphase: fact\noutcomes: {outcomes_json}\n---\n{hook} watches its input.\n"
    );
    vec![
        HubFile::new("PACK.md", pack_md),
        HubFile::new(format!("hooks/{hook}/HOOK.md"), hook_md),
        HubFile::new(format!("hooks/{hook}/intent.md"), intent),
        HubFile::new(format!("hooks/{hook}/body.js"), body),
    ]
}

/// The agent's own put of `local` with one hook; answers the binding id.
fn put_agent_local_hook(
    vault: &Vault,
    agent: EntityId,
    hook: &str,
    verbs_json: &str,
    outcomes_json: &str,
    intent: &str,
    body: &str,
) -> EntityId {
    let files = local_files_for_hook(hook, verbs_json, outcomes_json, intent, body);
    let writer = vault
        .observed_write_actor(WriteActor::new(agent, EdgeActorClass::Agent))
        .expect("observe the agent writer");
    match vault
        .put_local_pack_as_agent(&writer, files)
        .expect("the agent puts its local pack")
    {
        PackInstallDisposition::Installed(receipt) => {
            assert_eq!(receipt.pack_name, "local", "the put installs local");
        }
        other => panic!("the agent put installs local: {other:?}"),
    }
    let bindings = vault.pack_hook_bindings().expect("list hook bindings");
    let (binding_id, row) = bindings
        .into_iter()
        .find(|(_, row)| row.pack == "local" && row.hook == hook)
        .expect("the agent hook binds");
    assert_eq!(
        row.author,
        HookAuthor::Agent { agent },
        "the hook binds as its authoring agent"
    );
    assert!(row.enabled, "the new binding runs");
    binding_id
}

/// One landed claim with `predicate` about a fresh person; answers the claim id.
fn land_fact_claim(vault: &Vault, predicate: &str) -> EntityId {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"hook subject",
        )
        .expect("put the claim subject");
    let claim_id = EntityId::now();
    let body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        rmpv::Value::from("fixture input"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("build the claim body");
    vault
        .put_claim(&claim_id, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("land the fact claim");
    claim_id
}

/// A hook sandbox that always emits `nothing`, whatever body it runs.
struct AlwaysNothingRuntime;

impl HookBodyRuntime for AlwaysNothingRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        Ok(HookBodyRun {
            outcome_json: r#"{"kind":"nothing"}"#.to_owned(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

/// A hook sandbox that emits `nothing` for the last good body and a propose
/// note for any body carrying the candidate marker.
struct BodyAwareRuntime;

impl HookBodyRuntime for BodyAwareRuntime {
    fn run_hook(
        &self,
        body: &str,
        _input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        let outcome_json = if body.contains("CANDIDATE_MARKER") {
            r#"{"kind":"propose","note":{"title":"regen note","body":"candidate","about":[]}}"#
                .to_owned()
        } else {
            r#"{"kind":"nothing"}"#.to_owned()
        };
        Ok(HookBodyRun {
            outcome_json,
            fuel_used: None,
            host_calls: 1,
        })
    }
}

/// A regenerator that answers every intent with one fixed candidate body.
struct FixedBodyRegenerator {
    candidate: String,
}

impl HookRegenerator for FixedBodyRegenerator {
    fn regenerate(
        &self,
        _request: &HookRegenRequest,
    ) -> std::result::Result<String, HookRegenFailure> {
        Ok(self.candidate.clone())
    }
}

/// An identical regen fingerprint adopts through the agent's own put.
///
/// Canon `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:450`
/// "An identical fingerprint adopts."
#[test]
fn an_identical_regen_fingerprint_adopts_through_the_agents_own_put() {
    let fixture = SelfFixture::open("self-hooks-identical");
    let agent = fixture.agent_id("self-hooks-identical-agent");
    let hook = "idem-hook";
    let last_good = "return {kind: \"nothing\"};";
    let candidate = "return {kind: \"nothing\"}; // regen candidate";
    let binding = put_agent_local_hook(
        &fixture.vault,
        agent,
        hook,
        "[\"claim.landed:example.idem.input\"]",
        "[\"nothing\"]",
        "Watch example.idem.input claims and do nothing.",
        last_good,
    );
    let _input_claim = land_fact_claim(&fixture.vault, "example.idem.input");
    let pass = FactHookRunner::new()
        .run_pass(&fixture.vault, &AlwaysNothingRuntime, 256)
        .expect("the runner takes the fact");
    assert_eq!(pass.runs, 1, "one saved run seeds the golden set: {pass:?}");
    let decided = fixture
        .vault
        .regenerate_hook(
            &AlwaysNothingRuntime,
            &FixedBodyRegenerator {
                candidate: candidate.to_owned(),
            },
            binding,
        )
        .expect("regen decides");
    assert!(
        matches!(decided, HookRegenOutcome::AutoAdopt { .. }),
        "an identical fingerprint is AutoAdopt: {decided:?}"
    );
    let caller = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let binding_hex = binding.to_hex();
    let got: Value = door::invoke(
        &caller,
        "self.hooks.regen.get",
        json!({"binding": binding_hex}),
    )
    .expect("the agent reads its own regen record");
    let candidate_hash = got["candidate_hash"]
        .as_str()
        .expect("a candidate waits")
        .to_owned();
    assert_eq!(candidate_hash.len(), 64, "a body hash: {got}");
    assert_eq!(
        got["record"]["pending"]["outcome"].as_str(),
        Some("auto_adopt"),
        "the pending decision is AutoAdopt: {got}"
    );
    assert_ne!(
        got["record"]["body_hash"].as_str(),
        Some(candidate_hash.as_str()),
        "the last good body is not the candidate yet: {got}"
    );
    let adopted: Value = door::invoke(
        &caller,
        "self.hooks.regen.adopt",
        json!({"binding": binding_hex, "candidate_hash": candidate_hash}),
    )
    .expect("the identical fingerprint adopts");
    assert_eq!(
        adopted["outcome"].as_str(),
        Some("installed"),
        "the agent put installs the candidate: {adopted}"
    );
    assert_eq!(
        adopted["receipt"]["pack_name"].as_str(),
        Some("local"),
        "the adopt puts local: {adopted}"
    );
    let got_again: Value = door::invoke(
        &caller,
        "self.hooks.regen.get",
        json!({"binding": binding_hex}),
    )
    .expect("the agent reads the adopted record");
    assert!(
        got_again
            .get("candidate_hash")
            .and_then(Value::as_str)
            .is_none(),
        "no candidate waits after the adopt: {got_again}"
    );
    assert!(
        got_again["record"]["pending"].is_null(),
        "the decision enacted: {got_again}"
    );
    assert_eq!(
        got_again["record"]["body_hash"].as_str(),
        Some(candidate_hash.as_str()),
        "the record stands on the candidate: {got_again}"
    );
    let bindings = fixture.vault.pack_hook_bindings().expect("list bindings");
    let rebound = bindings
        .iter()
        .find(|(_, row)| row.pack == "local" && row.hook == hook && row.body_hash == candidate_hash)
        .expect("the candidate binds under a new id");
    assert_eq!(
        rebound.1.author,
        HookAuthor::Agent { agent },
        "the rebound hook stays the agent's"
    );
    assert!(rebound.1.enabled, "the rebound hook runs");
    let rebound_body = fixture
        .vault
        .pack_hook_body(&rebound.1)
        .expect("read the rebound body");
    assert_eq!(
        rebound_body,
        candidate.as_bytes(),
        "the hook runs the candidate body"
    );
}

/// A changed regen waits for the owner: the agent's adopt is refused and the
/// hook body is unchanged.
///
/// Canon `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:450`
/// "A diff needs a human stamp."
#[test]
fn a_changed_regen_waits_for_the_owner() {
    let fixture = SelfFixture::open("self-hooks-diff");
    let agent = fixture.agent_id("self-hooks-diff-agent");
    let hook = "diff-hook";
    let last_good = "return {kind: \"nothing\"};";
    let candidate =
        "return {kind: \"propose\", note: {title: \"regen note\"}}; // CANDIDATE_MARKER";
    let binding = put_agent_local_hook(
        &fixture.vault,
        agent,
        hook,
        "[\"claim.landed:example.diff.input\"]",
        "[\"nothing\", \"propose\"]",
        "Watch example.diff.input claims and do nothing.",
        last_good,
    );
    let _input_claim = land_fact_claim(&fixture.vault, "example.diff.input");
    let pass = FactHookRunner::new()
        .run_pass(&fixture.vault, &BodyAwareRuntime, 256)
        .expect("the runner takes the fact");
    assert_eq!(pass.runs, 1, "one saved run seeds the golden set: {pass:?}");
    let decided = fixture
        .vault
        .regenerate_hook(
            &BodyAwareRuntime,
            &FixedBodyRegenerator {
                candidate: candidate.to_owned(),
            },
            binding,
        )
        .expect("regen decides");
    assert!(
        matches!(decided, HookRegenOutcome::NeedsHumanStamp { .. }),
        "a diff is NeedsHumanStamp: {decided:?}"
    );
    let caller = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let binding_hex = binding.to_hex();
    let got: Value = door::invoke(
        &caller,
        "self.hooks.regen.get",
        json!({"binding": binding_hex}),
    )
    .expect("the agent reads its own regen record");
    let candidate_hash = got["candidate_hash"]
        .as_str()
        .expect("a candidate waits")
        .to_owned();
    assert_eq!(
        got["record"]["pending"]["outcome"].as_str(),
        Some("needs_human_stamp"),
        "the pending decision waits for a stamp: {got}"
    );
    let refused = door::invoke(
        &caller,
        "self.hooks.regen.adopt",
        json!({"binding": binding_hex, "candidate_hash": candidate_hash}),
    )
    .expect_err("a diff waits for the owner");
    assert_eq!(refused.code, "INVALID_STATE", "the stamp refusal code");
    assert_eq!(
        refused.message, "this regen changes what the hook does: it needs the owner's stamp",
        "the stamp refusal message"
    );
    let bindings = fixture.vault.pack_hook_bindings().expect("list bindings");
    let current = bindings
        .iter()
        .find(|(id, _)| **id == binding)
        .expect("the binding still stands");
    assert!(
        current.1.enabled,
        "the refused adopt leaves the hook running"
    );
    let kept = fixture
        .vault
        .pack_hook_body(&current.1)
        .expect("read the kept body");
    assert_eq!(
        kept,
        last_good.as_bytes(),
        "the hook keeps its last good body"
    );
    assert!(
        bindings
            .iter()
            .all(|(_, row)| row.body_hash != candidate_hash),
        "no rebound binding installs the refused candidate"
    );
    let got_again: Value = door::invoke(
        &caller,
        "self.hooks.regen.get",
        json!({"binding": binding_hex}),
    )
    .expect("the decision still waits");
    assert_eq!(
        got_again["candidate_hash"].as_str(),
        Some(candidate_hash.as_str()),
        "the same candidate still waits: {got_again}"
    );
}

/// An agent reads only the regen record of its own hook.
///
/// Door `scripts/sdk/verbs/self.hooks.regen.get.json:2`
/// "Read the regen record of a hook this agent authored" (no canon line names
/// this read; the engine refuses any other binding as unknown).
#[test]
fn an_agent_reads_only_the_regen_record_of_its_own_hook() {
    let fixture = SelfFixture::open("self-hooks-own-read");
    let first_agent = fixture.agent_id("self-hooks-own-first");
    let second_agent = fixture.agent_id("self-hooks-own-second");
    let hook = "own-hook";
    let last_good = "return {kind: \"nothing\"};";
    let binding = put_agent_local_hook(
        &fixture.vault,
        first_agent,
        hook,
        "[\"claim.landed:example.own.input\"]",
        "[\"nothing\"]",
        "Watch example.own.input claims and do nothing.",
        last_good,
    );
    let binding_hex = binding.to_hex();
    let first_caller = fixture.vault.memory(first_agent, EdgeActorClass::Agent);
    let own: Value = door::invoke(
        &first_caller,
        "self.hooks.regen.get",
        json!({"binding": binding_hex}),
    )
    .expect("the author reads its own record");
    assert_eq!(
        own["record"]["body_hash"].as_str().map(str::len),
        Some(64),
        "the own record names its last good body: {own}"
    );
    assert!(
        own.get("candidate_hash").and_then(Value::as_str).is_none(),
        "no candidate waits before any regen: {own}"
    );
    assert!(
        own["record"]["pending"].is_null(),
        "no decision waits before any regen: {own}"
    );
    let second_caller = fixture.vault.memory(second_agent, EdgeActorClass::Agent);
    let foreign = door::invoke(
        &second_caller,
        "self.hooks.regen.get",
        json!({"binding": binding_hex}),
    )
    .expect_err("another agent's hook is not read");
    assert_eq!(foreign.code, "NOT_FOUND", "the foreign read refusal code");
    assert_eq!(
        foreign.message, "hook binding is unknown or withheld",
        "the foreign read refusal message"
    );
    let unknown_hex = EntityId::now().to_hex();
    let unknown = door::invoke(
        &first_caller,
        "self.hooks.regen.get",
        json!({"binding": unknown_hex}),
    )
    .expect_err("an unknown binding is not read");
    assert_eq!(unknown.code, "NOT_FOUND", "the unknown read refusal code");
    assert_eq!(
        unknown.message, "hook binding is unknown or withheld",
        "the unknown read refusal message"
    );
    let own_again: Value = door::invoke(
        &first_caller,
        "self.hooks.regen.get",
        json!({"binding": binding_hex}),
    )
    .expect("the own record still reads");
    assert_eq!(
        own_again["record"]["body_hash"], own["record"]["body_hash"],
        "refused reads change nothing"
    );
    let bindings = fixture.vault.pack_hook_bindings().expect("list bindings");
    assert_eq!(bindings.len(), 1, "refused reads bind nothing");
    let kept = fixture
        .vault
        .pack_hook_body(&bindings[0].1)
        .expect("read the kept body");
    assert_eq!(
        kept,
        last_good.as_bytes(),
        "refused reads keep the hook body"
    );
}
