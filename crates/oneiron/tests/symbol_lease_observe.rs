//! NO-DOOR SYMBOL-LEASE-OBSERVATION (tests/e2e/code-custody.test.ts
//! CODE-CUSTODY-03): a leased run reads its own symbol declaration, held or
//! waiting, and the TASKs it waits behind now, through
//! `self.code.symbols.observe` (`Memory::repo_symbols_observe_for_run`),
//! without renewing, releasing or changing it. A renewal moves the expiry,
//! so it is not a read.
//!
//! Two agent runs are real: each agent is an enabled AGENT_DEF paired to the
//! owner, holds an owner-minted Access Grant with repo bounds, and runs a
//! TASK the owner assigned it, on a claimed attempt the host sealed with an
//! executor run. The repo is a committed snapshot the owner ingested, a
//! member of the root PROJECT, with its merge queue initialized at that
//! commit. A revoked Grant is refused on the next observation.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test symbol_lease_observe`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{PointRead, ScopedReadActorKey};
use oneiron::code_run::HostSelfDispatcher;
use oneiron::code_symbol::code_symbol_entity_id;
use oneiron::codebase::RepoRef;
use oneiron::consent::AuthenticatedOwner;
use oneiron::contract_oracle::{ContractOracle, ContractSpec, WorkspaceGraph};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{RepoAccessBounds, Scope, ScopeAxis};
use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::memory::repo_doors::{
    RepoRunBinding, RepoSymbolDeclarationView, RepoSymbolsDeclareInput, RepoSymbolsObserveInput,
    RepoSymbolsReleaseInput, RepoWorkOpenInput,
};
use oneiron::merge_queue::MergeQueue;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MAIN: &str = "refs/heads/main";
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:symbol-lease-observe";
/// A declaration's lifetime here: long past the test, so no expiry moves a
/// row while it runs.
const TTL_SECONDS: u64 = 3_600;

fn git(dir: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git").args(args).current_dir(dir).output()?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// A Git repository on `refs/heads/main` with two Rust files in one commit,
/// and that commit's 40-hex id.
fn committed_repo() -> TestResult<(tempfile::TempDir, String)> {
    let dir = tempfile::tempdir()?;
    git(dir.path(), &["init", "--quiet"])?;
    git(dir.path(), &["symbolic-ref", "HEAD", MAIN])?;
    std::fs::write(
        dir.path().join("math.rs"),
        "pub fn add_one(value: u32) -> u32 {\n    value + 1\n}\n",
    )?;
    std::fs::write(
        dir.path().join("label.rs"),
        "pub fn label() -> &'static str {\n    \"ready\"\n}\n",
    )?;
    git(dir.path(), &["add", "--", "math.rs", "label.rs"])?;
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
            "two files",
        ],
    )?;
    let commit = git(dir.path(), &["rev-parse", "HEAD"])?;
    Ok((dir, commit))
}

/// An enabled, active agent definition the owner creates as `agent_id`.
fn create_enabled_agent(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent_id: &str,
) -> TestResult<EntityId> {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Symbol lease observation fixture agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))?,
        },
    )?;
    Ok(agent)
}

/// The agent's own credential, paired by the owner and proven held.
fn paired_agent_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: &AuthenticatedOwner,
    agent: EntityId,
    binding_seed: u8,
) -> TestResult<VerifiedSlip> {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = vault.issue_owner_pairing_link(
        issuer,
        owner,
        scope,
        3_600,
        PairingPrincipal {
            holder_ref: Some(holder.clone()),
            actor_class: Some("agent".to_owned()),
            ..PairingPrincipal::default()
        },
    )?;
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )?;
    let slip = vault.redeem_pairing_link(
        issuer,
        &link.code,
        &holder,
        binding_key,
        &signing_key.sign(&transcript).to_bytes(),
    )?;
    let signature = signing_key
        .sign(&slip.binding_transcript(REQUEST_CHALLENGE)?)
        .to_bytes();
    Ok(vault.verify_capability_slip(&issuer.public_key(), &slip, REQUEST_CHALLENGE, &signature)?)
}

/// One agent's live run on the repo: its TASK, its sealed run binding and
/// the work it opened at the queue's green commit.
struct AgentRun {
    task: EntityId,
    binding: RepoRunBinding,
    /// The read lane of the agent's own credential, as the binding reads.
    reader: ScopedReadActorKey,
    actor: WriteActor,
    work: EntityId,
    grant: EntityId,
}

struct Fixture {
    vault: Vault,
    _vault_dir: tempfile::TempDir,
    _repo_dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    symbol: EntityId,
    a: AgentRun,
    b: AgentRun,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let vault_dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        let vault = Vault::open_owned(vault_dir.path(), config)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        // The owner's agent Grant act is carried by this install's live
        // machine profile, as a serving start enrols it (FIX 4648).
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let owner_memory = vault
            .memory(owner, EdgeActorClass::Human)
            .with_owner_authorship(&owner_proof);
        let project = vault.root_project()?;

        // The repo: a committed snapshot the owner ingested, a member of the
        // root PROJECT, its queue green at that commit.
        let (repo_dir, commit) = committed_repo()?;
        let folder = repo_dir.path().canonicalize()?;
        let snapshot = owner_memory.code_snapshot_ingest_as(
            &owner_proof,
            CodeSnapshotIngestRequest {
                project_id: project.to_hex(),
                pointer: CodeRepoPointer {
                    local_folder: folder.to_str().ok_or("UTF-8 repo path")?.to_owned(),
                    commit: commit.clone(),
                },
                repository: None,
            },
        )?;
        let repo = snapshot.repo;
        vault.put_project_member(repo, project)?;
        let spec = ContractSpec::default();
        let baseline = ContractOracle::new(&vault).record_baseline(
            spec.clone(),
            ContractOracle::capture(&spec, &folder, BTreeMap::new())?,
        )?;
        let pointers = MergeQueue::open(&vault, RepoRef::parse(&snapshot.repo_ref)?)?
            .initialize(&baseline.id, WorkspaceGraph::unfiltered())?;
        assert_eq!(pointers.green, commit, "the queue is green at the commit");

        // The one symbol both runs declare: `add_one` in math.rs, by its
        // current CODE_SYMBOL id.
        let manifest = vault
            .get_code_symbol_manifest(&repo)?
            .ok_or("the ingest kept the snapshot's symbol manifest")?;
        let revision = manifest
            .symbols
            .iter()
            .find(|symbol| symbol.path == "math.rs" && symbol.name == "add_one")
            .ok_or("math.rs defines add_one")?;
        let symbol = code_symbol_entity_id(&manifest.repo_identity, revision)?;

        let bounds = RepoAccessBounds {
            repo,
            project,
            refs: BTreeSet::from([MAIN.to_owned()]),
            readable: BTreeSet::from(["*.rs".to_owned()]),
            editable: BTreeSet::from(["*.rs".to_owned()]),
        };
        let agent_a = create_enabled_agent(&vault, &owner_proof, "symbol-observe-agent-a")?;
        let agent_b = create_enabled_agent(&vault, &owner_proof, "symbol-observe-agent-b")?;
        let slip_a = paired_agent_slip(&vault, &issuer, &owner_proof, agent_a, 0x51)?;
        let slip_b = paired_agent_slip(&vault, &issuer, &owner_proof, agent_b, 0x52)?;
        let grant_a = mint_repo_grant(&vault, &owner_proof, agent_a, &bounds)?;
        let grant_b = mint_repo_grant(&vault, &owner_proof, agent_b, &bounds)?;

        // Both TASKs are created and both tries claimed before any symbol
        // is declared.
        let leased_a = leased_try(&vault, &owner_memory, owner, agent_a, "observe A")?;
        let leased_b = leased_try(&vault, &owner_memory, owner, agent_b, "observe B")?;
        let a = agent_run(&vault, &slip_a, leased_a, repo, grant_a)?;
        let b = agent_run(&vault, &slip_b, leased_b, repo, grant_b)?;
        Ok(Self {
            vault,
            _vault_dir: vault_dir,
            _repo_dir: repo_dir,
            owner_proof,
            symbol,
            a,
            b,
        })
    }

    fn observe(&self, run: &AgentRun) -> oneiron::memory::MemoryResult<RepoSymbolDeclarationView> {
        Ok(self
            .vault
            .memory(run.actor.entity_ref(), run.actor.actor_class())
            .repo_symbols_observe_for_run(&run.binding, RepoSymbolsObserveInput { work: run.work })?
            .output)
    }

    fn declare(&self, run: &AgentRun) -> TestResult<RepoSymbolDeclarationView> {
        Ok(self
            .vault
            .memory(run.actor.entity_ref(), run.actor.actor_class())
            .repo_symbols_declare_for_run(
                &run.binding,
                RepoSymbolsDeclareInput {
                    work: run.work,
                    symbols: vec![self.symbol],
                    ttl_seconds: TTL_SECONDS,
                },
            )?
            .output)
    }
}

fn mint_repo_grant(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent: EntityId,
    bounds: &RepoAccessBounds,
) -> TestResult<EntityId> {
    let mut authority_scope = Scope::top();
    authority_scope.verbs =
        ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let minted = mint_agent_grant_as(
        vault,
        owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: Some(bounds.clone()),
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
        },
    )?;
    Ok(minted.grant.grant_ref)
}

/// The owner's TASK for `agent`, and its claimed agent try.
fn leased_try(
    vault: &Vault,
    owner_memory: &oneiron::memory::Memory<'_>,
    owner: EntityId,
    agent: EntityId,
    label: &str,
) -> TestResult<(EntityId, WriteActor, oneiron::attempt_queue::AttemptRecord)> {
    let created = owner_memory.tasks_create(
        &TaskCreateSpec::new(rmpv::Value::Nil, Some(label.to_owned()), Some(owner), None)
            .with_assignee(TaskAssignee::AgentDef {
                agent_def_ref: agent,
            }),
    )?;
    let task = created
        .task_ref
        .ok_or("the owner's TASK lands, not a proposal")?;
    let Some(TaskRouteOutcome::AgentDispatch { attempt_ref, .. }) = created.route else {
        return Err("an agent-definition assignee routes to an agent dispatch".into());
    };
    // The dispatch rides the runner's queue kind; other rows the fresh vault
    // queued are claimed past.
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: format!("symbol-observe-{}", agent.to_hex()),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == attempt_ref {
            let leased = queue.get(row.id)?.ok_or("a claimed try reads back")?;
            assert_eq!(leased.task_ref.as_deref(), Some(task.to_hex().as_str()));
            return Ok((task, WriteActor::new(agent, EdgeActorClass::Agent), leased));
        }
    }
    Err("the TASK's agent try is ready to claim".into())
}

/// The run the host seals for a claimed try, read on the agent's own
/// credential, with the work it opens at the queue's green commit.
fn agent_run(
    vault: &Vault,
    slip: &VerifiedSlip,
    (task, actor, leased): (EntityId, WriteActor, oneiron::attempt_queue::AttemptRecord),
    repo: EntityId,
    grant: EntityId,
) -> TestResult<AgentRun> {
    let host = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, &leased)?
        .live_run_host_binding(EntityId::now())?;
    let reader: ScopedReadActorKey = vault
        .credential_read_key(slip)?
        .ok_or("the paired agent's credential reads")?;
    let binding = RepoRunBinding::for_live_host(vault, actor, &host, reader.clone())?;
    let work = vault
        .memory(actor.entity_ref(), actor.actor_class())
        .repo_work_open_for_run(
            &binding,
            RepoWorkOpenInput {
                repo,
                portable_repo: None,
                git_ref: MAIN.to_owned(),
            },
        )?
        .output
        .work;
    Ok(AgentRun {
        task,
        binding,
        reader,
        actor,
        work,
        grant,
    })
}

#[test]
fn a_run_observes_its_held_or_waiting_declaration_without_changing_it() -> TestResult {
    let fixture = Fixture::new()?;
    let (a, b) = (&fixture.a, &fixture.b);

    // No declaration yet: there is nothing current to read.
    let none = fixture
        .observe(a)
        .expect_err("a run with no declaration observes none");
    assert_eq!(none.code, "repo_stale_lease", "{none:?}");

    let held = fixture.declare(a)?;
    assert!(held.held, "A declares first and holds");
    let waiting = fixture.declare(b)?;
    assert!(!waiting.held, "B overlaps A's live declaration and waits");

    // B's lane reads A's TASK, so A shows among B's blockers.
    let lane = fixture
        .vault
        .scoped_read(b.reader.clone())
        .read(&[PointRead::id(a.task)], None)?;
    assert!(
        lane.value[0].as_ref().is_some_and(|row| row.body.is_some()),
        "B's lane reads A's TASK"
    );
    assert_eq!(waiting.blockers, vec![a.task]);

    // A observes its held declaration as declared; B its waiting one, with
    // A as its blocker. Each read twice: the id and expiry do not move.
    for _ in 0..2 {
        let seen = fixture.observe(a)?;
        assert_eq!(
            (
                seen.declaration,
                seen.task,
                seen.work,
                seen.expires_at,
                seen.held
            ),
            (held.declaration, a.task, a.work, held.expires_at, true),
        );
        assert_eq!(seen.symbols, vec![fixture.symbol]);
        assert!(
            seen.blockers.is_empty(),
            "a held declaration waits behind none"
        );

        let seen = fixture.observe(b)?;
        assert_eq!(
            (
                seen.declaration,
                seen.task,
                seen.work,
                seen.expires_at,
                seen.held
            ),
            (
                waiting.declaration,
                b.task,
                b.work,
                waiting.expires_at,
                false
            ),
        );
        assert_eq!(seen.symbols, vec![fixture.symbol]);
        assert_eq!(seen.blockers, vec![a.task]);
    }

    // A releases. B's declaration stays waiting as stored, with no blocker
    // left; observing it neither promotes nor renews it.
    fixture
        .vault
        .memory(a.actor.entity_ref(), a.actor.actor_class())
        .repo_symbols_release_for_run(
            &a.binding,
            RepoSymbolsReleaseInput {
                work: a.work,
                declaration: held.declaration,
            },
        )?;
    let released = fixture
        .observe(a)
        .expect_err("A's released declaration is no longer current");
    assert_eq!(released.code, "repo_stale_lease", "{released:?}");
    let seen = fixture.observe(b)?;
    assert_eq!(
        (seen.declaration, seen.expires_at, seen.held),
        (waiting.declaration, waiting.expires_at, false),
    );
    assert!(seen.blockers.is_empty(), "A's release leaves B no blocker");

    // The owner revokes B's Grant: B's next observation is refused.
    revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: b.grant,
            seen: None,
        },
    )?;
    let revoked = fixture
        .observe(b)
        .expect_err("a revoked Grant admits no observation");
    assert_eq!(revoked.code, "repo_no_membership", "{revoked:?}");
    Ok(())
}
