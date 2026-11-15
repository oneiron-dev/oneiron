//! The run repo door tests' shared fixture (`symbol_lease_observe.rs`,
//! `repo_member_read.rs`, `repo_queue_drive.rs`): a fresh owned vault, and a
//! repo that is a committed two-file snapshot the owner ingested, a member of
//! the root PROJECT, with its merge queue initialized green at that commit.
//! The queue is either initialized natively, so nothing drives it, or by
//! the owner's checked init on the commit's check plan, which enrolls it
//! for the automatic driver ([`RepoFixture::enrolled`]).
//!
//! Each agent run is real: the agent is an enabled AGENT_DEF paired to the
//! owner, and runs a TASK the owner assigned it, on a claimed attempt the
//! host sealed with an executor run. Its repo access is an owner-minted
//! Access Grant with repo bounds.
#![allow(dead_code)] // each integration binary uses a subset of these helpers

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::HostSelfDispatcher;
use oneiron::code_symbol::code_symbol_entity_id;
use oneiron::codebase::RepoRef;
use oneiron::consent::AuthenticatedOwner;
use oneiron::contract_oracle::{ContractOracle, ContractSpec, WorkspaceGraph};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{RepoAccessBounds, Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::memory::merge_queue_doors::MergeQueueInitializeRequest;
use oneiron::memory::repo_doors::{RepoRunBinding, RepoWorkOpenInput};
use oneiron::merge_queue::{
    MergeQueue, QueueCheckEnvironment, QueueCheckExecution, QueueCheckHost, QueueCheckInputs,
    QueueCheckInvocation, QueueCheckNeed, QueueCheckRun, QueueCheckStatus, QueueCommandReceipt,
    REPO_CHECK_PLAN_PATH,
};
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::json;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(crate) const MAIN: &str = "refs/heads/main";
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:repo-run-fixture";

/// The repo's two files, as committed.
pub(crate) const MATH_RS: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 1\n}\n";
pub(crate) const LABEL_RS: &str = "pub fn label() -> &'static str {\n    \"ready\"\n}\n";

/// The enrolled repo's check plan: one fast and one slow command, no
/// contract outputs. The test checker host reports each command it is
/// handed as passed; nothing runs it.
const CHECK_PLAN: &str = r#"{"schema_version":1,"fast":[{"argv":["true"],"env_allowlist":{},"platform":{},"declared_outputs":[],"secret_taint_refs":[],"class":"verify"}],"slow":[{"argv":["true"],"env_allowlist":{},"platform":{},"declared_outputs":[],"secret_taint_refs":[],"class":"verify"}]}"#;

/// How the fixture initializes the repo's queue.
#[derive(Clone, Copy, PartialEq, Eq)]
enum QueueInit {
    /// The low-level init: no checked configuration, so nothing drives it.
    Native,
    /// The owner's checked init on the commit's check plan, which enrolls
    /// the queue for the automatic driver.
    Checked,
}

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
/// and its check plan too for a checked init, and that commit's 40-hex id.
fn committed_repo(init: QueueInit) -> TestResult<(tempfile::TempDir, String)> {
    let dir = tempfile::tempdir()?;
    git(dir.path(), &["init", "--quiet"])?;
    git(dir.path(), &["symbolic-ref", "HEAD", MAIN])?;
    std::fs::write(dir.path().join("math.rs"), MATH_RS)?;
    std::fs::write(dir.path().join("label.rs"), LABEL_RS)?;
    git(dir.path(), &["add", "--", "math.rs", "label.rs"])?;
    if init == QueueInit::Checked {
        let plan = dir.path().join(REPO_CHECK_PLAN_PATH);
        std::fs::create_dir_all(plan.parent().ok_or("the plan has a folder")?)?;
        std::fs::write(&plan, CHECK_PLAN)?;
        git(dir.path(), &["add", "--", REPO_CHECK_PLAN_PATH])?;
    }
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

/// A fresh owned vault, its owner, and the repo the owner ingested.
pub(crate) struct RepoFixture {
    pub(crate) vault: Vault,
    _vault_dir: tempfile::TempDir,
    _repo_dir: tempfile::TempDir,
    pub(crate) issuer: HostSlipIssuer,
    pub(crate) owner: EntityId,
    pub(crate) owner_proof: AuthenticatedOwner,
    pub(crate) project: EntityId,
    /// The ingested snapshot's CODE, a member of the root PROJECT.
    pub(crate) repo: EntityId,
    /// The snapshot's fork hash, the read doors' snapshot selector.
    pub(crate) snapshot: String,
    /// The commit `refs/heads/main` names, and the queue's green.
    pub(crate) commit: String,
}

impl RepoFixture {
    /// The repo with its queue initialized natively: nothing drives it.
    pub(crate) fn new() -> TestResult<Self> {
        Self::build(QueueInit::Native)
    }

    /// The repo with its queue initialized by the owner's checked init,
    /// enrolled for the automatic driver.
    pub(crate) fn enrolled() -> TestResult<Self> {
        Self::build(QueueInit::Checked)
    }

    fn build(init: QueueInit) -> TestResult<Self> {
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
        let project = vault.root_project()?;

        // The repo: a committed snapshot the owner ingested, a member of the
        // root PROJECT, its queue green at that commit.
        let (repo_dir, commit) = committed_repo(init)?;
        let folder = repo_dir.path().canonicalize()?;
        let snapshot = vault
            .memory(owner, EdgeActorClass::Human)
            .with_owner_authorship(&owner_proof)
            .code_snapshot_ingest_as(
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
        let queue = MergeQueue::open(&vault, RepoRef::parse(&snapshot.repo_ref)?)?;
        match init {
            QueueInit::Native => {
                let spec = ContractSpec::default();
                let baseline = ContractOracle::new(&vault).record_baseline(
                    spec.clone(),
                    ContractOracle::capture(&spec, &folder, BTreeMap::new())?,
                )?;
                let pointers = queue.initialize(&baseline.id, WorkspaceGraph::unfiltered())?;
                assert_eq!(pointers.green, commit, "the queue is green at the commit");
            }
            QueueInit::Checked => {
                checked_init(&vault, owner, &owner_proof, repo, &commit)?;
                let enrolled = vault.queue_driver_configurations()?;
                assert_eq!(enrolled.len(), 1, "the checked init enrolls the one queue");
                assert_eq!(enrolled[0].repo, repo);
                assert_eq!(
                    queue.pointers()?.green,
                    commit,
                    "the queue is green at the commit"
                );
            }
        }
        Ok(Self {
            vault,
            _vault_dir: vault_dir,
            _repo_dir: repo_dir,
            issuer,
            owner,
            owner_proof,
            project,
            repo,
            snapshot: snapshot.snapshot,
            commit,
        })
    }

    /// The owner's own Memory handle, with its authorship bound.
    pub(crate) fn owner_memory(&self) -> Memory<'_> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.owner_proof)
    }

    /// The current CODE_SYMBOL id of `name` in `path`, from the snapshot's
    /// symbol manifest.
    pub(crate) fn symbol(&self, path: &str, name: &str) -> TestResult<EntityId> {
        let manifest = self
            .vault
            .get_code_symbol_manifest(&self.repo)?
            .ok_or("the ingest kept the snapshot's symbol manifest")?;
        let revision = manifest
            .symbols
            .iter()
            .find(|symbol| symbol.path == path && symbol.name == name)
            .ok_or("the snapshot defines the symbol")?;
        Ok(code_symbol_entity_id(&manifest.repo_identity, revision)?)
    }

    /// Repo bounds on `refs/heads/main` that read and edit the given globs.
    pub(crate) fn bounds(&self, readable: &[&str], editable: &[&str]) -> RepoAccessBounds {
        RepoAccessBounds {
            repo: self.repo,
            project: self.project,
            refs: BTreeSet::from([MAIN.to_owned()]),
            readable: readable.iter().map(|glob| (*glob).to_owned()).collect(),
            editable: editable.iter().map(|glob| (*glob).to_owned()).collect(),
        }
    }
}

/// The owner's checked init of `repo`'s queue at `commit`, run to its end by
/// the checker's own claim and run on [`PassingChecks`].
fn checked_init(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    repo: EntityId,
    commit: &str,
) -> TestResult {
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .merge_queue_init_as(
            owner_proof,
            MergeQueueInitializeRequest {
                repo,
                baseline_commit: commit.to_owned(),
                contract_baseline_ref: None,
            },
        )?;
    let pending = vault.pending_queue_checks()?;
    assert_eq!(pending.len(), 1, "the init request is the one queued work");
    let work = vault
        .claim_queue_check(&pending[0], "repo-run-fixture-checker", 1)?
        .ok_or("the checker claims the init work")?;
    let done = vault.run_queue_check(&work, &mut PassingChecks, &|| false)?;
    if done.status != (QueueCheckStatus::Completed { passed: true }) {
        return Err(format!("the checked init did not complete: {:?}", done.status).into());
    }
    Ok(())
}

/// The test's checker host: it reports each command of a check's frozen plan
/// as exited zero, with no contract output. It stands in for the isolated
/// executor an operator configures.
pub(crate) struct PassingChecks;

impl QueueCheckHost for PassingChecks {
    fn environment(&mut self) -> Result<QueueCheckEnvironment, QueueCheckNeed> {
        Ok(QueueCheckEnvironment {
            backend: "host".to_owned(),
            executor: "host".to_owned(),
            runtime: None,
            image: None,
            helper: Vec::new(),
            toolchain: BTreeMap::new(),
            limits: None,
            network: "deny".to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        })
    }

    fn execute(
        &mut self,
        _invocation: &QueueCheckInvocation<'_>,
        inputs: &QueueCheckInputs,
        _stop: &dyn Fn() -> bool,
    ) -> oneiron::Result<QueueCheckExecution> {
        Ok(QueueCheckExecution::Completed(QueueCheckRun {
            commands: inputs
                .commands
                .iter()
                .map(|command| QueueCommandReceipt {
                    argv: command.argv.clone(),
                    status: Some(0),
                    signal: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    declared_outputs: BTreeMap::new(),
                })
                .collect(),
            contract_outputs: BTreeMap::new(),
            session: None,
            input_before: "unchanged".to_owned(),
            input_after: "unchanged".to_owned(),
        }))
    }
}

/// An enabled, active agent definition the owner creates as `agent_id`.
pub(crate) fn create_enabled_agent(
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
                "desc": "Repo run fixture agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))?,
        },
    )?;
    Ok(agent)
}

/// The agent's own credential, paired by the owner and proven held.
pub(crate) fn paired_agent_slip(
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

/// An owner-minted Access Grant for `agent`, read and write, with `bounds`
/// as its repo bounds or with none.
pub(crate) fn mint_repo_grant(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent: EntityId,
    bounds: Option<&RepoAccessBounds>,
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
            repo_bounds: bounds.cloned(),
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )?;
    Ok(minted.grant.grant_ref)
}

/// The owner's TASK for `agent`, and its claimed agent try.
pub(crate) fn leased_try(
    vault: &Vault,
    owner_memory: &Memory<'_>,
    owner: EntityId,
    agent: EntityId,
    label: &str,
) -> TestResult<(EntityId, WriteActor, AttemptRecord)> {
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
                lease_owner: format!("repo-run-{}", agent.to_hex()),
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
/// credential.
pub(crate) struct RunBinding {
    pub(crate) task: EntityId,
    pub(crate) binding: RepoRunBinding,
    /// The read lane of the agent's own credential, as the binding reads.
    pub(crate) reader: ScopedReadActorKey,
    pub(crate) actor: WriteActor,
}

impl RunBinding {
    /// The run's own Memory handle: the agent, as the binding names it.
    pub(crate) fn memory<'v>(&self, vault: &'v Vault) -> Memory<'v> {
        vault.memory(self.actor.entity_ref(), self.actor.actor_class())
    }
}

/// The run the host seals for `leased`, read on `slip`'s credential.
pub(crate) fn bind_run(
    vault: &Vault,
    slip: &VerifiedSlip,
    (task, actor, leased): (EntityId, WriteActor, AttemptRecord),
) -> TestResult<RunBinding> {
    let host = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, &leased)?
        .live_run_host_binding(EntityId::now())?;
    let reader: ScopedReadActorKey = vault
        .credential_read_key(slip)?
        .ok_or("the paired agent's credential reads")?;
    let binding = RepoRunBinding::for_live_host(vault, actor, &host, reader.clone())?;
    Ok(RunBinding {
        task,
        binding,
        reader,
        actor,
    })
}

/// One agent's live run on the repo: its TASK, its sealed run binding and
/// the work it opened at the queue's green commit.
pub(crate) struct AgentRun {
    pub(crate) task: EntityId,
    pub(crate) binding: RepoRunBinding,
    /// The read lane of the agent's own credential, as the binding reads.
    pub(crate) reader: ScopedReadActorKey,
    pub(crate) actor: WriteActor,
    pub(crate) work: EntityId,
    pub(crate) grant: EntityId,
}

/// The run the host seals for a claimed try, read on the agent's own
/// credential, with the work it opens at the queue's green commit.
pub(crate) fn agent_run(
    vault: &Vault,
    slip: &VerifiedSlip,
    leased: (EntityId, WriteActor, AttemptRecord),
    repo: EntityId,
    grant: EntityId,
) -> TestResult<AgentRun> {
    let RunBinding {
        task,
        binding,
        reader,
        actor,
    } = bind_run(vault, slip, leased)?;
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
