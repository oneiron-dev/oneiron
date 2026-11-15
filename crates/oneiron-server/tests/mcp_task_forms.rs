#![cfg(oneiron_test_support)]
//! L1-03 PR 3 (canon ARCH-0028 `#mcp-tasks`, owner ruling ONEIRON-MCP-TASKS =
//! AB; PLAN-L1-03 D12): the form questions of an MCP task over a
//! saved-workflow run.
//!
//! The owner dispatches a one-step saved workflow as a task; the step's agent
//! asks the owner questions, each with two options.
//! - A poll that declares form elicitation answers `input_required` with one
//!   form: one property per open question, named by its ask and revision,
//!   each a choice among the question's options and never free text.
//! - An accepted form answers each ask with the owner's word, as evidence:
//!   no gate decision is minted, and the next poll works again.
//! - A declined form voids the owner's seat on each ask; the asks go on to
//!   settle by their own rules, and the form is gone.
//! - A cancelled form stops the run, as `tasks/cancel` does.
//! - A changed question set is a new form under a new key, and a response
//!   under the old key answers nothing.
//! - A step parked on a verb hook's ask waits on an approval: never a form.
//!   A question asked beside it is, and the status line names both.
//! - A poll that does not declare form elicitation sees `working` and the
//!   count.
//! - An ask the agent raised before the run began is not the run's, and a
//!   question that offers no option to choose is never a form's.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test mcp_task_forms`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use oneiron::agent_def::workflow::WorkflowDefinition;
use oneiron::agent_dispatch::AgentDispatcher;
use oneiron::attempt_queue::AttemptId;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskHandle, TaskAskOption, TaskAskOptionId, TaskAskQuestion, TaskAskSpec,
    TaskAskStatus, TaskAskTarget,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::verb_hook_ask::HookAsk;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION;
use oneiron_server::test_doors::workflow_park::{claim_step, park_step};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
const TOOL_FIRST: &str = "/mcp/tool-first";
const TASKS: &str = "io.modelcontextprotocol/tasks";
const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
/// The options every question of the fixture offers.
const OPTIONS: [&str; 2] = ["shipped", "held"];
/// The `self.use` calls of the step's round answered before the one the
/// verb hook asks about.
const ANSWERED_USES: u64 = 2;

/// What a poll declares of its client: the Tasks extension always, and the
/// elicitation it can show.
#[derive(Clone, Copy)]
enum Elicitation {
    /// `elicitation: {"form": {}}`.
    Form,
    /// `elicitation: {}`: a bare declaration means form.
    Bare,
    /// `elicitation: {"url": {}}`: URL mode only, no form.
    UrlOnly,
    /// No elicitation declared.
    None,
}

/// A rooted vault behind the MCP gateway; its owner; the agent that runs the
/// owner's one-step saved workflow and asks the owner questions about a
/// TURN, under its own Auto ceiling.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    agent: EntityId,
    workflow: EntityId,
    question: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let agent = saved_agent(&vault, "forms.asker")?;
        // The agent asks under its own Auto ceiling; the owner and the agent
        // read the vault's records, so the ask's census binds its TURN for
        // both. The shipped rows stay.
        let view = policy_manifests_as_owner(
            &vault,
            &owner_proof,
            &PolicyManifestRead { manifest_ref: None },
        )?;
        let default = view
            .manifests
            .iter()
            .find(|entry| entry.manifest_ref == view.default_manifest_ref)
            .ok_or("default policy manifest missing")?;
        let mut manifest = default.manifest.clone();
        manifest.actor_ceilings.push(ActorCeiling {
            actor_class: "agent".into(),
            actor_ref: Some(agent.to_hex()),
            ceiling: PolicyCeiling::Auto,
        });
        let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
        for actor in [owner, agent] {
            rows.push(PolicyScopedGrantRow {
                // Bare census keys carry no actor class.
                actor_class: None,
                actor_ref: Some(actor.to_hex()),
                effector: "core:read".into(),
                scope: Scope::top(),
                selectors: None,
                budget: None,
                receipt_required: false,
            });
        }
        manifest.scoped_grants = Some(rows);
        put_policy_manifest_as_owner(
            &vault,
            &owner_proof,
            PolicyManifestPut {
                manifest_ref: Some(default.manifest_ref.clone()),
                expected_body_hash: Some(default.body_hash.clone()),
                manifest,
            },
        )?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let question = EntityId::now();
        let now = vault.now_recorded_at();
        vault.put_entity(
            &question,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))?,
        )?;
        let workflow = EntityId::now();
        vault.save_workflow(
            &workflow,
            &WorkflowDefinition::new("mcp task forms", vec![agent])?,
            2,
        )?;
        let app = build_app(Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("mcp-task-forms".into()),
                ..Default::default()
            },
        )?));
        Ok(Self {
            app,
            vault,
            issuer,
            root,
            owner,
            owner_proof,
            agent,
            workflow,
            question,
            _dir: dir,
        })
    }

    /// One JSON-RPC request to the tool-first endpoint as the owner, under
    /// the root slip and a fresh holder proof: the parsed reply.
    async fn rpc(&self, method: &str, params: Value) -> TestResult<Value> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self.issuer.binding_proof(&self.root, &challenge)?;
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::post(TOOL_FIRST)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", MCP_PROTOCOL_VERSION)
            .header("authorization", format!("Bearer {}", self.root.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .body(Body::from(
                json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                    .to_string(),
            ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8_lossy(&bytes);
        let reply: Value =
            serde_json::from_str(&body).unwrap_or_else(|_| Value::String(body.into_owned()));
        assert_eq!(status, 200, "{reply}");
        Ok(reply)
    }

    /// The owner's declared `vault.workflows.dispatch`: the task's id.
    async fn task(&self, intent_key: &str) -> TestResult<String> {
        let reply = self
            .rpc(
                "tools/call",
                json!({
                    "name": "vault.workflows.dispatch",
                    "arguments": verb_arguments(json!({
                        "workflow_ref": self.workflow.to_hex(),
                        "intent_key": intent_key,
                        "briefing": "Ship the release notes.",
                    })),
                    "_meta": declaration(Elicitation::None),
                }),
            )
            .await?;
        Ok(reply["result"]["taskId"]
            .as_str()
            .ok_or_else(|| format!("a declared dispatch answers a task: {reply}"))?
            .to_owned())
    }

    /// `tasks/get` on `task_id`, declaring `elicitation`: its result.
    async fn get(&self, task_id: &str, elicitation: Elicitation) -> TestResult<Value> {
        let reply = self
            .rpc(
                "tasks/get",
                json!({ "taskId": task_id, "_meta": declaration(elicitation) }),
            )
            .await?;
        Ok(reply
            .get("result")
            .cloned()
            .ok_or_else(|| format!("tasks/get answers a task: {reply}"))?)
    }

    /// `tasks/update` on `task_id` with `response` under the form key `key`:
    /// its result.
    async fn update(&self, task_id: &str, key: &str, response: Value) -> TestResult<Value> {
        let reply = self
            .rpc(
                "tasks/update",
                json!({
                    "taskId": task_id,
                    "inputResponses": { key: response },
                    "_meta": declaration(Elicitation::Form),
                }),
            )
            .await?;
        Ok(reply
            .get("result")
            .cloned()
            .ok_or_else(|| format!("tasks/update answers: {reply}"))?)
    }

    /// The step's agent asks the owner one question about the TURN under
    /// `intent_key`, at `revision`, with the two options.
    fn ask(&self, intent_key: &str, label: &str, revision: u64) -> TestResult<TaskAskHandle> {
        self.ask_offering(intent_key, label, revision, &OPTIONS)
    }

    /// The step's agent asks the owner one question about the TURN under
    /// `intent_key`, at `revision`, offering `options`.
    fn ask_offering(
        &self,
        intent_key: &str,
        label: &str,
        revision: u64,
        options: &[&str],
    ) -> TestResult<TaskAskHandle> {
        let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(self.question));
        what.revision = revision;
        what.label = Some(label.to_owned());
        for &option in options {
            what.options
                .insert(TaskAskOptionId::new(option)?, TaskAskOption::new(option));
        }
        let mut spec = TaskAskSpec::shorthand(
            Some(TaskAskTarget::People(BTreeSet::from([self.owner]))),
            what,
            Some(self.vault.now_recorded_at() + 3600),
            Default::default(),
        );
        spec.intent_key = intent_key.to_owned();
        Ok(self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .tasks_ask(&spec)?
            .handle)
    }

    /// An ask's status, as its asker reads it.
    fn status(&self, ask: TaskAskHandle) -> TestResult<TaskAskStatus> {
        Ok(self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .tasks_ask_status(ask)?)
    }

    /// The seats voided on an ask, as its asker reads them.
    fn voided(&self, ask: TaskAskHandle) -> TestResult<Vec<EntityId>> {
        Ok(self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .tasks_ask_option_link_voids(ask)?)
    }

    /// The one open run's root.
    fn open_root(&self) -> TestResult<AttemptId> {
        let roots = AgentDispatcher::new(&self.vault).open_workflow_roots()?;
        let [root] = roots[..] else {
            return Err(format!("expected one open run, found {}", roots.len()).into());
        };
        Ok(root)
    }
}

/// A custom agent definition the pump can dispatch.
fn saved_agent(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or("the default agent is seeded")?;
    definition.logical_id = None;
    definition.agent_id = format!("test.{name}");
    definition.instructions = Some("Ask before shipping.".to_owned());
    definition.skills.clear();
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

/// A generated verb's tool-first arguments over its typed `input`.
fn verb_arguments(input: Value) -> Value {
    json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "consent": {
            "policy_ref": "policy:agent-session",
            "purpose": "run the owner's saved workflow",
        },
        "arguments": { "spec": input },
    })
}

/// A request's `_meta`: the Tasks extension and `elicitation`.
fn declaration(elicitation: Elicitation) -> Value {
    let mut capabilities = json!({ "extensions": { TASKS: {} } });
    let declared = match elicitation {
        Elicitation::Form => Some(json!({ "form": {} })),
        Elicitation::Bare => Some(json!({})),
        Elicitation::UrlOnly => Some(json!({ "url": {} })),
        Elicitation::None => None,
    };
    if let Some(declared) = declared {
        capabilities["elicitation"] = declared;
    }
    json!({ CLIENT_CAPABILITIES: capabilities })
}

/// A question's form property: its ask and revision.
fn property(ask: TaskAskHandle, revision: u64) -> String {
    format!("{}-r{revision}", ask.group_ref.to_hex())
}

/// A task's one form: its key and its schema's properties.
fn form(task: &Value) -> TestResult<(String, Map<String, Value>)> {
    let requests = task["inputRequests"]
        .as_object()
        .ok_or_else(|| format!("the task carries inputRequests: {task}"))?;
    let [(key, request)] = requests.iter().collect::<Vec<_>>()[..] else {
        return Err(format!("one form per round: {task}").into());
    };
    assert_eq!(request["method"], "elicitation/create", "{task}");
    assert_eq!(request["params"]["mode"], "form", "{task}");
    assert_eq!(
        request["params"]["requestedSchema"]["type"], "object",
        "{task}"
    );
    let properties = request["params"]["requestedSchema"]["properties"]
        .as_object()
        .ok_or_else(|| format!("the form has properties: {task}"))?
        .clone();
    Ok((key.clone(), properties))
}

/// `ask`'s word, when it settled on the owner's word for `option`.
fn settled_on(status: &TaskAskStatus, owner: EntityId, option: &str) -> bool {
    let TaskAskStatus::Settled(result) = status else {
        return false;
    };
    result.picked.as_ref().map(TaskAskOptionId::as_str) == Some(option)
        && result.evidence.iter().any(|evidence| {
            evidence.person_ref == owner
                && evidence.word.option.as_ref().map(TaskAskOptionId::as_str) == Some(option)
        })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs `test` as the server's binary runs its app, on the engine's stack.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn open_asks_make_the_task_input_required_with_one_form() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let task = fixture.task("forms-open").await?;
        let first = fixture.ask("forms-open-a", "Ship the notes?", 1)?;
        let second = fixture.ask("forms-open-b", "Tag the release?", 1)?;

        let polled = fixture.get(&task, Elicitation::Form).await?;
        assert_eq!(polled["status"], "input_required", "{polled}");
        assert_eq!(
            polled["statusMessage"], "waiting on 2 questions",
            "{polled}"
        );
        let (key, properties) = form(&polled)?;
        assert!(key.starts_with("form-"), "{key}");
        let names: BTreeSet<_> = properties.keys().cloned().collect();
        assert_eq!(
            names,
            BTreeSet::from([property(first, 1), property(second, 1)]),
            "one property per open question, named by its ask and revision"
        );
        for (name, schema) in &properties {
            assert_eq!(schema["type"], "string", "{name}: {schema}");
            let choices = schema["oneOf"]
                .as_array()
                .ok_or_else(|| format!("every property is a choice, never free text: {schema}"))?;
            let offered: BTreeSet<_> = choices
                .iter()
                .map(|choice| choice["const"].as_str().unwrap_or_default())
                .collect();
            assert_eq!(offered, BTreeSet::from(OPTIONS), "{name}: {schema}");
            assert!(
                choices.iter().all(|choice| choice["title"].is_string()),
                "{schema}"
            );
        }
        assert_eq!(properties[&property(first, 1)]["title"], "Ship the notes?");

        // A bare `elicitation: {}` declares form too.
        let bare = fixture.get(&task, Elicitation::Bare).await?;
        assert_eq!(bare["status"], "input_required", "{bare}");
        assert_eq!(form(&bare)?.0, key, "the same questions, the same form");
        Ok(())
    })
}

#[test]
fn an_accepted_form_answers_each_ask_as_evidence_not_approval() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let task = fixture.task("forms-accept").await?;
        let first = fixture.ask("forms-accept-a", "Ship the notes?", 1)?;
        let second = fixture.ask("forms-accept-b", "Tag the release?", 1)?;
        let (key, _) = form(&fixture.get(&task, Elicitation::Form).await?)?;
        let gate_decisions = fixture.vault.gate_decisions(1_000)?.len();

        let updated = fixture
            .update(
                &task,
                &key,
                json!({
                    "action": "accept",
                    "content": {
                        (property(first, 1)): "shipped",
                        (property(second, 1)): "held",
                    },
                }),
            )
            .await?;
        assert_eq!(updated["resultType"], "complete", "{updated}");

        let first_status = fixture.status(first)?;
        assert!(
            settled_on(&first_status, fixture.owner, "shipped"),
            "the first ask holds the owner's word: {first_status:?}"
        );
        let second_status = fixture.status(second)?;
        assert!(
            settled_on(&second_status, fixture.owner, "held"),
            "the second ask holds the owner's word: {second_status:?}"
        );
        assert_eq!(
            fixture.vault.gate_decisions(1_000)?.len(),
            gate_decisions,
            "a form answer is evidence, never an approval: no gate decision is minted"
        );

        let polled = fixture.get(&task, Elicitation::Form).await?;
        assert_eq!(polled["status"], "working", "{polled}");
        assert!(polled.get("inputRequests").is_none(), "{polled}");
        Ok(())
    })
}

#[test]
fn a_declined_form_voids_the_callers_seats_and_the_run_goes_on() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let task = fixture.task("forms-decline").await?;
        let first = fixture.ask("forms-decline-a", "Ship the notes?", 1)?;
        let second = fixture.ask("forms-decline-b", "Tag the release?", 1)?;
        let (key, _) = form(&fixture.get(&task, Elicitation::Form).await?)?;

        let updated = fixture
            .update(&task, &key, json!({ "action": "decline" }))
            .await?;
        assert_eq!(updated["resultType"], "complete", "{updated}");

        for ask in [first, second] {
            assert_eq!(
                fixture.voided(ask)?,
                vec![fixture.owner],
                "the owner's own seat is void"
            );
            let status = fixture.status(ask)?;
            assert!(
                matches!(status, TaskAskStatus::Pending { .. }),
                "the server never fills an answer: the ask settles by its own rules: {status:?}"
            );
        }
        let polled = fixture.get(&task, Elicitation::Form).await?;
        assert_eq!(polled["status"], "working", "the run goes on: {polled}");
        assert_eq!(polled["statusMessage"], "step 1 of 1", "{polled}");
        assert!(
            polled.get("inputRequests").is_none(),
            "no form for the declined asks again: {polled}"
        );
        Ok(())
    })
}

#[test]
fn a_cancelled_form_stops_the_run() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let task = fixture.task("forms-cancel").await?;
        let ask = fixture.ask("forms-cancel-a", "Ship the notes?", 1)?;
        let (key, _) = form(&fixture.get(&task, Elicitation::Form).await?)?;

        let updated = fixture
            .update(&task, &key, json!({ "action": "cancel" }))
            .await?;
        assert_eq!(updated["resultType"], "complete", "{updated}");

        let polled = fixture.get(&task, Elicitation::Form).await?;
        assert_eq!(polled["status"], "cancelled", "{polled}");
        assert!(
            matches!(fixture.status(ask)?, TaskAskStatus::Pending { .. }),
            "a cancel answers no question"
        );
        Ok(())
    })
}

#[test]
fn a_form_key_from_an_old_round_is_ignored() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let task = fixture.task("forms-round").await?;
        let first = fixture.ask("forms-round-a", "Ship the notes?", 1)?;
        let second = fixture.ask("forms-round-b", "Tag the release?", 1)?;
        let (old_key, _) = form(&fixture.get(&task, Elicitation::Form).await?)?;

        // The agent asks the first question again, changed: a new ask at
        // revision 2.
        let revised = fixture.ask("forms-round-a-2", "Ship the notes today?", 2)?;
        let (new_key, properties) = form(&fixture.get(&task, Elicitation::Form).await?)?;
        assert_ne!(new_key, old_key, "a changed question set is a new form");
        assert!(
            properties.contains_key(&property(revised, 2)),
            "{properties:?}"
        );

        let updated = fixture
            .update(
                &task,
                &old_key,
                json!({
                    "action": "accept",
                    "content": {
                        (property(first, 1)): "shipped",
                        (property(second, 1)): "held",
                        (property(revised, 2)): "shipped",
                    },
                }),
            )
            .await?;
        assert_eq!(updated["resultType"], "complete", "{updated}");
        for ask in [first, second, revised] {
            let status = fixture.status(ask)?;
            assert!(
                matches!(status, TaskAskStatus::Pending { .. }),
                "a response under an old key answers nothing: {status:?}"
            );
        }
        let polled = fixture.get(&task, Elicitation::Form).await?;
        assert_eq!(form(&polled)?.0, new_key, "{polled}");
        Ok(())
    })
}

#[test]
fn an_approval_wait_is_never_a_form() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let hook = HookAsk::on_verb(
            &fixture.vault,
            fixture.owner,
            &fixture.owner_proof,
            "self.use",
        )?;
        let task = fixture.task("forms-approval").await?;
        let root = fixture.open_root()?;
        let now = fixture.vault.now_recorded_at();
        let first = claim_step(&fixture.vault, root, now, ANSWERED_USES)?
            .ok_or("the step's first try runs")?;
        let approval = hook.ask(&fixture.vault, &first.actor, first.next_use)?;
        park_step(&fixture.vault, &first, approval, now)?;

        let polled = fixture.get(&task, Elicitation::Form).await?;
        assert_eq!(polled["status"], "working", "{polled}");
        assert_eq!(
            polled["statusMessage"], "waiting on an approval",
            "{polled}"
        );
        assert!(
            polled.get("inputRequests").is_none(),
            "an approval is never a form question: {polled}"
        );
        assert!(
            !polled.to_string().contains(&approval.to_hex()),
            "the hook's ask is named nowhere in the task: {polled}"
        );

        // A question the agent asks beside it is a form's; the approval still
        // is not, and the status line names both.
        let question = fixture.ask("forms-approval-a", "Ship the notes?", 1)?;
        let polled = fixture.get(&task, Elicitation::Form).await?;
        assert_eq!(polled["status"], "input_required", "{polled}");
        assert_eq!(
            polled["statusMessage"], "waiting on 1 question and an approval",
            "{polled}"
        );
        let (_, properties) = form(&polled)?;
        assert_eq!(
            properties.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([property(question, 1)]),
            "{polled}"
        );
        assert!(
            !polled.to_string().contains(&approval.to_hex()),
            "the hook's ask is named nowhere in the task: {polled}"
        );
        Ok(())
    })
}

#[test]
fn a_client_without_form_elicitation_sees_working() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let task = fixture.task("forms-plain").await?;
        fixture.ask("forms-plain-a", "Ship the notes?", 1)?;
        fixture.ask("forms-plain-b", "Tag the release?", 1)?;

        for elicitation in [Elicitation::None, Elicitation::UrlOnly] {
            let polled = fixture.get(&task, elicitation).await?;
            assert_eq!(polled["status"], "working", "{polled}");
            assert_eq!(
                polled["statusMessage"], "waiting on 2 questions",
                "{polled}"
            );
            assert!(polled.get("inputRequests").is_none(), "{polled}");
        }
        Ok(())
    })
}

#[test]
fn an_ask_from_before_the_run_or_with_no_choice_is_never_its_question() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let earlier = fixture.ask("forms-scope-earlier", "Ship last week's notes?", 1)?;
        // The run begins a recorded second after the agent's earlier ask.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let task = fixture.task("forms-scope").await?;
        let choiceless = fixture.ask_offering("forms-scope-open", "Anything else?", 1, &[])?;
        let plain = fixture.ask("forms-scope-plain", "Tag the release?", 1)?;

        let polled = fixture.get(&task, Elicitation::Form).await?;
        assert_eq!(polled["status"], "input_required", "{polled}");
        assert_eq!(polled["statusMessage"], "waiting on 1 question", "{polled}");
        let (_, properties) = form(&polled)?;
        assert!(
            !properties.contains_key(&property(earlier, 1)),
            "an ask raised before the run began is not the run's: {polled}"
        );
        assert!(
            !properties.contains_key(&property(choiceless, 1)),
            "a question with no option to choose is never a form's: {polled}"
        );
        assert_eq!(
            properties.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([property(plain, 1)]),
            "{polled}"
        );
        Ok(())
    })
}
