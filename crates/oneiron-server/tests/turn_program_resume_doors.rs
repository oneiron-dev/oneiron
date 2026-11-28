//! Public facade doors for resuming paused turn programs on a copy beside its source.
//! The owner can preview and resume a selection. An agent and a second person cannot,
//! and the agent's paused-program list shows only its own arming.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::claim::ScopedReadActorKey;
use oneiron::dreamer_runner::{
    ArmTurnProgram, PausedTurnProgramsView, ProgramTrigger, ResumePausedTurnProgramsPreview,
    ResumedTurnPrograms,
};
use oneiron::federation::ScopeAxis;
use oneiron::feeds::{FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest};
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::store::ports::ManualClock;
use oneiron::test_support::restore_tempdir;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::build_app;
use oneiron_server::config::{BackupConfig, SyncServerConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::owner_backup::attach_owner_host;
use serde_json::{Value, json};
use tower::ServiceExt;

const PAUSED: &str = "vault.turn_programs.paused";
const PREVIEW: &str = "vault.owner_confirm.preview";
const RESUME: &str = "vault.turn_programs.resume";
const RESTORED_AT: u64 = 1_800_000_000;
const SNAPSHOT_AT: u64 = RESTORED_AT - 120;
const A_DUE: u64 = RESTORED_AT - 60;
const B_DUE: u64 = RESTORED_AT + 60;
const REPEAT_SECS: u64 = 60;
const QUIET_SECS: u64 = 600;

/// An active callable SKILL, enough to pin an arming without running code.
fn active_callable_skill(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let files: [(&str, &[u8]); 2] = [
        (
            "SKILL.md",
            concat!(
                "---\nname: fixture.callable\ndescription: Increment a number\nversion: 1\n",
                "role: callable\ncall:\n  reference: scripts/call.js\n",
                "  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n",
                "---\nAn executable fixture.\n",
            )
            .as_bytes(),
        ),
        (
            "scripts/call.js",
            b"finish(JSON.stringify({result:skillArgs.value + 1}));",
        ),
    ];
    let hash = canonical_skill_tree_hash(files).expect("hash the fixture tree");
    let mut record = SkillRecord::new(
        "fixture.callable",
        "Increment a number",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: "scripts/call.js".into(),
            arguments: json!({"value": "integer"}),
            returns: json!({"result": "integer"}),
        }),
    )
    .with_content_hash(hash);
    vault
        .put_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)
        .expect("put the callable candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &record, TimeRange { start: 2, end: 2 }, 2)
        .expect("activate the callable");
    id
}

/// Arms a program through the actor's public door and returns its registration.
fn arm(memory: &Memory<'_>, skill: EntityId, trigger: ProgramTrigger) -> EntityId {
    memory
        .arm_turn_program(&ArmTurnProgram {
            skill,
            executor: "fixture.executor@1".into(),
            args: json!({"value": 41}),
            conversation: None,
            trigger,
            expected: None,
            project: None,
        })
        .expect("arm the program")
        .registration
}

/// Writes a PERSON for a real human or agent credential, and an entry the feed can see.
fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("write a person");
    id
}

/// Who calls a facade door, on its own holder proof.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// The self-hosted vault's owner on the host root slip.
    Owner,
    /// A second live PERSON on a human slip.
    Person,
    /// A live PERSON on an agent slip, whose own timer is on the copy.
    Agent,
}

/// A holder's own slip and its encoded token for an in-process request.
struct Credential {
    slip: CapabilitySlip,
    token: String,
}

/// A paused copy, served with credentials minted or verified on that copy.
struct Served {
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner: Credential,
    person: Credential,
    agent: Credential,
    owner_actor: EntityId,
    agent_actor: EntityId,
    a: EntityId,
    b: EntityId,
    feed: EntityId,
    idle: EntityId,
    agent_timer: EntityId,
    _dir: tempfile::TempDir,
}

/// The fixture holder key whose private half signs each person or agent request anew.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x6D; 32])
}

/// Mints an unattenuated-on-records read/write slip of the named class, not owner-grade.
fn credential(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    actor: EntityId,
    class: &str,
) -> Credential {
    let mut claims = root.claims.clone();
    let id = EntityId::now();
    claims.slip_id[..16].copy_from_slice(id.as_bytes());
    claims.slip_id[16..].copy_from_slice(id.as_bytes());
    claims.parent_id = None;
    claims.holder_ref = actor.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("mint a credential on the copy");
    let token = slip.to_token().expect("encode the credential");
    Credential { slip, token }
}

/// Serves a side restore of four owner armings and an agent timer; its original host root is
/// recovered into the copy's own installed keystore before the server tries to load it.
fn served() -> Served {
    let dir = restore_tempdir();
    let clock = ManualClock::new(SNAPSHOT_AT);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let source = Vault::open_owned(dir.path().join("source"), config.clone())
        .expect("open the source under its writer lease");
    source.install_device_keystore(Arc::new(MemoryKeystore::new()));
    source
        .prepare_install_signing()
        .expect("source install signing");
    let source_issuer = Arc::new(
        source
            .bootstrap_host_slip_issuer()
            .expect("source host issuer"),
    );
    source
        .ensure_host_root_slip(&source_issuer)
        .expect("root the source");
    source
        .provision_engine_machine_identities(&source_issuer)
        .expect("provision the engine machines");
    let owner_actor = source
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    source
        .ensure_serving_install_profile(&source_issuer, MachineRole::Unanswered)
        .expect("the source's serving profile");
    source.hold_checkpoint_root_signer(source_issuer.clone());
    source.ensure_vault_key().expect("mint the vault data key");

    let memory = source.memory(owner_actor, EdgeActorClass::Human);
    let skill = active_callable_skill(&source);
    let lane = source.scoped_read(
        ScopedReadActorKey::with_actor_class(owner_actor.to_hex(), "human")
            .expect("owner lane key"),
    );
    let subscription = source
        .feed_subscribe(
            &lane,
            &FeedSubscribeRequest {
                selector: FeedSelector {
                    sources: vec![FeedSource::Changes],
                    kinds: Vec::new(),
                    entity_types: Vec::new(),
                    predicates: Vec::new(),
                },
                start: FeedStart::Head,
            },
        )
        .expect("subscribe at the feed head")
        .subscription;
    let a = arm(
        &memory,
        skill,
        ProgramTrigger::Timer {
            first_at: A_DUE,
            every_secs: 0,
        },
    );
    let b = arm(
        &memory,
        skill,
        ProgramTrigger::Timer {
            first_at: B_DUE,
            every_secs: REPEAT_SECS,
        },
    );
    let feed = arm(&memory, skill, ProgramTrigger::Feed { subscription });
    let idle = arm(
        &memory,
        skill,
        ProgramTrigger::Idle {
            quiet_secs: QUIET_SECS,
        },
    );
    let second_person = person(&source);
    let agent_actor = person(&source);
    let agent_timer = arm(
        &source.memory(agent_actor, EdgeActorClass::Agent),
        skill,
        ProgramTrigger::Timer {
            first_at: B_DUE,
            every_secs: 0,
        },
    );

    let image = dir.path().join("image");
    let key = source.checkpoint_key().expect("derive the checkpoint key");
    source
        .snapshot_checkpoint(&image, SNAPSHOT_AT)
        .expect("take the checkpoint");
    clock.set(RESTORED_AT);
    let copy_path = dir.path().join("copy");
    let (copy, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &copy_path,
        config,
        &source.side_restore_source().expect("the restore's source"),
        RESTORED_AT,
    )
    .expect("restore beside the source");
    copy.install_device_keystore(Arc::new(MemoryKeystore::new()));
    copy.prepare_install_signing()
        .expect("copy install signing");
    copy.prepare_host_issuer_custody_logged();
    let issuer = copy
        .bootstrap_host_slip_issuer()
        .expect("load the restored host issuer");
    assert_eq!(issuer.public_key(), source_issuer.public_key());
    let vault = Arc::new(copy);
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("turn-program-resume-doors".into()),
            ..Default::default()
        },
    )
    .expect("create the server on the copy");
    let server = attach_owner_host(server, &copy_path, BackupConfig::default());
    let slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("the copy's host root slip");
    let token = slip.to_token().expect("root slip token");
    let person = credential(&vault, &issuer, &slip, second_person, "human");
    let agent = credential(&vault, &issuer, &slip, agent_actor, "agent");

    Served {
        vault,
        app: build_app(Arc::new(server)),
        issuer,
        owner: Credential { slip, token },
        person,
        agent,
        owner_actor,
        agent_actor,
        a,
        b,
        feed,
        idle,
        agent_timer,
        _dir: dir,
    }
}

impl Served {
    /// Returns the slip and token belonging to this caller alone.
    fn credential(&self, caller: Caller) -> &Credential {
        match caller {
            Caller::Owner => &self.owner,
            Caller::Person => &self.person,
            Caller::Agent => &self.agent,
        }
    }

    /// Signs a fresh binding for this request: the host root or the holder's own key.
    fn binding(&self, caller: Caller) -> String {
        let timestamp = self.vault.now_recorded_at();
        let slip = &self.credential(caller).slip;
        if matches!(caller, Caller::Owner) {
            let nonce = EntityId::now().to_hex();
            let challenge = format!("oneiron-request:{timestamp}:{nonce}");
            let signature: String = self
                .issuer
                .binding_proof(slip, challenge.as_bytes())
                .expect("owner holder proof")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
        } else {
            holder_proof(slip, &holder_key(), timestamp)
                .expect("holder proof")
                .to_string()
        }
    }

    /// Sends a request through the real in-process app and reads its status and JSON body.
    async fn send(
        &self,
        caller: Caller,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let token = &self.credential(caller).token;
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", self.binding(caller));
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("response body");
        let body = serde_json::from_slice(&bytes).expect("JSON response");
        (status, body)
    }

    /// Posts to the named facade door with the selected caller's credential.
    async fn post(&self, caller: Caller, verb: &str, input: Value) -> (StatusCode, Value) {
        self.send(
            caller,
            Method::POST,
            &format!("/v1/core/facade/{verb}"),
            Some(input),
        )
        .await
    }

    /// Requires a successful facade call and returns its response body.
    async fn ok(&self, caller: Caller, verb: &str, input: Value) -> Value {
        let (status, body) = self.post(caller, verb, input).await;
        assert_eq!(status, StatusCode::OK, "{caller:?} at {verb}: {body}");
        body
    }

    /// Reads exactly the paused page the caller's credential can see.
    async fn paused(&self, caller: Caller) -> PausedTurnProgramsView {
        serde_json::from_value(self.ok(caller, PAUSED, json!({})).await)
            .expect("a paused-program page")
    }

    /// Reads the count independently through the owner status route.
    async fn status_count(&self) -> u64 {
        let (status, body) = self
            .send(Caller::Owner, Method::GET, "/v1/owner/status", None)
            .await;
        assert_eq!(status, StatusCode::OK, "owner status: {body}");
        body["paused_turn_programs"]
            .as_u64()
            .expect("status counts paused programs")
    }
}

/// Checks for the door's specific refusal, not a bad token, scope, or input.
fn assert_forbidden(status: StatusCode, body: &Value, caller: Caller, message: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{caller:?}: {body}");
    assert_eq!(body["error"]["code"], "FORBIDDEN", "{caller:?}: {body}");
    assert_eq!(body["error"]["message"], message, "{caller:?}: {body}");
}

/// An agent and a second person cannot act on an owner's confirm or obtain their own sheet.
#[test]
fn resume_and_its_preview_refuse_an_agent_and_a_second_person() {
    run_on_engine_stack("resume-owner-refusals", || async {
        let s = served();
        let preview_input = json!({"verb": RESUME, "input": {"registrations": [s.a]}});
        let preview = s.ok(Caller::Owner, PREVIEW, preview_input.clone()).await;
        let confirm = preview["confirm"]
            .as_str()
            .expect("the owner's live confirm");
        let resume_input = json!({"registrations": [s.a], "confirm": confirm});
        assert_eq!(
            s.vault.paused_turn_program_count().expect("initial count"),
            5
        );

        for caller in [Caller::Agent, Caller::Person] {
            let (status, body) = s.post(caller, RESUME, resume_input.clone()).await;
            assert_forbidden(
                status,
                &body,
                caller,
                "vault.turn_programs.resume is the vault owner's",
            );
            assert_eq!(
                s.vault
                    .paused_turn_program_count()
                    .expect("count after resume"),
                5
            );

            let (status, body) = s.post(caller, PREVIEW, preview_input.clone()).await;
            let message = match caller {
                Caller::Agent => "vault.owner_confirm.preview is a live person's own act",
                _ => "vault.owner_confirm.preview is the vault owner's",
            };
            assert_forbidden(status, &body, caller, message);
            assert_eq!(
                s.vault
                    .paused_turn_program_count()
                    .expect("count after preview"),
                5
            );
        }
    });
}

/// The owner confirms two of five paused programs over the facade, and both reads see the drop.
#[test]
fn owner_status_and_paused_list_both_follow_a_confirmed_selection() {
    run_on_engine_stack("resume-owner-round-trip", || async {
        let s = served();
        let before = s.paused(Caller::Owner).await;
        let all = BTreeSet::from([s.a, s.b, s.feed, s.idle, s.agent_timer]);
        assert_eq!(before.paused, 5);
        assert_eq!(before.programs.len(), 5);
        assert_eq!(
            before
                .programs
                .iter()
                .map(|row| row.registration)
                .collect::<BTreeSet<_>>(),
            all,
        );
        assert_eq!(s.status_count().await, before.paused);

        let ids = [s.a, s.feed];
        let preview = s
            .ok(
                Caller::Owner,
                PREVIEW,
                json!({"verb": RESUME, "input": {"registrations": ids}}),
            )
            .await;
        let sheet: ResumePausedTurnProgramsPreview =
            serde_json::from_value(preview["takes"].clone()).expect("the resume sheet");
        assert_eq!(sheet.programs.len(), 2);
        let chosen: Vec<_> = before
            .programs
            .iter()
            .filter(|row| ids.contains(&row.registration))
            .collect();
        for (item, row) in sheet.programs.iter().zip(chosen) {
            assert_eq!(&item.program, row);
            assert_eq!(item.program.actor, s.owner_actor);
            assert_eq!(item.fires_at_once, item.program.registration == s.a);
        }
        let confirm = preview["confirm"].as_str().expect("the owner's confirm");
        let value = s
            .ok(
                Caller::Owner,
                RESUME,
                json!({"registrations": ids, "confirm": confirm}),
            )
            .await;
        let answer: ResumedTurnPrograms = serde_json::from_value(value).expect("resumed");
        assert_eq!(answer.resumed, sheet.programs);
        assert_eq!(answer.still_paused, 3);

        let after = s.paused(Caller::Owner).await;
        assert_eq!(after.paused, answer.still_paused);
        assert_eq!(after.programs.len(), 3);
        let left: Vec<_> = before
            .programs
            .into_iter()
            .filter(|row| !ids.contains(&row.registration))
            .collect();
        assert_eq!(after.programs, left);
        assert_eq!(s.status_count().await, after.paused);
    });
}

/// An agent sees its own paused timer but none of the four paused programs of the owner.
#[test]
fn an_agent_reads_only_its_own_paused_program() {
    run_on_engine_stack("resume-agent-paused-list", || async {
        let s = served();
        assert_eq!(
            s.vault.paused_turn_program_count().expect("copy's total"),
            5
        );
        let page = s.paused(Caller::Agent).await;
        assert_eq!(page.paused, 1);
        assert_eq!(page.programs.len(), 1);
        let row = &page.programs[0];
        assert_eq!(row.registration, s.agent_timer);
        assert_eq!(row.actor, s.agent_actor);
        assert_eq!(row.actor_class, "agent");
        assert_eq!(row.paused_at, RESTORED_AT);
    });
}
