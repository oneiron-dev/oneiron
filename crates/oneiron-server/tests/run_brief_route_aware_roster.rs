//! A run's PEOPLE roster follows every live code-mode route: only an
//! all-on-device run reads an about line derived from a fact whose world
//! reads on this install alone. Own-server and third-party chat routes,
//! and a third-party browser planner beside local chat, withhold the line.
//! A held brief is rechecked under the routes now, not those at its read.
//!
//! Expected red on main b6d680a03cf: tests 1 and 5 fail at their first
//! `Some(LINE)` assertion because main always reads the run roster off-device.
//! Controls 2-4 should pass on both main and the fixed head; all five should
//! pass on the head.
//!
//! The native chat view is a managed EXL3 row with an absent weights
//! manifest. Its supervisor cannot install or launch anything. A data-only
//! model pack selects that view for chat alone, leaving an optional browser
//! planner on its own configured route. No model request is sent.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! run_brief_route_aware_roster`.
#![cfg(oneiron_test_support)]
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use engine_stack::on_engine_stack;
use oneiron::authority::{
    ActSurface, MachineOwnership, MachineRole, ModelOrder, ReadLocation, SealedCopies, WorldPrivacy,
};
use oneiron::claim::{CallerLocality, ScopedReadActorKey};
use oneiron::federation::Scope;
use oneiron::llm::manifest::ModelRole;
use oneiron::memory::Memory;
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallStatus};
use oneiron::test_doors::derive::{About, Derived, Named, about_facts, commit};
use oneiron::test_doors::steward::{dreamer, owner as owner_proof};
use oneiron::{EdgeActorClass, EntityId, ModelLocality, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::ModelRuntime;
use oneiron_server::test_doors::replay_admission::{
    pin_every_role, route_locality_bound, runtime_keeping_owner_choices, seat_models,
};
use oneiron_server::test_doors::run_brief_people::{run_brief_about_lines, run_brief_fallen_rows};
use oneiron_server::test_doors::supervised_rerank::permit_worker_launch;
use oneiron_server::{config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NAME: &str = "Owen Marsh";
const LINE: &str = "Owen keeps the reading group's lantern list.";

// Model workers are process-wide; one fixture owns their configuration at a time.
static HOST_TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Copy)]
enum Routes {
    OnDevice,
    OwnServer,
    ThirdParty,
    BrowserOffDevice,
}

impl Routes {
    fn has_native_chat(self) -> bool {
        matches!(self, Self::OnDevice | Self::BrowserOffDevice)
    }
}

struct Fixture {
    server: Arc<SyncServer>,
    agent: EntityId,
    person: EntityId,
    claim: EntityId,
    runtime: ModelRuntime,
    _host: AiHost,
    _endpoint: TcpListener,
    _dir: tempfile::TempDir,
}

/// The testkit's owner and invoke pattern, kept local because this server
/// crate does not depend on oneiron-testkit.
fn owner(vault: &Vault) -> Memory<'_> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    vault.memory(owner, EdgeActorClass::Human)
}

fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    oneiron::verbs::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

fn id_at(answer: &Value, pointer: &str) -> EntityId {
    let hex = answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer}: {answer:#}"));
    EntityId::from_hex(hex).expect("the returned entity id")
}

impl Fixture {
    async fn new(routes: Routes) -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        // Server boot roots and profiles the install, retains its root
        // signer and provisions the Dreamer's machine writer.
        let server = SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("run-brief-roster-off-device".into()),
                ..Default::default()
            },
        )?;
        let proof = owner_proof(&vault)?;
        let owner = owner(&vault);
        let machine = vault
            .local_machine()?
            .ok_or("this install has no machine")?
            .id;
        vault.set_machine_role(
            &proof,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )?;

        let world = vault.create_world(
            &proof,
            "Reading group on this install",
            vault.now_recorded_at(),
        )?;
        vault.set_world_privacy_as(
            &proof,
            ActSurface::ThisInstall,
            world,
            WorldPrivacy {
                read: ReadLocation::OneMachine(machine),
                sealed: SealedCopies::Off,
                models: ModelOrder::Inherit,
            },
            None,
        )?;

        let agent = vault.new_entity_id()?;
        call(
            &owner,
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "run-brief-people-reader",
                    "desc": "an agent whose brief reads the people roster",
                    "version": "1",
                },
            }),
        );
        call(
            &owner,
            "vault.disclosure.ceiling.set",
            json!({"connection": format!("agent:{}", agent.to_hex()), "ceiling": "restricted"}),
        );
        // The run uses with_actor_class, with no proof or credential. Give
        // that key a floor, rather than an alternative read Grant.
        let view =
            policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
        let default = view
            .manifests
            .iter()
            .find(|entry| entry.manifest_ref == view.default_manifest_ref)
            .ok_or("default policy manifest missing")?;
        let mut manifest = default.manifest.clone();
        let mut grants = manifest.scoped_grants.clone().unwrap_or_default();
        grants.push(PolicyScopedGrantRow {
            actor_class: Some("agent".into()),
            actor_ref: Some(agent.to_hex()),
            effector: "core:read".into(),
            scope: Scope::top(),
            selectors: None,
            budget: None,
            receipt_required: false,
        });
        manifest.scoped_grants = Some(grants);
        put_policy_manifest_as_owner(
            &vault,
            &proof,
            PolicyManifestPut {
                manifest_ref: Some(default.manifest_ref.clone()),
                expected_body_hash: Some(default.body_hash.clone()),
                manifest,
            },
        )?;

        let evidence = message(&vault, "Owen introduced themself at the reading group")?;
        let created = call(
            &owner,
            "vault.people.create",
            json!({
                "identity": {"name": NAME},
                "identity_evidence_refs": [evidence.to_hex()],
                "occurred_at": vault.now_recorded_at(),
            }),
        );
        let person = id_at(&created, "/person/id_hex");
        let fact = json!({
            "predicate": "project.note",
            "subject_ref": person.to_hex(),
            "value": "Owen keeps the lantern list for the reading group.",
            "confidence": 0.9,
            "source": "user_stated",
            "world_ref": world.to_hex(),
        });
        let remembered = call(&owner, "vault.remember", fact);
        let claim = id_at(&remembered, "/claim/id");

        let dreamer = dreamer(&vault)?;
        let (digest, line_bands) = about_facts(&vault, dreamer, EdgeActorClass::System, person)?;
        assert!(
            !line_bands.is_empty(),
            "FIXTURE: the Dreamer reads the owner's fact about the person."
        );
        let committed = commit(
            &vault,
            dreamer,
            EdgeActorClass::System,
            "run-brief-roster-off-device",
            &[Derived::About(About {
                local: "about",
                person: Named::Stored(person),
                written_from: digest,
                lines: line_bands.iter().map(|band| (*band, LINE)).collect(),
            })],
        )?;
        let [item] = committed.items.as_slice() else {
            panic!("FIXTURE: one about item: {:?}", committed.items);
        };
        assert!(
            item.landed,
            "FIXTURE: the Dreamer's about line lands with these reasons: {:?}.",
            item.reasons
        );
        // Keep the endpoint bound but serve no HTTP or model calls. The
        // native worker fails on its absent manifest before starting a process.
        let endpoint = TcpListener::bind("127.0.0.1:0")?;
        let toml = models_toml(
            routes,
            dir.path(),
            &format!("http://{}", endpoint.local_addr()?),
        );
        let models = ModelsConfig::from_toml(&toml, None)?;
        permit_worker_launch();
        let runtime = runtime_keeping_owner_choices(&toml, vault.clone())?;
        let role = ModelRole::GenerativeReasoner;
        let rungs = seat_models(&runtime, role);
        let [chat] = rungs.as_slice() else {
            panic!("FIXTURE: the chat seat must have exactly one model, found {rungs:?}.");
        };
        if routes.has_native_chat() {
            install_chat_pack(&vault, chat.as_str())?;
        } else {
            let at = match routes {
                Routes::OwnServer => ModelLocality::OwnServer,
                Routes::ThirdParty => ModelLocality::ThirdParty,
                _ => unreachable!(),
            };
            pin_every_role(&vault, chat, at)?;
        }
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let fixture = Self {
            server: Arc::new(server),
            agent,
            person,
            claim,
            runtime,
            _host: host,
            _endpoint: endpoint,
            _dir: dir,
        };
        fixture.assert_owner_sees_the_line();
        assert!(
            fixture.reads(fixture.person, CallerLocality::OffDevice)?
                && fixture.reads(fixture.claim, CallerLocality::OnDevice)?,
            "FIXTURE: the run key reads the PERSON off-device and the fact on-device."
        );
        assert!(
            !fixture.reads(fixture.claim, CallerLocality::OffDevice)?,
            "FIXTURE: the world's read location keeps the fact off-device."
        );
        let at = match routes {
            Routes::OnDevice | Routes::BrowserOffDevice => ModelLocality::OnDevice,
            Routes::OwnServer => ModelLocality::OwnServer,
            Routes::ThirdParty => ModelLocality::ThirdParty,
        };
        fixture.assert_route(role, at, at)?;
        if matches!(routes, Routes::BrowserOffDevice) {
            fixture.assert_route(
                ModelRole::BrowserPlanner,
                ModelLocality::ThirdParty,
                ModelLocality::ThirdParty,
            )?;
        } else {
            assert!(
                fixture.runtime.seat(ModelRole::BrowserPlanner).is_none(),
                "FIXTURE: no rung serves the browser planner."
            );
        }
        Ok(fixture)
    }

    fn reads(&self, id: EntityId, locality: CallerLocality) -> TestResult<bool> {
        let key = ScopedReadActorKey::with_actor_class(
            self.agent.to_hex(),
            EdgeActorClass::Agent.gate_actor_class(),
        )
        .ok_or("the run key did not build")?
        .at(locality);
        Ok(self
            .server
            .vault()
            .scoped_read(key)
            .is_entity_readable(&id)?)
    }

    fn assert_owner_sees_the_line(&self) {
        let owner = owner(self.server.vault());
        let person = self.person.to_hex();
        for page in 0..100_u32 {
            let listed = call(&owner, "vault.people.list", json!({"page": page}));
            let rows = listed["people"]
                .as_array()
                .expect("the owner's roster rows");
            if let Some(row) = rows.iter().find(|row| row["person"] == person.as_str()) {
                assert_eq!(
                    row["name"], NAME,
                    "FIXTURE: the owner reads the person's name."
                );
                assert_eq!(
                    row["about"], LINE,
                    "FIXTURE: the owner's roster shows the Dreamer's line in this row: {row:#}."
                );
                return;
            }
            if listed["more"] == 0 || rows.is_empty() {
                break;
            }
        }
        panic!("FIXTURE: the owner's roster must list the person");
    }

    /// The server has no public runtime accessor. This second runtime is
    /// built from identical TOML over the same vault and live owner choices.
    fn assert_route(
        &self,
        role: ModelRole,
        locality: ModelLocality,
        bound: ModelLocality,
    ) -> TestResult {
        let seat = self
            .runtime
            .seat(role)
            .ok_or("the model role has no seat")?;
        let route = self
            .runtime
            .route_role(self.server.vault(), role, seat)
            .map_err(|error| error.to_string())?;
        assert_eq!(
            route.locality, locality,
            "FIXTURE: the live {role:?} route has the required locality."
        );
        assert_eq!(
            route_locality_bound(&self.runtime, self.server.vault(), role, role)?,
            bound,
            "FIXTURE: the live {role:?} ladder has the required prompt locality bound."
        );
        Ok(())
    }

    fn move_chat_to_cloud(&self) -> TestResult {
        let rungs = seat_models(&self.runtime, ModelRole::Checker);
        let [cloud] = rungs.as_slice() else {
            panic!("FIXTURE: the checker seat must name one cloud model, found {rungs:?}.");
        };
        pin_every_role(self.server.vault(), cloud, ModelLocality::ThirdParty)?;
        self.assert_route(
            ModelRole::GenerativeReasoner,
            ModelLocality::ThirdParty,
            ModelLocality::ThirdParty,
        )
    }

    /// The rows a run brief staged now shows of the PERSON: the PERSON and
    /// the facts of the line its roster picks at the run key's band.
    fn staged_rows(&self) -> TestResult<Vec<EntityId>> {
        let key = ScopedReadActorKey::with_actor_class(
            self.agent.to_hex(),
            EdgeActorClass::Agent.gate_actor_class(),
        )
        .ok_or("the run key did not build")?
        .at(CallerLocality::OnDevice);
        let vault = self.server.vault();
        let applied = vault.scoped_read(key).read_receipt(None, 0)?.applied;
        let ceiling = (!applied.deny_all).then_some(applied.max_sensitivity_band);
        let (_, facts) = vault
            .person_about_sourced(self.person, ceiling)?
            .ok_or("FIXTURE: the run key's band shows a line")?;
        Ok(std::iter::once(self.person).chain(facts).collect())
    }

    /// The rows the run's recheck finds fallen in a held brief that showed
    /// `shown`, the PERSON on its roster.
    fn held_brief_fallen(&self, shown: &[EntityId]) -> TestResult<BTreeSet<EntityId>> {
        Ok(run_brief_fallen_rows(
            &self.server,
            self.agent,
            shown,
            &BTreeSet::from([self.person]),
        )
        .map_err(|error| format!("the held brief's recheck failed: {error}"))?)
    }

    fn brief_about(&self) -> TestResult<Option<String>> {
        let rows = run_brief_about_lines(&self.server, self.agent)
            .map_err(|error| format!("the run brief roster did not build: {error}"))?;
        let (_, about) = rows
            .into_iter()
            .find(|(person, _)| *person == self.person)
            .ok_or("the PERSON must still stand on the run brief roster")?;
        Ok(about)
    }
}

/// An existing MESSAGE is the identity evidence for the new PERSON.
fn message(vault: &Vault, content: &str) -> TestResult<EntityId> {
    let id = vault.new_entity_id()?;
    let now = vault.now_recorded_at();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("content"),
            rmpv::Value::from(content),
        )]),
    )?;
    vault.put_entity(
        &id,
        ENTITY_TYPE_MESSAGE,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &body,
    )?;
    Ok(id)
}

/// A native EXL3 launch slot exists even before its first successful
/// install. The absent manifest makes that install fail permanently, before
/// any environment setup, download, process launch or qualification call.
fn models_toml(routes: Routes, dir: &Path, endpoint: &str) -> String {
    let chat = if matches!(routes, Routes::ThirdParty) {
        "cloud:stub-chat"
    } else {
        "house-chat:stub-chat"
    };
    let mut text = format!(
        r#"
[dreamer]
enabled = false
[workflows]
enabled = false
[providers.house-chat]
kind = "local-openai-compat"
base_url = "{endpoint}"
revision = "v1"
[providers.cloud]
kind = "openai-compat"
base_url = "{endpoint}"
revision = "v1"
[roles.generative_reasoner]
rungs = [{{ model = "{chat}" }}]
"#,
    );
    if routes.has_native_chat() {
        text.push_str(&format!(
            r#"
[workers.brief-native-chat]
model = "house-chat:stub-chat"
kind = "exl3"
mode = "managed"
weights_manifest = "{}"
models_dir = "{}"
runtime_root = "{}"
"#,
            dir.join("absent-weights.json").display(),
            dir.join("models").display(),
            dir.join("runtime").display(),
        ));
    }
    if matches!(routes, Routes::OnDevice) {
        // Serve a cloud model by id so a live manifest pin can later select
        // it on this same server, without adding a browser planner rung.
        text.push_str("\n[roles.checker]\nmodel = \"cloud:stub-chat\"\n");
    }
    if matches!(routes, Routes::BrowserOffDevice) {
        text.push_str("\n[roles.browser_planner]\nmodel = \"cloud:stub-chat\"\n");
    }
    text
}

/// Pick only chat's native view. A global manifest route would pin the
/// browser planner to that same slot's on-device route too, defeating the
/// mixed-route control. A model pack leaves that role on its own seat.
fn install_chat_pack(vault: &Vault, model: &str) -> TestResult {
    let name = "fixture.run-brief-routes";
    let document = json!({
        "format": 1,
        "season": "brief-routes",
        "released_epoch_day": 0,
        "roles": {
            "generative_reasoner": [{
                "access": {"kind": "local_gpu"},
                "model": model,
                "when": "Chat uses this install's supervised native channel."
            }]
        }
    });
    let installed = vault.put_pack(
        &owner_proof(vault)?,
        vec![
            HubFile::new(
                "PACK.md",
                format!(
                    "---\nname: {name}\ndescription: Local chat route fixture.\n\
                     version: 1.0.0\nkind: model\n---\nData-only test model pack.\n"
                ),
            ),
            HubFile::new("knowledge/model-pack.json", document.to_string()),
        ],
    )?;
    let PackInstallDisposition::Installed(receipt) = installed else {
        panic!("FIXTURE: the data-only model pack must install, found {installed:?}.");
    };
    assert_eq!(
        receipt.status,
        PackInstallStatus::Active,
        "FIXTURE: the owner installs the chat model pack active."
    );
    call(
        &owner(vault),
        "vault.settings.set",
        json!({
            "key": "models.pack_preference",
            "scope": {"kind": "vault"},
            "value": {"mode": "pinned_pack", "pack": name},
        }),
    );
    Ok(())
}

#[test]
fn an_all_on_device_run_reads_its_brief_on_this_device() -> TestResult {
    on_engine_stack(|| async {
        let _turn = HOST_TURN.lock().await;
        let fixture = Fixture::new(Routes::OnDevice).await?;
        assert_eq!(
            fixture.brief_about()?.as_deref(),
            Some(LINE),
            "An all-on-device run reads the about line backed by this install's fact."
        );
        Ok(())
    })
}

#[test]
fn an_own_server_route_reads_its_brief_off_this_device() -> TestResult {
    on_engine_stack(|| async {
        let _turn = HOST_TURN.lock().await;
        let fixture = Fixture::new(Routes::OwnServer).await?;
        assert_eq!(
            fixture.brief_about()?,
            None,
            "An own-server chat route withholds the about line backed by this install's fact."
        );
        Ok(())
    })
}

#[test]
fn a_third_party_rung_reads_its_brief_off_this_device() -> TestResult {
    on_engine_stack(|| async {
        let _turn = HOST_TURN.lock().await;
        let fixture = Fixture::new(Routes::ThirdParty).await?;
        assert_eq!(
            fixture.brief_about()?,
            None,
            "A third-party chat rung withholds the about line backed by this install's fact."
        );
        Ok(())
    })
}

#[test]
fn a_browser_planner_route_off_this_device_reads_its_brief_off_this_device() -> TestResult {
    on_engine_stack(|| async {
        let _turn = HOST_TURN.lock().await;
        let fixture = Fixture::new(Routes::BrowserOffDevice).await?;
        assert_eq!(
            fixture.brief_about()?,
            None,
            "A third-party browser planner widens local chat's brief reader off-device."
        );
        Ok(())
    })
}

#[test]
fn a_held_brief_whose_route_leaves_the_device_finds_its_fact_fallen() -> TestResult {
    on_engine_stack(|| async {
        let _turn = HOST_TURN.lock().await;
        let fixture = Fixture::new(Routes::OnDevice).await?;
        assert_eq!(
            fixture.brief_about()?.as_deref(),
            Some(LINE),
            "The brief initially shows the about line while every route stays on-device."
        );
        let sources = fixture.staged_rows()?;
        assert!(
            sources.contains(&fixture.claim),
            "FIXTURE: the held line's source rows include its contributing fact."
        );
        assert!(
            fixture.held_brief_fallen(&sources)?.is_empty(),
            "The held brief has no fallen row while its routes stay on-device."
        );

        // Only the live model manifest changes; the server and all stored
        // PEOPLE, about lines, facts and world privacy rows stay the same.
        fixture.move_chat_to_cloud()?;
        assert!(
            fixture.reads(fixture.claim, CallerLocality::OnDevice)?
                && !fixture.reads(fixture.claim, CallerLocality::OffDevice)?
                && fixture.reads(fixture.person, CallerLocality::OffDevice)?,
            "FIXTURE: the move leaves the fact device-only and the PERSON readable off-device."
        );
        assert!(
            fixture
                .held_brief_fallen(&sources)?
                .contains(&fixture.claim),
            "The held brief finds its device-only fact fallen after the route leaves the device."
        );
        assert_eq!(
            fixture.brief_about()?,
            None,
            "A fresh brief withholds the line after the same server's route leaves the device."
        );
        Ok(())
    })
}
