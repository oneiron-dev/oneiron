//! A pumped run's self brief is judged off-device, even for a run on this
//! install. A PERSON stays on its roster, but its Dreamer-written `about`
//! line follows every fact it was written from: a fact in a world read on
//! this install only withholds the line. Base reality and the same world
//! widened by the owner to read everywhere still show it.
//!
//! Red on main 43174859d40: `run_people` reads on-device and `read_people`
//! picks a stored line by band without judging its contributing fact. The
//! first test therefore gets `Some(LINE)` instead of `None`; both controls
//! pass. The fixed head reads off-device and judges every contributor under
//! the run key's own floor, so all three pass.
//!
//! The owner gives this uncredentialed run key one policy read row. An agent
//! Grant alone is not its own floor. The name ceiling is opened separately,
//! so name masking cannot explain an absent line. Each fixture first proves
//! the owner's own roster shows the committed line.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! run_brief_roster_off_device`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use engine_stack::on_engine_stack;
use oneiron::authority::{
    ActSurface, MachineOwnership, MachineRole, ModelOrder, ReadLocation, SealedCopies, WorldPrivacy,
};
use oneiron::claim::{CallerLocality, ScopedReadActorKey};
use oneiron::federation::Scope;
use oneiron::memory::Memory;
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::test_doors::derive::{About, Derived, Named, about_facts, commit};
use oneiron::test_doors::steward::{dreamer, owner as owner_proof};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::run_brief_people::run_brief_about_lines;
use oneiron_server::{config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NAME: &str = "Owen Marsh";
const LINE: &str = "Owen keeps the reading group's lantern list.";

#[derive(Clone, Copy)]
enum FactWorld {
    Base,
    ThisInstall,
}

struct Fixture {
    server: Arc<SyncServer>,
    agent: EntityId,
    person: EntityId,
    claim: EntityId,
    world: Option<EntityId>,
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
    fn new(fact_world: FactWorld) -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        // Server boot roots and profiles the install, retains its root
        // signer and provisions the Dreamer's machine writer.
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("run-brief-roster-off-device".into()),
                ..Default::default()
            },
        )?);
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

        let world = match fact_world {
            FactWorld::Base => None,
            FactWorld::ThisInstall => {
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
                Some(world)
            }
        };

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
        let mut fact = json!({
            "predicate": "project.note",
            "subject_ref": person.to_hex(),
            "value": "Owen keeps the lantern list for the reading group.",
            "confidence": 0.9,
            "source": "user_stated",
        });
        if let Some(world) = world {
            fact["world_ref"] = json!(world.to_hex());
        }
        let remembered = call(&owner, "vault.remember", fact);
        let claim = id_at(&remembered, "/claim/id");

        let dreamer = dreamer(&vault)?;
        let (digest, line_bands) = about_facts(&vault, dreamer, EdgeActorClass::System, person)?;
        assert!(
            !line_bands.is_empty(),
            "FIXTURE: the Dreamer reads the owner's fact about the person"
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
            "FIXTURE: the Dreamer's about line lands: {:?}",
            item.reasons
        );
        let fixture = Self {
            server,
            agent,
            person,
            claim,
            world,
            _dir: dir,
        };
        fixture.assert_owner_sees_the_line();
        assert!(
            fixture.reads(fixture.person, CallerLocality::OffDevice)?
                && fixture.reads(fixture.claim, CallerLocality::OnDevice)?,
            "FIXTURE: the run key reads the PERSON off-device and the fact on-device"
        );
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
                    "FIXTURE: the owner reads the person's name"
                );
                assert_eq!(
                    row["about"], LINE,
                    "FIXTURE: the owner's roster shows the Dreamer's line: {row:#}"
                );
                return;
            }
            if listed["more"] == 0 || rows.is_empty() {
                break;
            }
        }
        panic!("FIXTURE: the owner's roster must list the person");
    }

    fn widen_world(&self) -> TestResult {
        let vault = self.server.vault();
        let proof = owner_proof(vault)?;
        vault.set_world_privacy_as(
            &proof,
            ActSurface::ThisInstall,
            self.world.ok_or("the fixture has no second world")?,
            WorldPrivacy {
                read: ReadLocation::Everywhere,
                sealed: SealedCopies::Off,
                models: ModelOrder::Inherit,
            },
            None,
        )?;
        Ok(())
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

#[test]
fn run_brief_shows_no_about_line_written_from_a_world_read_on_this_install_only() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new(FactWorld::ThisInstall)?;
        assert!(
            !fixture.reads(fixture.claim, CallerLocality::OffDevice)?,
            "FIXTURE: the world's read location keeps the fact off-device"
        );
        assert_eq!(
            fixture.brief_about()?,
            None,
            "the PERSON stays on the run brief, but its on-install fact withholds its about line"
        );
        Ok(())
    })
}

#[test]
fn run_brief_shows_about_line_written_from_base_reality() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new(FactWorld::Base)?;
        assert!(
            fixture.reads(fixture.claim, CallerLocality::OffDevice)?,
            "FIXTURE: the run key reads the base-reality fact off-device"
        );
        assert_eq!(fixture.brief_about()?.as_deref(), Some(LINE));
        Ok(())
    })
}

#[test]
fn run_brief_shows_about_line_once_the_world_reads_everywhere() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new(FactWorld::ThisInstall)?;
        assert!(
            !fixture.reads(fixture.claim, CallerLocality::OffDevice)?,
            "FIXTURE: the fact is initially kept on this install"
        );
        fixture.widen_world()?;
        fixture.assert_owner_sees_the_line();
        assert!(
            fixture.reads(fixture.claim, CallerLocality::OffDevice)?,
            "FIXTURE: widening only the read location admits the same fact off-device"
        );
        assert_eq!(fixture.brief_about()?.as_deref(), Some(LINE));
        Ok(())
    })
}
