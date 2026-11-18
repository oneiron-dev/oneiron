//! Restriction wave 14, C22 (Engine RULING RESTRICTION-WAVE-14-ROWS, 16 Nov 03:37): the owner's
//! Setting key `dreamer.action_mode.auto_apply_patch`, off by default.
//! - Off, the night's action-mode finding freezes its band's agent-ceiling patch and the agent's
//!   ceiling stays: only the owner's apply puts it on, as before.
//! - On, a fresh finding under the owner's own policy applies its frozen patch in the night's
//!   write, through the owner's fenced ceiling writer, with the inverse on its applied row, and
//!   the owner's revert of that finding puts the ceiling back.
//! - A policy row an agent holding the policy key's Grant line wrote is not the owner's, so its
//!   patch is not applied even with the key on.
//! - The key is in the catalogue and the owner sets it. On is the looser value: an agent's
//!   change turning it on waits on the owner's answer.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! setting_action_mode_auto_apply`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::affect::state_index::{ENGAGEMENT, GOAL_VELOCITY, StateIndexEvidence};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::maintenance::{AppliedMaintenance, MaintenanceTarget};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_TURN};
use oneiron::setting::{SetBy, SetSetting, SetSettingOutcome, SettingCaller, set_line, spec_named};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::action_mode_pass::run_action_mode_pass;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vad, VadAnnotation, VadAnnotationSource, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const AUTO_APPLY: &str = "dreamer.action_mode.auto_apply_patch";
const POLICY: &str = "dreamer.action_mode.policy";
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned (as
    /// tests/setting_dreamer_2.rs opens it), whose shipped policy reads the state index's
    /// signals and the action-mode finding as normal.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        declare_predicates_normal(&vault, &["state.", "dreamer.action_mode."]);
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner,
            owner_proof,
        }
    }

    /// An enabled, active agent definition the owner creates at `ceiling`, with no Grant.
    fn agent(&self, ceiling: &str) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("action-mode-agent-{}", id.to_hex()),
                    "desc": "action-mode auto-apply fixture",
                    "version": "1.0.0",
                    "ceiling": ceiling,
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        id
    }

    /// The owner's Grant to `agent` listing `vault.settings.set` and `key`'s own set line.
    fn key_grant(&self, agent: EntityId, key: &str) {
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "vault.settings.set".to_owned(),
            set_line(key),
        ]));
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the agent a Grant");
        assert!(minted.grant.confers, "the Grant confers");
    }

    fn set(&self, caller: SettingCaller<'_>, key: &str, value: Value) -> SetSettingOutcome {
        self.vault
            .set_setting(caller, SetSetting::vault_value(key, value))
            .unwrap_or_else(|error| panic!("set {key}: {error}"))
    }

    fn set_as_owner(&self, key: &str, value: Value) -> SetSettingOutcome {
        self.set(SettingCaller::Owner(&self.owner_proof), key, value)
    }

    /// The owner's state index, derived from one annotated TURN and the two signals, so the
    /// door's pass reads it with every input present.
    fn seed_state_index(&self) {
        let vault = &self.vault;
        let at = || TimeRange { start: T0, end: T0 };
        let turn = vault.new_entity_id().expect("turn id");
        vault
            .put_entity(&turn, ENTITY_TYPE_TURN, at(), T0, b"turn")
            .expect("a TURN");
        vault
            .annotate_turn_vad(
                &turn,
                VadAnnotation::new(
                    Vad {
                        valence: 0.5,
                        arousal: 0.6,
                        dominance: 0.9,
                    },
                    VadAnnotationSource::UserSelfReport,
                    T0,
                )
                .expect("annotation"),
            )
            .expect("the TURN is annotated");
        let facet = vault.default_facet().expect("vault default facet");
        let signal = |predicate: &str, value: f32| -> EntityId {
            let id = EntityId::now();
            let mut body = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(self.owner),
                rmpv::Value::F32(value),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .expect("signal claim");
            body.source = Some(ClaimSource::Observed);
            body.scope_facet = facet;
            vault.put_claim(&id, &body, at(), T0).expect("signal put");
            id
        };
        let evidence = StateIndexEvidence {
            vad_turns: vec![turn],
            goal_velocity: signal(GOAL_VELOCITY, 0.7),
            engagement: signal(ENGAGEMENT, 0.8),
        };
        vault
            .derive_state_index(&self.owner, &evidence, T0)
            .expect("the owner's state index");
    }

    fn ceiling(&self, agent: EntityId) -> &'static str {
        self.vault
            .get_agent_definition(&agent)
            .expect("definition read")
            .expect("the agent's definition")
            .ceiling
            .as_str()
    }

    /// The finding's row on the owner's applied list.
    fn applied(&self, finding: EntityId) -> AppliedMaintenance {
        self.vault
            .applied_dreamer_maintenance(&self.owner_proof, 100)
            .expect("the owner's applied list")
            .into_iter()
            .find(|row| matches!(row.target, MaintenanceTarget::Finding(id) if id == finding))
            .expect("the finding is on the applied list")
    }

    /// One night's pass, which must file a finding the Dreamer applied at Auto.
    fn night(&self, now: u64) -> EntityId {
        let finding = run_action_mode_pass(&self.vault, now)
            .expect("the action-mode pass")
            .expect("the index falls in the policy's band");
        let body = self
            .vault
            .get_claim(&finding)
            .expect("finding read")
            .expect("the finding");
        assert_eq!(
            body.approval,
            ClaimApprovalStatus::Auto,
            "the finding landed applied, not held in the run tray"
        );
        finding
    }
}

/// One band over the whole index whose mode sets `agent`'s ceiling to auto.
fn policy(agent: EntityId) -> Value {
    json!({
        "window": {
            "window_secs": 604_800,
            "expected_goal_completions": 5,
            "expected_engaged_days": 4,
        },
        "rules": [{
            "mode": "delegate",
            "min_index": 0.0,
            "max_index": 1.0,
            "effect": {"agent": agent.to_hex(), "ceiling": "auto"},
        }],
    })
}

fn applied_now(outcome: &SetSettingOutcome) -> bool {
    matches!(
        outcome,
        SetSettingOutcome::Applied {
            sequence: Some(_),
            ..
        }
    )
}

/// Declares each prefix normal (criticality and sensitivity) in the shipped default policy, as
/// tests/claim_facet_birth.rs does.
fn declare_predicates_normal(vault: &Vault, prefixes: &[&str]) {
    let axes = json!({ "criticality": "normal", "sensitivity": "normal" });
    for id in vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("policy manifests")
    {
        let Some(bytes) = vault.get(&id).expect("policy manifest read") else {
            continue;
        };
        let mut manifest: Value = rmp_serde::from_slice(&bytes).expect("policy manifest body");
        if manifest["pack_id"] != SHIPPED_POLICY_PACK {
            continue;
        }
        let rules = manifest
            .as_object_mut()
            .expect("policy manifest map")
            .entry("rules")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("policy rules list");
        for &prefix in prefixes {
            let index = match rules.iter().position(|rule| rule["prefix"] == prefix) {
                Some(index) => index,
                None => {
                    rules.push(json!({ "prefix": prefix }));
                    rules.len() - 1
                }
            };
            rules[index]["axes"] = axes.clone();
        }
        oneiron::test_support::put_policy_manifest_bytes(
            vault,
            id,
            &rmp_serde::to_vec_named(&manifest).expect("policy manifest encode"),
        )
        .expect("policy manifest put");
        return;
    }
    panic!("the vault holds no shipped policy manifest");
}

#[test]
fn the_key_is_in_the_catalogue_and_the_owner_sets_it() {
    let spec = spec_named(AUTO_APPLY).expect("the key is in the catalogue");
    assert_eq!(spec.set_by, SetBy::Owner, "the owner sets it");
    assert!(spec.item.is_none(), "one setting, not a family");
}

#[test]
fn with_the_key_off_the_finding_freezes_its_patch_and_the_ceiling_stays() {
    let fixture = Fixture::rooted();
    let agent = fixture.agent("proposed");
    assert!(applied_now(&fixture.set_as_owner(POLICY, policy(agent))));
    fixture.seed_state_index();

    let finding = fixture.night(T0 + 60);

    assert_eq!(fixture.ceiling(agent), "proposed", "no patch applied");
    let row = fixture.applied(finding);
    assert_eq!(row.kind, "finding", "the row holds the finding alone");
    let value: Value = serde_json::from_str(
        fixture
            .vault
            .get_claim(&finding)
            .unwrap()
            .unwrap()
            .value
            .as_str()
            .expect("the finding's value is JSON text"),
    )
    .expect("the finding's value");
    assert_eq!(value["effect"]["agent"], json!(agent.to_hex()));
    assert_eq!(value["effect"]["ceiling"], json!("auto"));
}

#[test]
fn with_the_key_on_the_night_applies_the_frozen_patch_and_the_owners_revert_puts_it_back() {
    let fixture = Fixture::rooted();
    let agent = fixture.agent("proposed");
    assert!(applied_now(&fixture.set_as_owner(POLICY, policy(agent))));
    assert!(applied_now(&fixture.set_as_owner(AUTO_APPLY, json!(true))));
    fixture.seed_state_index();

    let finding = fixture.night(T0 + 60);

    assert_eq!(
        fixture.ceiling(agent),
        "auto",
        "the frozen patch applied with the finding"
    );
    let row = fixture.applied(finding);
    assert_eq!(row.kind, "action_mode", "the row holds the patch's inverse");
    assert!(row.attempt.is_some(), "the night's attempt wrote it");
    assert!(row.reverted.is_none());

    let reverted = fixture
        .vault
        .revert_dreamer_maintenance(
            &fixture.owner_proof,
            MaintenanceTarget::Finding(finding),
            T0 + 120,
        )
        .expect("the owner reverts the finding");
    assert_eq!(reverted.restored, vec![agent], "{reverted:?}");
    assert_eq!(
        fixture.ceiling(agent),
        "proposed",
        "the revert put the ceiling back"
    );
}

#[test]
fn a_policy_an_agent_wrote_is_not_applied_with_the_key_on() {
    let fixture = Fixture::rooted();
    let agent = fixture.agent("proposed");
    let holder = fixture.agent("proposed");
    fixture.key_grant(holder, POLICY);
    let outcome = fixture.set(SettingCaller::Agent(holder), POLICY, policy(agent));
    assert!(
        applied_now(&outcome),
        "the key's Grant line sets a policy the owner never set: {outcome:?}"
    );
    assert!(applied_now(&fixture.set_as_owner(AUTO_APPLY, json!(true))));
    fixture.seed_state_index();

    let finding = fixture.night(T0 + 60);

    assert_eq!(
        fixture.ceiling(agent),
        "proposed",
        "a patch the owner did not write is not applied"
    );
    assert_eq!(fixture.applied(finding).kind, "finding");
}

#[test]
fn an_agents_change_turning_the_key_on_waits_on_the_owner() {
    let fixture = Fixture::rooted();
    let holder = fixture.agent("proposed");
    fixture.key_grant(holder, AUTO_APPLY);
    let outcome = fixture.set(SettingCaller::Agent(holder), AUTO_APPLY, json!(true));
    assert!(
        matches!(outcome, SetSettingOutcome::Pending { .. }),
        "on is looser than off, so the change waits on the owner: {outcome:?}"
    );
}
