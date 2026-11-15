//! DESIGN 15-setting-primitive, stage 2 (SETTING-DREAMER D3): the Dreamer's wake policy, the
//! projector policy and the sieve policy are Setting keys.
//! - each key is in the catalogue with its setter and its order: the wake policy is the wake
//!   cadence class's, the projector policy the maintenance cadence class's, the sieve's budgets the
//!   work budget class's, its scoring the owner's;
//! - a new vault reads the shipped policies;
//! - the owner's `Vault::set_setting` is what the readers return;
//! - a holder of the work budget class lowers the sieve's budgets at once, also under the owner's
//!   row, and its raise and its scoring change do not apply;
//! - a holder of the maintenance cadence class moves the projector policy either way;
//! - a holder of the wake cadence class moves the wake policy's cadence at once; its move of the
//!   absent role off companion (which widens the Coach's sealed-pad reads) files an ask and moves
//!   nothing until the owner says yes (RULING SETTING-DREAMER-WAKE-ORDER = A);
//! - a value the type's check refuses is refused, and the value in force stands;
//! - the owner's action `dreamer.wake_policy.set` sets the key and is signed on the key's target.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dreamer_3`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::check_in::HolderAnswer;
use oneiron::code_run::actions::{
    ActionArgument, ActionHostBinding, ActionRegistry, AgentActionCall,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_wake::{AgentWakeRole, DreamerWakePolicy, ProjectorPolicy, SievePolicy};
use oneiron::federation::{EngineControlClass, Scope, ScopeAxis};
use oneiron::lens::{LensText, SelfUiActionId};
use oneiron::policy_setting_doors::{action_principal, policy_setting_target};
use oneiron::receipt::AuthorityAuditQuery;
use oneiron::setting::{
    Order, Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, ValueKind, spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const WAKE: &str = "dreamer.wake.policy";
const PROJECTOR: &str = "dreamer.projector.policy";
const BUDGETS: &str = "dreamer.sieve.budgets";
const SCORING: &str = "dreamer.sieve.scoring";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned (as
    /// tests/setting_primitive.rs opens it).
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
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner,
            owner_proof,
        }
    }

    /// An enabled, active agent definition the owner creates, with no Grant.
    fn agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("dreamer-wake-setting-agent-{}", id.to_hex()),
                    "desc": "setting dreamer wake fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        id
    }

    fn set(
        &self,
        caller: SettingCaller<'_>,
        key: &str,
        value: Value,
    ) -> oneiron::Result<SetSettingOutcome> {
        self.vault
            .set_setting(caller, SetSetting::vault_value(key, value))
    }

    fn set_as_owner(&self, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.set(SettingCaller::Owner(&self.owner_proof), key, value)
    }

    /// An agent the owner creates, Grants `read`, `vault.settings.set` and `vault.settings.get`,
    /// and gives the `engine.controls` class `class`: a holder that may ask the owner.
    fn granted_holder(&self, class: EngineControlClass) -> EntityId {
        let agent = self.agent();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            ["read", "vault.settings.set", "vault.settings.get"]
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the Grant");
        assert!(minted.grant.confers, "the Grant confers");
        self.controls(agent, class);
        agent
    }

    /// The owner's `engine.controls` grant of `class` to `agent`.
    fn controls(&self, agent: EntityId, class: EngineControlClass) {
        self.vault
            .grant_engine_controls(&self.owner_proof, agent, &[class].into_iter().collect())
            .expect("the owner's engine.controls grant");
    }

    /// The owner's policy setting acts on the main log, as the owner's audit lists them: each
    /// entry's detail (`<setting> set`) and its target (32 hex).
    fn setting_acts(&self) -> Vec<(String, String)> {
        self.vault
            .authority_audit(
                &self.owner_proof,
                &AuthorityAuditQuery {
                    limit: Some(500),
                    ..AuthorityAuditQuery::default()
                },
            )
            .expect("the owner's audit")
            .rows
            .into_iter()
            .filter(|row| row.source_op == "policy_setting")
            .map(|row| {
                (
                    row.detail.unwrap_or_default(),
                    row.subject_ref.unwrap_or_default(),
                )
            })
            .collect()
    }
}

fn applied(outcome: SetSettingOutcome) {
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the change applies and is recorded: {outcome:?}"
    );
}

fn not_applied(outcome: &oneiron::Result<SetSettingOutcome>, what: &str) {
    assert!(
        !matches!(outcome, Ok(SetSettingOutcome::Applied { .. })),
        "{what}: the change does not apply: {outcome:?}"
    );
}

/// The shipped sieve_policy_defaults.json.
fn shipped_sieve() -> SievePolicy {
    serde_json::from_value(json!({
        "max_turns_per_pass": 64,
        "max_scan_per_pass": 4096,
        "max_text_bytes_per_pass": 32768,
        "date_interest": 100,
        "name_interest": 100,
        "absolute_date_confidence": 90,
        "relative_date_confidence": 80,
        "vague_date_confidence": 50,
        "name_confidence": 70,
        "initial_name_confidence": 40,
        "katakana_name_confidence": 40,
        "uncertain_low": 35,
        "uncertain_high": 75,
    }))
    .expect("the shipped sieve policy")
}

fn scoring() -> Value {
    json!({
        "date_interest": 120,
        "name_interest": 80,
        "absolute_date_confidence": 95,
        "relative_date_confidence": 85,
        "vague_date_confidence": 55,
        "name_confidence": 65,
        "initial_name_confidence": 45,
        "katakana_name_confidence": 35,
        "uncertain_low": 30,
        "uncertain_high": 70,
    })
}

fn budgets(turns: u32, scan: u32, bytes: u32) -> Value {
    json!({
        "max_turns_per_pass": turns,
        "max_scan_per_pass": scan,
        "max_text_bytes_per_pass": bytes,
    })
}

fn wake_json(policy: &DreamerWakePolicy) -> Value {
    serde_json::to_value(policy).expect("a wake policy")
}

#[test]
fn each_key_is_in_the_catalogue_with_its_setter_and_order() {
    let rows = [
        (
            WAKE,
            SetBy::Class(EngineControlClass::WakeCadence),
            Order::Custom,
        ),
        (
            PROJECTOR,
            SetBy::Class(EngineControlClass::MaintenanceCadence),
            Order::Neutral,
        ),
        (
            BUDGETS,
            SetBy::Class(EngineControlClass::WorkBudget),
            Order::Each,
        ),
        (SCORING, SetBy::Owner, Order::None),
    ];
    for (name, set_by, order) in rows {
        let spec =
            spec_named(name).unwrap_or_else(|error| panic!("{name} in the catalogue: {error}"));
        assert_eq!(spec.set_by, set_by, "{name}: who sets it");
        assert_eq!(spec.kind.order(), order, "{name}: its order");
        assert_eq!(
            spec.restore,
            Restore::Live,
            "{name}: a restore keeps the live choice"
        );
        assert!(spec.item.is_none(), "{name}: one setting, not a family");
    }
}

#[test]
fn a_new_vault_reads_the_shipped_policies() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    assert_eq!(
        vault.dreamer_projector_policy().unwrap(),
        ProjectorPolicy {
            min_new_statements: 1
        }
    );
    assert_eq!(vault.dreamer_sieve_policy().unwrap(), shipped_sieve());
    let wake = vault.dreamer_wake_policy().unwrap();
    assert_eq!(wake.wake_grain_turns, 1);
    assert_eq!(wake.new_records, 50);
    assert_eq!(wake.agent_cadence.absent_role, AgentWakeRole::Worker);
}

#[test]
fn the_owners_set_is_what_the_readers_return() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    applied(
        fixture
            .set_as_owner(PROJECTOR, json!({"min_new_statements": 3}))
            .unwrap(),
    );
    assert_eq!(
        vault.dreamer_projector_policy().unwrap(),
        ProjectorPolicy {
            min_new_statements: 3
        }
    );

    applied(
        fixture
            .set_as_owner(BUDGETS, budgets(128, 8192, 65536))
            .unwrap(),
    );
    applied(fixture.set_as_owner(SCORING, scoring()).unwrap());
    let mut expected: Value = serde_json::to_value(shipped_sieve()).unwrap();
    for (field, value) in budgets(128, 8192, 65536)
        .as_object()
        .unwrap()
        .iter()
        .chain(scoring().as_object().unwrap())
    {
        expected[field] = value.clone();
    }
    assert_eq!(
        serde_json::to_value(vault.dreamer_sieve_policy().unwrap()).unwrap(),
        expected,
        "the policy composes the owner's budgets and scoring"
    );

    let mut wake = vault.dreamer_wake_policy().unwrap();
    wake.wake_grain_turns = 4;
    wake.nightly_secs = 7_200;
    wake.agent_cadence.absent_role = AgentWakeRole::Companion;
    applied(fixture.set_as_owner(WAKE, wake_json(&wake)).unwrap());
    assert_eq!(vault.dreamer_wake_policy().unwrap(), wake);
    assert_eq!(vault.wake_grain().unwrap().turns_per_wake, 4);
}

#[test]
fn a_work_budget_holder_lowers_the_sieve_budgets_and_its_raise_does_not_apply() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let holder = fixture.agent();
    fixture.controls(holder, EngineControlClass::WorkBudget);

    applied(
        fixture
            .set_as_owner(BUDGETS, budgets(32, 2048, 16384))
            .unwrap(),
    );
    applied(
        fixture
            .set(
                SettingCaller::Agent(holder),
                BUDGETS,
                budgets(16, 1024, 8192),
            )
            .unwrap(),
    );
    let lowered = vault.dreamer_sieve_policy().unwrap();
    assert_eq!(
        (
            lowered.max_turns_per_pass,
            lowered.max_scan_per_pass,
            lowered.max_text_bytes_per_pass
        ),
        (16, 1024, 8192),
        "the holder lowers the budgets under the owner's row"
    );

    let raise = fixture.set(
        SettingCaller::Agent(holder),
        BUDGETS,
        budgets(16, 4096, 8192),
    );
    not_applied(&raise, "a raise of one budget");
    let scoring_change = fixture.set(SettingCaller::Agent(holder), SCORING, scoring());
    not_applied(&scoring_change, "the scoring");
    let projector = fixture.set(
        SettingCaller::Agent(holder),
        PROJECTOR,
        json!({"min_new_statements": 4}),
    );
    not_applied(&projector, "the projector policy, another class's");

    let after = vault.dreamer_sieve_policy().unwrap();
    assert_eq!(after, lowered, "the lowered policy stands");
    assert_eq!(
        (after.date_interest, after.uncertain_high),
        (100, 75),
        "the scoring stays the shipped one"
    );
}

#[test]
fn a_maintenance_cadence_holder_moves_the_projector_policy_either_way() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let holder = fixture.agent();
    fixture.controls(holder, EngineControlClass::MaintenanceCadence);

    for value in [5, 0, 2] {
        applied(
            fixture
                .set(
                    SettingCaller::Agent(holder),
                    PROJECTOR,
                    json!({"min_new_statements": value}),
                )
                .unwrap(),
        );
        assert_eq!(
            vault.dreamer_projector_policy().unwrap(),
            ProjectorPolicy {
                min_new_statements: value
            }
        );
    }
    let lower = fixture.set(SettingCaller::Agent(holder), BUDGETS, budgets(8, 512, 4096));
    not_applied(&lower, "the sieve's budgets, another class's");
    assert_eq!(vault.dreamer_sieve_policy().unwrap(), shipped_sieve());
}

#[test]
fn a_wake_cadence_holder_moves_the_cadence_and_asks_to_move_the_absent_role_off_companion() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let holder = fixture.granted_holder(EngineControlClass::WakeCadence);

    let mut companion = vault.dreamer_wake_policy().unwrap();
    companion.agent_cadence.absent_role = AgentWakeRole::Companion;
    companion.new_records = 10;
    applied(
        fixture
            .set(SettingCaller::Agent(holder), WAKE, wake_json(&companion))
            .unwrap(),
    );
    assert_eq!(vault.dreamer_wake_policy().unwrap(), companion);

    let mut slower = companion;
    slower.new_records = 200;
    slower.nightly_secs = 43_200;
    slower.agent_cadence.worker.event = false;
    applied(
        fixture
            .set(SettingCaller::Agent(holder), WAKE, wake_json(&slower))
            .unwrap(),
    );
    assert_eq!(vault.dreamer_wake_policy().unwrap(), slower);

    // The move off companion widens the Coach's sealed-pad reads: it files an ask.
    let mut worker = slower;
    worker.agent_cadence.absent_role = AgentWakeRole::Worker;
    let ask = SetSetting::vault_value(WAKE, wake_json(&worker));
    let outcome = vault
        .set_setting(SettingCaller::Agent(holder), ask.clone())
        .expect("the holder's move off companion");
    let SetSettingOutcome::Pending { check_in } = outcome else {
        panic!("the move off companion asks the owner: {outcome:?}");
    };
    assert_eq!(
        vault.dreamer_wake_policy().unwrap(),
        slower,
        "nothing moves until the owner says yes"
    );

    let check_in = EntityId::from_hex(&check_in).expect("the check-in's id");
    let row = vault
        .pending_check_in(&check_in)
        .expect("the check-in reads")
        .expect("the pending check-in");
    oneiron::test_doors::check_in::answer_verified(
        vault,
        &fixture.owner_proof,
        &check_in,
        &row.effect_digest,
        HolderAnswer::Approve,
    )
    .expect("the owner approves");
    applied(
        vault
            .set_setting(
                SettingCaller::Agent(holder),
                SetSetting {
                    check_in_ref: Some(check_in),
                    ..ask
                },
            )
            .expect("the approved move"),
    );
    assert_eq!(vault.dreamer_wake_policy().unwrap(), worker);
}

#[test]
fn a_value_its_check_refuses_is_refused_and_the_value_in_force_stands() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    let refused = [
        (BUDGETS, budgets(0, 4096, 32768), "no turns per pass"),
        (BUDGETS, budgets(64, 32, 32768), "a scan below the turns"),
        (BUDGETS, budgets(64, 4096, 0), "no text bytes per pass"),
    ];
    for (key, value, what) in refused {
        assert!(fixture.set_as_owner(key, value).is_err(), "{what}");
    }
    let mut over = scoring();
    over["name_confidence"] = json!(101);
    assert!(
        fixture.set_as_owner(SCORING, over).is_err(),
        "a confidence above 100"
    );
    let mut inverted = scoring();
    inverted["uncertain_low"] = json!(80);
    assert!(
        fixture.set_as_owner(SCORING, inverted).is_err(),
        "a low edge above the high one"
    );
    let shipped = vault.dreamer_wake_policy().unwrap();
    let mut no_idle = shipped;
    no_idle.idle_secs = 0;
    assert!(
        fixture.set_as_owner(WAKE, wake_json(&no_idle)).is_err(),
        "an idle wait of 0"
    );
    let mut short_quiet = shipped;
    short_quiet.quiet_weave_secs = 1;
    short_quiet.idle_secs = 60;
    assert!(
        fixture.set_as_owner(WAKE, wake_json(&short_quiet)).is_err(),
        "a quiet window below the idle wait"
    );

    assert_eq!(vault.dreamer_sieve_policy().unwrap(), shipped_sieve());
    assert_eq!(vault.dreamer_wake_policy().unwrap(), shipped);
}

#[test]
fn the_owners_wake_policy_action_sets_the_key_and_is_signed_on_its_target() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let before = fixture.setting_acts();

    let mut policy = vault.dreamer_wake_policy().unwrap();
    policy.wake_grain_turns = 3;
    policy.quiet_weave_secs = 1_800;
    let actor = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    let key = vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("the owner's read key");
    let principal = action_principal(actor, key).expect("the owner's principal");
    let call = AgentActionCall {
        verb_id: SelfUiActionId::new("dreamer.wake_policy.set").expect("action id"),
        args: vec![ActionArgument::Text(
            LensText::new(serde_json::to_string(&policy).unwrap()).expect("policy text"),
        )],
        idempotency_key: "setting-dreamer-3-wake".into(),
    };
    ActionRegistry::app()
        .expect("the app's action table")
        .execute_call(
            vault,
            actor,
            &principal,
            &call,
            ActionHostBinding {
                owner: Some(&fixture.owner_proof),
                owner_surface: Some(ActSurface::ThisInstall),
                ..ActionHostBinding::default()
            },
        )
        .expect("the owner's wake policy action");
    assert_eq!(vault.dreamer_wake_policy().unwrap(), policy);

    let acts: Vec<(String, String)> = fixture
        .setting_acts()
        .into_iter()
        .filter(|act| !before.contains(act))
        .collect();
    assert_eq!(
        acts,
        [(
            format!("{WAKE} set"),
            policy_setting_target(WAKE).expect("target").to_hex(),
        )],
        "one act, on the key's own target"
    );
}
