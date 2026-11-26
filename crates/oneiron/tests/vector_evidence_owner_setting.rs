//! EMBEDDER-ENDPOINT-VECTOR-FLOORS PR B (Engine ANSWER 27 Nov 01:45): the owner sets the no-match
//! floors of one embedding space with the catalogue key `retrieval.vector_evidence`, one item per
//! space (its model id, `org/name@revision`), value `{floor, strong}`, refused outside
//! `0 <= floor <= strong <= 1`. The owner's row for the vault's space judges every score there,
//! of every kind, before a host-measured kind pair and the host's pair. A row for another space
//! judges nothing, and a row with no space is refused; an agent's change waits on the owner's
//! answer, standing approval or not (review round 1 of #10562); the key is the same on every
//! machine of the vault.
//!
//! The fixture is the EMBED-PACK one (`pipeline/tests/fusion_lists.rs`): a target whose vector
//! sits at cosine 0.29 to the query and shares no word with it, which the engine's default floors
//! (0.30/0.50) withhold, and noise at 0.12.
//!
//! Red on the base: the catalogue has no `retrieval.vector_evidence` key, so every set is refused
//! and `spec_named` finds nothing.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! vector_evidence_owner_setting`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::config::VectorEvidenceFloors;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingScope, SettingSync, set_line, spec_named,
    widen_line, widen_scope_line,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const KEY: &str = "retrieval.vector_evidence";
/// The space the fixture vault's vectors are pinned to.
const SPACE: &str = "test/model@v1";
/// A space the vault's vectors are not in.
const OTHER_SPACE: &str = "test/other@v1";
const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

/// A unit vector at `cosine` to [`QUERY`].
fn at(cosine: f32) -> [f32; 4] {
    [cosine, (1.0 - cosine * cosine).sqrt(), 0.0, 0.0]
}

fn floors(floor: f32, strong: f32) -> VectorEvidenceFloors {
    VectorEvidenceFloors { floor, strong }
}

/// A rooted vault with vectors in [`SPACE`], its owner's proof, a target at cosine 0.29 to
/// [`QUERY`] and noise at 0.12. The vault drops first.
struct Fixture {
    vault: Vault,
    proof: AuthenticatedOwner,
    target: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.dimensions = QUERY.len();
        config.embedding_model = Some(SPACE.to_owned());
        let vault = Vault::open(dir.path(), config).expect("seeded vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = HostSlipIssuer::from_seed(&[0x5b; HOST_ISSUER_SEED_BYTES])
            .expect("independent host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        // This install is not the owner's machine, so it holds the root's key, which proves the
        // owner's acts, as a serving host holds its own (row CARRIER-OWNER-PROOF;
        // `setting_pack_accept.rs`). Without it the owner's set waits for an owner key and is
        // refused `OwnerKeyRequired` (FIX VECTOR-EVIDENCE-OWNER-SETTING-TEST-RED).
        vault.hold_checkpoint_root_signer(Arc::new(issuer));
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let fixture = Self {
            vault,
            proof,
            target: EntityId::now(),
            _dir: dir,
        };
        fixture.put_turn(
            fixture.target,
            "the mechanic says the automobile needs new brakes",
            at(0.29),
        );
        fixture.put_turn(
            EntityId::now(),
            "renew the passport before october",
            at(0.12),
        );
        fixture
    }

    fn put_turn(&self, id: EntityId, text: &str, vector: [f32; 4]) {
        let body = rmp_serde::to_vec_named(&json!({ "content": text })).expect("turn body");
        self.vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: LEARNED_AT,
                    end: LEARNED_AT,
                },
                LEARNED_AT,
                &body,
            )
            .text(&id, &[("body", text)])
            .vector(&id, &vector)
            .commit()
            .expect("the turn, its text and its vector");
    }

    /// Whether a pack for a query that shares no word with the target, its vector at 0.29 to the
    /// target's, leads with the target; `false` when the no-match check withholds the pack.
    fn pack_finds_target(&self) -> bool {
        let pack = self
            .vault
            .context_pack()
            .search_text("who fixes my car", 10)
            .search_vector(&QUERY, 10)
            .run()
            .expect("the pack runs");
        pack.results.first().map(|entity| entity.id) == Some(self.target)
    }

    /// `caller`'s change of the row for `space`: `value`, or a clear for `None`.
    fn set(
        &self,
        caller: SettingCaller<'_>,
        space: &str,
        value: Option<Value>,
    ) -> oneiron::Result<SetSettingOutcome> {
        let mut change = SetSetting::vault_value(KEY, Value::Null);
        change.item = Some(space.to_owned());
        change.value = value;
        self.vault.set_setting(caller, change)
    }

    /// The owner sets `space`'s floors to `floor` and `strong`.
    fn owner_sets(&self, space: &str, floor: f64, strong: f64) {
        let outcome = self
            .set(
                SettingCaller::Owner(&self.proof),
                space,
                Some(json!({ "floor": floor, "strong": strong })),
            )
            .unwrap_or_else(|error| panic!("the owner sets {space}'s floors: {error}"));
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's floors apply at once: {outcome:?}"
        );
    }
}

#[test]
fn the_owners_floors_for_the_vaults_space_judge_its_packs() {
    let fixture = Fixture::open();
    assert!(
        !fixture.pack_finds_target(),
        "the engine's 0.30/0.50 withhold a paraphrase at 0.29"
    );
    fixture.owner_sets(SPACE, 0.15, 0.25);
    assert!(
        fixture.pack_finds_target(),
        "under the owner's 0.15/0.25 the paraphrase at 0.29 is evidence"
    );
    let cleared = fixture
        .set(SettingCaller::Owner(&fixture.proof), SPACE, None)
        .expect("the owner clears the row");
    assert!(
        matches!(cleared, SetSettingOutcome::Applied { .. }),
        "{cleared:?}"
    );
    assert!(
        !fixture.pack_finds_target(),
        "with the row cleared the host's floors judge again"
    );
}

#[test]
fn the_owners_floors_judge_before_a_host_measured_kind_pair() {
    let fixture = Fixture::open();
    fixture
        .vault
        .set_vector_evidence_for(SPACE, ENTITY_TYPE_TURN, floors(0.15, 0.25))
        .expect("the host measured this kind's floors");
    assert!(
        fixture.pack_finds_target(),
        "the host's measured 0.15/0.25 for TURN count the paraphrase"
    );
    fixture.owner_sets(SPACE, 0.30, 0.50);
    assert!(
        !fixture.pack_finds_target(),
        "the owner's 0.30/0.50 for the space judge the TURN in place of the host's pair"
    );
}

#[test]
fn a_row_for_another_space_judges_nothing() {
    let fixture = Fixture::open();
    fixture.owner_sets(OTHER_SPACE, 0.15, 0.25);
    assert!(
        !fixture.pack_finds_target(),
        "floors for a space the vault's vectors are not in change nothing"
    );
}

#[test]
fn floors_outside_zero_floor_strong_one_are_refused() {
    let fixture = Fixture::open();
    for value in [
        json!({ "floor": 0.30, "strong": 0.25 }),
        json!({ "floor": -0.10, "strong": 0.25 }),
        json!({ "floor": 0.15, "strong": 1.50 }),
        // Just outside the bounds at JSON precision, inside them once narrowed to f32.
        json!({ "floor": 0.15, "strong": 1.000_000_01 }),
        json!({ "floor": 0.250_000_001, "strong": 0.25 }),
        json!({ "floor": 0.15 }),
        json!({ "floor": "0.15", "strong": 0.25 }),
    ] {
        let refused = fixture.set(
            SettingCaller::Owner(&fixture.proof),
            SPACE,
            Some(value.clone()),
        );
        assert!(refused.is_err(), "{value} is refused: {refused:?}");
    }
    assert!(
        !fixture.pack_finds_target(),
        "no refused value judges the space"
    );
}

#[test]
fn an_item_that_names_no_embedding_space_is_refused() {
    let fixture = Fixture::open();
    for item in [
        "pplx-embed-v1-0.6b",
        "perplexity-ai/pplx-embed-v1-0.6b",
        "test@model/v1",
        "test/model@v1@v2",
        "test/mo del@v1",
    ] {
        let refused = fixture.set(
            SettingCaller::Owner(&fixture.proof),
            item,
            Some(json!({ "floor": 0.15, "strong": 0.25 })),
        );
        assert!(refused.is_err(), "{item:?} is refused: {refused:?}");
    }
}

/// An enabled agent with a live owner Grant naming `read`, `vault.settings.set` and `lines`.
fn agent_holding(fixture: &Fixture, lines: &[String]) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        &fixture.vault,
        &fixture.proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": format!("evidence-floor-setter-{}", agent.to_hex()),
                "desc": "Vector evidence key test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("the owner creates an enabled agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(
        ["read".to_owned(), "vault.settings.set".to_owned()]
            .into_iter()
            .chain(lines.iter().cloned())
            .collect(),
    );
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner mints the agent a Grant");
    assert!(minted.grant.confers, "the Grant confers");
    agent
}

#[test]
fn an_agents_floors_wait_for_the_owner_and_judge_nothing() {
    let fixture = Fixture::open();
    let agent = agent_holding(&fixture, &[set_line(KEY)]);
    let outcome = fixture
        .set(
            SettingCaller::Agent(agent),
            SPACE,
            Some(json!({ "floor": 0.15, "strong": 0.25 })),
        )
        .expect("the agent's change answers");
    assert!(
        matches!(outcome, SetSettingOutcome::Pending { .. }),
        "an agent's floors wait on the owner's answer: {outcome:?}"
    );
    assert!(
        !fixture.pack_finds_target(),
        "the space keeps the host's floors until the owner says yes"
    );
}

#[test]
fn the_floors_are_the_same_on_every_machine_of_the_vault() {
    let spec = spec_named(KEY).expect("the key is in the catalogue");
    assert_eq!(
        spec.sync,
        SettingSync::Vault,
        "a space's floors describe the model, the same on every machine"
    );
    let domain = spec.item.expect("one item per embedding space");
    assert!((domain.admits)(SPACE));
    assert!(!(domain.admits)("test/model"));
}

#[test]
fn a_row_with_no_space_is_refused() {
    let fixture = Fixture::open();
    let mut change = SetSetting::vault_value(KEY, json!({ "floor": 0.15, "strong": 0.25 }));
    change.item = None;
    let error = fixture
        .vault
        .set_setting(SettingCaller::Owner(&fixture.proof), change)
        .expect_err("a row with no item would judge every space");
    assert!(
        error.to_string().contains("one embedding space's own"),
        "the refusal names the reason: {error}"
    );
    assert!(
        !fixture.pack_finds_target(),
        "the vault's space keeps the host's floors"
    );
}

/// Review round 1 of #10562: the owner's standing approval does not cover the key. An agent whose
/// live owner Grant lists the key's widening line and the vault's scope line still waits on the
/// owner's answer to its change; on the base the change landed at once, as a standing widening.
#[test]
fn an_agent_with_the_owners_standing_approval_still_waits_for_the_owner() {
    let fixture = Fixture::open();
    let lines = [
        Some(widen_line(KEY)),
        widen_scope_line(&SettingScope::Vault),
    ];
    let agent = agent_holding(&fixture, &lines.into_iter().flatten().collect::<Vec<_>>());
    let outcome = fixture
        .set(
            SettingCaller::Agent(agent),
            SPACE,
            Some(json!({ "floor": 0.15, "strong": 0.25 })),
        )
        .expect("the agent's change answers");
    assert!(
        matches!(outcome, SetSettingOutcome::Pending { .. }),
        "a standing approval lands no floors: {outcome:?}"
    );
    assert!(!fixture.pack_finds_target());
}
