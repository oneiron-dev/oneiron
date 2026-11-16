//! Restriction wave 5, C127 (Engine RULING 03:31, RESTRICTION-WAVE-5-ASK (3) = A): how long a
//! room-wide offer card with no fixed deadline stays open with no engagement is the owner's
//! `genui.room_offer.idle_secs`, the ruled day (OF-530 = A) by default.
//! - the key moved: a card quiet for 25 hours still reads open where the owner gave three days;
//! - the default: a card reads open 23 hours after its last engagement and aged out at 24.
//!
//! Fixture: the vault's owner hosts a group room; a custom agent, made through the
//! agent-definition door and given the room read as `agent_room_offer` gives it, mints its
//! room-wide card at T0. The owner's offer listing reads the card's state.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test room_offer_idle_setting_key`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{OfferDraft, OfferState, OffersRequest};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

const T0: u64 = 1_790_000_000;
const HOUR: u64 = 60 * 60;
const IDLE: &str = "genui.room_offer.idle_secs";

/// The shipped default policy pack, whose manifest the agent's room read is added to.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

/// A rooted vault on a clock the test moves, its embedded owner, a group room the owner created
/// and so hosts, and a custom agent that reads the room.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    room: EntityId,
    agent: EntityId,
}

impl Fixture {
    fn open() -> Self {
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
        let receipt = vault
            .memory(owner, EdgeActorClass::Human)
            .conversations_create(&ConversationCreateInput {
                id: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body: json!({
                    "v": 1,
                    "kind": "group",
                    "member_ids": [owner.to_hex()],
                    "title": "idle offer room",
                }),
                text: None,
            })
            .expect("group room");
        let room = EntityId::from_hex(&receipt.id).expect("room id");
        let agent = create_agent(&vault, owner);
        permit_room_reads(&vault, agent);
        Self {
            vault,
            clock,
            _dir: dir,
            owner,
            room,
            agent,
        }
    }

    /// The owner sets `key` vault-wide to `value`; the change applies at once.
    fn owner_sets(&self, key: &str, value: serde_json::Value) {
        let proof = self
            .vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("owner proof");
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&proof),
                SetSetting::vault_value(key, value),
            )
            .unwrap_or_else(|error| panic!("the owner sets {key}: {error:?}"));
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change of {key} applies at once: {outcome:?}"
        );
    }

    /// The agent's room-wide card, with no fixed deadline, minted now.
    fn mint_card(&self) {
        self.vault
            .memory(self.agent, EdgeActorClass::Agent)
            .rooms_offer(&OfferDraft {
                room: self.room,
                branch: None,
                agent: self.agent,
                what: "Summarise the open questions in this room.".to_owned(),
                artifact_ref: Some("artifact:open-questions".to_owned()),
                spend_scope: None,
                until: None,
                intent_key: "idle-offer-1".to_owned(),
            })
            .expect("the agent mints its room-wide card");
    }

    /// The agent's room-wide card as the owner's offer listing reads it now.
    fn card_state(&self) -> OfferState {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_offers(&OffersRequest {
                room: self.room,
                branch: None,
                after: None,
                limit: None,
            })
            .expect("the owner lists the room's cards")
            .rows
            .into_iter()
            .find(|card| card.agent == self.agent && card.branch.is_none())
            .expect("the agent's room-wide card is listed")
            .state
    }
}

/// A custom agent made through the agent-definition door, as the owner.
fn create_agent(vault: &Vault, owner: EntityId) -> EntityId {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(json!({
        "agent_id": "idle-offer-agent",
        "display_name": "idle-offer-agent",
        "desc": "idle-offer-agent offers one artifact",
        "version": "1",
    }))
    .expect("agent definition");
    let host = vault.memory(owner, EdgeActorClass::Human);
    oneiron::verbs::create_agent_definition_as(
        vault,
        &host
            .embedded_owner("vault.agents.create")
            .expect("owner proof"),
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )
    .expect("agent created");
    agent
}

/// Lets `agent` read the vault's room records: one actor-bound `core:read` row added to the
/// shipped policy manifest, its other rows kept (as `agent_room_offer` does).
fn permit_room_reads(vault: &Vault, agent: EntityId) {
    let mut shipped = None;
    for id in vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("manifests")
    {
        let Some(bytes) = vault.get(&id).expect("manifest bytes") else {
            continue;
        };
        let manifest: serde_json::Value = rmp_serde::from_slice(&bytes).expect("manifest");
        if manifest["pack_id"] == SHIPPED_POLICY_PACK {
            shipped = Some((id, manifest));
            break;
        }
    }
    let (id, mut manifest) = shipped.expect("the vault holds the shipped policy manifest");
    let mut read = Scope::top();
    read.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    manifest["scoped_grants"]
        .as_array_mut()
        .expect("scoped grants")
        .push(json!({
            "actor_ref": agent.to_hex(),
            "effector": "core:read",
            "scope": read,
            "receipt_required": false,
            "selectors": {"entity_types": [ENTITY_TYPE_CONVERSATION]},
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("manifest bytes"),
    )
    .expect("room read granted");
}

#[test]
fn a_room_wide_card_the_owner_gave_three_days_is_still_open_after_a_quiet_day() {
    let fx = Fixture::open();
    fx.owner_sets(IDLE, json!(3 * 24 * HOUR));
    fx.mint_card();

    fx.clock.set(T0 + 25 * HOUR);
    assert!(
        matches!(fx.card_state(), OfferState::Open { .. }),
        "a card the owner gave three days is open 25 hours after its last engagement"
    );
}

#[test]
fn a_room_wide_card_by_default_ages_out_a_day_after_its_last_engagement() {
    let fx = Fixture::open();
    fx.mint_card();

    fx.clock.set(T0 + 23 * HOUR);
    assert!(
        matches!(fx.card_state(), OfferState::Open { .. }),
        "a default card is open 23 hours after its last engagement"
    );
    fx.clock.set(T0 + 24 * HOUR);
    assert_eq!(
        fx.card_state(),
        OfferState::AgedOut,
        "a default card ages out a day after its last engagement"
    );
}
