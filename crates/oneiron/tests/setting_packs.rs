//! DESIGN 15-setting-primitive, stage 6.0 part 2: the default layer.
//! - a fresh vault accepts this build's defaults at open, writing no change row, and a read with
//!   no deciding row starts there; the engine pack does not run again for the same build;
//! - a tighter default replaces the accepted one, receipted `tighter` by the pack;
//! - a looser default leaves every read as it was and waits in a proposal; the owner's yes lands
//!   it, receipted `looser` and naming the owner; a second yes, or an agent's, is refused;
//! - a yes over a default that moved since, or to a proposal a newer update replaced, is refused;
//! - a lost accepted default reads strictest, and the pack door does not repair it;
//! - the owner's vault value reads over any default;
//! - on a key with no order every changed default is a proposal; on a neutral key it lands.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_packs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{ChangeDirection, ENGINE_PACK, Setter, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    apply_engine_pack, apply_pack_defaults, lose_pack_row, pack_row_revision,
    plant_undecodable_row, setting_change,
};
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const SET: &str = "vault.settings.set";
const ACCEPT: &str = "vault.settings.accept_defaults";
const T0: u64 = 1_790_000_000;
const CAP: &str = "test.ordered_cap";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
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
            _issuer: issuer,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// An enabled, active agent definition the owner creates.
    fn agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("setting-agent-{}", id.to_hex()),
                    "desc": "setting primitive fixture",
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

    /// The pack door over `defaults`, as an update of `pack`.
    fn update(&self, pack: &str, defaults: &[(&str, Value)]) -> oneiron::setting::PackApplied {
        apply_pack_defaults(&self.vault, pack, defaults)
            .expect("the pack door runs")
            .expect("the defaults are new to the head")
    }

    /// The change that wrote `key`'s row in the engine pack's layer.
    fn layer_change(&self, key: &str) -> oneiron::setting::SettingChange {
        let revision = pack_row_revision(&self.vault, key, ENGINE_PACK)
            .expect("the layer reads")
            .expect("a readable layer row");
        setting_change(&self.vault, revision)
            .expect("the change stream reads")
            .expect("the change stands")
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> String {
    format!(
        "{:?}",
        invoke(memory, verb, input).expect_err("the call is refused")
    )
}

fn get(memory: &Memory<'_>, key: &str) -> Value {
    call(memory, GET, json!({ "key": key }))
}

/// `vault.settings.list`'s entry for `key`.
fn entry(memory: &Memory<'_>, key: &str) -> Value {
    let listed = call(memory, LIST, json!({ "prefix": key }));
    listed["keys"]
        .as_array()
        .expect("the list's keys")
        .iter()
        .find(|entry| entry["key"] == key)
        .cloned()
        .unwrap_or_else(|| panic!("the list names {key}"))
}

fn engine_scope() -> SettingScope {
    SettingScope::Pack(ENGINE_PACK.to_owned())
}

#[test]
fn a_fresh_vault_accepts_the_build_defaults_at_open_and_reads_start_there() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();

    let listed = entry(&owner, CAP);
    assert_eq!(listed["default"], json!(10));
    assert_eq!(listed["accepted_default"], json!(10));
    assert!(listed.get("proposed_default").is_none(), "{listed}");
    assert!(
        listed["rows"].as_array().expect("rows").is_empty(),
        "a pack's row is no stored choice: {listed}"
    );
    let read = get(&owner, CAP);
    assert_eq!(read["value"], json!(10));
    assert_eq!(read["source"], json!({ "from": "default" }));

    // A first default is no move: the open wrote no change row, and the row's revision is 0.
    assert_eq!(
        pack_row_revision(&fx.vault, CAP, ENGINE_PACK).expect("the layer reads"),
        Some(0)
    );
    assert!(
        setting_change(&fx.vault, 1)
            .expect("the change stream reads")
            .is_none(),
        "a fresh vault's open writes no setting change"
    );
    // The same build does not weigh its defaults twice.
    assert_eq!(apply_engine_pack(&fx.vault).expect("the engine pack"), None);
}

#[test]
fn a_tighter_default_replaces_the_accepted_one_receipted_tighter_by_the_pack() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();

    let applied = fx.update(ENGINE_PACK, &[(CAP, json!(5))]);
    assert_eq!(applied.moved, vec![CAP.to_owned()]);
    assert!(applied.proposed.is_empty() && applied.lost.is_empty());

    let read = get(&owner, CAP);
    assert_eq!(read["value"], json!(5));
    assert_eq!(read["source"], json!({ "from": "default" }));
    assert_eq!(entry(&owner, CAP)["accepted_default"], json!(5));
    let change = fx.layer_change(CAP);
    assert_eq!(change.direction, Some(ChangeDirection::Tighter));
    assert_eq!(change.setter, Setter::Pack);
    assert_eq!(change.scope, engine_scope());
    assert_eq!(change.by, None);
}

#[test]
fn a_looser_default_waits_for_the_owners_yes_and_lands_once_receipted_looser() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();

    let applied = fx.update(ENGINE_PACK, &[(CAP, json!(20))]);
    assert_eq!(applied.proposed, vec![CAP.to_owned()]);
    assert!(applied.moved.is_empty());
    // Every read is as it was: the accepted default stays.
    assert_eq!(get(&owner, CAP)["value"], json!(10));
    let listed = entry(&owner, CAP);
    assert_eq!(listed["accepted_default"], json!(10));
    let proposed = &listed["proposed_default"];
    assert_eq!(proposed["pack"], json!(ENGINE_PACK));
    assert_eq!(proposed["value"], json!(20));
    assert_eq!(proposed["direction"], json!("looser"));
    let proposal = proposed["proposal"]
        .as_str()
        .expect("a proposal digest")
        .to_owned();

    // No agent says yes for the owner.
    let agent = fx.agent();
    let agent_memory = fx.vault.memory(agent, EdgeActorClass::Agent);
    refused(
        &agent_memory,
        ACCEPT,
        json!({ "pack": ENGINE_PACK, "proposal": proposal }),
    );
    assert_eq!(get(&owner, CAP)["value"], json!(10));

    let accepted = call(
        &owner,
        ACCEPT,
        json!({ "pack": ENGINE_PACK, "proposal": proposal }),
    );
    assert_eq!(accepted, json!({ "keys": [CAP] }));
    assert_eq!(get(&owner, CAP)["value"], json!(20));
    let listed = entry(&owner, CAP);
    assert_eq!(listed["accepted_default"], json!(20));
    assert!(listed.get("proposed_default").is_none(), "{listed}");
    let change = fx.layer_change(CAP);
    assert_eq!(change.direction, Some(ChangeDirection::Looser));
    assert_eq!(change.setter, Setter::Pack);
    assert_eq!(change.by, Some(fx.owner));

    let again = refused(
        &owner,
        ACCEPT,
        json!({ "pack": ENGINE_PACK, "proposal": proposal }),
    );
    assert!(again.contains("no waiting proposal"), "{again}");
}

#[test]
fn a_yes_over_a_default_that_moved_or_to_a_replaced_proposal_is_refused() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();

    fx.update(ENGINE_PACK, &[(CAP, json!(20))]);
    let first = entry(&owner, CAP)["proposed_default"]["proposal"]
        .as_str()
        .expect("a proposal")
        .to_owned();
    // A newer update replaces the waiting proposal: the older one is no longer the pack's.
    fx.update(ENGINE_PACK, &[(CAP, json!(30))]);
    let second = entry(&owner, CAP)["proposed_default"]["proposal"]
        .as_str()
        .expect("a proposal")
        .to_owned();
    assert_ne!(first, second);
    let replaced = refused(
        &owner,
        ACCEPT,
        json!({ "pack": ENGINE_PACK, "proposal": first }),
    );
    assert!(replaced.contains("no waiting proposal"), "{replaced}");

    // The accepted row changes under the waiting proposal: the yes lands nothing.
    plant_undecodable_row(&fx.vault, CAP, engine_scope()).expect("a damaged layer row");
    let moved = refused(
        &owner,
        ACCEPT,
        json!({ "pack": ENGINE_PACK, "proposal": second }),
    );
    assert!(moved.contains("moved since proposal"), "{moved}");
    assert_eq!(
        get(&owner, CAP)["value"],
        json!(0),
        "the damaged row reads strictest"
    );
}

#[test]
fn a_lost_accepted_default_reads_strictest_and_the_pack_door_does_not_repair_it() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();

    lose_pack_row(&fx.vault, CAP, ENGINE_PACK).expect("the row is lost");
    let read = get(&owner, CAP);
    assert_eq!(read["value"], json!(0), "the key's strictest value");
    assert_eq!(
        read["source"],
        json!({ "from": "unreadable", "scope": { "kind": "pack", "id": ENGINE_PACK } })
    );
    assert_eq!(entry(&owner, CAP)["accepted_default"], Value::Null);

    let applied = fx.update(ENGINE_PACK, &[(CAP, json!(10))]);
    assert_eq!(applied.lost, vec![CAP.to_owned()]);
    assert!(applied.landed.is_empty() && applied.moved.is_empty());
    assert_eq!(get(&owner, CAP)["value"], json!(0));
}

#[test]
fn the_owners_vault_value_reads_over_any_default() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();

    let set = call(
        &owner,
        SET,
        json!({ "key": CAP, "scope": { "kind": "vault" }, "value": 8 }),
    );
    assert_eq!(set["status"], json!("applied"), "{set}");
    fx.update(ENGINE_PACK, &[(CAP, json!(3))]);
    assert_eq!(entry(&owner, CAP)["accepted_default"], json!(3));
    let read = get(&owner, CAP);
    assert_eq!(read["value"], json!(8));
    assert_eq!(
        read["source"],
        json!({ "from": "row", "scope": { "kind": "vault" } })
    );

    // On a key that reads one row, too, and through an accepted looser default.
    let number = "test.owner_number";
    call(
        &owner,
        SET,
        json!({ "key": number, "scope": { "kind": "vault" }, "value": 9 }),
    );
    fx.update(ENGINE_PACK, &[(number, json!(1))]);
    let proposal = entry(&owner, number)["proposed_default"]["proposal"]
        .as_str()
        .expect("a proposal")
        .to_owned();
    call(
        &owner,
        ACCEPT,
        json!({ "pack": ENGINE_PACK, "proposal": proposal }),
    );
    assert_eq!(entry(&owner, number)["accepted_default"], json!(1));
    assert_eq!(get(&owner, number)["value"], json!(9));
}

#[test]
fn a_key_with_no_order_proposes_every_changed_default_and_a_neutral_key_takes_it() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();

    let number = "test.class_number";
    let label = "test.neutral_label";
    let label_default = entry(&owner, label)["default"].clone();
    let applied = fx.update(
        ENGINE_PACK,
        &[(number, json!(3)), (label, json!("renamed"))],
    );
    assert_eq!(applied.proposed, vec![number.to_owned()]);
    assert_eq!(applied.moved, vec![label.to_owned()]);

    // A smaller number is no safer on a key with no order: it waits, and the read is unchanged.
    assert_eq!(get(&owner, number)["value"], json!(7));
    assert_eq!(
        entry(&owner, number)["proposed_default"]["direction"],
        json!("unordered")
    );
    // A label guards nothing: its new default lands, receipted neutral.
    assert_ne!(label_default, json!("renamed"));
    assert_eq!(get(&owner, label)["value"], json!("renamed"));
    assert_eq!(
        fx.layer_change(label).direction,
        Some(ChangeDirection::Neutral)
    );
}
