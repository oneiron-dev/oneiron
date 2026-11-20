//! DESIGN 15-setting-primitive, stage 7c-3c "the owner's yes travels, and the table beside"
//! (section 1.5, "A holder's yes replaces the rows"; section 1.6, "Packs across machines"):
//! - on a rooted vault, the owner's yes to a pack's held defaults appends one act with his act,
//!   naming the table's digest and the keys he accepts, on a target of its own per pack and
//!   table, so the pack door's head stays; the table's bytes are beside the head;
//! - another machine's yes to the table this install weighed lands its keys here as the owner's,
//!   and this install's waiting proposal closes;
//! - a yes to a newer table of the `engine` pack proves that table: this install weighs it from
//!   the bytes beside the act, as a build that ships it would (its tighter default lands, and the
//!   head takes the newer version, so the older build's door acts no more), and the yes's keys
//!   land;
//! - while those bytes have not arrived every row reads as before the yes, and their arrival lands
//!   it; bytes that are not the named table make each key the yes accepts read its strictest
//!   value;
//! - a yes to an older table changes nothing here: this install's own proposal waits;
//! - a yes that came before this install's door weighed its table lands when the door weighs it,
//!   and the door's head then holds nothing back;
//! - a vault with no authority root is one machine: its yes appends nothing.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! setting_pack_accept`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{ENGINE_PACK, ENGINE_PACK_VERSION, PackApplied, Setter};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    EnrolledMachine, PackHeadView, apply_pack_defaults_at, enroll_machine_with_key,
    land_pack_table, land_setting_pack_accept_from, pack_head_digest, pack_head_version,
    pack_row_revision, pack_table_here, pack_table_of, setting_change,
    setting_pack_accept_frontier_of, setting_pack_accepts, setting_pack_heads,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const ACCEPT: &str = "vault.settings.accept_defaults";
const T0: u64 = 1_790_000_000;
/// An ordered key whose default is 10 and strictest value 0; a lower cap is tighter.
const CAP: &str = "test.ordered_cap";
/// Another ordered key whose default is 10; a lower budget is tighter.
const BUDGET: &str = "test.work_budget";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    issuer: Option<HostSlipIssuer>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A vault with no authority root: one machine. Opened owned: the writer lease is what lets
    /// the owner's handle call the owner verbs by name.
    fn unrooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            issuer: None,
            owner,
            owner_proof,
        }
    }

    /// A rooted vault whose install carries acts.
    fn rooted() -> Self {
        let mut fx = Self::unrooted();
        let issuer = fx.vault.bootstrap_host_slip_issuer().expect("host issuer");
        fx.vault.ensure_host_root_slip(&issuer).expect("host root");
        fx.vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        fx.vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        fx.issuer = Some(issuer);
        fx
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// Another of the owner's own machines.
    fn second_machine(&self, seed: u8) -> EnrolledMachine {
        assert!(self.issuer.is_some(), "a rooted vault enrols machines");
        enroll_machine_with_key(&self.vault, &self.owner_proof, seed).expect("enrolled")
    }

    /// The engine pack's door over `defaults`, as a build that ships `version` of the pack runs
    /// it: what it did, or `None` when it did not act.
    fn update_at(&self, version: &str, defaults: &[(&str, Value)]) -> Option<PackApplied> {
        apply_pack_defaults_at(&self.vault, ENGINE_PACK, version, defaults)
            .expect("the pack door runs")
    }

    /// The engine pack's live head acts.
    fn heads(&self) -> Vec<PackHeadView> {
        setting_pack_heads(&self.vault, ENGINE_PACK).expect("the heads read")
    }

    /// The owner's live yeses to defaults of the engine pack's table `digest`.
    fn accepts(&self, digest: &str) -> Vec<PackHeadView> {
        setting_pack_accepts(&self.vault, (ENGINE_PACK, digest)).expect("the yeses read")
    }

    /// The version the engine pack's head row keeps.
    fn version(&self) -> String {
        pack_head_version(&self.vault, ENGINE_PACK)
            .expect("the head row reads")
            .expect("the door ran at open")
    }

    /// The digest of the defaults the engine pack's door last weighed here.
    fn digest(&self) -> String {
        pack_head_digest(&self.vault, ENGINE_PACK)
            .expect("the head row reads")
            .expect("the door ran at open")
    }

    /// The owner's yes to the engine pack's defaults `accepted` of the table `digest` names
    /// under `version`, decided on `machine` and landed here on the pack's acts as they stand
    /// now: whether the fold here counts it.
    fn yes_from(
        &self,
        machine: &EnrolledMachine,
        (version, digest): (&str, &str),
        accepted: &[&str],
    ) -> bool {
        let frontier =
            setting_pack_accept_frontier_of(&self.vault, (ENGINE_PACK, digest)).expect("frontier");
        land_setting_pack_accept_from(
            &self.vault,
            (machine, &frontier),
            (ENGINE_PACK, version, digest, &[]),
            (self.owner, accepted),
            T0,
        )
        .expect("the act lands")
    }

    /// Lands `pack`'s table of `defaults` beside its head acts, as a peer's row arrives; its
    /// digest.
    fn table_arrives(&self, defaults: &[(&str, Value)]) -> String {
        let (digest, bytes) = pack_table_of(ENGINE_PACK, defaults).expect("the table encodes");
        land_pack_table(&self.vault, (ENGINE_PACK, &digest), &bytes).expect("the row lands");
        digest
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn value(memory: &Memory<'_>, key: &str) -> Value {
    call(memory, GET, json!({ "key": key }))["value"].clone()
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

/// The digest of the proposal that waits for `CAP`'s new default.
fn waiting_proposal(memory: &Memory<'_>) -> String {
    entry(memory, CAP)["proposed_default"]["proposal"]
        .as_str()
        .expect("a proposal waits")
        .to_owned()
}

#[test]
fn the_owners_yes_on_a_rooted_vault_appends_one_head_act_naming_its_table_and_keys() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    let applied = fx
        .update_at(ENGINE_PACK_VERSION, &[(CAP, json!(20))])
        .expect("new defaults");
    assert_eq!(applied.proposed, vec![CAP.to_owned()]);
    let table = fx.digest();

    let accepted = call(
        &owner,
        ACCEPT,
        json!({ "pack": ENGINE_PACK, "proposal": waiting_proposal(&owner) }),
    );
    assert_eq!(accepted, json!({ "keys": [CAP] }));
    assert_eq!(value(&owner, CAP), json!(20));

    // One yes, the owner's, to the table the door weighed; the door's head stays.
    let yeses = fx.accepts(&table);
    assert_eq!(yeses.len(), 1, "{yeses:?}");
    assert_eq!(yeses[0].owner, Some(fx.owner));
    assert_eq!(yeses[0].accepted, vec![CAP.to_owned()]);
    assert_eq!(yeses[0].held, Vec::<String>::new());
    assert_eq!(yeses[0].digest, table);
    assert_eq!(yeses[0].version, ENGINE_PACK_VERSION);
    let heads = fx.heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert_eq!(heads[0].owner, None);
    assert_eq!(heads[0].digest, table);

    // The table the yes names is beside it.
    let (digest, bytes) = pack_table_of(ENGINE_PACK, &[(CAP, json!(20))]).expect("encodes");
    assert_eq!(digest, table);
    assert_eq!(
        pack_table_here(&fx.vault, (ENGINE_PACK, &table)).expect("the row reads"),
        Some(bytes)
    );
}

#[test]
fn a_peers_yes_to_the_table_this_install_weighed_lands_its_key_as_the_owners() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    let other = fx.second_machine(7);
    fx.update_at(ENGINE_PACK_VERSION, &[(CAP, json!(20))])
        .expect("new defaults");
    assert_eq!(value(&owner, CAP), json!(10));
    assert_eq!(entry(&owner, CAP)["proposed_default"]["value"], json!(20));

    // The other machine's door weighed the same table, and the owner said yes there.
    assert!(
        fx.yes_from(&other, (ENGINE_PACK_VERSION, &fx.digest()), &[CAP]),
        "counted"
    );
    assert_eq!(value(&owner, CAP), json!(20));
    let listed = entry(&owner, CAP);
    assert_eq!(listed["accepted_default"], json!(20));
    assert!(listed.get("proposed_default").is_none(), "{listed}");
    let revision = pack_row_revision(&fx.vault, CAP, ENGINE_PACK)
        .expect("the layer reads")
        .expect("a readable layer row");
    let change = setting_change(&fx.vault, revision)
        .expect("the change stream reads")
        .expect("the change stands");
    assert_eq!(change.setter, Setter::Pack);
    assert_eq!(change.by, Some(fx.owner));
}

#[test]
fn a_peers_yes_to_a_newer_engine_table_lands_from_the_table_beside_it() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    let other = fx.second_machine(7);
    fx.update_at("1.0.0", &[(CAP, json!(10)), (BUDGET, json!(10))])
        .expect("this build's defaults");

    // A newer build loosens the cap and tightens the budget; its door held the cap, and the
    // owner said yes to it there. The table's bytes arrive beside the act.
    let table = fx.table_arrives(&[(CAP, json!(20)), (BUDGET, json!(5))]);
    assert_eq!(
        value(&owner, CAP),
        json!(10),
        "a table alone proves nothing"
    );
    assert!(fx.yes_from(&other, ("2.0.0", &table), &[CAP]), "counted");

    assert_eq!(value(&owner, CAP), json!(20), "the owner's yes");
    assert_eq!(
        value(&owner, BUDGET),
        json!(5),
        "the proved table's tighter default"
    );
    assert_eq!(fx.version(), "2.0.0");
    assert_eq!(fx.digest(), table);
    assert!(entry(&owner, CAP).get("proposed_default").is_none());

    // This build's door acts no more: the head this install proved is newer.
    assert_eq!(
        fx.update_at("1.0.0", &[(CAP, json!(10)), (BUDGET, json!(10))]),
        None
    );
    assert_eq!(value(&owner, CAP), json!(20));
}

#[test]
fn a_yes_to_a_newer_table_whose_bytes_have_not_arrived_lands_when_they_do() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    let other = fx.second_machine(7);
    fx.update_at("1.0.0", &[(CAP, json!(10))])
        .expect("this build's defaults");
    let (table, bytes) = pack_table_of(ENGINE_PACK, &[(CAP, json!(20))]).expect("encodes");

    assert!(fx.yes_from(&other, ("2.0.0", &table), &[CAP]), "counted");
    assert_eq!(value(&owner, CAP), json!(10), "as before the yes");
    assert_eq!(fx.version(), "1.0.0");

    land_pack_table(&fx.vault, (ENGINE_PACK, &table), &bytes).expect("the row lands");
    assert_eq!(value(&owner, CAP), json!(20));
    assert_eq!(fx.version(), "2.0.0");
}

#[test]
fn a_newer_table_beside_a_yes_that_is_not_the_named_table_reads_strictest() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    let other = fx.second_machine(7);
    fx.update_at("1.0.0", &[(CAP, json!(10))])
        .expect("this build's defaults");
    let (table, _) = pack_table_of(ENGINE_PACK, &[(CAP, json!(20))]).expect("encodes");
    let (_, other_bytes) = pack_table_of(ENGINE_PACK, &[(CAP, json!(30))]).expect("encodes");
    land_pack_table(&fx.vault, (ENGINE_PACK, &table), &other_bytes).expect("the row lands");

    assert!(fx.yes_from(&other, ("2.0.0", &table), &[CAP]), "counted");
    let read = call(&owner, GET, json!({ "key": CAP }));
    assert_eq!(read["value"], json!(0), "the key's strictest value");
    assert_eq!(
        read["source"],
        json!({ "from": "unreadable", "scope": { "kind": "pack", "id": ENGINE_PACK } })
    );
    assert_eq!(fx.version(), "1.0.0", "no table was weighed");
}

#[test]
fn a_peers_yes_to_an_older_table_changes_nothing_here() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    let other = fx.second_machine(7);
    fx.update_at("2.0.0", &[(CAP, json!(30))])
        .expect("this build's defaults");
    let older = fx.table_arrives(&[(CAP, json!(20))]);

    assert!(fx.yes_from(&other, ("1.0.0", &older), &[CAP]), "counted");
    assert_eq!(value(&owner, CAP), json!(10));
    assert_eq!(fx.version(), "2.0.0");
    assert_eq!(entry(&owner, CAP)["proposed_default"]["value"], json!(30));
}

#[test]
fn a_yes_that_came_before_this_installs_door_weighed_its_table_lands_when_it_does() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    let other = fx.second_machine(7);
    fx.update_at("1.0.0", &[(CAP, json!(10))])
        .expect("this build's defaults");
    let (table, _) = pack_table_of(ENGINE_PACK, &[(CAP, json!(20))]).expect("encodes");

    // The other machine runs another build of the same version: no version here proves its
    // table, so its yes waits.
    assert!(fx.yes_from(&other, ("1.0.0", &table), &[CAP]), "counted");
    assert_eq!(value(&owner, CAP), json!(10));

    // This install's door weighs that table: the yes lands the default it would hold back, and
    // the door's head holds nothing.
    let applied = fx
        .update_at("1.0.0", &[(CAP, json!(20))])
        .expect("the same version's other defaults");
    assert_eq!(applied.moved, vec![CAP.to_owned()]);
    assert!(applied.proposed.is_empty(), "{applied:?}");
    assert_eq!(value(&owner, CAP), json!(20));
    assert!(entry(&owner, CAP).get("proposed_default").is_none());
    let heads = fx.heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert_eq!(heads[0].digest, table);
    assert_eq!(heads[0].held, Vec::<String>::new());
}

#[test]
fn an_unrooted_vaults_yes_appends_nothing_and_lands_here() {
    let fx = Fixture::unrooted();
    let owner = fx.as_owner();
    fx.update_at(ENGINE_PACK_VERSION, &[(CAP, json!(20))])
        .expect("new defaults");

    let accepted = call(
        &owner,
        ACCEPT,
        json!({ "pack": ENGINE_PACK, "proposal": waiting_proposal(&owner) }),
    );
    assert_eq!(accepted, json!({ "keys": [CAP] }));
    assert_eq!(value(&owner, CAP), json!(20));
    assert_eq!(fx.heads(), Vec::new());
}
