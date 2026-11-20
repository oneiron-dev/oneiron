//! DESIGN 15-setting-primitive, stage 7c-3a "the pack head travels" (section 1.6, "Packs across
//! machines"):
//! - on a rooted vault, the pack door's update appends one head act in its own write: the
//!   pack's version, the digest of its defaults, and the keys it held at their earlier accepted
//!   value; a later update's act replaces it;
//! - a vault with no authority root is one machine: its door appends nothing, and its head row
//!   keeps the version it acted under;
//! - an older build never proposes its older defaults back: the door does not act for a version
//!   older than its head's, and acts for an equal version with other defaults;
//! - another machine's head changes no row here and holds no door back, even when it ships this
//!   build's defaults under a newer version: a reader proves a version only by its own build.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! setting_pack_head`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{ENGINE_PACK, ENGINE_PACK_VERSION, PackApplied};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    EnrolledMachine, PackHeadView, apply_pack_defaults_at, enroll_machine_with_key,
    land_setting_pack_head_from, pack_head_digest, pack_head_version, setting_pack_frontier_of,
    setting_pack_heads,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const T0: u64 = 1_790_000_000;
/// An ordered key whose default is 10; a lower cap is tighter.
const CAP: &str = "test.ordered_cap";

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

    /// `machine`'s head act for the engine pack, on its acts as they stand now: whether the fold
    /// here counts it.
    fn head_from(&self, machine: &EnrolledMachine, (version, digest): (&str, &str)) -> bool {
        let frontier = setting_pack_frontier_of(&self.vault, ENGINE_PACK).expect("frontier");
        land_setting_pack_head_from(
            &self.vault,
            machine,
            &frontier,
            (ENGINE_PACK, version, digest, &[CAP]),
            T0,
        )
        .expect("the act lands")
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn cap(memory: &Memory<'_>) -> Value {
    call(memory, GET, json!({ "key": CAP }))["value"].clone()
}

/// `vault.settings.list`'s entry for `CAP`.
fn cap_entry(memory: &Memory<'_>) -> Value {
    let listed = call(memory, LIST, json!({ "prefix": CAP }));
    listed["keys"]
        .as_array()
        .expect("the list's keys")
        .iter()
        .find(|entry| entry["key"] == CAP)
        .cloned()
        .unwrap_or_else(|| panic!("the list names {CAP}"))
}

#[test]
fn an_update_on_a_rooted_vault_appends_one_head_act_with_its_version_digest_and_held_keys() {
    let fx = Fixture::rooted();
    // The door ran at open, before the vault had a root: no act names that run.
    assert_eq!(fx.heads(), Vec::new());

    let applied = fx
        .update_at(ENGINE_PACK_VERSION, &[(CAP, json!(20))])
        .expect("new defaults");
    assert_eq!(applied.proposed, vec![CAP.to_owned()]);
    let heads = fx.heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert_eq!(heads[0].version, ENGINE_PACK_VERSION);
    assert_eq!(heads[0].digest, fx.digest());
    assert_eq!(heads[0].held, vec![CAP.to_owned()]);

    // The next update saw that act: its own replaces it, and it holds nothing back.
    let applied = fx
        .update_at(ENGINE_PACK_VERSION, &[(CAP, json!(5))])
        .expect("new defaults");
    assert_eq!(applied.moved, vec![CAP.to_owned()]);
    let heads = fx.heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert_eq!(heads[0].digest, fx.digest());
    assert_eq!(heads[0].held, Vec::<String>::new());
    assert_eq!(cap(&fx.as_owner()), json!(5));
}

#[test]
fn an_unrooted_vault_appends_no_head_act_and_keeps_the_version_it_acted_under() {
    let fx = Fixture::unrooted();
    assert_eq!(fx.version(), ENGINE_PACK_VERSION);

    let applied = fx
        .update_at("0.2.0", &[(CAP, json!(5))])
        .expect("new defaults");
    assert_eq!(applied.moved, vec![CAP.to_owned()]);
    assert_eq!(fx.heads(), Vec::new());
    assert_eq!(fx.version(), "0.2.0");
    assert_eq!(cap(&fx.as_owner()), json!(5));
}

#[test]
fn an_older_build_does_not_propose_its_older_defaults_back() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    fx.update_at("0.2.0", &[(CAP, json!(5))])
        .expect("a newer build's defaults");
    let weighed = fx.digest();

    // An older build ships the older, looser default: its door does not act, so nothing is
    // proposed and no act is appended.
    assert_eq!(fx.update_at("0.1.0", &[(CAP, json!(20))]), None);
    assert_eq!(cap(&owner), json!(5));
    assert!(cap_entry(&owner).get("proposed_default").is_none());
    assert_eq!(fx.digest(), weighed);
    assert_eq!(fx.version(), "0.2.0");
    let heads = fx.heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert_eq!(heads[0].version, "0.2.0");

    // A build of the same version with other defaults acts: versions tell releases apart.
    let applied = fx
        .update_at("0.2.0", &[(CAP, json!(4))])
        .expect("the same version's other defaults");
    assert_eq!(applied.moved, vec![CAP.to_owned()]);
    // A newer build's looser default is weighed, and waits for a holder.
    let applied = fx
        .update_at("0.3.0", &[(CAP, json!(20))])
        .expect("a newer build's defaults");
    assert_eq!(applied.proposed, vec![CAP.to_owned()]);
    assert_eq!(cap(&owner), json!(4));
    assert_eq!(fx.version(), "0.3.0");
}

#[test]
fn another_machines_head_changes_no_row_here_and_holds_no_door_back() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    let other = fx.second_machine(7);
    let shipped = fx.digest();

    // This build's own defaults under a newer version: the table is the one this build ships,
    // but a version is proved only by a build that runs it.
    assert!(fx.head_from(&other, ("9.0.0", &shipped)), "counted");
    // A table this build does not ship.
    assert!(fx.head_from(&other, ("9.0.0", &"ab".repeat(32))), "counted");
    assert_eq!(fx.heads().len(), 1, "the second act saw the first");
    assert_eq!(cap(&owner), json!(10));
    assert!(cap_entry(&owner).get("proposed_default").is_none());
    assert_eq!(fx.version(), ENGINE_PACK_VERSION);
    assert_eq!(fx.digest(), shipped);

    // The door still acts for this build's version, and its act replaces the other machine's.
    let applied = fx
        .update_at(ENGINE_PACK_VERSION, &[(CAP, json!(5))])
        .expect("new defaults");
    assert_eq!(applied.moved, vec![CAP.to_owned()]);
    assert_eq!(cap(&owner), json!(5));
    let heads = fx.heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert_eq!(heads[0].version, ENGINE_PACK_VERSION);
    assert_eq!(heads[0].digest, fx.digest());
}
