//! Design pass 34, section 3.2 (row L1; RULING L1-PACK-LAYER-READ = A, Engine 21:15 25 Nov): a
//! pack's table of setting defaults (`knowledge/setting-defaults.json`) is a preset for the
//! engine's settings, loaded and proven from an installed pack as the `engine` pack's own table
//! is:
//! - installing the pack proposes every default, tighter or not, and changes nothing in force;
//!   the owner's one yes lands them; an update proposes again and changes nothing in force;
//! - on a key that does not read met, the row the owner's yes wrote reads before the engine
//!   pack's; a key whose rows meet is never loosened by a pack;
//! - removing the pack closes its waiting proposal, and what the owner accepted stays;
//! - on a rooted vault the door's head act carries the installed table, and the owner's yes to
//!   it appends and lands;
//! - only a capability pack carries a table, never the `local` pack, and every key is one this
//!   build knows with a value its kind takes.
//!
//! On a tree without the facet the table file is plain pack data: the install proposes nothing,
//! so every test below fails where it reads the waiting proposal or the refused source.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test pack_setting_presets`
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{PackInstallDisposition, PackSource};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    PackHeadView, pack_head_digest, setting_pack_accepts, setting_pack_heads,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const ACCEPT: &str = "vault.settings.accept_defaults";
const T0: u64 = 1_790_000_000;
/// A cap whose rows meet: default 10, strictest 0, lower is tighter.
const CAP: &str = "test.ordered_cap";
/// A number whose rows do not meet: default 7.
const NUMBER: &str = "test.owner_number";
/// The preset pack.
const PACK: &str = "example.lanepreset";
/// Where a pack keeps its table of setting defaults (`pack_catalog::SETTING_DEFAULTS_FILE`),
/// named here as a pack author writes it.
const TABLE_FILE: &str = "knowledge/setting-defaults.json";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A vault with no authority root: one machine, opened owned so the owner's handle calls the
    /// owner verbs by name.
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
            owner,
            owner_proof,
        }
    }

    /// A rooted vault whose install, the owner's own machine, carries acts.
    fn rooted() -> Self {
        let fx = Self::unrooted();
        let issuer: HostSlipIssuer = fx.vault.bootstrap_host_slip_issuer().expect("host issuer");
        fx.vault.ensure_host_root_slip(&issuer).expect("host root");
        fx.vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        fx.vault
            .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
            .expect("serving install profile");
        fx
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner's put of version `version` of the preset pack, carrying `table`; it lands
    /// Active.
    fn put(&self, version: &str, table: &Value) {
        match self
            .vault
            .put_pack(&self.owner_proof, files(PACK, "capability", version, table))
        {
            Ok(PackInstallDisposition::Installed(receipt)) => assert_eq!(receipt.pack_name, PACK),
            other => panic!("the owner's put installs the data-only preset pack: {other:?}"),
        }
    }

    /// The preset pack's live head acts.
    fn heads(&self) -> Vec<PackHeadView> {
        setting_pack_heads(&self.vault, PACK).expect("the heads read")
    }
}

/// A data-only pack `name` of `kind` at `version`, whose one data file is `table`.
fn files(name: &str, kind: &str, version: &str, table: &Value) -> Vec<HubFile> {
    let manifest = format!(
        "---\nname: {name}\ndescription: A lane's preset for the engine's settings.\nversion: {version}\nkind: {kind}\n---\nA data-only pack: one table of setting defaults.\n"
    );
    vec![
        HubFile::new("PACK.md", manifest),
        HubFile::new(TABLE_FILE, table.to_string()),
    ]
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

/// The default the preset pack proposes for `key`, and the digest of its proposal.
fn waiting(memory: &Memory<'_>, key: &str) -> (Value, String) {
    let proposed = entry(memory, key)["proposed_default"].clone();
    assert_eq!(
        proposed["pack"],
        json!(PACK),
        "the preset pack proposes {key}"
    );
    let digest = proposed["proposal"]
        .as_str()
        .expect("a proposal waits")
        .to_owned();
    (proposed["value"].clone(), digest)
}

/// The owner's yes to the preset pack's waiting proposal `proposal`: the keys it landed, in name
/// order.
fn accept(memory: &Memory<'_>, proposal: &str) -> Vec<String> {
    let landed = call(
        memory,
        ACCEPT,
        json!({ "pack": PACK, "proposal": proposal }),
    );
    let mut keys: Vec<String> = landed["keys"]
        .as_array()
        .expect("the keys the yes landed")
        .iter()
        .map(|key| key.as_str().expect("a key").to_owned())
        .collect();
    keys.sort();
    keys
}

#[test]
fn a_pack_update_changes_no_value_in_force() {
    let fx = Fixture::unrooted();
    let owner = fx.as_owner();

    // The install proposes both defaults, the tighter cap too, and nothing in force moves.
    fx.put("1.0.0", &json!({ CAP: 5, NUMBER: 9 }));
    assert_eq!(value(&owner, CAP), json!(10));
    assert_eq!(value(&owner, NUMBER), json!(7));
    let (cap, proposal) = waiting(&owner, CAP);
    assert_eq!(cap, json!(5));
    assert_eq!(waiting(&owner, NUMBER), (json!(9), proposal.clone()));

    // The owner's one yes lands them.
    assert_eq!(accept(&owner, &proposal), [CAP, NUMBER]);
    assert_eq!(value(&owner, CAP), json!(5));
    assert_eq!(value(&owner, NUMBER), json!(9));

    // An update proposes again, a tighter cap too, and changes nothing in force.
    fx.put("1.1.0", &json!({ CAP: 3, NUMBER: 11 }));
    assert_eq!(value(&owner, CAP), json!(5), "no yes, no new cap");
    assert_eq!(value(&owner, NUMBER), json!(9), "no yes, no new number");
    let (cap, update) = waiting(&owner, CAP);
    assert_eq!(cap, json!(3));
    assert_ne!(update, proposal, "the update's proposal is a new one");
    assert_eq!(waiting(&owner, NUMBER), (json!(11), update));
}

#[test]
fn an_accepted_preset_value_reads_on_a_key_that_does_not_meet() {
    let fx = Fixture::unrooted();
    let owner = fx.as_owner();
    fx.put("1.0.0", &json!({ NUMBER: 9 }));
    let (_, proposal) = waiting(&owner, NUMBER);
    assert_eq!(accept(&owner, &proposal), [NUMBER]);
    // The engine pack still holds its row of 7; the owner's yes reads first.
    assert_eq!(value(&owner, NUMBER), json!(9));
}

#[test]
fn a_pack_never_loosens_a_key_whose_rows_meet() {
    let fx = Fixture::unrooted();
    let owner = fx.as_owner();
    fx.put("1.0.0", &json!({ CAP: 20 }));
    let (cap, proposal) = waiting(&owner, CAP);
    assert_eq!(cap, json!(20));
    assert_eq!(accept(&owner, &proposal), [CAP]);
    // The read is the meet of the pack's row and the engine pack's: still 10.
    assert_eq!(value(&owner, CAP), json!(10));
}

#[test]
fn a_removed_packs_proposal_closes_and_what_the_owner_accepted_stays() {
    let fx = Fixture::unrooted();
    let owner = fx.as_owner();
    fx.put("1.0.0", &json!({ NUMBER: 9 }));
    let (_, proposal) = waiting(&owner, NUMBER);
    accept(&owner, &proposal);
    fx.put("1.1.0", &json!({ NUMBER: 11 }));
    let (_, update) = waiting(&owner, NUMBER);

    fx.vault
        .remove_pack(&fx.owner_proof, PACK)
        .expect("the owner removes the pack");
    assert_eq!(entry(&owner, NUMBER)["proposed_default"], Value::Null);
    assert!(
        invoke(&owner, ACCEPT, json!({ "pack": PACK, "proposal": update })).is_err(),
        "no yes lands a default of a pack that is gone"
    );
    assert_eq!(value(&owner, NUMBER), json!(9));

    // Installed again, the pack proposes again.
    fx.put("1.1.0", &json!({ NUMBER: 11 }));
    assert_eq!(waiting(&owner, NUMBER).0, json!(11));
    assert_eq!(value(&owner, NUMBER), json!(9));
}

#[test]
fn on_a_rooted_vault_the_owners_yes_to_an_installed_table_appends_and_lands() {
    let fx = Fixture::rooted();
    let owner = fx.as_owner();
    fx.put("1.0.0", &json!({ NUMBER: 9 }));
    assert_eq!(fx.heads().len(), 1, "the door's head travels as one act");
    let digest = pack_head_digest(&fx.vault, PACK)
        .expect("the head row reads")
        .expect("the door weighed the installed table");

    let (_, proposal) = waiting(&owner, NUMBER);
    assert_eq!(accept(&owner, &proposal), [NUMBER]);
    assert_eq!(value(&owner, NUMBER), json!(9));
    assert_eq!(
        setting_pack_accepts(&fx.vault, (PACK, &digest))
            .expect("the yeses read")
            .len(),
        1,
        "the owner's yes is one act naming the installed table"
    );
}

#[test]
fn a_table_outside_a_capability_pack_or_with_an_unknown_key_or_value_refuses_the_source() {
    let table = json!({ NUMBER: 9 });
    assert!(PackSource::from_files(files(PACK, "capability", "1.0.0", &table)).is_ok());
    assert!(
        PackSource::from_files(files(PACK, "connector", "1.0.0", &table)).is_err(),
        "a table rides a capability pack"
    );
    assert!(
        PackSource::from_files(files("local", "capability", "1.0.0", &table)).is_err(),
        "the local pack carries no table"
    );
    assert!(
        PackSource::from_files(files(
            PACK,
            "capability",
            "1.0.0",
            &json!({ "test.no_such_key": 1 })
        ))
        .is_err(),
        "every key is one this build knows"
    );
    assert!(
        PackSource::from_files(files(
            PACK,
            "capability",
            "1.0.0",
            &json!({ NUMBER: "nine" })
        ))
        .is_err(),
        "every value is one its key's kind takes"
    );
    assert!(
        PackSource::from_files(files(PACK, "capability", "1.0.0", &json!([NUMBER, 9]))).is_err(),
        "the table is one JSON object"
    );
}
