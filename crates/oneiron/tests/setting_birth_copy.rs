//! DESIGN 15-setting-primitive, stage 7c-3b: a project's birth travels as a copy (section 1.6,
//! `born` and "A copy carries no value"):
//! - on a rooted vault the door that creates a project appends one engine copy whose row is the
//!   project's own row of a `born` key, naming the source key's heads: the live acts of its vault
//!   row and the engine pack's head act (appended first where none of this install's table is
//!   live);
//! - another machine reads the copy as the named acts read there: a copy of the owner's row reads
//!   as a row, a copy of the pack's default reads seeded;
//! - a machine whose pack head names another table cannot prove the named one: the project reads
//!   strictest until it can;
//! - the fold counts a birth only as the first act on its row and only when it names the source's
//!   live heads; a birth that copies another key than the one `born` names reads strictest;
//! - a vault with no authority root appends nothing: the row is this install's alone;
//! - a clear beside a set on the source's vault row gives the default there, so a birth of that
//!   row reads the set met with the default, on every machine;
//! - a birth names each pack that holds the source or none: where one has no head act to name,
//!   the row is this install's alone, since a part of the layer reads looser than the whole.
//!
//! "Another machine" here is this install after it forgets every row the projection wrote: it
//! holds the log and none of those rows, as a machine that took the log from another does.
//!
//! Test keys: `test.born_depth` (lower is stricter, default 10, strictest 0, vault and project;
//! born from `test.born_depth_default`), `test.born_depth_default` (vault, default 7),
//! `test.ordered_cap` (vault and project, default 10). Test pack: `test.pre_version`, whose door
//! ran with no version before the vault had a root, so no head act can name it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! setting_birth_copy`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{
    ENGINE_PACK, ENGINE_PACK_VERSION, SetSetting, SettingCaller, SettingMode, SettingScope,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    EnrolledMachine, SlotName, apply_pack_defaults_at, enroll_machine_with_key,
    forget_projected_setting_rows, land_setting_act_from, land_setting_copy_from, pack_head_digest,
    setting_copy_names, setting_frontier_of, setting_pack_heads, setting_slot_heads,
};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_authority::authority::AuthorityEntryHash;
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const BORN: &str = "test.born_depth";
const BORN_DEFAULT: &str = "test.born_depth_default";
const CAP: &str = "test.ordered_cap";
const PRE_VERSION_PACK: &str = "test.pre_version";
const T0: u64 = 1_790_000_000;

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

    /// A rooted vault whose install carries acts. Its pack door ran at open, before the root:
    /// no head act names that run.
    fn rooted() -> Self {
        let mut fx = Self::unrooted();
        fx.root();
        fx
    }

    /// Gives the vault its authority root, and this install the identities that carry acts.
    fn root(&mut self) {
        let issuer = self
            .vault
            .bootstrap_host_slip_issuer()
            .expect("host issuer");
        self.vault
            .ensure_host_root_slip(&issuer)
            .expect("host root");
        self.vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        self.vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        self.issuer = Some(issuer);
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn second_machine(&self, seed: u8) -> EnrolledMachine {
        assert!(self.issuer.is_some(), "a rooted vault enrols machines");
        enroll_machine_with_key(&self.vault, &self.owner_proof, seed).expect("enrolled")
    }

    /// A new project under the vault's root project, through the project write door.
    fn new_project(&self) -> EntityId {
        let root = self.vault.root_project().expect("the vault's root project");
        let id = EntityId::now();
        let record =
            ProjectRecord::new(id, Some(root), root, self.owner).expect("a project record");
        self.vault
            .put_project(id, &record, self.vault.now_recorded_at())
            .expect("the project is written");
        id
    }

    /// The owner's value `value` on the vault's row of `key`.
    fn owner_sets(&self, key: &str, value: Value) {
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting::vault_value(key, value),
            )
            .expect("the owner's change");
    }

    /// `test.born_depth` read by a reader that knows `project`.
    fn born_at(&self, project: EntityId) -> Value {
        let at = json!([project_ref(project)]);
        invoke(&self.as_owner(), GET, json!({ "key": BORN, "at": at }))
            .unwrap_or_else(|error| panic!("{GET} answers: {error:?}"))
    }

    /// What the live copy on `project`'s row of `test.born_depth` names: each row's key and
    /// scope, and the act.
    fn birth_names(&self, project: EntityId) -> Vec<(String, SettingScope, AuthorityEntryHash)> {
        setting_copy_names(&self.vault, born_row(project)).expect("the copy's names read")
    }

    /// The live acts on the vault's row of `test.born_depth_default`.
    fn source_heads(&self) -> Vec<AuthorityEntryHash> {
        setting_slot_heads(
            &self.vault,
            (BORN_DEFAULT, None, SettingMode::Value, SettingScope::Vault),
        )
        .expect("the source's heads read")
    }

    /// This install as another machine that took the log: every row the projection wrote is
    /// forgotten, then projected again from the log.
    fn as_another_machine(&self) {
        forget_projected_setting_rows(&self.vault).expect("the projected rows are forgotten");
        self.vault.project_settings().expect("the projection runs");
    }

    /// A birth of `project`'s row of `test.born_depth`, signed by `machine` and landed here as a
    /// peer's entry lands, naming `names` (each a row of `key` at a scope, and an act): whether
    /// the fold here counts it.
    fn birth_from(
        &self,
        machine: &EnrolledMachine,
        project: EntityId,
        (key, names): (&str, &[(SettingScope, AuthorityEntryHash)]),
        ts: u64,
    ) -> bool {
        let frontier = setting_frontier_of(&self.vault, &[]).expect("frontier");
        let names: Vec<(SlotName<'_>, AuthorityEntryHash)> = names
            .iter()
            .map(|(scope, act)| ((key, None, SettingMode::Value, scope.clone()), *act))
            .collect();
        land_setting_copy_from(
            &self.vault,
            machine,
            &frontier,
            &[(born_row(project), names)],
            ts,
        )
        .expect("the copy lands")
        .1
    }
}

fn born_row(project: EntityId) -> SlotName<'static> {
    (
        BORN,
        None,
        SettingMode::Value,
        SettingScope::Project(project),
    )
}

fn project_ref(id: EntityId) -> Value {
    json!({ "kind": "project", "id": id.to_hex() })
}

fn source(from: &str, project: EntityId) -> Value {
    json!({ "from": from, "scope": project_ref(project) })
}

fn engine_scope() -> SettingScope {
    SettingScope::Pack(ENGINE_PACK.to_owned())
}

/// The engine pack's head act a birth of `project` names.
fn pack_head_named(fx: &Fixture, project: EntityId) -> AuthorityEntryHash {
    fx.birth_names(project)
        .into_iter()
        .find(|(_, scope, _)| *scope == engine_scope())
        .map(|(_, _, act)| act)
        .expect("the birth names the engine pack's head")
}

#[test]
fn a_birth_names_the_owners_vault_row_and_the_pack_head_and_another_machine_reads_it_as_a_row() {
    let fx = Fixture::rooted();
    assert_eq!(
        setting_pack_heads(&fx.vault, ENGINE_PACK).expect("heads"),
        Vec::new()
    );
    fx.owner_sets(BORN_DEFAULT, json!(5));
    let source_act = fx.source_heads();
    assert_eq!(source_act.len(), 1, "the owner's act on the source");

    let made = fx.new_project();
    let read = fx.born_at(made);
    assert_eq!(read["value"], json!(5), "{read}");
    assert_eq!(read["source"], source("row", made), "{read}");

    let heads = setting_slot_heads(&fx.vault, born_row(made)).expect("heads");
    assert_eq!(heads.len(), 1, "one birth: {heads:?}");
    let names = fx.birth_names(made);
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names.contains(&(BORN_DEFAULT.to_owned(), SettingScope::Vault, source_act[0])),
        "the source's vault act: {names:?}"
    );
    pack_head_named(&fx, made);
    // The door appended this install's head, since none was live.
    let pack_heads = setting_pack_heads(&fx.vault, ENGINE_PACK).expect("heads");
    assert_eq!(pack_heads.len(), 1, "{pack_heads:?}");
    assert_eq!(
        Some(pack_heads[0].digest.clone()),
        pack_head_digest(&fx.vault, ENGINE_PACK).expect("the head row reads"),
    );

    fx.as_another_machine();
    let read = fx.born_at(made);
    assert_eq!(
        read["value"],
        json!(5),
        "the copy reads as the owner's act: {read}"
    );
    assert_eq!(read["source"], source("row", made), "{read}");
}

#[test]
fn a_birth_from_the_packs_default_travels_seeded() {
    let fx = Fixture::rooted();
    let made = fx.new_project();
    let read = fx.born_at(made);
    assert_eq!(read["value"], json!(7), "{read}");
    assert_eq!(read["source"], source("seeded", made), "{read}");
    let names = fx.birth_names(made);
    assert_eq!(names.len(), 1, "only the pack's head: {names:?}");
    assert_eq!(names[0].1, engine_scope(), "{names:?}");

    // A second birth names the same head: no other act is appended.
    let second = fx.new_project();
    assert_eq!(pack_head_named(&fx, second), pack_head_named(&fx, made));
    assert_eq!(
        setting_pack_heads(&fx.vault, ENGINE_PACK)
            .expect("heads")
            .len(),
        1
    );

    fx.as_another_machine();
    for project in [made, second] {
        let read = fx.born_at(project);
        assert_eq!(read["value"], json!(7), "{read}");
        assert_eq!(read["source"], source("seeded", project), "{read}");
    }
}

#[test]
fn a_machine_whose_head_names_another_table_reads_the_birth_strictest_until_it_proves_it() {
    let fx = Fixture::rooted();
    let made = fx.new_project();
    assert_eq!(fx.born_at(made)["value"], json!(7));

    // This install's door now weighs other defaults: its head names another table.
    let applied = apply_pack_defaults_at(
        &fx.vault,
        ENGINE_PACK,
        ENGINE_PACK_VERSION,
        &[(BORN_DEFAULT, json!(3))],
    )
    .expect("the pack door runs")
    .expect("new defaults");
    assert_eq!(applied.moved, vec![BORN_DEFAULT.to_owned()]);

    fx.as_another_machine();
    let read = fx.born_at(made);
    assert_eq!(
        read["value"],
        json!(0),
        "the named table is not proved here: {read}"
    );
    assert_eq!(read["source"], source("unreadable", made), "{read}");

    // A project born under the new table names its head, which this install proves.
    let later = fx.new_project();
    assert_ne!(pack_head_named(&fx, later), pack_head_named(&fx, made));
    fx.as_another_machine();
    let read = fx.born_at(later);
    assert_eq!(read["value"], json!(3), "{read}");
    assert_eq!(read["source"], source("seeded", later), "{read}");
}

#[test]
fn a_birth_counts_only_as_the_first_act_on_its_row() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x62);
    let made = fx.new_project();
    let names: Vec<(SettingScope, AuthorityEntryHash)> = fx
        .birth_names(made)
        .into_iter()
        .map(|(_, scope, act)| (scope, act))
        .collect();

    assert!(
        !fx.birth_from(&other, made, (BORN_DEFAULT, &names), T0),
        "a second birth on a row that has an act"
    );
    assert_eq!(
        setting_slot_heads(&fx.vault, born_row(made))
            .expect("heads")
            .len(),
        1
    );

    // The same names on a project with no act on its row count.
    let fresh = EntityId::now();
    assert!(fx.birth_from(&other, fresh, (BORN_DEFAULT, &names), T0 + 1));
    fx.vault.project_settings().expect("the projection runs");
    let read = fx.born_at(fresh);
    assert_eq!(read["value"], json!(7), "{read}");
    assert_eq!(read["source"], source("seeded", fresh), "{read}");
}

#[test]
fn a_birth_counts_only_when_it_names_the_sources_live_heads() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x63);
    fx.owner_sets(BORN_DEFAULT, json!(5));
    let replaced = fx.source_heads()[0];
    let made = fx.new_project();
    let pack = (engine_scope(), pack_head_named(&fx, made));
    fx.owner_sets(BORN_DEFAULT, json!(4));
    let live = fx.source_heads();
    assert_eq!(live.len(), 1);
    assert_ne!(live[0], replaced);

    let fresh = EntityId::now();
    let stale = [(SettingScope::Vault, replaced), pack.clone()];
    assert!(
        !fx.birth_from(&other, fresh, (BORN_DEFAULT, &stale), T0),
        "a replaced act of the source"
    );
    let short = [pack.clone()];
    assert!(
        !fx.birth_from(&other, fresh, (BORN_DEFAULT, &short), T0 + 1),
        "a birth that leaves out the source's live act"
    );
    let heads = [(SettingScope::Vault, live[0]), pack];
    assert!(fx.birth_from(&other, fresh, (BORN_DEFAULT, &heads), T0 + 2));
    fx.vault.project_settings().expect("the projection runs");
    let read = fx.born_at(fresh);
    assert_eq!(read["value"], json!(4), "{read}");
    assert_eq!(read["source"], source("row", fresh), "{read}");
}

#[test]
fn a_birth_that_copies_another_key_than_born_names_reads_strictest() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x64);
    let made = fx.new_project();
    let pack = (engine_scope(), pack_head_named(&fx, made));

    // The heads of another key: no act on its vault row, and the engine pack's head.
    let fresh = EntityId::now();
    assert!(
        fx.birth_from(&other, fresh, (CAP, &[pack]), T0),
        "the fold does not read the catalogue: the names are that key's heads"
    );
    fx.vault.project_settings().expect("the projection runs");
    let read = fx.born_at(fresh);
    assert_eq!(read["value"], json!(0), "{read}");
    assert_eq!(read["source"], source("unreadable", fresh), "{read}");
}

#[test]
fn a_vault_with_no_root_appends_no_birth() {
    let fx = Fixture::unrooted();
    let made = fx.new_project();
    let read = fx.born_at(made);
    assert_eq!(read["value"], json!(7), "{read}");
    assert_eq!(read["source"], source("seeded", made), "{read}");
    assert_eq!(
        setting_slot_heads(&fx.vault, born_row(made)).expect("heads"),
        Vec::new()
    );
    assert_eq!(
        setting_pack_heads(&fx.vault, ENGINE_PACK).expect("heads"),
        Vec::new()
    );
}

#[test]
fn a_birth_of_a_set_beside_a_clear_on_the_vault_row_reads_their_meet_with_the_default() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x65);
    let vault_row = (BORN_DEFAULT, None, SettingMode::Value, SettingScope::Vault);
    let empty = setting_frontier_of(&fx.vault, &[vault_row.clone()]).expect("frontier");
    fx.owner_sets(BORN_DEFAULT, json!(9));
    // Another machine's clear, signed before it saw the owner's 9: the two stand side by side,
    // and the row reads 9 met with the default 7 the clear gives.
    land_setting_act_from(&fx.vault, &other, fx.owner, &empty, vault_row, None, T0)
        .expect("the clear lands");
    assert_eq!(fx.source_heads().len(), 2, "the set and the clear");

    let made = fx.new_project();
    let read = fx.born_at(made);
    assert_eq!(read["value"], json!(7), "{read}");
    assert_eq!(read["source"], source("row", made), "{read}");
    let names = fx.birth_names(made);
    assert_eq!(names.len(), 3, "both acts and the pack's head: {names:?}");

    fx.as_another_machine();
    let read = fx.born_at(made);
    assert_eq!(
        read["value"],
        json!(7),
        "the clear gives the default, never no bound: {read}"
    );
    assert_eq!(read["source"], source("row", made), "{read}");
}

#[test]
fn a_birth_whose_source_a_pack_with_no_head_act_holds_stays_on_this_install() {
    let mut fx = Fixture::unrooted();
    apply_pack_defaults_at(&fx.vault, PRE_VERSION_PACK, "", &[(BORN_DEFAULT, json!(3))])
        .expect("the pack door runs")
        .expect("new defaults");
    fx.root();

    let made = fx.new_project();
    let read = fx.born_at(made);
    assert_eq!(
        read["value"],
        json!(3),
        "the layer's meet of the engine's 7 and the pack's 3: {read}"
    );
    assert_eq!(read["source"], source("seeded", made), "{read}");
    assert_eq!(
        setting_slot_heads(&fx.vault, born_row(made)).expect("heads"),
        Vec::new(),
        "a birth naming the engine pack alone would read 7"
    );
}
