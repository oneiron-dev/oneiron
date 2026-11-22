//! DESIGN 15-setting-primitive, stage 7c-3d: a birth reads the owner's yeses it saw, and no other
//! (section 1.6, "A copy carries no value. It names the acts it copies, and it reads as they
//! read"; a later change of the default does not move a birth):
//! - an owner's yes the birth did not see (decided on the pack's yeses as they stood before the
//!   birth) lands the vault's default, and another machine still reads the born row at the
//!   default the birth copied, the one the yes's table held back;
//! - a birth made after a yes landed its source's default names that yes beside the pack's head,
//!   and another machine reads the yes's value;
//! - a birth names the yes of each table whose landing its source's row still stands on, the
//!   older table's beside the newest's;
//! - the fold counts a birth's yes name only where the act is live on the frontier of the table
//!   its row names, its row spells a table, and the birth names that pack's head too.
//!
//! "Another machine" here is this install after it forgets every row the projection wrote: it
//! holds the log and none of those rows, as a machine that took the log from another does. Its
//! pack layer, and the yeses landed there, stay: they are its own record of what it accepted.
//!
//! Test keys: `test.born_depth` (lower is stricter, default 10, strictest 0, vault and project;
//! born from `test.born_depth_default`), `test.born_depth_default` (vault, default 7). The
//! engine pack's door weighs a table whose default for `test.born_depth_default` is 9, looser:
//! it waits for a holder's yes.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! setting_birth_yes`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{ENGINE_PACK, ENGINE_PACK_VERSION, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    EnrolledMachine, PackHeadView, SettingFrontier, SlotName, apply_pack_defaults_at,
    enroll_machine_with_key, forget_projected_setting_rows, land_setting_copy_from,
    land_setting_pack_accept_from, pack_head_digest, setting_copy_names, setting_frontier_of,
    setting_pack_accept_frontier_of, setting_pack_accepts, setting_pack_heads,
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
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault whose install, the owner's own machine, carries acts: its engine acts (the
    /// pack's head, the births) stand with no owner key's proof (row CARRIER-OWNER-PROOF). Opened
    /// owned: the writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
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
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
            .expect("serving install profile");
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

    fn second_machine(&self, seed: u8) -> EnrolledMachine {
        enroll_machine_with_key(&self.vault, &self.owner_proof, seed).expect("enrolled")
    }

    /// The engine pack's door weighs a table whose default for `test.born_depth_default` is 9,
    /// looser than the 7 the vault accepted: the default waits for a holder's yes, and the door's
    /// head act holds the key. The table's digest.
    fn weighs_a_looser_default(&self) -> String {
        let applied = apply_pack_defaults_at(
            &self.vault,
            ENGINE_PACK,
            ENGINE_PACK_VERSION,
            &[(BORN_DEFAULT, json!(9))],
        )
        .expect("the pack door runs")
        .expect("new defaults");
        assert_eq!(applied.proposed, vec![BORN_DEFAULT.to_owned()]);
        assert_eq!(self.default_value(), json!(7));
        pack_head_digest(&self.vault, ENGINE_PACK)
            .expect("the head row reads")
            .expect("the door ran")
    }

    /// The engine pack's door weighs another table at the same version, whose default for
    /// `test.born_depth_default` is `value`, looser than the row the vault holds: the default
    /// waits for a holder's yes. The table's digest.
    fn weighs_another_table(&self, value: i64) -> String {
        let applied = apply_pack_defaults_at(
            &self.vault,
            ENGINE_PACK,
            ENGINE_PACK_VERSION,
            &[(BORN_DEFAULT, json!(value))],
        )
        .expect("the pack door runs")
        .expect("new defaults");
        assert_eq!(applied.proposed, vec![BORN_DEFAULT.to_owned()]);
        pack_head_digest(&self.vault, ENGINE_PACK)
            .expect("the head row reads")
            .expect("the door ran")
    }

    /// The vault's default of `test.born_depth_default`, as read here.
    fn default_value(&self) -> Value {
        invoke(&self.as_owner(), GET, json!({ "key": BORN_DEFAULT }))
            .unwrap_or_else(|error| panic!("{GET} answers: {error:?}"))["value"]
            .clone()
    }

    /// The owner's yes to the default of `test.born_depth_default` in the engine pack's table
    /// `table`, decided on `machine` on the yeses to that table as they stand now, and landed
    /// here: whether the fold here counts it.
    fn yes_on(&self, machine: &EnrolledMachine, table: &str, ts: u64) -> bool {
        let frontier =
            setting_pack_accept_frontier_of(&self.vault, (ENGINE_PACK, table)).expect("frontier");
        self.yes_signed_on(machine, (&frontier, table), ts)
    }

    /// [`Self::yes_on`], decided on `frontier`: the yeses to `table` as an earlier read found
    /// them.
    fn yes_signed_on(
        &self,
        machine: &EnrolledMachine,
        (frontier, table): (&SettingFrontier, &str),
        ts: u64,
    ) -> bool {
        land_setting_pack_accept_from(
            &self.vault,
            (machine, frontier),
            (ENGINE_PACK, ENGINE_PACK_VERSION, table, &[]),
            (self.owner, &[BORN_DEFAULT]),
            ts,
        )
        .expect("the act lands")
    }

    /// The owner's live yeses to the engine pack's table `table`.
    fn yeses(&self, table: &str) -> Vec<PackHeadView> {
        setting_pack_accepts(&self.vault, (ENGINE_PACK, table)).expect("the yeses read")
    }

    /// The engine pack's live head act the door appended.
    fn pack_head(&self) -> AuthorityEntryHash {
        let heads = setting_pack_heads(&self.vault, ENGINE_PACK).expect("the heads read");
        assert_eq!(heads.len(), 1, "{heads:?}");
        heads[0].act
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

    /// This install as another machine that took the log: every row the projection wrote is
    /// forgotten, then projected again from the log.
    fn as_another_machine(&self) {
        forget_projected_setting_rows(&self.vault).expect("the projected rows are forgotten");
        self.vault.project_settings().expect("the projection runs");
    }

    /// A birth of `project`'s row of `test.born_depth` naming `names`, signed by `machine` on the
    /// log as it stands and landed here as a peer's entry lands: whether the fold here counts it.
    /// An entry the log refuses outright counts for nothing either.
    fn birth_counts(
        &self,
        machine: &EnrolledMachine,
        project: EntityId,
        names: Vec<(SlotName<'_>, AuthorityEntryHash)>,
        ts: u64,
    ) -> bool {
        let frontier = setting_frontier_of(&self.vault, &[]).expect("frontier");
        matches!(
            land_setting_copy_from(
                &self.vault,
                machine,
                &frontier,
                &[(born_row(project), names)],
                ts
            ),
            Ok((_, true))
        )
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

/// A birth's name of the engine pack's row of `test.born_depth_default`: the pack's head where
/// `table` is `None`, an owner's yes to the table `table` spells otherwise.
fn pack_name(table: Option<&str>, act: AuthorityEntryHash) -> (SlotName<'_>, AuthorityEntryHash) {
    (
        (BORN_DEFAULT, table, SettingMode::Value, engine_scope()),
        act,
    )
}

#[test]
fn a_yes_the_birth_did_not_see_leaves_another_machines_born_row_at_the_default_it_copied() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x71);
    let table = fx.weighs_a_looser_default();
    // The other machine's yes is decided on the yeses to the table as they stand before the
    // birth: the birth does not see it, and it does not see the birth.
    let before = setting_pack_accept_frontier_of(&fx.vault, (ENGINE_PACK, &table))
        .expect("the yeses' frontier");
    let made = fx.new_project();
    let read = fx.born_at(made);
    assert_eq!(read["value"], json!(7), "{read}");
    assert_eq!(read["source"], source("seeded", made), "{read}");

    assert!(
        fx.yes_signed_on(&other, (&before, &table), T0 + 1),
        "counted"
    );
    assert_eq!(fx.default_value(), json!(9), "the yes lands here");
    let yeses = fx.yeses(&table);
    assert_eq!(yeses.len(), 1, "{yeses:?}");
    let names = fx.birth_names(made);
    assert!(
        names.iter().all(|(_, _, act)| *act != yeses[0].act),
        "{names:?}"
    );

    fx.as_another_machine();
    assert_eq!(fx.default_value(), json!(9), "its record keeps the yes");
    let read = fx.born_at(made);
    assert_eq!(
        read["value"],
        json!(7),
        "the birth copied the default the table held back: {read}"
    );
    assert_eq!(read["source"], source("seeded", made), "{read}");
}

#[test]
fn a_birth_after_a_yes_names_it_and_another_machine_reads_the_yes() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x72);
    let table = fx.weighs_a_looser_default();
    assert!(fx.yes_on(&other, &table, T0 + 1), "counted");
    assert_eq!(fx.default_value(), json!(9));
    let yeses = fx.yeses(&table);
    assert_eq!(yeses.len(), 1, "{yeses:?}");

    let made = fx.new_project();
    let read = fx.born_at(made);
    assert_eq!(read["value"], json!(9), "{read}");
    assert_eq!(read["source"], source("seeded", made), "{read}");
    let names = fx.birth_names(made);
    assert_eq!(names.len(), 2, "the pack's head and the yes: {names:?}");
    assert!(
        names.contains(&(BORN_DEFAULT.to_owned(), engine_scope(), yeses[0].act)),
        "{names:?}"
    );
    assert!(
        names.contains(&(BORN_DEFAULT.to_owned(), engine_scope(), fx.pack_head())),
        "{names:?}"
    );

    fx.as_another_machine();
    let read = fx.born_at(made);
    assert_eq!(read["value"], json!(9), "{read}");
    assert_eq!(read["source"], source("seeded", made), "{read}");
}

#[test]
fn a_birth_names_the_yes_of_each_table_whose_landing_its_sources_row_stands_on() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x74);
    let first = fx.weighs_a_looser_default();
    assert!(fx.yes_on(&other, &first, T0 + 1), "counted");
    assert_eq!(fx.default_value(), json!(9));
    let second = fx.weighs_another_table(11);
    assert_ne!(second, first);
    assert!(fx.yes_on(&other, &second, T0 + 2), "counted");
    assert_eq!(
        fx.default_value(),
        json!(11),
        "the newer yes lands on the older one"
    );
    let first_yes = fx.yeses(&first);
    let second_yes = fx.yeses(&second);
    assert_eq!(first_yes.len(), 1, "{first_yes:?}");
    assert_eq!(second_yes.len(), 1, "{second_yes:?}");

    let made = fx.new_project();
    let read = fx.born_at(made);
    assert_eq!(read["value"], json!(11), "{read}");
    let names = fx.birth_names(made);
    assert!(
        names.contains(&(BORN_DEFAULT.to_owned(), engine_scope(), second_yes[0].act)),
        "the newest table's yes: {names:?}"
    );
    assert!(
        names.contains(&(BORN_DEFAULT.to_owned(), engine_scope(), first_yes[0].act)),
        "the older table's yes, whose landing the newest one's stands on: {names:?}"
    );
    assert_eq!(names.len(), 3, "the pack's head and both yeses: {names:?}");

    fx.as_another_machine();
    let read = fx.born_at(made);
    assert_eq!(read["value"], json!(11), "{read}");
    assert_eq!(read["source"], source("seeded", made), "{read}");
}

#[test]
fn a_birth_counts_a_yes_name_only_live_on_its_tables_frontier_and_beside_its_packs_head() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x73);
    let table = fx.weighs_a_looser_default();
    assert!(fx.yes_on(&other, &table, T0 + 1), "counted");
    let yes = fx.yeses(&table)[0].act;
    let head = fx.pack_head();
    let fresh = EntityId::now();

    assert!(
        !fx.birth_counts(
            &other,
            fresh,
            vec![pack_name(None, head), pack_name(Some(&table), head)],
            T0 + 2
        ),
        "the pack's head named as a yes to its table"
    );
    assert!(
        !fx.birth_counts(
            &other,
            fresh,
            vec![pack_name(None, head), pack_name(Some("not-a-table"), yes)],
            T0 + 3
        ),
        "a yes name whose row spells no table"
    );
    assert!(
        !fx.birth_counts(&other, fresh, vec![pack_name(Some(&table), yes)], T0 + 4),
        "a yes name without its pack's head"
    );

    assert!(fx.birth_counts(
        &other,
        fresh,
        vec![pack_name(None, head), pack_name(Some(&table), yes)],
        T0 + 5
    ));
    fx.as_another_machine();
    let read = fx.born_at(fresh);
    assert_eq!(read["value"], json!(9), "{read}");
    assert_eq!(read["source"], source("seeded", fresh), "{read}");
}
