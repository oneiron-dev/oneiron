//! DESIGN 15-setting-primitive, stage 7c-2: seeded and born (section 1.6, "Explicit against
//! seeded", "The no-op test is on the slot's own row", `born`, "What the empty slot gives").
//! - a new project starts with its row of a `born` key, copied from the key it names: a copy of
//!   the pack's default reads `seeded`, a copy of the owner's row reads as a row;
//! - the owner's set of the same value over a seeded row writes the act; the row becomes the
//!   owner's, the read says `row`, and the change row shows prior equal to value;
//! - a project with no row reads the strictest value, never the wider one;
//! - a wider row someone set decides only when it makes the value stricter, and one row someone
//!   set among the deciders makes the read explicit, even when a seeded row holds the value;
//! - a move carries a seeded row as seeded, and a row someone set as theirs.
//!
//! Test keys: `test.born_depth` (lower is stricter, default 10, strictest 0, vault and project;
//! born from `test.born_depth_default`), `test.born_depth_default` (vault, default 7).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_seeded`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{SetSetting, SetSettingOutcome, Setter, SettingCaller, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{carry_settings_between, setting_change};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
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
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// An owned vault with no authority root: one machine, whose new projects need no signed
    /// birth.
    fn open() -> Self {
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

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// A new project under `parent` (the vault's root project when `None`), through the project
    /// write door.
    fn new_project(&self, parent: Option<EntityId>) -> EntityId {
        let root = self.vault.root_project().expect("the vault's root project");
        let id = EntityId::now();
        let record = ProjectRecord::new(id, Some(parent.unwrap_or(root)), root, self.owner)
            .expect("a project record");
        self.vault
            .put_project(id, &record, self.vault.now_recorded_at())
            .expect("the project is written");
        id
    }

    fn owner_sets(&self, request: SetSetting) -> SetSettingOutcome {
        self.vault
            .set_setting(SettingCaller::Owner(&self.owner_proof), request)
            .expect("the owner's change")
    }

    /// The owner's value `value` on `scope`'s value row of `key`.
    fn owner_sets_at(&self, key: &str, scope: SettingScope, value: Value) -> SetSettingOutcome {
        self.owner_sets(SetSetting {
            scope,
            ..SetSetting::vault_value(key, value)
        })
    }

    /// `key` read by a reader that knows `lines`: a project, then its ancestors nearest first.
    fn get(&self, key: &str, lines: &[EntityId]) -> Value {
        let at = Value::Array(lines.iter().copied().map(project).collect());
        invoke(&self.as_owner(), GET, json!({ "key": key, "at": at }))
            .unwrap_or_else(|error| panic!("{GET} answers: {error:?}"))
    }
}

fn project(id: EntityId) -> Value {
    json!({ "kind": "project", "id": id.to_hex() })
}

fn source(from: &str, scope: Value) -> Value {
    json!({ "from": from, "scope": scope })
}

fn applied_sequence(outcome: &SetSettingOutcome) -> Option<u64> {
    let SetSettingOutcome::Applied { sequence, .. } = outcome else {
        panic!("an applied change: {outcome:?}");
    };
    *sequence
}

#[test]
fn a_new_project_starts_with_its_row_copied_from_the_default_and_reads_seeded() {
    let fx = Fixture::open();
    let made = fx.new_project(None);

    let read = fx.get(BORN, &[made]);
    assert_eq!(read["value"], json!(7), "the source's default: {read}");
    assert_eq!(read["source"], source("seeded", project(made)), "{read}");

    let vault = fx.get(BORN, &[]);
    assert_eq!(
        vault["value"],
        json!(10),
        "a read that names no project: {vault}"
    );
    assert_eq!(vault["source"], json!({ "from": "default" }), "{vault}");
}

#[test]
fn a_project_born_from_a_default_the_owner_set_reads_its_row() {
    let fx = Fixture::open();
    fx.owner_sets(SetSetting::vault_value(BORN_DEFAULT, json!(4)));
    let made = fx.new_project(None);

    let read = fx.get(BORN, &[made]);
    assert_eq!(read["value"], json!(4), "the owner's default: {read}");
    assert_eq!(read["source"], source("row", project(made)), "{read}");
}

#[test]
fn the_owners_equal_value_over_the_seeded_row_writes_and_the_row_becomes_the_owners() {
    let fx = Fixture::open();
    let made = fx.new_project(None);

    let outcome = fx.owner_sets_at(BORN, SettingScope::Project(made), json!(7));
    let sequence = applied_sequence(&outcome).expect("an equal value over a seeded row writes");
    let change = setting_change(&fx.vault, sequence)
        .expect("the change stream reads")
        .expect("the change stands");
    assert_eq!(change.setter, Setter::Owner);
    assert!(change.value.is_some(), "{change:?}");
    assert_eq!(change.prior, change.value, "prior equals value: {change:?}");

    let read = fx.get(BORN, &[made]);
    assert_eq!(read["value"], json!(7), "{read}");
    assert_eq!(read["source"], source("row", project(made)), "{read}");

    let again = fx.owner_sets_at(BORN, SettingScope::Project(made), json!(7));
    assert_eq!(
        applied_sequence(&again),
        None,
        "the owner's own row with that value writes nothing"
    );
}

#[test]
fn a_project_with_no_row_reads_the_strictest_value_never_the_wider_one() {
    let fx = Fixture::open();
    let made = fx.new_project(None);
    fx.owner_sets(SetSetting {
        scope: SettingScope::Project(made),
        value: None,
        ..SetSetting::vault_value(BORN, json!(0))
    });

    let read = fx.get(BORN, &[made]);
    assert_eq!(read["value"], json!(0), "strictest: {read}");
    assert_eq!(
        read["source"],
        source("unreadable", project(made)),
        "{read}"
    );

    fx.owner_sets(SetSetting::vault_value(BORN, json!(9)));
    let read = fx.get(BORN, &[made]);
    assert_eq!(
        read["value"],
        json!(0),
        "the vault's row stands in for no birth row: {read}"
    );
    let vault = fx.get(BORN, &[]);
    assert_eq!(vault["value"], json!(9), "the vault's own read: {vault}");
}

#[test]
fn a_wider_row_someone_set_decides_only_when_it_makes_the_value_stricter() {
    let fx = Fixture::open();
    let made = fx.new_project(None);

    fx.owner_sets(SetSetting::vault_value(BORN, json!(9)));
    let read = fx.get(BORN, &[made]);
    assert_eq!(read["value"], json!(7), "{read}");
    assert_eq!(
        read["source"],
        source("seeded", project(made)),
        "a looser vault row decides nothing: {read}"
    );

    fx.owner_sets(SetSetting::vault_value(BORN, json!(7)));
    let read = fx.get(BORN, &[made]);
    assert_eq!(
        read["source"],
        source("seeded", project(made)),
        "an equal vault row decides nothing: {read}"
    );

    fx.owner_sets(SetSetting::vault_value(BORN, json!(3)));
    let read = fx.get(BORN, &[made]);
    assert_eq!(read["value"], json!(3), "{read}");
    assert_eq!(
        read["source"],
        source("row", json!({ "kind": "vault" })),
        "a stricter vault row decides: {read}"
    );
}

#[test]
fn an_owners_row_below_keeps_the_read_explicit_when_a_seeded_parent_row_is_stricter() {
    let fx = Fixture::open();
    let parent = fx.new_project(None);
    let child = fx.new_project(Some(parent));
    fx.owner_sets_at(BORN, SettingScope::Project(child), json!(9));

    let read = fx.get(BORN, &[child, parent]);
    assert_eq!(
        read["value"],
        json!(7),
        "the parent's seeded row narrows: {read}"
    );
    assert_eq!(
        read["source"],
        source("row", project(parent)),
        "the owner's row on the child decided first, so the read is explicit: {read}"
    );

    let seeded = fx.new_project(Some(parent));
    let read = fx.get(BORN, &[seeded, parent]);
    assert_eq!(
        read["source"],
        source("seeded", project(seeded)),
        "every deciding row is a copy of the default: {read}"
    );
}

#[test]
fn a_move_carries_seeded_rows_as_seeded_and_a_row_someone_set_as_theirs() {
    let fx = Fixture::open();
    let parent = fx.new_project(None);
    let seeded = fx.new_project(Some(parent));
    assert_eq!(
        carry_settings_between(&fx.vault, seeded, &[seeded, parent], &[seeded])
            .expect("the move carries"),
        1,
        "the parent's row is carried"
    );
    let read = fx.get(BORN, &[seeded]);
    assert_eq!(read["value"], json!(7), "{read}");
    assert_eq!(
        read["source"],
        source("seeded", project(seeded)),
        "a carried copy of the default is seeded: {read}"
    );

    let set = fx.new_project(None);
    let moved = fx.new_project(Some(set));
    fx.owner_sets_at(BORN, SettingScope::Project(set), json!(5));
    carry_settings_between(&fx.vault, moved, &[moved, set], &[moved]).expect("the move carries");
    let read = fx.get(BORN, &[moved]);
    assert_eq!(read["value"], json!(5), "{read}");
    assert_eq!(
        read["source"],
        source("carried", project(moved)),
        "the owner's row, carried, decides: {read}"
    );
}
