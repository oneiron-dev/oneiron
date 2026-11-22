//! DESIGN 15-setting-primitive, stage 7c-2: what a thing of a `born` key reads before its row
//! arrives, and which keys may be born (section 1.6, `born`; "Fold states, and the read's
//! source": "Or a thing of a born key has no row yet ... standing: Pending; for the born thing
//! also source: Unreadable").
//! - a project with no row of a born key reads the strictest value, source unreadable at the
//!   project, standing pending; its own row reads settled;
//! - every born key in the catalogue starts at a project, from a vault key with no item that is
//!   not learned and not born itself, whose default its own type decodes and that names a
//!   strictest value, and names a strictest value itself.
//!
//! Its read door and the `born` field are new in this stage, so this file runs on the head only;
//! the red/green runs of the read are in `setting_seeded`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_born_pending`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::setting::{
    ScopeKind, SetSetting, SettingCaller, SettingScope, SettingSource, SettingStanding, catalogue,
    spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::setting::born_depth_read;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

const BORN: &str = "test.born_depth";
const T0: u64 = 1_790_000_000;

#[test]
fn a_project_with_no_row_of_a_born_key_reads_strictest_and_pending() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let root = vault.root_project().expect("the vault's root project");
    let made = EntityId::now();
    let record = ProjectRecord::new(made, Some(root), root, owner).expect("a project record");
    vault
        .put_project(made, &record, vault.now_recorded_at())
        .expect("the project is written");
    let at = [SettingScope::Project(made)];

    let born = born_depth_read(&vault, &at).expect("the read");
    assert_eq!(born.value, 7, "the birth row: {born:?}");
    assert_eq!(
        born.source,
        SettingSource::Seeded(SettingScope::Project(made))
    );
    assert_eq!(born.standing, SettingStanding::Settled);

    vault
        .set_setting(
            SettingCaller::Owner(&owner_proof),
            SetSetting {
                scope: SettingScope::Project(made),
                value: None,
                ..SetSetting::vault_value(BORN, json!(0))
            },
        )
        .expect("the owner clears the project's row");
    let missing = born_depth_read(&vault, &at).expect("the read");
    assert_eq!(missing.value, 0, "strictest: {missing:?}");
    assert_eq!(
        missing.source,
        SettingSource::Unreadable(SettingScope::Project(made))
    );
    assert_eq!(missing.revision, 0);
    assert_eq!(missing.standing, SettingStanding::Pending);

    let vault_read = born_depth_read(&vault, &[]).expect("the vault's read");
    assert_eq!(vault_read.value, 10);
    assert_eq!(vault_read.source, SettingSource::Default);
    assert_eq!(vault_read.standing, SettingStanding::Settled);
}

#[test]
fn every_born_key_starts_at_a_project_from_a_vault_key_whose_default_it_decodes() {
    let born: Vec<_> = catalogue()
        .into_iter()
        .filter(|spec| spec.born.is_some())
        .collect();
    assert!(
        born.iter().any(|spec| spec.name == BORN),
        "the test catalogue's born key is listed"
    );
    for spec in born {
        let from = spec.born.expect("a born key").from;
        let narrowest = ScopeKind::NARROWEST_FIRST
            .into_iter()
            .find(|kind| spec.scopes.contains(kind));
        assert_eq!(
            narrowest,
            Some(ScopeKind::Project),
            "`{}` is born at a project: the project doors write the row",
            spec.name
        );
        assert!(spec.item.is_none(), "`{}` is no family", spec.name);
        assert!(!spec.is_learned(), "`{}` is not learned", spec.name);
        assert!(
            spec.kind.strictest_value().expect("encodes").is_some(),
            "`{}` names the strictest value a thing with no row reads",
            spec.name
        );
        let source = spec_named(from).unwrap_or_else(|_| panic!("`{from}` is a catalogue key"));
        assert_eq!(
            source.scopes,
            &[ScopeKind::Vault],
            "`{from}` sits at the vault alone"
        );
        assert!(source.born.is_none(), "`{from}` is not born itself");
        assert!(source.item.is_none(), "`{from}` is no family");
        assert!(!source.is_learned(), "`{from}` is not learned");
        assert!(
            source.kind.strictest_value().expect("encodes").is_some(),
            "`{from}` names a strictest value, so a row of it that does not read leaves the \
             birth pending and never fails the project's creation"
        );
        let default = source.kind.default_value().expect("the default encodes");
        assert!(
            spec.kind.decodes(&default),
            "`{}` decodes `{from}`'s default",
            spec.name
        );
    }
}
