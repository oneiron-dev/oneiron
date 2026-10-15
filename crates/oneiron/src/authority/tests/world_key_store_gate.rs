//! The store gate knows this branch's authority shapes as the fold does, and
//! no wider (Astra #1422e F1; the Engine's ruling). A machine's install key,
//! which signs no roster row, stores that machine's key records as it stores
//! its settings edits. A root record's own anchor stores it, and that anchor
//! then stores its machine marks, locally and through sync; it never signs
//! a roster row. Each check fails before: the gate vouched for a settings
//! edit's install key alone, and learned no anchor.
use super::machine_identity::host;
use super::support::authority_key_from_ed;
use super::world_key_doors::{enrol_own, fresh_install, key_records, set};
use super::world_privacy::{edit_by, land, settings, stored_entries, world_row};
use super::world_reissue::{admit, issue, sync};
use super::*;
use crate::Vault;
use crate::error::ErrorKind;
use crate::world_keys::WorldKeyStatus;

const HERE: EditOrigin = EditOrigin::ThisMachine;
const AT: TimeRange = TimeRange { start: 3, end: 3 };

fn install_signing(vault: &Vault) -> ed25519_dalek::SigningKey {
    let txn = vault.store.env.read_txn().unwrap();
    crate::identity::read_machine_signing_key_in_txn(vault, &txn)
        .unwrap()
        .unwrap()
}

fn put_replicated(vault: &Vault, entry: &AuthorityLogEntry) -> crate::error::Result<()> {
    vault
        .batch()
        .put_replicated(
            &authority_log_entity_id(entry)?,
            ENTITY_TYPE_AUTHORITY_LOG,
            AT,
            3,
            &encode_authority_log_entry_body(entry)?,
        )
        .commit()
}

/// The settings door's ensure step stores the world's key record, which
/// this machine's install key signs alone. That key is no roster key.
#[test]
fn a_machines_install_key_stores_its_worlds_key_record() {
    let host = host();
    let machine = enrol_own(&host);
    let world = world_row(&host);
    set(&host, world, ReadLocation::MyMachines);
    let fold = host.vault.authority_fold().unwrap();
    let install = authority_key_from_ed(&install_signing(&host.vault));
    assert!(!fold.roster.contains_key(&install));
    let key = fold.current_world_key(world).unwrap();
    assert!(key.signers.contains(&machine));
    let records = key_records(&host.vault, world);
    assert!(!records.is_empty());
    assert!(records.iter().all(|record| record.machine == machine));
}

/// `ensure_world_key` on a private world whose settings edit is stored and
/// that has no key yet stores the record it mints.
#[test]
fn ensure_stores_a_key_for_a_stored_private_world() {
    let host = host();
    let machine = enrol_own(&host);
    let world = world_row(&host);
    let signing = install_signing(&host.vault);
    let edit = edit_by(
        &host,
        machine,
        &signing,
        world,
        settings(ReadLocation::MyMachines),
    );
    land(&host, &[edit]);
    assert!(
        host.vault
            .authority_fold()
            .unwrap()
            .current_world_key(world)
            .is_none()
    );
    let status = host.vault.ensure_world_key(&host.owner, world).unwrap();
    let WorldKeyStatus::Minted(id) = status else {
        panic!("a private world with no key mints one: {status:?}");
    };
    let fold = host.vault.authority_fold().unwrap();
    assert_eq!(fold.current_world_key(world).map(|key| key.id), Some(id));
}

/// The vault's first recovery root activates: its anchor stores the root
/// record it signs alone.
#[test]
fn the_first_recovery_root_activates() {
    let host = host();
    enrol_own(&host);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    host.vault
        .activate_owner_root(&host.owner, HERE, prepared, &BTreeSet::new())
        .unwrap();
    assert_eq!(host.vault.authority_fold().unwrap().root_anchors().len(), 1);
}

/// R's anchor marks a fresh install "yours" from R's own install, and a
/// third install stores the root and the mark through the replicated door.
#[test]
fn an_anchors_machine_mark_lands_locally_and_through_sync() {
    let host = host();
    let [issuer, a, peer] = [(); 3].map(|()| fresh_install(&host));
    let root = issue(&issuer, &[]);
    admit(&issuer, &root, &a);
    let held: BTreeSet<_> = stored_entries(&peer.vault)
        .iter()
        .map(|entry| authority_entry_hash(entry).unwrap())
        .collect();
    let rows: Vec<_> = stored_entries(&issuer.vault)
        .into_iter()
        .map(|entry| (authority_entry_hash(&entry).unwrap(), entry))
        .filter(|(hash, _)| !held.contains(hash))
        .collect();
    let staged: Vec<_> = rows.iter().map(|(hash, entry)| (*hash, entry)).collect();
    for index in crate::authority::authority_stage_order(&staged) {
        put_replicated(&peer.vault, &rows[index].1).unwrap();
    }
    let anchor = root.seed.anchor().verifying_key().to_bytes();
    let fold = peer.vault.authority_fold().unwrap();
    assert!(fold.root_anchors().contains_key(&anchor));
    assert!(
        fold.machine(a.machine())
            .is_some_and(|machine| machine.anchored.contains_key(&anchor))
    );
}

/// A fresh install restores the kit, and so anchors itself with R's seed:
/// it is mine under R.
#[test]
fn a_fresh_install_restores_the_kit_and_anchors_itself() {
    let host = host();
    let [issuer, install] = [(); 2].map(|()| fresh_install(&host));
    let root = issue(&issuer, &[]);
    sync(&issuer.vault, &install.vault);
    install
        .vault
        .restore_world_keys(&install.owner, HERE, &root.seed, None)
        .unwrap();
    let fold = install.vault.authority_fold().unwrap();
    assert!(fold.trusted_machine(install.machine()).is_some());
}

/// The negative check: an owner anchor's signature on a roster row, a slip
/// revocation, waits at the gate as unowned, locally and through sync.
#[test]
fn an_anchor_signs_no_roster_row() {
    let host = host();
    let issuer = fresh_install(&host);
    let root = issue(&issuer, &[]);
    let fold = issuer.vault.authority_fold().unwrap();
    let row = anchor_signed_entry(
        &fold,
        &root.seed.anchor(),
        AuthorityOp::SlipRevoke { slip_id: [7; 32] },
        2,
    )
    .unwrap();
    let local = issuer.vault.put_authority_log_entry(&row, AT, 3).map(drop);
    let replicated = put_replicated(&issuer.vault, &row);
    for result in [local, replicated] {
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::AuthorityLogSignerPending
        );
    }
}
