use super::*;
use crate::{EntityId, temporal::TimeRange};

#[test]
fn checkpoint_restore_binds_live_exterior_claim_keys_across_paths() {
    use crate::store::{GateDecisionId, GateDecisionRecord};
    let root = tempfile::tempdir().unwrap();
    let source_path = root.path().join("source");
    let source = Vault::open(&source_path, VaultConfig::device()).unwrap();
    let claim_id = [0xC1; 16];
    let decision = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: 40,
        outcome: "approved".into(),
        reason_codes: vec!["gate.test.checkpoint".into()],
        receipt_reasons: vec![],
        system_notices: vec![],
        actor_class: "agent".into(),
        actor_ref: Some("private-restore-receipt".into()),
        content_kind: "claim".into(),
        policy_manifest_version: "v0".into(),
        claim_id: Some(claim_id),
        grant_ref: None,
        diff_handle: vec![1],
        read_frontier_hash: [2; 32],
        redacted_at: None,
    };
    source
        .with_write_txn(|txn| source.store.append_gate_decision_in_txn(txn, &decision))
        .unwrap();
    let image = root.path().join("checkpoint");
    source.snapshot_checkpoint(&image, 100).unwrap();
    let key = root
        .path()
        .join(".source.gate-decision-keys")
        .join(crate::entity_id::bytes_to_hex_lower(&claim_id));
    let key_bytes = std::fs::read(&key).unwrap();
    assert!(
        !std::fs::read(&image)
            .unwrap()
            .windows(32)
            .any(|v| v == key_bytes)
    );
    let destination_parent = root.path().join("different-parent");
    std::fs::create_dir(&destination_parent).unwrap();
    let destination = destination_parent.join("different-name");
    let (restored, _) = Vault::restore_checkpoint(
        &image,
        &destination,
        VaultConfig::device(),
        RestoreReason::Restore,
        120,
    )
    .unwrap();
    assert!(restored.gate_decisions(100).unwrap().contains(&decision));
    drop(restored);
    // The image never carries a copy of this key. Removing CURRENT custody
    // makes a second restore fail rather than resurrecting the old receipt.
    std::fs::remove_file(key).unwrap();
    let invalid_image = root.path().join("no-key-checkpoint");
    assert!(source.snapshot_checkpoint(&invalid_image, 125).is_err());
    assert!(!invalid_image.exists());
    let refused = root.path().join("missing-live-key");
    assert!(
        Vault::restore_checkpoint(
            &image,
            &refused,
            VaultConfig::device(),
            RestoreReason::Migrate,
            130,
        )
        .is_err()
    );
    assert!(
        !refused.exists(),
        "restore must preflight before creating the destination"
    );
}

/// ARCH-0038 #erasure-completeness (REV-9 item 9): erase destroys the claim's
/// gate-decision key in the same act, so a pre-erase image restores as the
/// vault at that time without the receipts the erase redacted.
#[test]
fn erase_destroys_the_claim_key_so_a_pre_erase_image_restores_without_its_receipts() {
    use crate::store::{GateDecisionId, GateDecisionRecord};
    let root = tempfile::tempdir().unwrap();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let erased = EntityId::now();
    let kept = EntityId::now();
    for id in [erased, kept] {
        source
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 10, end: 10 },
                10,
                b"erase fixture",
            )
            .expect("put fixture entity");
    }
    let receipt = |claim: EntityId| GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: 40,
        outcome: "approved".into(),
        reason_codes: vec!["gate.test.erase".into()],
        receipt_reasons: vec![],
        system_notices: vec![],
        actor_class: "agent".into(),
        actor_ref: Some("private-erased-receipt".into()),
        content_kind: "claim".into(),
        policy_manifest_version: "v0".into(),
        claim_id: Some(*claim.as_bytes()),
        grant_ref: None,
        diff_handle: vec![1],
        read_frontier_hash: [2; 32],
        redacted_at: None,
    };
    let (erased_receipt, kept_receipt) = (receipt(erased), receipt(kept));
    source
        .with_write_txn(|txn| {
            source
                .store
                .append_gate_decision_in_txn(txn, &erased_receipt)?;
            source.store.append_gate_decision_in_txn(txn, &kept_receipt)
        })
        .expect("append claim receipts");
    let image = root.path().join("pre-erase");
    source
        .snapshot_checkpoint(&image, 100)
        .expect("pre-erase image");
    let custody = root.path().join(".source.gate-decision-keys");
    let key = custody.join(crate::entity_id::bytes_to_hex_lower(erased.as_bytes()));
    assert!(key.exists());

    source
        .delete_entity_with_reason(&erased, crate::DeleteReason::UserHardDelete)
        .expect("erase the claim");
    assert!(
        !key.exists(),
        "erase destroys the claim key in the same act"
    );
    assert!(
        custody
            .join(format!(
                ".retired-{}",
                crate::entity_id::bytes_to_hex_lower(erased.as_bytes())
            ))
            .exists()
    );
    let skeleton = source
        .gate_decisions(10)
        .expect("live ledger reads")
        .into_iter()
        .find(|row| row.decision_id == erased_receipt.decision_id)
        .expect("the erased claim keeps its skeleton");
    assert!(skeleton.redacted_at.is_some() && skeleton.actor_ref.is_none());

    let (restored, _) = Vault::restore_checkpoint(
        &image,
        &root.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        120,
    )
    .expect("a pre-erase image still restores");
    let rows = restored.gate_decisions(10).expect("restored ledger reads");
    assert!(
        rows.iter()
            .all(|row| row.decision_id != erased_receipt.decision_id),
        "the erased claim's receipt does not decrypt back from the image"
    );
    assert!(
        rows.contains(&kept_receipt),
        "other claims' receipts restore"
    );
    let txn = restored.store.env.read_txn().unwrap();
    assert!(
        restored
            .store
            .gate_decisions_for_claim_in_txn(&txn, erased.as_bytes())
            .unwrap()
            .is_empty()
    );
}

/// Erase is complete: a hold asked for after the erase commits, before its
/// key is destroyed, never keeps the erased receipts readable from a
/// pre-erase image (ARCH-0038 #erasure-completeness; Greptile on #1335).
#[test]
fn a_hold_after_an_erase_commits_never_keeps_its_receipts_readable() {
    use crate::store::{GateDecisionId, GateDecisionRecord};
    let root = tempfile::tempdir().unwrap();
    let source = std::sync::Arc::new(
        Vault::open(root.path().join("source"), VaultConfig::device()).unwrap(),
    );
    let erased = EntityId::now();
    source
        .put_entity(
            &erased,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"erase fixture",
        )
        .expect("put fixture entity");
    let receipt = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: 40,
        outcome: "approved".into(),
        reason_codes: vec!["gate.test.erase".into()],
        receipt_reasons: vec![],
        system_notices: vec![],
        actor_class: "agent".into(),
        actor_ref: Some("private-erased-receipt".into()),
        content_kind: "claim".into(),
        policy_manifest_version: "v0".into(),
        claim_id: Some(*erased.as_bytes()),
        grant_ref: None,
        diff_handle: vec![1],
        read_frontier_hash: [2; 32],
        redacted_at: None,
    };
    source
        .with_write_txn(|txn| source.store.append_gate_decision_in_txn(txn, &receipt))
        .expect("append claim receipt");
    let image = root.path().join("pre-erase");
    source
        .snapshot_checkpoint(&image, 100)
        .expect("pre-erase image");
    let key = root
        .path()
        .join(".source.gate-decision-keys")
        .join(crate::entity_id::bytes_to_hex_lower(erased.as_bytes()));
    assert!(key.exists());

    // Another caller asks for a hold after the erase commits, just before
    // its finisher destroys the key.
    let holder = std::sync::Arc::clone(&source);
    let claim = *erased.as_bytes();
    let hold = std::rc::Rc::new(std::cell::Cell::new(None));
    let hold_result = std::rc::Rc::clone(&hold);
    crate::store::arm_before_retire_lock(move || {
        hold_result.set(Some(
            holder
                .set_gate_decision_partition_hold(Some(claim), true)
                .is_ok(),
        ));
    });
    source
        .delete_entity_with_reason(&erased, crate::DeleteReason::UserHardDelete)
        .expect("erase the claim");
    assert!(!key.exists(), "the erase still destroys the claim key");
    assert_eq!(
        hold.get(),
        Some(false),
        "the erased partition refuses a hold"
    );

    let (restored, _) = Vault::restore_checkpoint(
        &image,
        &root.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        120,
    )
    .expect("a pre-erase image still restores");
    assert!(
        restored
            .gate_decisions(10)
            .expect("restored ledger reads")
            .iter()
            .all(|row| row.decision_id != receipt.decision_id),
        "the erased claim's receipt does not decrypt back from the image"
    );
}

/// A person claim with one receipt encrypted under the claim's key.
fn claim_with_receipt(vault: &Vault) -> (EntityId, crate::store::GateDecisionRecord) {
    use crate::store::{GateDecisionId, GateDecisionRecord};
    let claim = EntityId::now();
    vault
        .put_entity(
            &claim,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"custody fixture",
        )
        .expect("put fixture entity");
    let receipt = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: 40,
        outcome: "approved".into(),
        reason_codes: vec!["gate.test.custody".into()],
        receipt_reasons: vec![],
        system_notices: vec![],
        actor_class: "agent".into(),
        actor_ref: Some("private-custody-receipt".into()),
        content_kind: "claim".into(),
        policy_manifest_version: "v0".into(),
        claim_id: Some(*claim.as_bytes()),
        grant_ref: None,
        diff_handle: vec![1],
        read_frontier_hash: [2; 32],
        redacted_at: None,
    };
    vault
        .with_write_txn(|txn| vault.store.append_gate_decision_in_txn(txn, &receipt))
        .expect("append claim receipt");
    (claim, receipt)
}

/// Commits an erase of `claim` whose finisher has not run (the process
/// stopped in between): the key is still on disk.
fn commit_unfinished_erase(vault: &Vault, claim: &EntityId) {
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .redact_gate_decisions_for_claim_in_txn(&mut wtxn, claim.as_bytes(), 50)
        .expect("commit an erase");
    wtxn.commit().unwrap();
}

/// How a side restore reads its source's live custody state: from the open
/// vault, from disk beside whoever holds the vault (the CLI rehearsal beside
/// a running server), or by keeping the open vault's live authority.
#[derive(Clone, Copy, Debug)]
enum Side {
    Open,
    Disk,
    KeepingAuthority,
}
const SIDES: [Side; 3] = [Side::Open, Side::Disk, Side::KeepingAuthority];

/// Restores `image` beside the vault at `<root>/source` into `<root>/copy`
/// through `side`, and returns the source, reopened when `Disk` closed it.
fn restore_beside(side: Side, source: Vault, root: &Path, image: &Path) -> (Vault, Vault) {
    let destination = root.join("copy");
    let (copy, _) = match side {
        Side::Open => Vault::restore_checkpoint_beside(
            image,
            &destination,
            VaultConfig::device(),
            &source.side_restore_source().expect("source state"),
            120,
        ),
        Side::Disk => {
            drop(source);
            let state = SideRestoreSource::read(&root.join("source")).expect("source state");
            let restored = Vault::restore_checkpoint_beside(
                image,
                &destination,
                VaultConfig::device(),
                &state,
                120,
            )
            .expect("side restore");
            let source = Vault::open(root.join("source"), VaultConfig::device()).unwrap();
            return (source, restored.0);
        }
        Side::KeepingAuthority => Vault::restore_checkpoint_keeping_authority(
            image,
            &destination,
            VaultConfig::device(),
            &source,
            120,
        ),
    }
    .expect("side restore");
    (source, copy)
}

/// A source vault with one claim receipt, and a copy of it restored beside it.
fn side_copy(
    root: &Path,
    side: Side,
) -> (Vault, Vault, EntityId, crate::store::GateDecisionRecord) {
    let source = Vault::open(root.join("source"), VaultConfig::device()).unwrap();
    let (claim, receipt) = claim_with_receipt(&source);
    let image = root.join("image");
    source.snapshot_checkpoint(&image, 100).expect("image");
    let (source, copy) = restore_beside(side, source, root, &image);
    (source, copy, claim, receipt)
}

/// ARCH-0038 #erasure-completeness, "Key custody in a side restore" (REV-9
/// item 11): custody forks at a side restore, so an erase in the copy never
/// reaches the source's keys or receipts.
#[test]
fn an_erase_in_a_side_copy_never_reaches_its_source() {
    for side in SIDES {
        let root = tempfile::tempdir().unwrap();
        let (source, copy, claim, receipt) = side_copy(root.path(), side);
        copy.delete_entity_with_reason(&claim, crate::DeleteReason::UserHardDelete)
            .expect("erase in the copy");
        assert!(
            !copy
                .gate_decisions(100)
                .expect("the copy's ledger reads")
                .contains(&receipt),
            "{side:?}: the erase redacts the copy's receipt"
        );
        assert!(
            source
                .gate_decisions(100)
                .expect("the source's receipts still decrypt")
                .contains(&receipt),
            "{side:?}"
        );
    }
}

/// The other direction: an erase in the source never reaches a side copy.
#[test]
fn an_erase_in_the_source_never_reaches_its_side_copy() {
    for side in SIDES {
        let root = tempfile::tempdir().unwrap();
        let (source, copy, claim, receipt) = side_copy(root.path(), side);
        source
            .delete_entity_with_reason(&claim, crate::DeleteReason::UserHardDelete)
            .expect("erase in the source");
        assert!(
            copy.gate_decisions(100)
                .expect("the copy's receipts still decrypt")
                .contains(&receipt),
            "{side:?}"
        );
    }
}

/// The fork copies only the keys still live in the source's custody: a key
/// destroyed before the restore, or one whose retirement the source has
/// committed but not yet carried out, never reaches the copy, and the copy
/// restores without the receipts it decrypted.
#[test]
fn a_side_restore_copies_no_key_the_source_destroyed_or_committed_to_destroy() {
    let hex = |claim: &EntityId| crate::entity_id::bytes_to_hex_lower(claim.as_bytes());
    for side in SIDES {
        let root = tempfile::tempdir().unwrap();
        let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
        let (live, live_receipt) = claim_with_receipt(&source);
        let (destroyed, destroyed_receipt) = claim_with_receipt(&source);
        let (committed, committed_receipt) = claim_with_receipt(&source);
        let image = root.path().join("image");
        source.snapshot_checkpoint(&image, 100).expect("image");
        source
            .delete_entity_with_reason(&destroyed, crate::DeleteReason::UserHardDelete)
            .expect("erase before the restore");
        commit_unfinished_erase(&source, &committed);
        let source_custody = root.path().join(".source.gate-decision-keys");
        assert!(source_custody.join(hex(&committed)).exists());

        let (_source, copy) = restore_beside(side, source, root.path(), &image);
        let copy_custody = root.path().join(".copy.gate-decision-keys");
        assert!(
            copy_custody.join(hex(&live)).exists(),
            "{side:?}: the copy holds its own copy of a live key"
        );
        for claim in [destroyed, committed] {
            assert!(!copy_custody.join(hex(&claim)).exists(), "{side:?}");
        }
        let rows = copy.gate_decisions(100).expect("the copy's ledger reads");
        assert!(rows.contains(&live_receipt), "{side:?}");
        assert!(
            rows.iter().all(|row| {
                row.decision_id != destroyed_receipt.decision_id
                    && row.decision_id != committed_receipt.decision_id
            }),
            "{side:?}"
        );
    }
}

/// A side restore refused after its fork leaves no copy of a live key: the
/// custody it forked goes with the destination it removes.
#[test]
fn a_refused_side_restore_leaves_no_forked_key_behind() {
    let root = tempfile::tempdir().unwrap();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let owner = source.ensure_embedded_owner_actor().unwrap();
    claim_with_receipt(&source);
    let image = root.path().join("image");
    source.snapshot_checkpoint(&image, 100).expect("image");
    // Reviving an owner deleted since is refused after the restore has run.
    source
        .delete_entity_with_options(&owner, crate::deletion::DeleteEntityOptions { purge: true })
        .unwrap();
    let destination = root.path().join("copy");
    assert!(
        Vault::restore_checkpoint_keeping_authority(
            &image,
            &destination,
            VaultConfig::device(),
            &source,
            120,
        )
        .is_err()
    );
    assert!(!destination.exists());
    assert!(!root.path().join(".copy.gate-decision-keys").exists());
}

/// A restore never shreds custody its vault is not bound to. Its first
/// handle names the custody beside its destination while the image binds
/// another; here that custody is a side copy's that moved away, and the
/// restored image carries an erase its source committed but did not finish.
#[test]
fn a_restore_never_shreds_custody_its_vault_is_not_bound_to() {
    let root = tempfile::tempdir().unwrap();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let (claim, receipt) = claim_with_receipt(&source);
    let image = root.path().join("image");
    source.snapshot_checkpoint(&image, 100).expect("image");
    let (source, copy) = restore_beside(Side::Open, source, root.path(), &image);
    drop(copy);
    std::fs::rename(root.path().join("copy"), root.path().join("moved")).unwrap();
    commit_unfinished_erase(&source, &claim);
    let pending = root.path().join("pending");
    source
        .snapshot_checkpoint(&pending, 110)
        .expect("image with the erase pending");

    // In its vault's place at the path the copy left: keep-mode custody.
    let (restored, _) = Vault::restore_checkpoint(
        &pending,
        &root.path().join("copy"),
        VaultConfig::device(),
        RestoreReason::Restore,
        130,
    )
    .expect("restore");
    drop(restored);
    let moved = Vault::open(root.path().join("moved"), VaultConfig::device()).unwrap();
    assert!(
        moved
            .gate_decisions(100)
            .expect("the moved copy's receipts still decrypt")
            .contains(&receipt)
    );
}

/// Whether `result` is the read-only door's refusal of a path that holds no
/// vault.
fn refused_as_no_vault<T>(result: Result<T>) -> bool {
    matches!(
        result,
        Err(Error::Store(crate::error::StoreError::VaultRootPreflight {
            problem: crate::error::VaultRootProblem::NotAnExistingVaultRoot { .. },
            ..
        }))
    )
}

/// A side restore needs its source's live state, or it could copy a key the
/// source has committed to destroy (REV-9 item 11, Astra A1): a source that
/// is missing, empty or gone by the time the restore starts refuses it, and
/// no key is copied.
#[test]
fn a_side_restore_refuses_a_source_it_cannot_read() {
    let root = tempfile::tempdir().unwrap();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let (claim, _) = claim_with_receipt(&source);
    let image = root.path().join("image");
    source.snapshot_checkpoint(&image, 100).expect("image");
    commit_unfinished_erase(&source, &claim);
    drop(source);
    std::fs::create_dir(root.path().join("empty")).unwrap();
    for missing in ["elsewhere", "empty"] {
        assert!(
            refused_as_no_vault(SideRestoreSource::read(&root.path().join(missing))),
            "{missing}"
        );
    }
    let state = SideRestoreSource::read(&root.path().join("source")).expect("source state");
    std::fs::rename(root.path().join("source"), root.path().join("moved")).unwrap();
    let destination = root.path().join("copy");
    assert!(refused_as_no_vault(Vault::restore_checkpoint_beside(
        &image,
        &destination,
        VaultConfig::device(),
        &state,
        120,
    )));
    assert!(!destination.exists());
    assert!(!root.path().join(".copy.gate-decision-keys").exists());
}

/// Each side restore reads its source's live state when it starts, so a key
/// retirement the source committed between two restores from one source
/// never reaches the second copy (Astra A5).
#[test]
fn each_side_restore_reads_its_source_when_it_starts() {
    let hex = |claim: &EntityId| crate::entity_id::bytes_to_hex_lower(claim.as_bytes());
    for side in [Side::Open, Side::Disk] {
        let root = tempfile::tempdir().unwrap();
        let source_path = root.path().join("source");
        let source = Vault::open(&source_path, VaultConfig::device()).unwrap();
        let (claim, receipt) = claim_with_receipt(&source);
        let image = root.path().join("image");
        source.snapshot_checkpoint(&image, 100).expect("image");
        let restore = |state: &SideRestoreSource<'_>, copy: &str| {
            Vault::restore_checkpoint_beside(
                &image,
                &root.path().join(copy),
                VaultConfig::device(),
                state,
                120,
            )
            .expect("side restore")
            .0
        };
        let (_first, second) = if matches!(side, Side::Open) {
            let state = source.side_restore_source().unwrap();
            let first = restore(&state, "first");
            commit_unfinished_erase(&source, &claim);
            (first, restore(&state, "second"))
        } else {
            drop(source);
            let state = SideRestoreSource::read(&source_path).unwrap();
            let first = restore(&state, "first");
            let source = Vault::open(&source_path, VaultConfig::device()).unwrap();
            commit_unfinished_erase(&source, &claim);
            drop(source);
            (first, restore(&state, "second"))
        };
        assert!(
            root.path()
                .join(".first.gate-decision-keys")
                .join(hex(&claim))
                .exists(),
            "{side:?}: the first copy took the key while it was live"
        );
        assert!(
            !root
                .path()
                .join(".second.gate-decision-keys")
                .join(hex(&claim))
                .exists(),
            "{side:?}"
        );
        let rows = second
            .gate_decisions(100)
            .expect("the second copy's ledger reads");
        assert!(
            rows.iter()
                .all(|row| row.decision_id != receipt.decision_id),
            "{side:?}"
        );
    }
}

/// A vault this process holds is read through its own handle, never through
/// a second LMDB environment over the same files, under its own name or any
/// other (Astra A3).
#[test]
fn a_side_restore_source_never_reopens_a_vault_this_process_holds() {
    let root = tempfile::tempdir().unwrap();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let held = |path: &Path| {
        matches!(
            SideRestoreSource::read(path),
            Err(Error::Store(crate::error::StoreError::VaultRootPreflight {
                problem: crate::error::VaultRootProblem::DuplicateOpenRoot { .. },
                ..
            }))
        )
    };
    assert!(held(&root.path().join("source")));
    std::fs::rename(root.path().join("source"), root.path().join("renamed")).unwrap();
    assert!(held(&root.path().join("renamed")));
    drop(source);
    assert!(SideRestoreSource::read(&root.path().join("renamed")).is_ok());
}

/// The vault a restore in its place set aside still binds the custody its
/// replacement keeps. ARCH-0038, "Key custody in a side restore": an erase
/// or age sweep in one vault never reaches the other vault's keys or
/// receipts. So it is archived: it reads, an erase in it is refused and the
/// replacement's keys stay, and it is no side restore's source. Once the
/// owner activates it as a side vault its custody is its own, and an erase
/// in it no longer reaches the replacement.
#[test]
fn a_vault_a_restore_replaced_is_archived_until_activated() {
    let archived = |result: Result<()>| {
        matches!(
            result,
            Err(Error::Store(crate::error::StoreError::ArchivedVault))
        )
    };
    let root = tempfile::tempdir().unwrap();
    let vault_path = root.path().join("vault");
    let previous_path = root.path().join("previous");
    let source = Vault::open(&vault_path, VaultConfig::device()).unwrap();
    let (claim, receipt) = claim_with_receipt(&source);
    let image = root.path().join("image");
    source.snapshot_checkpoint(&image, 100).expect("image");
    // As `oneiron restore` runs it: the copy is made beside, swapped into
    // the vault's place, and the vault it replaced is archived.
    let staged = root.path().join("staged");
    let (replacement, _) =
        Vault::restore_checkpoint_replacing(&image, &staged, VaultConfig::device(), &source, 120)
            .expect("restore");
    drop(replacement);
    source
        .archive_replaced()
        .expect("archive the replaced vault");
    drop(source);
    std::fs::rename(&vault_path, &previous_path).unwrap();
    std::fs::rename(&staged, &vault_path).unwrap();
    let replacement = Vault::open(&vault_path, VaultConfig::device()).unwrap();

    let previous = Vault::open(&previous_path, VaultConfig::device()).unwrap();
    assert!(
        previous
            .gate_decisions(100)
            .expect("the archive reads")
            .contains(&receipt)
    );
    assert!(archived(
        previous
            .delete_entity_with_reason(&claim, crate::DeleteReason::UserHardDelete)
            .map(|_| ())
    ));
    assert!(archived(previous.side_restore_source().map(|_| ())));
    drop(previous);
    assert!(
        replacement
            .gate_decisions(100)
            .expect("the replacement's receipts still decrypt")
            .contains(&receipt)
    );

    let activated = Vault::activate_archived(
        &previous_path,
        VaultConfig::device(),
        &replacement.side_restore_source().unwrap(),
    )
    .expect("activate");
    activated
        .delete_entity_with_reason(&claim, crate::DeleteReason::UserHardDelete)
        .expect("erase in the activated vault");
    assert!(
        replacement
            .gate_decisions(100)
            .expect("the replacement's receipts still decrypt")
            .contains(&receipt)
    );
}

#[test]
fn canonical_snapshot_rebuilds_indexes_excludes_runtime_and_mints_epoch() {
    let root = tempfile::tempdir().unwrap();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let id = EntityId::now();
    source
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 20 },
            30,
            b"canonical person",
        )
        .text(&id, &[("body", "restore searchable")])
        .phonetic(&id, &["RSTR"])
        .commit()
        .unwrap();
    source
        .with_write_txn(|txn| {
            source
                .store
                .vault_meta
                .put(txn, b"dreamer:budget:test", b"spent")?;
            source
                .store
                .vault_meta
                .put(txn, b"retr_run:test", b"runtime")?;
            source.store.ppr_cache.put(txn, b"derived", b"cache")?;
            Ok(())
        })
        .unwrap();
    let observations = [crate::self_heal::DiagnosticObservation {
        source_ref: id,
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [1; 32],
        observed_at: 50,
    }];
    let diagnostics = crate::self_heal::run_deterministic_detectors(
        &source,
        &crate::self_heal::DiagnosticWorkingSet {
            scope_ref: "restore-diagnostic",
            observations: &observations,
        },
        &[&crate::self_heal::ConsentDeniedDetector],
    )
    .unwrap();
    assert_eq!(diagnostics.len(), 1);
    let path = root.path().join("checkpoint");
    let checkpoint_id = source.snapshot_checkpoint(&path, 100).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    let after = EntityId::now();
    source
        .put_entity(
            &after,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: 101,
                end: 101,
            },
            101,
            b"after checkpoint",
        )
        .unwrap();
    for (index, reason) in [
        RestoreReason::Restore,
        RestoreReason::Wake,
        RestoreReason::Migrate,
    ]
    .into_iter()
    .enumerate()
    {
        let (restored, report) = Vault::restore_checkpoint(
            &path,
            &root.path().join(format!("restored-{index}")),
            VaultConfig::device(),
            reason,
            200,
        )
        .unwrap();
        assert_eq!(
            restored.get(&id).unwrap(),
            Some(b"canonical person".to_vec())
        );
        assert_eq!(restored.get(&after).unwrap(), None);
        assert!(
            restored
                .entities_by_type(crate::registry::ENTITY_TYPE_PERSON)
                .unwrap()
                .contains(&id)
        );
        assert_eq!(report.rebuilt_text_documents, 1);
        let txn = restored.store.env.read_txn().unwrap();
        assert!(
            restored
                .store
                .vault_meta
                .get(&txn, b"dreamer:budget:test")
                .unwrap()
                .is_none()
        );
        assert!(
            restored
                .store
                .vault_meta
                .get(&txn, b"retr_run:test")
                .unwrap()
                .is_none()
        );
        assert!(restored.store.ppr_cache.is_empty(&txn).unwrap());
        assert!(!restored.store.phonetic_index.is_empty(&txn).unwrap());
        assert!(!restored.store.text_postings.is_empty(&txn).unwrap());
        drop(txn);
        assert!(
            restored
                .entities_by_type(crate::registry::ENTITY_TYPE_DIAGNOSTIC)
                .unwrap()
                .is_empty()
        );
        let epochs = restored.restore_epochs().unwrap();
        assert_eq!(epochs.len(), 1);
        assert_eq!(epochs[0].checkpoint_id, checkpoint_id);
        assert_eq!(epochs[0].restored_at, 200);
        assert_eq!(epochs[0].reason, reason);
    }
}
#[test]
fn corrupt_checkpoint_and_existing_destination_are_refused_without_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let vault = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let image = root.path().join("checkpoint");
    vault.snapshot_checkpoint(&image, 1).unwrap();
    let destination = root.path().join("existing");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("owned"), b"keep").unwrap();
    assert!(
        Vault::restore_checkpoint(
            &image,
            &destination,
            VaultConfig::device(),
            RestoreReason::Restore,
            2
        )
        .is_err()
    );
    assert_eq!(std::fs::read(destination.join("owned")).unwrap(), b"keep");
    let mut bytes = std::fs::read(&image).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&image, bytes).unwrap();
    assert!(
        Vault::restore_checkpoint(
            &image,
            &root.path().join("fresh"),
            VaultConfig::device(),
            RestoreReason::Restore,
            2
        )
        .is_err()
    );
    assert!(!root.path().join("fresh").exists());
}

#[test]
fn restore_rebuilds_pending_consent_indexes_and_preserves_insertion_order() {
    let root = tempfile::tempdir().unwrap();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let mut expected = Vec::new();
    for _ in 0..2 {
        let record = crate::store::PendingGateConsentRecord {
            version: crate::store::PENDING_GATE_CONSENT_VERSION,
            claim_id: *EntityId::now().as_bytes(),
            decision_id: crate::store::GateDecisionId::now(),
            created_at: 100,
            diff_handle: vec![1],
            read_frontier_hash: [2; 32],
            reason_codes: vec!["gate.pending.test".into()],
            dreamer_run_id: Some("pending-run".into()),
        };
        source
            .with_write_txn(|txn| source.store.put_pending_gate_consent_in_txn(txn, &record))
            .unwrap();
        expected.push(record);
    }
    // Damage only rebuildable sidecars, including an orphan. The primary
    // pending records, original index-state witness and sequence are intact.
    source
        .with_write_txn(|txn| {
            for prefix in [
                b"gate_pending:run_index:v1:".as_slice(),
                b"gate_pending:group_index:v1:",
                b"gate_pending:hash_index:v1:",
                b"gate_pending:sequence_index:v1:",
                b"gate_pending:critical_confirm_by_id:v1:",
            ] {
                let keys = source
                    .store
                    .vault_meta
                    .prefix_iter(&*txn, prefix)?
                    .map(|r| r.map(|(k, _)| k.to_vec()))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                for key in keys {
                    source.store.vault_meta.delete(txn, &key)?;
                }
                source
                    .store
                    .vault_meta
                    .put(txn, &[prefix, b"orphan"].concat(), b"corrupt")?;
            }
            Ok(())
        })
        .unwrap();
    let image = root.path().join("checkpoint");
    source.snapshot_checkpoint(&image, 110).unwrap();
    let (restored, _) = Vault::restore_checkpoint(
        &image,
        &root.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        120,
    )
    .unwrap();
    assert_eq!(
        restored
            .store
            .pending_gate_consents_for_run("pending-run")
            .unwrap(),
        expected
    );
    assert_eq!(
        restored
            .store
            .pending_gate_consents_for_group_key("pending-run")
            .unwrap(),
        expected
    );
    let txn = restored.store.env.read_txn().unwrap();
    let page = restored
        .store
        .pending_gate_consents_page_in_txn(&txn, None, None, 10)
        .unwrap();
    assert_eq!(
        page.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(page.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![1, 2]);
    drop(txn);
    // Rebuilt deletion witnesses still support normal lifecycle operations.
    restored
        .with_write_txn(|txn| {
            restored.store.delete_pending_gate_consent_in_txn(
                txn,
                &EntityId::from_bytes(expected[0].claim_id).unwrap(),
            )
        })
        .unwrap();
    assert_eq!(
        restored
            .store
            .pending_gate_consents_for_run("pending-run")
            .unwrap(),
        expected[1..]
    );
}

#[test]
fn checkpoint_omits_ingest_counters_but_preserves_quota_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let source = Vault::open(dir.path().join("source"), VaultConfig::device()).unwrap();
    let baseline = dir.path().join("baseline");
    source.snapshot_checkpoint(&baseline, 100).unwrap();
    let mut config = Vec::new();
    config.extend_from_slice(&4_u32.to_le_bytes());
    config.extend_from_slice(&60_u64.to_le_bytes());
    source
        .with_write_txn(|txn| {
            source
                .store
                .sync_queue
                .put(txn, b"m:maintenance_ingest_quota_config:v1", &config)?;
            Ok(())
        })
        .unwrap();
    let configured = dir.path().join("configured");
    source.snapshot_checkpoint(&configured, 100).unwrap();
    assert_ne!(
        std::fs::read(&baseline).unwrap(),
        std::fs::read(&configured).unwrap()
    );
    let mut key = b"m:maintenance_ingest_quota:v1:".to_vec();
    key.extend_from_slice(&[7; 32]);
    let mut count = Vec::new();
    count.extend_from_slice(&60_u64.to_le_bytes());
    count.extend_from_slice(&4_u32.to_le_bytes());
    source
        .with_write_txn(|txn| {
            source.store.sync_queue.put(txn, &key, &count)?;
            Ok(())
        })
        .unwrap();
    let counted = dir.path().join("counted");
    source.snapshot_checkpoint(&counted, 100).unwrap();
    assert_eq!(
        std::fs::read(&configured).unwrap(),
        std::fs::read(&counted).unwrap()
    );
}

#[test]
fn checkpoint_refuses_unreconstructable_explicit_vectors_before_creating_image() {
    for (entity_type, body) in [
        (crate::registry::ENTITY_TYPE_PERSON, b"person".as_slice()),
        (crate::registry::ENTITY_TYPE_SUMMARY, b"".as_slice()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = Some("test/model@v1".into());
        let source = Vault::open(dir.path().join("source"), config).unwrap();
        let id = EntityId::now();
        source
            .put_entity(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, body)
            .unwrap();
        let vector = vec![1.0, 0.0, 0.0, 0.0];
        source.put_vector(&id, &vector).unwrap();
        let checkpoint = dir.path().join("checkpoint");
        assert!(matches!(
            source.snapshot_checkpoint(&checkpoint, 100),
            Err(Error::InvalidConfig(_))
        ));
        assert!(!checkpoint.exists());
        assert_eq!(source.get_vector(&id).unwrap(), Some(vector));
    }
}

#[test]
fn checkpoint_requeues_nonempty_summary_vectors_for_embedding() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".into());
    let source = Vault::open(dir.path().join("source"), config.clone()).unwrap();
    // The bootstrap skills' seeded claims are embedding sources as well.
    let seeded_claims = source
        .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)
        .unwrap()
        .len();
    let id = EntityId::now();
    source
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange { start: 1, end: 1 },
            1,
            b"summary rebuild source",
        )
        .unwrap();
    source.put_vector(&id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
    let checkpoint = dir.path().join("checkpoint");
    source.snapshot_checkpoint(&checkpoint, 100).unwrap();
    let (restored, report) = Vault::restore_checkpoint(
        &checkpoint,
        &dir.path().join("restored"),
        config,
        RestoreReason::Restore,
        101,
    )
    .unwrap();
    assert_eq!(
        restored.get(&id).unwrap(),
        Some(b"summary rebuild source".to_vec())
    );
    assert_eq!(report.pending_embeddings, seeded_claims + 1);
    assert!(restored.get_vector(&id).unwrap().is_none());
}

/// A restore refuses a job row of another kind in the owner-retained key
/// range, where that kind's scans would never read it, before any
/// destination exists; an owner-retained row an earlier build wrote below
/// the range restores readable.
#[test]
fn restore_refuses_another_kinds_job_row_in_the_owner_retained_range() {
    use crate::attempt_queue::{AttemptId, AttemptQueue, EnqueueAttempt};
    let root = tempfile::tempdir().unwrap();
    let vault = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    AttemptQueue::new(&vault)
        .enqueue(EnqueueAttempt {
            kind: "test.retained".into(),
            payload: vec![1, 2, 3],
            dedupe_key: None,
            run_id: None,
            now: 1,
        })
        .unwrap();
    let template = AttemptQueue::new(&vault).list().unwrap().remove(0);
    let image = root.path().join("checkpoint");
    vault.snapshot_checkpoint(&image, 1).unwrap();
    let bytes = std::fs::read(&image).unwrap();
    let base: CheckpointImage = rmp_serde::from_slice(&bytes[41..]).unwrap();
    for (n, (first, kind, restores)) in [
        (0xff_u8, "test.retained", false),
        (0x00, crate::tagging::TAGGING_MARKER_KIND, true),
    ]
    .into_iter()
    .enumerate()
    {
        let mut id = [0x5a_u8; 16];
        id[0] = first;
        let mut row = template.clone();
        row.id = AttemptId::from_bytes(&id).unwrap();
        row.kind = kind.into();
        let mut crafted = base.clone();
        let rows = crafted.databases.get_mut("job_records").unwrap();
        rows.push((
            id.to_vec(),
            crate::attempt_queue::encode_signal_record(&row).unwrap(),
        ));
        rows.sort();
        let body = rmp_serde::to_vec_named(&crafted).unwrap();
        let mut file = b"ONEIRONC1".to_vec();
        file.extend_from_slice(blake3::hash(&body).as_bytes());
        file.extend_from_slice(&body);
        let crafted_path = root.path().join(format!("crafted-{n}"));
        std::fs::write(&crafted_path, file).unwrap();
        let destination = root.path().join(format!("restored-{n}"));
        let restored = Vault::restore_checkpoint(
            &crafted_path,
            &destination,
            VaultConfig::device(),
            RestoreReason::Restore,
            2,
        );
        assert_eq!(restored.is_ok(), restores, "{kind} row under {first:#04x}");
        if restores {
            let (vault, _) = restored.unwrap();
            assert!(
                AttemptQueue::new(&vault)
                    .get(row.id)
                    .unwrap()
                    .is_some_and(|stored| stored.kind == kind)
            );
        } else {
            assert!(!destination.exists(), "refused before the destination");
        }
    }
}
