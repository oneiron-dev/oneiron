//! A sealed AUTHORITY_LOG row in this vault (census L5-22): the door that
//! signs it stores the row in its scaffold form and the overlay record
//! beside it, sealed, and the vault's own reader opens the row whole, after
//! a reopen too.

use super::*;
use crate::side_table::{self, Raw, SideTable};
#[cfg(feature = "sync")]
use crate::store::authority_overlay_custody::{
    deliver_authority_overlay_custody_for_test, retire_authority_overlay_subject_for_test,
};
#[cfg(feature = "sync")]
use crate::sync::authority_overlay_custody::{
    ErasedSubject, OverlayAnswer, OverlayKeySession, OverlayOffer, answer_offer,
    apply_overlay_answer, offer_overlay_page, receive_keys, run_round_for_test,
    run_round_then_abort_for_test,
};
use crate::{OpenOptions, Vault, VaultConfig, VaultStorageId};

const SECRET: &[u8] = b"overlay rows host root placeholder words";

fn holds(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn a_slip_minted_with_records_is_stored_sealed_and_reads_back_whole() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [91; 32];
    claims.records = BTreeSet::from(["record:a".to_owned()]);
    claims.channels = BTreeSet::from(["channel:a".to_owned()]);
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let entry_hash = vault.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&entry_hash).unwrap();

    // The stored row is the scaffold: it names neither the record nor the
    // channel, and without its overlay record it reads as unavailable.
    let raw = vault.get_raw(&id).unwrap().unwrap();
    let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    assert!(authority_body_is_sealed(body).unwrap());
    assert!(
        decode_authority_log_entry_body(body)
            .is_err_and(|error| is_authority_overlay_unavailable(&error))
    );
    assert!(!holds(body, b"record:a"));
    assert!(!holds(body, b"channel:a"));

    // The overlay record is kept under the hash of the stored body, sealed:
    // it does not name them either.
    let overlay: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
        SideTable::new(&side_table::AUTHORITY_OVERLAY);
    let rtxn = vault.store.env.read_txn().unwrap();
    let row = overlay
        .get(&vault.store, &rtxn, blake3::hash(body).as_bytes())
        .unwrap()
        .expect("the mint row's overlay record");
    drop(rtxn);
    assert!(!holds(&row, b"record:a"));
    assert!(!holds(&row, b"channel:a"));

    // The vault's own reader opens the row whole.
    let entry = vault.get_authority_log_entry(&id).unwrap().unwrap();
    let AuthorityOp::SlipMint(action) = &entry.op else {
        panic!("the mint row must open as a slip mint, not {:?}", entry.op);
    };
    assert_eq!(action.claims.slip_id, slip.claims.slip_id);
    assert_eq!(
        action.claims.records,
        BTreeSet::from(["record:a".to_owned()])
    );
    assert_eq!(
        action.claims.channels,
        BTreeSet::from(["channel:a".to_owned()])
    );
    assert_eq!(authority_entry_hash(&entry).unwrap(), entry_hash);

    // And again after the vault is closed and opened at the same path.
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    assert_eq!(vault.get_authority_log_entry(&id).unwrap(), Some(entry));
}

/// T-LAND (census L5-22 1a-iii, RULING PLAN-L5-22-ERASED-ROWS = A): a
/// sealed row that reaches another install of the vault with its overlay
/// row, before custody delivers the key that opens it, lands as structure
/// only. Every row is held there, the history exports byte for byte, the
/// rows around it count, and the slip it minted grants nothing.
#[test]
fn a_sealed_row_whose_key_is_not_here_lands_as_structure_and_grants_nothing() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [92; 32];
    claims.records = BTreeSet::from(["record:b".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = home.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let (history, overlays) = home
        .export_signed_authority_history_with_overlays()
        .unwrap();
    assert!(
        overlays.contains_key(&mint_row),
        "the sealed mint row's overlay row travels with it",
    );

    let other_dir = tempfile::tempdir().unwrap();
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    other
        .import_signed_authority_history(&history, &overlays)
        .expect("a sealed row whose key is not here lands as structure");
    assert_eq!(other.export_signed_authority_history().unwrap(), history);
    let fold = other.authority_fold().unwrap();
    assert!(fold.pass_through_entries.contains(&mint_row));
    assert_eq!(fold.vault_id, home.authority_fold().unwrap().vault_id);
    assert!(fold.slips.mints.contains_key(&root.claims.slip_id));
    assert!(
        !fold.slips.mints.contains_key(&slip.claims.slip_id),
        "a row that does not open here makes nothing",
    );
}

/// T-REOPEN (census L5-22 1a-iii): the T-LAND sealed row, read back from
/// the stored log after the receiving vault restarts, still folds as
/// structure only: the stored-log reader path decodes it as a pass-through
/// row, the history still exports byte for byte, and the slip still grants
/// nothing.
#[test]
fn a_landed_sealed_row_still_folds_as_structure_after_a_restart() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [92; 32];
    claims.records = BTreeSet::from(["record:b".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = home.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let (history, overlays) = home
        .export_signed_authority_history_with_overlays()
        .unwrap();

    let other_dir = tempfile::tempdir().unwrap();
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    other
        .import_signed_authority_history(&history, &overlays)
        .expect("a sealed row whose key is not here lands as structure");
    drop(other);
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    assert_eq!(other.export_signed_authority_history().unwrap(), history);
    let fold = other.authority_fold().unwrap();
    assert!(fold.pass_through_entries.contains(&mint_row));
    assert_eq!(fold.vault_id, home.authority_fold().unwrap().vault_id);
    assert!(fold.slips.mints.contains_key(&root.claims.slip_id));
    assert!(
        !fold.slips.mints.contains_key(&slip.claims.slip_id),
        "a row that does not open here makes nothing",
    );
}

/// T-PAGE (census L5-22 1a-iii): the T-LAND sealed row over the signed-page
/// route, with its carried overlays beside the rows: the page lands, the
/// mint row folds as structure only, and the slip it minted grants nothing
/// while the root slip counts.
#[test]
fn a_sealed_row_on_a_signed_page_lands_as_structure() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [92; 32];
    claims.records = BTreeSet::from(["record:b".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let home_fold = home.authority_fold().unwrap();
    let mint_row = home_fold.slips.mints[&slip.claims.slip_id].entry_hash;
    let fetch = AuthorityHistoryFetch {
        selection: AuthorityHistorySelection::Hashes(
            home_fold
                .valid_entries
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
        ),
        parent_closure: true,
        limit: AUTHORITY_HISTORY_PAGE_MAX,
        ..Default::default()
    };
    let page = home.authority_history_page(&fetch).unwrap();
    assert!(
        page.overlays.contains_key(&mint_row),
        "the sealed mint row's overlay row travels with it",
    );

    let other_dir = tempfile::tempdir().unwrap();
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    other
        .import_signed_authority_page(&page.rows, &page.overlays)
        .expect("a sealed row on a signed page lands as structure");
    assert_eq!(
        other.export_signed_authority_history().unwrap(),
        home.export_signed_authority_history().unwrap()
    );
    let fold = other.authority_fold().unwrap();
    assert!(fold.pass_through_entries.contains(&mint_row));
    assert_eq!(fold.vault_id, home.authority_fold().unwrap().vault_id);
    assert!(fold.slips.mints.contains_key(&root.claims.slip_id));
    assert!(
        !fold.slips.mints.contains_key(&slip.claims.slip_id),
        "a row that does not open here makes nothing",
    );
}

/// T-RECEIPT (census L5-22 1a-iii): the T-LAND sealed row takes its
/// sequence receipt where it lands, though its record does not open there.
/// The receipt reads the envelope alone (signer, main log, sequence), so
/// the row's floor is set at its first observation and stays when the row
/// opens later; the same first observation adds the row to the totals the
/// checkpoint cutoffs read.
#[test]
fn a_sealed_row_whose_key_is_not_here_takes_its_sequence_receipt() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [92; 32];
    claims.records = BTreeSet::from(["record:b".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = home.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let mint_entry = home
        .get_authority_log_entry(&authority_log_entity_id_from_hash(&mint_row).unwrap())
        .unwrap()
        .expect("the home vault opens its own mint row");
    let (history, overlays) = home
        .export_signed_authority_history_with_overlays()
        .unwrap();

    let other_dir = tempfile::tempdir().unwrap();
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    other
        .import_signed_authority_history(&history, &overlays)
        .expect("a sealed row whose key is not here lands as structure");
    assert!(
        other
            .authority_fold()
            .unwrap()
            .pass_through_entries
            .contains(&mint_row)
    );
    let rtxn = other.store.env.read_txn().unwrap();
    let (_, receipted) =
        crate::authority::sequence_observation::authority_local_observations_receipted_in_txn(
            &other.store,
            &rtxn,
            &[crate::authority::fold_resume::RowMeta::of(
                Some(mint_row),
                &mint_entry,
            )],
        )
        .unwrap();
    assert!(
        receipted.contains(&mint_row),
        "a row that does not open here still takes its sequence receipt",
    );
}

/// T-CKPT (census L5-22 1a-iii): the T-LAND sealed mint, carried in an
/// image the home builds, attests and pins, reaches another install of the
/// vault that holds no key for it. Every covered row lands in the adoption,
/// the mint folds as structure only, and the slip it minted grants nothing
/// while the root slip counts, after a reopen too.
#[test]
fn an_adopted_image_over_a_sealed_row_lands_every_row_and_grants_nothing() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [93; 32];
    claims.records = BTreeSet::from(["record:c".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = home.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;

    let image = home.build_authority_checkpoint_v2().unwrap();
    assert!(
        image.rows[&mint_row].body.is_some(),
        "an image over a sealed row carries the sealed row's body",
    );
    assert!(image.rows.values().all(|row| row.body.is_some()));

    assert!(image.rows[&mint_row].sealed);
    assert_eq!(image.rows[&mint_row].op_kind, OP_KIND_SLIP_MINT);
    assert!(image.covers_sealed_row());

    home.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let id = home.write_authority_checkpoint_v2(&issuer).unwrap();
    let pin = home
        .authority_checkpoint_pin([7; 32])
        .unwrap()
        .expect("the home's attested checkpoint reaches quorum");
    assert_eq!(pin.checkpoint, id);
    let bundle = home
        .authority_checkpoint_bundle(&id)
        .unwrap()
        .expect("the home keeps its attested checkpoint bundle");

    let other_dir = tempfile::tempdir().unwrap();
    let storage_id = VaultStorageId::from_verified_pin(&pin);
    let other = Vault::open_owned_with(
        other_dir.path(),
        VaultConfig::default(),
        OpenOptions::default().adopt_storage_id(storage_id),
    )
    .unwrap();
    let adopted = match AuthorityCheckpointV2::decode(&bundle.image)
        .unwrap()
        .building_pin
    {
        Some(root) => other.adopt_recovered_authority_checkpoint(
            &pin,
            &bundle.image,
            &bundle.attestations,
            pin.digest().unwrap(),
            root,
        ),
        None => other.adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations),
    }
    .unwrap();
    assert_eq!(adopted, id);

    for hash in &image.covered {
        assert!(
            other
                .get_raw(&authority_log_entity_id_from_hash(hash).unwrap())
                .unwrap()
                .is_some(),
            "every covered authority row lands in the adoption",
        );
    }
    let fold = other.authority_fold().unwrap();
    assert!(fold.pass_through_entries.contains(&mint_row));
    assert!(!fold.valid_entries.contains(&mint_row));
    assert!(fold.slips.mints.contains_key(&root.claims.slip_id));
    assert!(
        !fold.slips.mints.contains_key(&slip.claims.slip_id),
        "a row that does not open here makes nothing",
    );
    assert_eq!(fold.vault_id, home.authority_fold().unwrap().vault_id);
    assert_eq!(
        other.export_signed_authority_history().unwrap(),
        home.export_signed_authority_history().unwrap()
    );

    drop(other);
    let other = Vault::open_owned_with(
        other_dir.path(),
        VaultConfig::default(),
        OpenOptions::default().adopt_storage_id(storage_id),
    )
    .unwrap();
    let fold = other.authority_fold().unwrap();
    assert!(fold.pass_through_entries.contains(&mint_row));
    assert!(!fold.valid_entries.contains(&mint_row));
    assert!(fold.slips.mints.contains_key(&root.claims.slip_id));
    assert!(
        !fold.slips.mints.contains_key(&slip.claims.slip_id),
        "a row that does not open here makes nothing",
    );
    assert_eq!(fold.vault_id, home.authority_fold().unwrap().vault_id);
}

/// T-ARC (census L5-22 1a-iii, RULING 11:52): a sealed mint lands on
/// another install as structure and its slip grants nothing. The live carrier
/// delivers the subject's key; the same stored row opens without reimport.
/// A matching inventory answers same, a second round changes nothing, and
/// the mint still counts after a reopen.
#[test]
#[cfg(feature = "sync")]
fn a_sealed_row_opens_and_counts_once_custody_delivers_its_key() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let home_id = EntityId::now();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    let slip_id = [94; 32];
    claims.slip_id = slip_id;
    claims.records = BTreeSet::from(["record:d".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = home.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&mint_row).unwrap();
    let entry = home.get_authority_log_entry(&id).unwrap().unwrap();
    let _subject = authority_overlay_subject(&entry.op).unwrap();
    let (history, overlays) = home
        .export_signed_authority_history_with_overlays()
        .unwrap();

    let other_dir = tempfile::tempdir().unwrap();
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    let other_id = EntityId::now();
    other
        .import_signed_authority_history(&history, &overlays)
        .unwrap();
    {
        let fold = other.authority_fold().unwrap();
        assert!(fold.pass_through_entries.contains(&mint_row));
        assert!(!fold.valid_entries.contains(&mint_row));
        assert!(!fold.slips.mints.contains_key(&slip_id));
        assert!(!other.capability_slip_id_is_live(&slip_id).unwrap());
    }

    run_round_for_test(&home, &home_id, &other, &other_id).unwrap();
    {
        let fold = other.authority_fold().unwrap();
        assert!(
            fold.valid_entries.contains(&mint_row),
            "the delivered key opens the stored mint row"
        );
        assert!(!fold.pass_through_entries.contains(&mint_row));
        assert!(fold.slips.mints.contains_key(&slip_id));
        assert!(other.capability_slip_id_is_live(&slip_id).unwrap());
        assert_eq!(other.get_authority_log_entry(&id).unwrap(), Some(entry));
        assert_eq!(other.export_signed_authority_history().unwrap(), history);
    }

    let (offer, _session) = offer_overlay_page(&home, &home_id, &other_id, None).unwrap();
    let answer = answer_offer(&other, &other_id, &home_id, &offer).unwrap();
    assert!(answer.same, "the delivered inventories answer same");
    run_round_for_test(&home, &home_id, &other, &other_id).unwrap();
    {
        let fold = other.authority_fold().unwrap();
        assert!(fold.valid_entries.contains(&mint_row));
        assert!(!fold.pass_through_entries.contains(&mint_row));
        assert!(fold.slips.mints.contains_key(&slip_id));
        assert!(other.capability_slip_id_is_live(&slip_id).unwrap());
    }

    drop(other);
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    let fold = other.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&mint_row));
    assert!(!fold.pass_through_entries.contains(&mint_row));
    assert!(fold.slips.mints.contains_key(&slip_id));
    assert!(other.capability_slip_id_is_live(&slip_id).unwrap());
}

/// T-ERASED (census L5-22 1a-iii, RULING 11:52): the home retires the
/// subject and its own row closes at once. The live carrier brings retirement
/// without a secret; the row stays a pass-through after a reopen too. The
/// key event refuses a stale live key, and a round carries retirement back
/// to the spare so neither install grants the slip.
#[test]
#[cfg(feature = "sync")]
fn an_erased_subject_stays_a_pass_through_for_good() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let home_id = EntityId::now();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    let slip_id = [95; 32];
    claims.slip_id = slip_id;
    claims.records = BTreeSet::from(["record:e".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = home.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&mint_row).unwrap();
    let entry = home.get_authority_log_entry(&id).unwrap().unwrap();
    let subject = authority_overlay_subject(&entry.op).unwrap();
    let (history, overlays) = home
        .export_signed_authority_history_with_overlays()
        .unwrap();

    let other_dir = tempfile::tempdir().unwrap();
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    let other_id = EntityId::now();
    other
        .import_signed_authority_history(&history, &overlays)
        .unwrap();
    let spare_dir = tempfile::tempdir().unwrap();
    let spare = Vault::open(spare_dir.path(), VaultConfig::default()).unwrap();
    let spare_id = EntityId::now();
    spare
        .import_signed_authority_history(&history, &overlays)
        .unwrap();
    run_round_for_test(&home, &home_id, &spare, &spare_id).unwrap();
    run_round_for_test(&home, &home_id, &other, &other_id).unwrap();
    {
        let fold = other.authority_fold().unwrap();
        assert!(fold.valid_entries.contains(&mint_row));
        assert!(!fold.pass_through_entries.contains(&mint_row));
        assert!(fold.slips.mints.contains_key(&slip_id));
        assert!(other.capability_slip_id_is_live(&slip_id).unwrap());
    }
    {
        let home_fold = home.authority_fold().unwrap();
        assert!(home_fold.valid_entries.contains(&mint_row));
        assert!(!home_fold.pass_through_entries.contains(&mint_row));
        assert!(home_fold.slips.mints.contains_key(&slip_id));
        assert!(home.capability_slip_id_is_live(&slip_id).unwrap());
    }

    retire_authority_overlay_subject_for_test(&home, &subject).unwrap();
    {
        let home_fold = home.authority_fold().unwrap();
        assert!(
            home_fold.pass_through_entries.contains(&mint_row),
            "the retired subject's row closes on the home at once"
        );
        assert!(!home_fold.valid_entries.contains(&mint_row));
        assert!(!home_fold.slips.mints.contains_key(&slip_id));
        assert!(!home.capability_slip_id_is_live(&slip_id).unwrap());
        assert_eq!(home.export_signed_authority_history().unwrap(), history);
        assert!(
            home.get_authority_log_entry(&id)
                .is_err_and(|error| is_authority_overlay_unavailable(&error))
        );
    }

    run_round_for_test(&home, &home_id, &other, &other_id).unwrap();
    {
        let fold = other.authority_fold().unwrap();
        assert!(fold.pass_through_entries.contains(&mint_row));
        assert!(!fold.valid_entries.contains(&mint_row));
        assert!(!fold.slips.mints.contains_key(&slip_id));
        assert!(!other.capability_slip_id_is_live(&slip_id).unwrap());
    }

    drop(other);
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    {
        let fold = other.authority_fold().unwrap();
        assert!(fold.pass_through_entries.contains(&mint_row));
        assert!(!fold.valid_entries.contains(&mint_row));
        assert!(!fold.slips.mints.contains_key(&slip_id));
        assert!(!other.capability_slip_id_is_live(&slip_id).unwrap());
    }

    assert!(deliver_authority_overlay_custody_for_test(&spare, &other, &subject).is_err());
    let fold = other.authority_fold().unwrap();
    assert!(fold.pass_through_entries.contains(&mint_row));
    assert!(!fold.valid_entries.contains(&mint_row));
    assert!(!fold.slips.mints.contains_key(&slip_id));
    assert!(!other.capability_slip_id_is_live(&slip_id).unwrap());

    run_round_for_test(&spare, &spare_id, &other, &other_id).unwrap();
    let fold = other.authority_fold().unwrap();
    assert!(fold.pass_through_entries.contains(&mint_row));
    assert!(!fold.valid_entries.contains(&mint_row));
    assert!(!fold.slips.mints.contains_key(&slip_id));
    assert!(!other.capability_slip_id_is_live(&slip_id).unwrap());
    let spare_fold = spare.authority_fold().unwrap();
    assert!(spare_fold.pass_through_entries.contains(&mint_row));
    assert!(!spare_fold.valid_entries.contains(&mint_row));
    assert!(!spare_fold.slips.mints.contains_key(&slip_id));
    assert!(!spare.capability_slip_id_is_live(&slip_id).unwrap());
}

/// T-ABORT (census L5-22 1a-iii, PLAN-L5-22-1A-III-6 pick 1): the live
/// carrier's home install writer aborts after the key event, leaving the key
/// file but no ready mark. The row stays structure after a reopen too; the
/// next round commits and the row opens.
#[test]
#[cfg(feature = "sync")]
fn a_key_an_aborted_writer_installed_opens_nothing_until_a_delivery_commits() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let home_id = EntityId::now();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    let slip_id = [96; 32];
    claims.slip_id = slip_id;
    claims.records = BTreeSet::from(["record:f".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = home.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&mint_row).unwrap();
    let entry = home.get_authority_log_entry(&id).unwrap().unwrap();
    let _subject = authority_overlay_subject(&entry.op).unwrap();
    let (history, overlays) = home
        .export_signed_authority_history_with_overlays()
        .unwrap();

    let other_dir = tempfile::tempdir().unwrap();
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    let other_id = EntityId::now();
    other
        .import_signed_authority_history(&history, &overlays)
        .unwrap();
    run_round_then_abort_for_test(&home, &home_id, &other, &other_id).unwrap();
    {
        let fold = other.authority_fold().unwrap();
        assert!(
            fold.pass_through_entries.contains(&mint_row),
            "a key file an aborted writer left opens nothing before a reopen"
        );
        assert!(!fold.valid_entries.contains(&mint_row));
        assert!(!fold.slips.mints.contains_key(&slip_id));
        assert!(!other.capability_slip_id_is_live(&slip_id).unwrap());
    }

    drop(other);
    let other = Vault::open(other_dir.path(), VaultConfig::default()).unwrap();
    {
        let fold = other.authority_fold().unwrap();
        assert!(
            fold.pass_through_entries.contains(&mint_row),
            "a key file an aborted writer left opens nothing"
        );
        assert!(!fold.valid_entries.contains(&mint_row));
        assert!(!fold.slips.mints.contains_key(&slip_id));
        assert!(!other.capability_slip_id_is_live(&slip_id).unwrap());
    }

    run_round_for_test(&home, &home_id, &other, &other_id).unwrap();
    let fold = other.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&mint_row));
    assert!(!fold.pass_through_entries.contains(&mint_row));
    assert!(fold.slips.mints.contains_key(&slip_id));
    assert!(other.capability_slip_id_is_live(&slip_id).unwrap());
}

#[test]
#[cfg(feature = "sync")]
fn a_held_key_session_closes_when_its_machine_offers_again() {
    let machine_dir = tempfile::tempdir().unwrap();
    let machine = Vault::open(machine_dir.path(), VaultConfig::default()).unwrap();
    let machine_id = EntityId::now();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = machine.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    let slip_id = [97; 32];
    claims.slip_id = slip_id;
    claims.records = BTreeSet::from(["record:d".to_owned()]);
    let slip = machine.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = machine.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&mint_row).unwrap();
    let entry = machine.get_authority_log_entry(&id).unwrap().unwrap();
    let _subject = authority_overlay_subject(&entry.op).unwrap();

    let (history, overlays) = machine
        .export_signed_authority_history_with_overlays()
        .unwrap();
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let home_id = EntityId::now();
    home.import_signed_authority_history(&history, &overlays)
        .unwrap();

    let (offer, session) = offer_overlay_page(&machine, &machine_id, &home_id, None).unwrap();
    assert_eq!(offer.ready.len(), 1);
    let (subject, key_ref) = offer.ready.iter().next().copied().unwrap();
    let answer = answer_offer(&home, &home_id, &machine_id, &offer).unwrap();
    assert!(answer.session.is_some());
    assert!(answer.wanted.contains(&(subject, key_ref)));
    let sent =
        apply_overlay_answer(&machine, &machine_id, &home_id, &offer, &session, answer).unwrap();
    assert_eq!(sent.len(), 1);

    let offer2 = OverlayOffer {
        digest: [0; 32],
        owed: false,
        after: None,
        through: None,
        ready: BTreeSet::new(),
        erased: BTreeMap::new(),
        session: offer_overlay_page(&machine, &machine_id, &home_id, None)
            .unwrap()
            .0
            .session,
    };
    let answer2 = answer_offer(&home, &home_id, &machine_id, &offer2).unwrap();
    assert!(answer2.session.is_none());
    assert!(
        receive_keys(&home, &home_id, &machine_id, sent).is_err(),
        "a batch sealed to the session the machine's next offer replaced must not install"
    );
    let fold = home.authority_fold().unwrap();
    assert!(fold.pass_through_entries.contains(&mint_row));
    assert!(!fold.valid_entries.contains(&mint_row));
}

#[test]
#[cfg(feature = "sync")]
fn an_offer_whose_session_key_does_not_import_retires_nothing() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let home_id = EntityId::now();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    let slip_id = [98; 32];
    claims.slip_id = slip_id;
    claims.records = BTreeSet::from(["record:d".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = home.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&mint_row).unwrap();
    let entry = home.get_authority_log_entry(&id).unwrap().unwrap();
    let _subject = authority_overlay_subject(&entry.op).unwrap();

    let machine_id = EntityId::now();
    let ready = offer_overlay_page(&home, &home_id, &machine_id, None)
        .unwrap()
        .0
        .ready;
    assert_eq!(ready.len(), 1);
    let (subject, key_ref) = ready.iter().next().copied().unwrap();
    assert!(
        home.authority_fold()
            .unwrap()
            .valid_entries
            .contains(&mint_row)
    );
    let offer = OverlayOffer {
        digest: [0; 32],
        owed: false,
        after: None,
        through: None,
        ready: BTreeSet::new(),
        erased: BTreeMap::from([(
            subject,
            ErasedSubject {
                refs: BTreeSet::from([key_ref]),
                destroyed: BTreeSet::new(),
            },
        )]),
        session: OverlayKeySession {
            ephemeral: vec![0u8; 3],
            nonce: [7; 32],
        },
    };
    assert!(answer_offer(&home, &home_id, &machine_id, &offer).is_err());
    assert!(
        home.authority_fold()
            .unwrap()
            .valid_entries
            .contains(&mint_row),
        "an offer refused for its session key must leave its subject's rows open"
    );
    assert!(
        offer_overlay_page(&home, &home_id, &machine_id, None)
            .unwrap()
            .0
            .ready
            .contains(&(subject, key_ref))
    );
}

#[test]
#[cfg(feature = "sync")]
fn an_offer_naming_a_subject_erased_with_no_key_is_refused_and_retires_nothing() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = Vault::open(home_dir.path(), VaultConfig::default()).unwrap();
    let home_id = EntityId::now();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    let slip_id = [99; 32];
    claims.slip_id = slip_id;
    claims.records = BTreeSet::from(["record:d".to_owned()]);
    let slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = home.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&mint_row).unwrap();
    let entry = home.get_authority_log_entry(&id).unwrap().unwrap();
    let _subject = authority_overlay_subject(&entry.op).unwrap();

    let machine_id = EntityId::now();
    let inventory_offer = offer_overlay_page(&home, &home_id, &machine_id, None)
        .unwrap()
        .0;
    assert_eq!(inventory_offer.ready.len(), 1);
    let (subject, _key_ref) = inventory_offer.ready.iter().next().copied().unwrap();
    assert!(
        home.authority_fold()
            .unwrap()
            .valid_entries
            .contains(&mint_row)
    );
    let offer = OverlayOffer {
        digest: [0; 32],
        owed: false,
        after: None,
        through: None,
        ready: BTreeSet::new(),
        erased: BTreeMap::from([(subject, ErasedSubject::default())]),
        session: inventory_offer.session,
    };
    assert!(
        answer_offer(&home, &home_id, &machine_id, &offer).is_err(),
        "an offer naming a subject erased with no key must be refused"
    );
    assert!(
        home.authority_fold()
            .unwrap()
            .valid_entries
            .contains(&mint_row)
    );
}

#[test]
#[cfg(feature = "sync")]
fn an_answer_naming_a_subject_erased_with_no_key_seals_nothing() {
    let machine_dir = tempfile::tempdir().unwrap();
    let machine = Vault::open(machine_dir.path(), VaultConfig::default()).unwrap();
    let machine_id = EntityId::now();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = machine.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    let slip_id = [100; 32];
    claims.slip_id = slip_id;
    claims.records = BTreeSet::from(["record:d".to_owned()]);
    let slip = machine.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = machine.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&mint_row).unwrap();
    let entry = machine.get_authority_log_entry(&id).unwrap().unwrap();
    let _subject = authority_overlay_subject(&entry.op).unwrap();

    let home_id = EntityId::now();
    let (offer, session) = offer_overlay_page(&machine, &machine_id, &home_id, None).unwrap();
    assert_eq!(offer.ready.len(), 1);
    let (subject, key_ref) = offer.ready.iter().next().copied().unwrap();
    let answer = OverlayAnswer {
        same: false,
        through: None,
        erased: BTreeMap::from([(subject, ErasedSubject::default())]),
        keys: Vec::new(),
        wanted: BTreeSet::from([(subject, key_ref)]),
        session: Some(
            offer_overlay_page(&machine, &machine_id, &home_id, None)
                .unwrap()
                .0
                .session,
        ),
    };
    assert!(
        apply_overlay_answer(&machine, &machine_id, &home_id, &offer, &session, answer).is_err(),
        "an answer naming a subject erased with no key must be refused before a key is sealed"
    );
    assert!(
        machine
            .authority_fold()
            .unwrap()
            .valid_entries
            .contains(&mint_row)
    );
}

#[test]
#[cfg(feature = "sync")]
fn a_wanted_key_of_a_subject_the_answer_names_erased_is_retired_not_sent() {
    let machine_dir = tempfile::tempdir().unwrap();
    let machine = Vault::open(machine_dir.path(), VaultConfig::default()).unwrap();
    let machine_id = EntityId::now();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = machine.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    let slip_id = [101; 32];
    claims.slip_id = slip_id;
    claims.records = BTreeSet::from(["record:d".to_owned()]);
    let slip = machine.mint_capability_slip(&issuer, claims).unwrap();
    let mint_row = machine.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&mint_row).unwrap();
    let entry = machine.get_authority_log_entry(&id).unwrap().unwrap();
    let _subject = authority_overlay_subject(&entry.op).unwrap();

    let home_id = EntityId::now();
    let (offer, session) = offer_overlay_page(&machine, &machine_id, &home_id, None).unwrap();
    assert_eq!(offer.ready.len(), 1);
    let (subject, key_ref) = offer.ready.iter().next().copied().unwrap();
    let answer = OverlayAnswer {
        same: false,
        through: None,
        erased: BTreeMap::from([(
            subject,
            ErasedSubject {
                refs: BTreeSet::from([key_ref]),
                destroyed: BTreeSet::new(),
            },
        )]),
        keys: Vec::new(),
        wanted: BTreeSet::from([(subject, key_ref)]),
        session: Some(
            offer_overlay_page(&machine, &machine_id, &home_id, None)
                .unwrap()
                .0
                .session,
        ),
    };
    let sent =
        apply_overlay_answer(&machine, &machine_id, &home_id, &offer, &session, answer).unwrap();
    assert!(
        sent.is_empty(),
        "a key of a subject the answer names erased must not be sent"
    );
    let fold = machine.authority_fold().unwrap();
    assert!(fold.pass_through_entries.contains(&mint_row));
    assert!(!fold.valid_entries.contains(&mint_row));
}
