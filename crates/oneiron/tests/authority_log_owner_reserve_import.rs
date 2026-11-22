//! Row OWNER-RESERVE-IMPORT-PARTIAL (Engine RULING OWNER-RESERVE-IMPORT = A,
//! option B): past the owner reserve, the owner's history import through his
//! verb `vault.authority.history.import` lands the rows the store door admits
//! and keeps each row the door holds at the reserve, with every row of the
//! import standing on one. The kept rows land once the owner raises the floor
//! row, with no second import, and never before it: no import passes the
//! reserve (option C stays out). The other import doors (the world key bundle,
//! the sealed-kit restore, the authority pages) still refuse whole. Red on main
//! 43174859: the verb refuses the whole import with `AuthorityLogFull`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_import`.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron::authority::{
    AuthorityLogEntry, AuthorityObservationPolicy, authority_entry_hash, authority_log_entity_id,
    decode_authority_log_entry_body, encode_authority_log_entry_body,
};
use oneiron::verbs::{SignedAuthorityHistory, import_authority_history_as_owner};
use oneiron::{EntityId, ErrorKind, Vault, VaultConfig};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    AT, FLOOD_CAP, FLOOR_BYTES, Flooder, Rooted, admit_flooder, flood_row, rooted, stored_history,
};

/// The owner's typed check that names the reserve.
const OWNER_RESERVE_CHECK: &str = "authority_log_owner_reserve";

fn set_floor(vault: &Vault, floor_bytes: u64) {
    vault
        .set_authority_observation_policy(AuthorityObservationPolicy {
            log_fold_memory_floor_bytes: Some(floor_bytes),
            ..AuthorityObservationPolicy::default()
        })
        .expect("the floor row");
}

/// Install A under the test's floor, with a machine the owner admitted that
/// floods.
fn floored_vault_with_flooder() -> (Rooted, Flooder) {
    let rooted = rooted();
    let flooder = admit_flooder(&rooted);
    set_floor(&rooted.vault, FLOOR_BYTES);
    assert!(
        !rooted
            .vault
            .authority_fold()
            .expect("the fold")
            .authority_log_past_bound(),
        "the fixture's log folds under the floor"
    );
    (rooted, flooder)
}

/// The flooder chains world edits on its admission until A's door holds
/// one at the owner reserve: that row, which A does not store, and the
/// world the chain edits.
fn flood_until_held(rooted: &Rooted, flooder: &Flooder) -> (AuthorityLogEntry, EntityId) {
    let world = EntityId::now();
    let mut parent = flooder.admission;
    for seq in 1..=FLOOD_CAP {
        let row = flood_row(rooted, flooder, world, seq, parent);
        match rooted.vault.put_authority_log_entry(&row, AT, 1) {
            Ok(_) => parent = authority_entry_hash(&row).expect("hash"),
            Err(error) if error.kind() == ErrorKind::AuthorityLogFull => return (row, world),
            Err(error) => panic!("flood row {seq} was refused, not held: {error}"),
        }
    }
    panic!("{FLOOD_CAP} flood rows landed and none waited at the owner reserve");
}

/// The row a second install of this vault signs under the host root: it
/// takes A's history, as sync does, and the host root rebinds its key there.
/// A row the host root signs is the owner's work at every install's door,
/// and A does not hold it yet.
fn host_root_row_from_a_second_install(rooted: &Rooted) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tempdir");
    let other = Vault::open(dir.path(), VaultConfig::device()).expect("the second install");
    other.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let history = stored_history(&rooted.vault);
    other
        .import_signed_authority_history(&history, &std::collections::BTreeMap::new())
        .expect("the second install takes the history");
    let issuer = oneiron::test_support::test_host_issuer();
    oneiron::test_support::bind_host_actor(&other, &issuer, EntityId::now(), "agent")
        .expect("the host root rebinds its key on the second install");
    let mut signed: Vec<Vec<u8>> = stored_history(&other)
        .into_iter()
        .filter(|row| !history.contains(row))
        .collect();
    assert_eq!(
        signed.len(),
        1,
        "the second install signed one row, the host root's"
    );
    signed.remove(0)
}

/// `rows` as the owner's verb takes them.
fn signed(rows: &[Vec<u8>]) -> SignedAuthorityHistory {
    SignedAuthorityHistory {
        entries: rows.iter().map(|row| STANDARD.encode(row)).collect(),
        overlays: std::collections::BTreeMap::new(),
    }
}

fn id_of(row: &AuthorityLogEntry) -> EntityId {
    authority_log_entity_id(row).expect("the row's id")
}

fn stored(vault: &Vault, row: &AuthorityLogEntry) -> bool {
    vault
        .get_authority_log_entry(&id_of(row))
        .expect("read")
        .is_some_and(|stored| stored == *row)
}

fn names_the_reserve(vault: &Vault) -> bool {
    vault
        .authority_log_checks()
        .expect("the checks")
        .iter()
        .any(|check| check.kind == OWNER_RESERVE_CHECK)
}

#[test]
fn the_owners_import_past_the_reserve_lands_his_row_and_the_held_row_once_the_floor_is_raised() {
    let (rooted, flooder) = floored_vault_with_flooder();
    let owners_bytes = host_root_row_from_a_second_install(&rooted);
    let owners_row = decode_authority_log_entry_body(&owners_bytes).expect("the owner's row");
    let (held, _) = flood_until_held(&rooted, &flooder);
    let import = vec![
        owners_bytes.clone(),
        encode_authority_log_entry_body(&held).expect("the held row's body"),
    ];
    let refused = rooted
        .vault
        .import_signed_authority_history(&import, &std::collections::BTreeMap::new())
        .expect_err("the whole-history door refuses an import past the reserve whole");
    assert_eq!(refused.kind(), ErrorKind::AuthorityLogFull, "{refused}");
    assert!(
        !stored(&rooted.vault, &owners_row),
        "the whole-history door writes nothing"
    );
    let imported = import_authority_history_as_owner(&rooted.vault, &rooted.proof, signed(&import))
        .expect("the owner's import lands the rows the door admits");
    assert_eq!(
        imported.entry_refs,
        vec![id_of(&owners_row).to_hex()],
        "the answer names the rows stored now: the owner's, not the held one"
    );
    assert!(stored(&rooted.vault, &owners_row), "the owner's row lands");
    assert!(
        !stored(&rooted.vault, &held),
        "the flooder's row waits: the owner's import does not pass the reserve"
    );
    assert!(
        names_the_reserve(&rooted.vault),
        "the owner's typed check names the reserve"
    );
    set_floor(&rooted.vault, 4 * FLOOR_BYTES);
    assert!(
        stored(&rooted.vault, &held),
        "the held row lands once the floor is raised, with no second import"
    );
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
}

#[test]
fn a_row_standing_on_a_held_row_waits_with_it_until_the_floor_lets_them_both_land() {
    let (rooted, flooder) = floored_vault_with_flooder();
    let (held, world) = flood_until_held(&rooted, &flooder);
    let child = flood_row(
        &rooted,
        &flooder,
        world,
        held.seq + 1,
        authority_entry_hash(&held).expect("hash"),
    );
    let import = vec![
        encode_authority_log_entry_body(&held).expect("the held row's body"),
        encode_authority_log_entry_body(&child).expect("its child's body"),
    ];
    let imported = import_authority_history_as_owner(&rooted.vault, &rooted.proof, signed(&import))
        .expect("an owner's import of rows the reserve holds answers, and keeps them");
    assert!(
        imported.entry_refs.is_empty(),
        "nothing lands past the reserve: {:?}",
        imported.entry_refs
    );
    assert!(!stored(&rooted.vault, &held) && !stored(&rooted.vault, &child));
    set_floor(&rooted.vault, FLOOR_BYTES);
    assert!(
        !stored(&rooted.vault, &held) && !stored(&rooted.vault, &child),
        "a write of the floor row that still holds them keeps them waiting"
    );
    assert!(
        names_the_reserve(&rooted.vault),
        "the owner's typed check still names the reserve"
    );
    set_floor(&rooted.vault, 4 * FLOOR_BYTES);
    assert!(
        stored(&rooted.vault, &held) && stored(&rooted.vault, &child),
        "both land, parent first, once the floor lets them"
    );
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
}
