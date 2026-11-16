//! A sealed AUTHORITY_LOG row in this vault (census L5-22): the door that
//! signs it stores the row in its scaffold form and the overlay record
//! beside it, sealed, and the vault's own reader opens the row whole, after
//! a reopen too.

use super::*;
use crate::side_table::{self, Raw, SideTable};
use crate::{Vault, VaultConfig};

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
