//! FIX GENESIS-FRAGILE-START-SCANS-AUTHORITY-LOG: the read behind the
//! fragile-genesis flag (`Vault::genesis_fragile_now`, asked at each start of
//! a vault whose root ever moved) looks for one valid enrolment of a live
//! owner key. It read, decoded and hashed every stored authority log row and
//! built the list of every enrolled key before it asked whether one was live.
//! Now it reads one row at a time and stops at the first such enrolment.
//!
//! `the_search_for_a_live_owner_key_enrolment_stops_at_the_first_one` is red
//! on a search that reads on past the enrolment (it reads every stored row,
//! and the enrolment is the last row of all four vaults by chance only). Its
//! answer is compared with the list read (`Vault::enrolled_owner_keys`),
//! which this change leaves as it was. The flag itself, before a root move,
//! after it and after a new kit's enrolment, is
//! `a_recovered_root_flags_the_vault_until_a_new_kit_is_enrolled` in
//! `oneiron-server`'s `tests/host_root_recovery.rs`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_enrolment_read`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::owner_device_answer::open_owner_device_vault;
use oneiron::test_doors::owner_key_enrolment_read::live_owner_key_enrolment_read;

/// The enrolment's place among the stored rows follows its hash, so one
/// vault could hold it last; four do so only by chance.
const VAULTS: usize = 4;

#[test]
fn the_search_for_a_live_owner_key_enrolment_stops_at_the_first_one() {
    for _ in 0..VAULTS {
        let dir = tempfile::tempdir().expect("a tempdir");
        let device = open_owner_device_vault(dir.path()).expect("the hosted device vault");

        // No owner key is enrolled: the search reads every stored row and
        // finds none, as the list read does.
        let before = live_owner_key_enrolment_read(&device.vault).expect("the search");
        assert!(
            before.stored.len() > 1,
            "the vault stores its root's rows before any enrolment"
        );
        assert!(!before.enrolled, "no owner key is enrolled yet");
        assert_eq!(
            before.rows_read,
            before.stored.len(),
            "with no live enrolment the search reads every stored row"
        );
        assert!(
            device
                .vault
                .enrolled_owner_keys()
                .expect("the list read")
                .iter()
                .all(|key| !key.live),
            "the list read holds no live owner key either"
        );

        device
            .enrol_owner_key()
            .expect("the owner enrols this install's owner signing key");

        let live: Vec<_> = device
            .vault
            .enrolled_owner_keys()
            .expect("the list read")
            .iter()
            .filter(|key| key.live)
            .map(|key| key.entry)
            .collect();
        assert_eq!(
            live.len(),
            1,
            "the list read holds the one enrolled key live"
        );
        let after = live_owner_key_enrolment_read(&device.vault).expect("the search");
        assert!(
            after.enrolled,
            "the search finds the enrolment the list holds"
        );
        let place = after
            .stored
            .iter()
            .position(|hash| *hash == live[0])
            .expect("the enrolment is a stored row");
        assert_eq!(
            after.rows_read,
            place + 1,
            "the search stops at the enrolment, row {} of {}",
            place + 1,
            after.stored.len()
        );
    }
}
