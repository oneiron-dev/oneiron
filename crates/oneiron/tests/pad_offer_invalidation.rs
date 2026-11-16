#![cfg(oneiron_test_support)]
//! FIX 22389 PAD-GRANT: a late joiner that could not use its offered pad
//! grant reports it to the home, and the home sets the offer back to pending
//! for an issuer to grant again. The report must retire only the offer the
//! joiner read: a replacement that an issuer offered meanwhile stays.
//!
//! The authority checks around the report (the joiner stands as the owner's
//! here, by the proof on its socket) are unchanged; the door runs the home's
//! row step past them.

use oneiron::test_doors::pad_offer_invalidation::{
    GrantRow, grant_row, put_offer, report_invalid_offers,
};
use oneiron::world_keys::{PadAdmissionTarget, SealedBundleGeneration};
use oneiron::{EntityId, Vault, VaultConfig};
use tempfile::TempDir;

/// The offered grant the joiner read and could not use.
const READ_OFFER: &[u8] = b"the offer the joiner read";
/// The offer an issuer made after the joiner read its own.
const REPLACEMENT_OFFER: &[u8] = b"the offer an issuer made since";

fn vault() -> (TempDir, Vault) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("the vault opens");
    // Bound as (_d, v): v drops before _d removes the LMDB files.
    (dir, vault)
}

fn generation() -> SealedBundleGeneration {
    SealedBundleGeneration {
        slot: 1,
        nonce: [3; 16],
    }
}

fn joiner() -> PadAdmissionTarget {
    PadAdmissionTarget {
        machine: EntityId::from_bytes([1; 16]).expect("a machine id"),
        encryption_key_digest: [5; 32],
    }
}

fn row(vault: &Vault) -> Option<GrantRow> {
    grant_row(vault, &generation(), &joiner()).expect("the grant row reads")
}

#[test]
fn invalid_report_keeps_a_concurrent_replacement_offer() {
    let (_d, v) = vault();
    put_offer(&v, &generation(), &joiner(), READ_OFFER).expect("the first offer is kept");
    put_offer(&v, &generation(), &joiner(), REPLACEMENT_OFFER).expect("the replacement is kept");

    report_invalid_offers(&v, generation(), joiner(), &[READ_OFFER.to_vec()])
        .expect("the report is taken");

    assert_eq!(
        row(&v),
        Some(GrantRow::Offered(REPLACEMENT_OFFER.to_vec())),
        "a report of the offer the joiner read keeps the replacement offered since"
    );
}

#[test]
fn invalid_report_of_the_held_offer_sets_it_back_to_pending() {
    let (_d, v) = vault();
    put_offer(&v, &generation(), &joiner(), READ_OFFER).expect("the offer is kept");

    report_invalid_offers(&v, generation(), joiner(), &[READ_OFFER.to_vec()])
        .expect("the report is taken");

    assert_eq!(
        row(&v),
        Some(GrantRow::Pending),
        "the offer the joiner could not use goes back to pending"
    );
}
