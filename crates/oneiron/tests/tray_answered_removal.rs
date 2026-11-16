//! FIX 22394 (CONSENT-TRAY): a tray removal that says `Answered` carries the
//! owner's answer.
//!
//! `TrayRemoval::Answered` was a bare variant any door could name. A removal
//! that says it skips recording the claim's owner-answer obligation, so a
//! confirm parked before obligations were recorded, removed as `Answered` by
//! a door that held no answer, left neither a row nor an obligation: the
//! critical claim read settled with no owner answer (red proof: the test
//! `answered_removal_without_an_answer_must_not_settle_a_critical_row` on
//! branch `opus-fix-c/proof-consent-tray-red`). The variant now carries an
//! `ObligationAnswered` that only the obligation's close builds, so that
//! misuse no longer compiles and needs no runtime test.
//!
//! The compliant path keeps its effect: the owner's own answer, revalidated
//! in the answering transaction, still settles the claim.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test tray_answered_removal`.

use oneiron::test_doors::tray_answered_removal::{
    SettledAround, remove_confirm_with_the_owners_answer,
};
use oneiron::{EntityId, Result, Vault, VaultConfig};

#[test]
fn owner_answered_removal_settles_a_critical_row() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let claim = EntityId::from_bytes([0x54; 16]).expect("fixture claim id");

    let around = remove_confirm_with_the_owners_answer(&vault, &claim)?;

    assert_eq!(
        around,
        Some(SettledAround {
            before: false,
            after: true,
        }),
        "the owner's answer to the confirm's item settles the critical claim"
    );
    Ok(())
}
