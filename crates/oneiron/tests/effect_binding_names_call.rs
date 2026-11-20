//! FIX [GATE-EFFECT-BINDING-NO-CALL-IDENTITY]: the Gate binds a held
//! scoped-MCP call's decision to that one call.
//!
//! The Gate's binding of an external-effect decision hashed a scoped call's
//! server, tool, data class and endpoint, but not which call it was. Two held
//! calls of one tool that differed only in their arguments, their call
//! sequence or their attempt therefore shared one binding, and the second
//! call's Pending answered with the first call's pending receipt: its
//! `decision_ref` named the other call's row, and a run review read that
//! row's later verdict as its own. The binding now names the call by its
//! pinned target (attempt, call sequence, digest of the frozen bytes), and
//! only a scoped call's: every other effect binds as before.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test effect_binding_names_call`.

use oneiron::test_doors::external_effect_binding::{HeldCallBindings, record_held_calls};
use oneiron::{Result, Vault, VaultConfig};

#[test]
fn two_held_calls_of_one_tool_hold_two_pending_receipts() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;

    let held = record_held_calls(&vault)?;

    assert_eq!(
        held.outcomes,
        vec!["pending"; 7],
        "the fail-closed policy holds every effect: {held:#?}"
    );
    assert_eq!(
        held,
        HeldCallBindings {
            outcomes: held.outcomes.clone(),
            retry_reuses_its_row: true,
            other_sequence_own_row: true,
            other_attempt_own_row: true,
            other_arguments_own_row: true,
            unscoped_target_shares_row: true,
            pending_rows: 5,
        },
        "each held call holds its own pending receipt, and its retry finds it again"
    );
    Ok(())
}
