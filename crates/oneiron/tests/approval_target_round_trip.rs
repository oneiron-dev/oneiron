//! FIX 22398 (APPROVAL-TARGET): every approval family spends what it
//! composed.
//!
//! An owner's approve-once press releases one send only if the digest the
//! family composes for that send is the key the Gate's spend lookup
//! recomposes from the effect it holds. The family now owns both halves
//! (`ApprovalTarget::approve_once_digest`, which the outbound and scoped-MCP
//! helpers call, and `ApprovalTarget::kept_press_retry_proof`, which the
//! ledger's kept-press check calls). This promise test pins the round trip
//! for every family: none fails today (brief 18), and a family whose composer
//! drifts from the lookup fails here, not closed in the field.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test approval_target_round_trip`.

use oneiron::test_doors::approval_target_round_trip::{FamilyRoundTrip, every_family_round_trip};
use oneiron::{Result, Vault, VaultConfig};

/// The families a press is kept for its retry.
const KEEPS_PRESS: [&str; 4] = [
    "linear_dispatch",
    "campaign",
    "scoped_mcp",
    "connector_slate",
];

#[test]
fn every_approval_family_spends_what_it_composed() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;

    let trips = every_family_round_trip(&vault)?;

    assert_eq!(trips.len(), 11, "every family is covered: {trips:#?}");
    for trip in &trips {
        let keeps = KEEPS_PRESS.contains(&trip.family);
        assert_eq!(
            trip,
            &FamilyRoundTrip {
                family: trip.family,
                composed: true,
                press_found: true,
                sibling_found: false,
                kept_press_retries: keeps.then_some(true),
                kept_press_strays: keeps.then_some(false),
            },
            "the owner's press on one {} send is spent by that send alone",
            trip.family
        );
    }
    Ok(())
}
