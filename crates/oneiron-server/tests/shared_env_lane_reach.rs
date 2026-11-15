//! A shared env's lane never falls back to full replication
//! (FIX-LIST [MEMBER-SELECTOR-SOCKET]; Engine RULING MEMBER-SELECTOR-SCOPE =
//! C, 15 Nov 04:0x; MEMBER-SYNC D8).
//!
//! The lane a member's paired slip opens: a slip naming no member grant
//! replicates in full, which the home's owner door admits for its vault's
//! owner alone (OWNER-GRADE-IS-NOT-OWNERSHIP H8). A slip naming a member
//! grant opens the member lane under that grant, built from the slip's own
//! claims (`grant_ref`, `holder_ref`, All): HOME proves the grant at the
//! upgrade (MEMBER-SYNC D1), so a fresh env with no local copy starts, and
//! a member's lane never falls back to full replication.
//!
//! The lane's reach is read through the `oneiron_test_support` door
//! (`oneiron_server::test_doors::shared_env_lane`); the grant row is seeded
//! with `oneiron/test-hooks`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support,oneiron/test-hooks
//! --test shared_env_lane_reach`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::sync::put_selector_test_federation_grant;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::test_doors::shared_env_lane::lane_reach;

/// The shared vault the member's grant is minted under.
const SHARED_VAULT_ID: u64 = 42;

fn open_env() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the env's vault");
    (dir, vault)
}

#[test]
fn a_slip_naming_no_member_grant_replicates_in_full() {
    let (_dir, vault) = open_env();
    let holder = EntityId::now().to_hex();
    assert_eq!(
        lane_reach(&vault, None, &holder).expect("the reach"),
        "full"
    );
}

#[test]
fn a_member_grant_this_env_holds_opens_the_member_lane() {
    let (_dir, vault) = open_env();
    let member = EntityId::now();
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        FederationGrantScope::vault(SHARED_VAULT_ID),
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    put_selector_test_federation_grant(&vault, &grant_id, &grant, vault.now_recorded_at())
        .expect("the member's grant");
    assert_eq!(
        lane_reach(&vault, Some(&grant_id.to_hex()), &member.to_hex()).expect("the reach"),
        format!("member {} {}", grant_id.to_hex(), member.to_hex()),
        "the lane reads under the grant its slip names"
    );
}

#[test]
fn a_member_grant_this_env_lacks_opens_the_member_lane() {
    let (_dir, vault) = open_env();
    let member = EntityId::now();
    let grant_id = EntityId::now();
    assert_eq!(
        lane_reach(&vault, Some(&grant_id.to_hex()), &member.to_hex()).expect("the reach"),
        format!("member {} {}", grant_id.to_hex(), member.to_hex()),
        "a member's lane with no copy of its grant opens from the slip's own claims \
         (MEMBER-SYNC D8)"
    );
}
