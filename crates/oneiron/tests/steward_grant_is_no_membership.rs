//! A base agent's Steward grant is no membership (untangle 6.3b; review of
//! #6913, #6914 and #6915). On a shared vault the Dreamer's grant is a
//! FEDERATION_GRANT row in the vault's scope with the Steward role, and the
//! membership doors took it for a member's row: `vault.members.change`
//! rewrote it in place at any role's default (back at Steward that is every
//! Steward verb, so the owner's narrowing was undone with no owner act),
//! `vault.members.remove` deleted it with no warning and no confirm, and the
//! roster listed the Dreamer's MACHINE as a member.
//!
//! Only the owner moves that grant, through its own door, which shows what
//! breaks and waits for his confirm. The membership doors skip it: a role
//! change or a removal that names the Dreamer is refused as it is for
//! anyone who is no member, and the roster does not list it. The doors
//! judge an Admin's call and the owner's in the same place, after the
//! caller's own power is checked, so the owner's refusal here is the
//! Admin's too.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_grant_is_no_membership`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::federation::FederationGrantRole as Role;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::steward::{
    GrantMark, STEWARD_READ_VERB, dreamer, grant_mark, owner, shared_roster, stand_steward_grant,
};

const READER: &str = "reader";
const SHARED: u64 = 42;

#[test]
fn no_membership_door_moves_the_dreamers_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let owner = owner(&vault).expect("owner proof");
    vault
        .initialize_shared_vault(&owner, SHARED, None, &[], 1)
        .expect("a shared vault");
    // The Dreamer's grant on the shared vault, as the owner narrowed it:
    // `read` alone.
    let grant = stand_steward_grant(&vault, dreamer, &[STEWARD_READ_VERB]).expect("read alone");
    let narrowed = Some(GrantMark::Minted {
        grant,
        verbs: BTreeSet::from([STEWARD_READ_VERB.to_owned()]),
    });
    assert_eq!(grant_mark(&vault, dreamer).expect("mark"), narrowed);

    assert!(
        vault
            .change_shared_member_role(&owner, SHARED, dreamer, Role::Member, None)
            .is_err(),
        "a role change that names the Dreamer is refused: its grant is no membership"
    );
    assert!(
        vault
            .change_shared_member_role(&owner, SHARED, dreamer, Role::Viewer, None)
            .is_err(),
        "at any role"
    );
    assert!(
        vault
            .remove_shared_member(&owner, SHARED, dreamer, None)
            .is_err(),
        "a removal that names the Dreamer is refused: the grant is revoked through its own door"
    );
    assert_eq!(
        grant_mark(&vault, dreamer).expect("mark"),
        narrowed,
        "the grant stands as the owner narrowed it: the same row, `read` alone"
    );
    let roster = shared_roster(&vault, SHARED).expect("roster");
    assert!(
        roster.iter().all(|(member, _)| *member != dreamer),
        "the roster lists members, not the engine's own actor: {roster:?}"
    );
    assert!(
        roster.iter().any(|(_, role)| *role == Role::Owner),
        "the roster still lists the Owner: {roster:?}"
    );
}
