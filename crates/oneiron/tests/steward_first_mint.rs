//! The host's first mint of the Dreamer's Steward grant (untangle 6.3b,
//! S63-2 = A). On an install a host has opened, the first mint copies the
//! live rows one to one: the shipped rows give the whole default, and the Dreamer reads and lands through the grant. A policy
//! with none of the rows records the opt-out and mints nothing, and the
//! Dreamer reads and lands nothing. A second open changes nothing. On the
//! base there is no mint.
//!
//! The grant the first mint writes is the engine actor's reach on the vault's
//! own root, not a member: the owner still shares the vault after it (review
//! of #6917, round 2; the membership guard counted it and refused).
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_first_mint`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::test_doors::steward::{
    GrantMark, STEWARD_VERBS, WeaveReach, dreamer, drop_dreamer_rows, grant_mark,
    open_owner_carrier_vault, owner, weave_reach,
};

const SHARED: u64 = 42;

#[test]
fn the_first_mint_copies_the_dreamers_rows() {
    for rows in [true, false] {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
        if !rows {
            drop_dreamer_rows(&vault).expect("no Dreamer rows");
        }
        let dreamer = dreamer(&vault).expect("the Dreamer");
        assert_eq!(grant_mark(&vault, dreamer).expect("mark"), None, "{rows}");

        vault.provision_system_agent_grants().expect("first mint");
        let mark = grant_mark(&vault, dreamer).expect("mark");
        let reach = weave_reach(&vault).expect("reach");
        if rows {
            let Some(GrantMark::Minted { verbs, .. }) = &mark else {
                panic!("the shipped rows mint the grant: {mark:?}");
            };
            let expected: BTreeSet<String> = STEWARD_VERBS
                .iter()
                .map(|verb| (*verb).to_owned())
                .collect();
            assert_eq!(verbs, &expected, "the whole default");
            assert_eq!(
                reach,
                WeaveReach {
                    reads: true,
                    lands_auto: true
                },
                "the grant reads and lands"
            );
        } else {
            assert_eq!(mark, Some(GrantMark::OptedOut), "no rows: the opt-out");
            assert_eq!(
                reach,
                WeaveReach {
                    reads: false,
                    lands_auto: false
                },
                "an opt-out reads and lands nothing"
            );
        }

        vault.provision_system_agent_grants().expect("second open");
        assert_eq!(
            grant_mark(&vault, dreamer).expect("mark"),
            mark,
            "a second open mints nothing"
        );
    }
}

#[test]
fn the_first_mint_does_not_close_sharing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    vault.provision_system_agent_grants().expect("first mint");
    let mark = grant_mark(&vault, dreamer).expect("mark");
    assert!(
        matches!(mark, Some(GrantMark::Minted { .. })),
        "the shipped rows mint the grant: {mark:?}"
    );

    let owner = owner(&vault).expect("owner proof");
    vault
        .initialize_shared_vault(&owner, SHARED, None, &[], 1)
        .expect("the owner shares a vault whose only grant is the Dreamer's");
    assert_eq!(
        grant_mark(&vault, dreamer).expect("mark"),
        mark,
        "sharing leaves the Dreamer's grant as it stood"
    );
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        WeaveReach {
            reads: true,
            lands_auto: true
        },
        "the Dreamer reads and lands through the same grant"
    );
    assert!(
        vault
            .initialize_shared_vault(&owner, SHARED, None, &[], 1)
            .is_err(),
        "a vault is shared once: the creation row closes it"
    );
}
