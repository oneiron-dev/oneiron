//! The host's first mint of the Dreamer's Steward grant (untangle 6.3b,
//! S63-2 = A). On an install a host has opened, the first mint copies the
//! live rows one to one: the shipped rows give the whole default, and the Dreamer reads and lands through the grant. A policy
//! with none of the rows records the opt-out and mints nothing, and the
//! Dreamer reads and lands nothing. A second open changes nothing. On the
//! base there is no mint.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_first_mint`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::test_doors::steward::{
    GrantMark, STEWARD_VERBS, WeaveReach, dreamer, drop_dreamer_rows, grant_mark,
    open_owner_carrier_vault, weave_reach,
};

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
