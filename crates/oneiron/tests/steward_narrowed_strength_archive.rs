//! X02's test pointed at a narrowed Steward grant (untangle 6.3; the X02
//! verdict, Engine and lead 9 Nov 16:5x; TESTS-MUST-RUN 19:05). The strength
//! archive takes back what the Dreamer landed, so it is judged by the grant
//! that let it land: with the Dreamer's full Steward grant the archive lands
//! and its receipt names that grant; with the grant narrowed to drop `derive`
//! (the `Generated` permit and the Auto ceiling it yields) nothing is
//! archived and no receipt is written. On main there is no Steward grant.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_narrowed_strength_archive`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::steward::{
    STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, STEWARD_VERBS, WeaveReach, a_month_on_ms,
    archive_every_quiet_claim, archive_quiet_claims, dreamer, stand_steward_grant,
    strength_archive_receipts, weave_reach,
};

const READER: &str = "reader";

/// The model's reply: one new person, named in T1, and its name.
fn reply() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

#[test]
fn the_strength_archive_is_judged_by_a_narrowed_steward_grant() {
    for narrowed in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
        let dreamer = dreamer(&vault).expect("the Dreamer");
        let full = stand_steward_grant(&vault, dreamer, &STEWARD_VERBS).expect("full grant");
        assert_eq!(
            weave_reach(&vault).expect("reach"),
            WeaveReach {
                reads: true,
                lands_auto: true
            },
            "the full grant reads and lands"
        );

        let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
            .expect("one consolidation pass");
        let [claim] = pass.landed.as_slice() else {
            panic!("one landed claim, found {}", pass.landed.len());
        };
        archive_every_quiet_claim(&vault).expect("strength policy");

        if narrowed {
            stand_steward_grant(&vault, dreamer, &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB])
                .expect("narrowed grant");
            assert_eq!(
                weave_reach(&vault).expect("reach"),
                WeaveReach {
                    reads: true,
                    lands_auto: false
                },
                "only the landing is narrowed"
            );
        }

        let archived = archive_quiet_claims(&vault, pass.attempt, a_month_on_ms(&vault))
            .expect("strength archive");
        let receipts = strength_archive_receipts(&vault, claim).expect("receipts");
        if narrowed {
            assert_eq!(archived, 0, "a narrowed grant archives nothing");
            assert!(receipts.is_empty(), "no receipt is written: {receipts:?}");
        } else {
            assert_eq!(archived, 1, "the full grant lets the archive land");
            let [receipt] = receipts.as_slice() else {
                panic!("one archive receipt, found {}", receipts.len());
            };
            assert_eq!(
                receipt.grant_ref.as_deref(),
                Some(full.to_hex().as_str()),
                "the receipt names the Dreamer's grant"
            );
            assert_ne!(receipt.read_frontier_hash, [0; 32]);
        }
    }
}
