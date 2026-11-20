//! The nightly merge writes one narrative per exposure group as a
//! `dreamer.arc.summary` claim, from only that group's proposals. The
//! narrative carries their words, so it is served only while one of them is:
//! once the owner erases every TURN its proposals cite, the proposals stop
//! being served and so does the arc summary, which stays in history (FIX
//! ARC-SUMMARY-SERVED-AFTER-ITS-PROPOSALS-LOSE-SUPPORT; canon ARCH-0004
//! hydration: "one whose cited sources are gone is not served";
//! code-mode-summary-sdk-v1: a summary must not keep an erased quotation).
//! One proposal still standing keeps the arc summary served.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test arc_summary_live_support`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::test_doors::consolidation::{
    consolidate_unbound_turn, consolidate_unbound_turn_pair, open_dreamer_vault,
};
use oneiron::test_doors::derive::claim_has_live_support;
use oneiron::test_doors::nightly_arc_summary::{cited_refs, write_arc_summary};
use oneiron::{EntityId, Vault};
use serde_json::json;

const READER: &str = "reader";

/// The narrative the scripted merge call wrote for the group.
const NARRATIVE: &str = "Owen gave his name and the name he goes by.";

/// Whether the read doors serve `claim`.
fn served(vault: &Vault, claim: &EntityId) -> bool {
    claim_has_live_support(vault, claim)
        .expect("read")
        .expect("the claim is stored")
}

/// One TURN in which the owner says Owen's name and nickname, and the two
/// claims one consolidation pass extracts from it, each citing that TURN.
/// The arc summary of the two is served; once the TURN is erased, neither
/// claim is served, and the arc summary is not served either but stays in
/// history.
/// Red on main 0aedc807c526: the arc summary's evidence is a bare list of the
/// proposal ids, which asks no live support, so it stays served.
#[test]
fn an_arc_summary_is_not_served_once_every_turn_its_proposals_cite_is_erased() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let reply = json!({
        "persons": [{"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [
            {
                "subject": "new:P1", "predicate": "profile.name", "value": "owen",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "owen"}],
            },
            {
                "subject": "new:P1", "predicate": "profile.nickname", "value": "o",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "call me o"}],
            },
        ],
    })
    .to_string();
    let pass = consolidate_unbound_turn(&vault, "my name is owen, call me o", None, None, &reply)
        .expect("one consolidation pass");
    assert_eq!(pass.landed.len(), 2, "both claims land: {:?}", pass.landed);
    for proposal in &pass.landed {
        assert_eq!(
            cited_refs(&vault, proposal).expect("read"),
            vec![pass.turn],
            "each proposal cites the one TURN"
        );
    }
    let arc = write_arc_summary(&vault, pass.attempt, &pass.landed, NARRATIVE)
        .expect("the arc summary lands");
    assert!(served(&vault, &arc), "the arc summary is served");

    assert!(
        vault.delete_entity(&pass.turn).expect("delete"),
        "the TURN existed"
    );

    for proposal in &pass.landed {
        assert!(
            !served(&vault, proposal),
            "a proposal whose only cited TURN is erased is not served"
        );
    }
    assert!(
        !served(&vault, &arc),
        "FAILBEFORE ARC-SUMMARY-SERVED-AFTER-ITS-PROPOSALS-LOSE-SUPPORT: the arc summary written \
         from two proposals is served after every TURN they cite is erased"
    );
    assert!(
        vault.get_claim(&arc).expect("read").is_some(),
        "the arc summary stays in history"
    );
}

/// Two TURNs, each naming Owen, and one claim from each. The arc summary of
/// the two stays served while one claim is: erasing the first TURN hides the
/// claim citing it and keeps the arc summary served; erasing the second hides
/// the other claim and the arc summary too.
/// The door takes the first proposal's exposure; live support is per cited
/// row, whatever exposure each proposal has.
/// Red on main 0aedc807c526 at its last assert, as above.
#[test]
fn an_arc_summary_is_served_while_one_of_its_proposals_is() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    // Each TURN names Owen, so either holds the quote.
    let reply = json!({
        "persons": [{"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1", "T2"]}],
        "candidates": [
            {
                "subject": "new:P1", "predicate": "profile.name", "value": "owen",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "owen"}],
            },
            {
                "subject": "new:P1", "predicate": "profile.nickname", "value": "o",
                "confidence": 0.8, "evidence_refs": [{"source": "T2", "quote": "owen"}],
            },
        ],
    })
    .to_string();
    let pass = consolidate_unbound_turn_pair(
        &vault,
        "this is owen",
        "owen goes by o",
        EntityId::now(),
        &reply,
    )
    .expect("one consolidation pass");
    assert_eq!(pass.landed.len(), 2, "both claims land: {:?}", pass.landed);
    let cites = |turn: EntityId| -> EntityId {
        *pass
            .landed
            .iter()
            .find(|proposal| cited_refs(&vault, proposal).expect("read") == vec![turn])
            .unwrap_or_else(|| panic!("a proposal cites only the TURN {turn:?}"))
    };
    let first = cites(pass.turn);
    let second_turn = cited_refs(
        &vault,
        &pass
            .landed
            .iter()
            .copied()
            .find(|id| *id != first)
            .expect("a second proposal"),
    )
    .expect("read")
    .into_iter()
    .next()
    .expect("the second proposal cites a TURN");
    assert_ne!(second_turn, pass.turn, "the proposals cite two TURNs");
    let second = cites(second_turn);
    let arc = write_arc_summary(&vault, pass.attempt, &[first, second], NARRATIVE)
        .expect("the arc summary lands");
    assert!(served(&vault, &arc), "the arc summary is served");

    assert!(
        vault.delete_entity(&pass.turn).expect("delete"),
        "the first TURN existed"
    );
    assert!(
        !served(&vault, &first),
        "the proposal citing the erased TURN is not served"
    );
    assert!(served(&vault, &second), "the other proposal is served");
    assert!(
        served(&vault, &arc),
        "the arc summary stays served while one of its proposals is"
    );

    assert!(
        vault.delete_entity(&second_turn).expect("delete"),
        "the second TURN existed"
    );
    assert!(!served(&vault, &second), "neither proposal is served");
    assert!(
        !served(&vault, &arc),
        "FAILBEFORE ARC-SUMMARY-SERVED-AFTER-ITS-PROPOSALS-LOSE-SUPPORT: the arc summary is \
         served after every TURN its proposals cite is erased"
    );
}
