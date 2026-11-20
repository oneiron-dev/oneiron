//! A read key that names the Coach is held to its Steward grant and its live
//! MACHINE binding whichever constructor built it (review of #6916, untangle
//! 6.6a). The Coach's jobs build their keys with `with_actor_class`
//! (browser programs, site skills, code-fix admission). On the first head
//! such a key carried no guard, so after the host revoked the Coach's binding
//! it kept reading by the read row its grant gives.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coach_binding_fence`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::test_doors::coach::coach;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::steward::{
    GrantMark, STEWARD_READ_VERB, class_key_reads, grant_mark, revoke_base_agent_bindings,
    stand_steward_grant,
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
fn a_key_built_for_the_coach_by_any_constructor_is_held_to_its_live_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
    let coach = coach(&vault).expect("the Coach");
    // The Dreamer has no grant here, so it weaves by its shipped rows.
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    // The read half of the Coach's default grant is all this test needs.
    let held = [STEWARD_READ_VERB];
    let grant = stand_steward_grant(&vault, coach, &held).expect("the Coach's grant");

    // A row the key reads while the grant and the binding are live: the
    // turn, or a claim the pass landed.
    let row = std::iter::once(pass.turn)
        .chain(pass.landed.iter().copied())
        .find(|row| class_key_reads(&vault, coach, *row).expect("read"))
        .expect("the key reads the turn or a landed claim while the binding is live");

    // The host revokes the Coach's binding; its grant stands as it was.
    let revoked = revoke_base_agent_bindings(&vault, coach).expect("revoke");
    assert!(revoked >= 1, "a live binding stood");
    let verbs: BTreeSet<String> = held.iter().map(|verb| (*verb).to_owned()).collect();
    assert_eq!(
        grant_mark(&vault, coach).expect("mark"),
        Some(GrantMark::Minted { grant, verbs }),
        "the grant still holds read: only the binding went"
    );

    assert!(
        !class_key_reads(&vault, coach, row).expect("read"),
        "a revoked binding reads nothing, whichever constructor built the key"
    );
}
