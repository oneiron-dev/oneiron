//! A read key that names the Dreamer is held to its Steward grant and its
//! live MACHINE binding whichever constructor built it (review of #6916;
//! untangle 6.3b, census X04). Only `for_engine_actor` set that guard on the
//! first head, so a key built by `with_actor_class`, as the engine's other
//! readers build theirs, kept reading by the grant-derived policy row after
//! the binding was revoked.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_binding_fence`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::steward::{
    GrantMark, STEWARD_VERBS, class_key_reads, dreamer, grant_mark, revoke_base_agent_bindings,
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
fn a_key_built_for_the_dreamer_by_any_constructor_is_held_to_its_live_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let grant = stand_steward_grant(&vault, dreamer, &STEWARD_VERBS).expect("full grant");
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");

    // A row the key reads while the grant and the binding are live: the
    // turn, or a claim the pass landed.
    let row = std::iter::once(pass.turn)
        .chain(pass.landed.iter().copied())
        .find(|row| class_key_reads(&vault, dreamer, *row).expect("read"))
        .expect("the key reads the turn or a landed claim while the binding is live");

    // The host revokes the Dreamer's binding; its grant stands as it was.
    let revoked = revoke_base_agent_bindings(&vault, dreamer).expect("revoke");
    assert!(revoked >= 1, "a live binding stood");
    let verbs: BTreeSet<String> = STEWARD_VERBS
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    assert_eq!(
        grant_mark(&vault, dreamer).expect("mark"),
        Some(GrantMark::Minted { grant, verbs }),
        "the grant still holds every verb: only the binding went"
    );

    assert!(
        !class_key_reads(&vault, dreamer, row).expect("read"),
        "a revoked binding reads nothing, whichever constructor built the key"
    );
}
