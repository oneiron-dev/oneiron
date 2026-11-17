//! UC-06 PR 8 guard: every ask module's intent key keeps its exact text, and each module reads
//! back exactly the key it writes.
//!
//! An intent key is stored in ask group bodies and in `LIVE_EDIT_GROUPS`, and an answer is routed
//! to its ask by it, so the move onto `task_verb::ask_intent` must not change one byte. These
//! tests pin each module's key for one fixture ask, its read of that key, and its refusal of an
//! upper-case id, an extra part and a missing part. They pass before the move and after it.
//!
//! Doors: `oneiron::test_doors::ask_intent_pins`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test ask_intent_keys`.

use oneiron::EntityId;
use oneiron::test_doors::ask_intent_pins as pins;

const A: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const B: &str = "1b2c3d4e5f60718293a4b5c6d7e8f90a";
const C: &str = "2c3d4e5f60718293a4b5c6d7e8f90a1b";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn id(hex: &str) -> EntityId {
    EntityId::from_lower_hex(hex).expect("FIXTURE: a lower-case 32-hex id")
}

#[test]
fn training_offer_intent_key_keeps_its_text_and_reads_back() {
    let key = pins::training_offer_key(id(A), id(B), DIGEST, id(C));
    assert_eq!(key, format!("training_offer/{A}/{DIGEST}/{B}/{C}"));
    assert_eq!(
        pins::training_offer_read(&key),
        Some((id(A), id(B), DIGEST.to_owned(), id(C)))
    );
    let upper_id = format!("training_offer/{}/{DIGEST}/{B}/{C}", A.to_uppercase());
    let upper_digest = format!("training_offer/{A}/{}/{B}/{C}", DIGEST.to_uppercase());
    let short_digest = format!("training_offer/{A}/{}/{B}/{C}", &DIGEST[..62]);
    for refused in [
        upper_id,
        upper_digest,
        short_digest,
        format!("{key}/{A}"),
        format!("training_offer/{A}/{DIGEST}/{B}"),
        format!("training_swap/{A}/{DIGEST}/{B}/{C}"),
    ] {
        assert_eq!(pins::training_offer_read(&refused), None, "{refused}");
    }
}

#[test]
fn training_swap_intent_key_keeps_its_text_and_reads_back() {
    let key = pins::training_swap_key(id(A), id(B), DIGEST, id(C));
    assert_eq!(key, format!("training_swap/{A}/{DIGEST}/{B}/{C}"));
    assert_eq!(
        pins::training_swap_read(&key),
        Some((id(A), id(B), DIGEST.to_owned(), id(C)))
    );
    let upper_turn = format!("training_swap/{A}/{DIGEST}/{B}/{}", C.to_uppercase());
    let upper_digest = format!("training_swap/{A}/{}/{B}/{C}", DIGEST.to_uppercase());
    for refused in [
        upper_turn,
        upper_digest,
        format!("{key}/{A}"),
        format!("training_swap/{A}/{DIGEST}/{B}"),
        format!("training_offer/{A}/{DIGEST}/{B}/{C}"),
    ] {
        assert_eq!(pins::training_swap_read(&refused), None, "{refused}");
    }
}

#[test]
fn comm_widen_intent_key_keeps_its_text_and_reads_back() {
    for reach in ["parent", "subtree", "project", "vault"] {
        let key = pins::comm_widen_key(id(A), reach, id(C)).expect("FIXTURE: a reach spelling");
        assert_eq!(key, format!("comm_widen/{A}/{reach}/{C}"));
        assert_eq!(
            pins::comm_widen_read(&key),
            Some((A.to_owned(), reach.to_owned(), id(C)))
        );
    }
    let upper_child = format!("comm_widen/{}/subtree/{C}", A.to_uppercase());
    let upper_turn = format!("comm_widen/{A}/subtree/{}", C.to_uppercase());
    for refused in [
        upper_child,
        upper_turn,
        format!("comm_widen/{A}/Subtree/{C}"),
        format!("comm_widen/{A}/world/{C}"),
        format!("comm_widen/{A}/subtree/{C}/{B}"),
        format!("comm_widen/{A}/subtree"),
        format!("code_consent/{A}"),
    ] {
        assert_eq!(pins::comm_widen_read(&refused), None, "{refused}");
    }
}

#[test]
fn code_consent_intent_key_keeps_its_text_and_reads_back() {
    let key = pins::code_consent_key(id(A));
    assert_eq!(key, format!("code_consent/{A}"));
    assert_eq!(pins::code_consent_read(&key), Some(id(A)));
    for refused in [
        format!("code_consent/{}", A.to_uppercase()),
        format!("{key}/{B}"),
        "code_consent/".to_owned(),
        format!("contribution_pair/{A}"),
    ] {
        assert_eq!(pins::code_consent_read(&refused), None, "{refused}");
    }
}

#[test]
fn contribution_pair_intent_key_keeps_its_text_and_reads_back() {
    let key = pins::contribution_pair_key(id(B));
    assert_eq!(key, format!("contribution_pair/{B}"));
    assert_eq!(pins::contribution_pair_read(&key), Some(id(B)));
    for refused in [
        format!("contribution_pair/{}", B.to_uppercase()),
        format!("{key}/{A}"),
        "contribution_pair/".to_owned(),
        format!("code_consent/{B}"),
    ] {
        assert_eq!(pins::contribution_pair_read(&refused), None, "{refused}");
    }
}

#[test]
fn consult_case_intent_keeps_its_text_and_reads_back() {
    assert_eq!(
        pins::consult_case_intent(id(A)),
        format!("consult_case/{A}")
    );
    let key = format!("consult_case/{A}/{B}");
    assert_eq!(
        pins::consult_case_read(&key, id(A)),
        Some((format!("consult_case/{A}"), id(B)))
    );
    assert_eq!(
        pins::consult_case_read(&key, id(C)),
        None,
        "a case ask is read only under its own case id"
    );
    for refused in [
        format!("consult_case/{}/{B}", A.to_uppercase()),
        format!("consult_case/{A}/{}", B.to_uppercase()),
        format!("{key}/{C}"),
        format!("consult_case/{A}"),
        format!("code_consent/{A}/{B}"),
    ] {
        assert_eq!(pins::consult_case_read(&refused, id(A)), None, "{refused}");
    }
}

#[test]
fn live_edit_intent_key_keeps_its_text_and_its_prefix_gate() {
    assert_eq!(
        pins::live_edit_key(id(A), id(B), 7),
        format!("office.live_edit.holders/{A}/{B}/7")
    );
    assert_eq!(
        pins::live_edit_key(id(A), id(B), u64::MAX),
        format!("office.live_edit.holders/{A}/{B}/{}", u64::MAX)
    );
    assert!(pins::live_edit_gate("office.live_edit.holders"));
    assert!(pins::live_edit_gate(&format!(
        "office.live_edit.holders/{A}"
    )));
    assert!(!pins::live_edit_gate("office.live_edit.holdersx"));
    assert!(!pins::live_edit_gate(&format!("code_consent/{A}")));
}
