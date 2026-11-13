//! The DAG append's source label follows who composed the words (Engine
//! ruling DAG-APPEND-SOURCE-LABEL-ENGINE-PATHS, ARCH-0040).
//!
//! A record that holds its writer's own words is labelled by the writer's
//! class: a person's is user-stated, every other writer's generated. A record
//! whose words the engine composed under its writer's actor, a scope
//! summary's reply, is generated even under a person's actor. The label is
//! read through `oneiron::test_doors::dag_append` from the functions the two
//! gate checks label with; a recorded gate decision keeps no source, so no
//! public read shows it. A source fence pins the scope summary's reply to the
//! composed check.
//!
//! A Retry's assistant TURN holds no words (its MESSAGE does), and since the
//! Engine TASK of 13 Nov 04:50 (FIX DAG-ENGINE-APPEND-PERSON-PENDS, the Retry
//! half) it meets the transcript gate the witness gives the reply it answers
//! again, with no source label. The fence pins it to that check, never to a
//! labelled one; tests/turn_retry_regenerated_turn.rs drives it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test dag_append_composed_source`.
#![cfg(oneiron_test_support)]

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use common::source_scan::{SourceTree, is_ident_byte, production_source};
use oneiron::claim::ClaimSource;
use oneiron::test_doors::dag_append;
use oneiron::{EdgeActorClass, EntityId, WriteActor};

/// The composed check's entry point, called as `name(`.
const COMPOSED_ENTRY: &str = "append_composed_in_txn";

/// The Retry TURN's transcript-gate entry point, called as `name(`.
const REGENERATED_TURN_ENTRY: &str = "append_regenerated_turn_at_in_txn";

/// Whether `code` calls `name`: `name(` with no identifier byte before it.
fn calls(code: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    code.match_indices(&needle)
        .any(|(at, _)| at == 0 || !is_ident_byte(code.as_bytes()[at - 1]))
}

#[test]
fn a_writers_own_append_is_labelled_by_the_writers_class() {
    let person = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    assert_eq!(dag_append::append_source(person), ClaimSource::UserStated);
    for class in [EdgeActorClass::Agent, EdgeActorClass::System] {
        assert_eq!(
            dag_append::append_source(WriteActor::new(EntityId::now(), class)),
            ClaimSource::Generated,
            "a {class:?} writer's append is generated"
        );
    }
}

#[test]
fn an_engine_composed_append_is_generated_even_under_a_persons_actor() {
    assert_eq!(dag_append::composed_append_source(), ClaimSource::Generated);
}

/// The scope summary's reply reaches the composed check and the Retry's turn
/// the transcript check, never the writer-labelled one, and no other
/// production path reaches either.
#[test]
fn the_summary_reply_takes_the_composed_check_and_the_retry_turn_the_transcript_check() {
    let tree = SourceTree::read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
    let mut composing = BTreeSet::new();
    let mut regenerating = BTreeSet::new();
    for (path, source) in tree.production_sources() {
        let code = production_source(source);
        let relative = tree.relative(path);
        if calls(&code, COMPOSED_ENTRY) {
            composing.insert(relative.clone());
        }
        if calls(&code, REGENERATED_TURN_ENTRY) {
            regenerating.insert(relative.clone());
        }
        if relative == "scope_summary/doors.rs" || relative == "conversation/turn_actions.rs" {
            assert!(
                !calls(&code, "append_in_txn") && !calls(&code, "append_at_in_txn"),
                "{relative} appends engine words through the writer-labelled check"
            );
        }
    }
    assert_eq!(
        composing,
        BTreeSet::from([
            "conversation_dag/writes.rs".to_owned(),
            "scope_summary/doors.rs".to_owned(),
        ]),
        "only the scope summary's reply, and the append door that defines it, use the composed check"
    );
    assert_eq!(
        regenerating,
        BTreeSet::from([
            "conversation/turn_actions.rs".to_owned(),
            "conversation_dag/writes.rs".to_owned(),
        ]),
        "only the Retry's turn, and the append door that defines it, use the transcript check"
    );
}
