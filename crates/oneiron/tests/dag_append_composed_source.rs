//! The DAG append's source label follows who composed the words (Engine
//! ruling DAG-APPEND-SOURCE-LABEL-ENGINE-PATHS, ARCH-0040).
//!
//! A record that holds its writer's own words is labelled by the writer's
//! class: a person's is user-stated, every other writer's generated. A record
//! whose words the engine composed under its writer's actor, a scope
//! summary's reply and a Retry's assistant turn, is generated even under a
//! person's actor. The label is read through `oneiron::test_doors::dag_append`
//! from the functions the two gate checks label with; a recorded gate
//! decision keeps no source, so no public read shows it. A source fence pins
//! the two engine paths to the composed check.
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

/// The composed check's two entry points, called as `name(`.
const COMPOSED_ENTRIES: [&str; 2] = ["append_composed_in_txn", "append_composed_at_in_txn"];

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

/// The scope summary's reply and the Retry's turn reach the composed check,
/// never the writer-labelled one, and no other production path reaches it.
#[test]
fn the_scope_summary_reply_and_the_retry_turn_append_through_the_composed_check() {
    let tree = SourceTree::read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
    let mut composing = BTreeSet::new();
    for (path, source) in tree.production_sources() {
        let code = production_source(source);
        if COMPOSED_ENTRIES.iter().any(|name| calls(&code, name)) {
            composing.insert(tree.relative(path));
        }
        let relative = tree.relative(path);
        if relative == "scope_summary/doors.rs" || relative == "conversation/turn_actions.rs" {
            assert!(
                !calls(&code, "append_in_txn") && !calls(&code, "append_at_in_txn"),
                "{relative} appends composed words through the writer-labelled check"
            );
        }
    }
    assert_eq!(
        composing,
        BTreeSet::from([
            "conversation/turn_actions.rs".to_owned(),
            "conversation_dag/writes.rs".to_owned(),
            "scope_summary/doors.rs".to_owned(),
        ]),
        "only the two engine paths, and the append door that defines them, use the composed check"
    );
}
