//! FIX 9839: a tainted observation that fits a Full view renders the
//! redacted view instead of aborting assembly with an integrity error.
//!
//! Both production restores behind [`OutputWorkingContext::assemble_with`] —
//! `restore_output` for context outputs and the executor's
//! `load_context_output` for replay observations — hand back the withheld
//! mark when the body may not enter model context. The assembler must not
//! verify that mark against the original body digest: the original body
//! integrity check stays separate from its redacted context projection.
//!
//! `cargo test --locked -p oneiron --all-features --test fix_9839_withheld_full_view`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::compaction::output::{
    OutputDecayPolicy, OutputRef, OutputTier, OutputWorkingContext,
};
use oneiron::store::result_manifest::CODE_RUN_OUTPUT_PREVIEW_WITHHELD;

/// A policy under which an entry recorded at turn 0 still shows Full at
/// turn 0.
fn full_policy() -> OutputDecayPolicy {
    OutputDecayPolicy {
        overview_after_turns: 10,
        stub_after_turns: 20,
    }
}

/// A context holding one entry recorded at turn 0 for `body`.
fn referenced(body: &[u8]) -> (OutputWorkingContext, OutputRef) {
    let source = OutputRef::from_bytes(body);
    let mut context = OutputWorkingContext::default();
    context
        .record_referenced(0, source, "the body's own preview")
        .expect("record one reference");
    (context, source)
}

#[test]
fn withheld_full_view_renders_the_mark_instead_of_failing() {
    let body: &[u8] = b"a body the secret scan marked";
    let (context, source) = referenced(body);
    let mut restore_calls = 0_u32;
    // The restore mimics both production restores: a body that may not
    // enter context reads as the withheld mark.
    let views = context
        .assemble_with(
            0,
            full_policy(),
            |got: OutputRef, _turn: u64| -> oneiron::Result<Option<Vec<u8>>> {
                restore_calls += 1;
                assert_eq!(got, source);
                Ok(Some(
                    CODE_RUN_OUTPUT_PREVIEW_WITHHELD.as_bytes().to_vec(),
                ))
            },
            |got: OutputRef, _turn: u64| -> oneiron::Result<bool> {
                assert_eq!(got, source);
                Ok(false)
            },
        )
        .expect("a withheld observation must not fail assembly");
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].tier, OutputTier::Full);
    assert_eq!(views[0].source, source);
    assert_eq!(
        views[0].bytes,
        CODE_RUN_OUTPUT_PREVIEW_WITHHELD.as_bytes()
    );
    assert_eq!(
        restore_calls, 0,
        "a withheld body is never read, as an overview's is not"
    );
}

#[test]
fn clean_full_view_returns_the_exact_body() {
    let body: &[u8] = b"an ordinary clean body";
    let (context, source) = referenced(body);
    let views = context
        .assemble_with(
            0,
            full_policy(),
            |_: OutputRef, _turn: u64| -> oneiron::Result<Option<Vec<u8>>> {
                Ok(Some(body.to_vec()))
            },
            |_: OutputRef, _turn: u64| -> oneiron::Result<bool> { Ok(true) },
        )
        .expect("a clean body assembles");
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].tier, OutputTier::Full);
    assert_eq!(views[0].source, source);
    assert_eq!(views[0].bytes, body);
}

#[test]
fn clean_full_view_still_rejects_tampered_bytes() {
    let body: &[u8] = b"an ordinary clean body";
    let (context, _source) = referenced(body);
    let result = context.assemble_with(
        0,
        full_policy(),
        |_: OutputRef, _turn: u64| -> oneiron::Result<Option<Vec<u8>>> {
            Ok(Some(b"different bytes".to_vec()))
        },
        |_: OutputRef, _turn: u64| -> oneiron::Result<bool> { Ok(true) },
    );
    assert!(
        result.is_err(),
        "the body integrity check still guards clean full views"
    );
}
