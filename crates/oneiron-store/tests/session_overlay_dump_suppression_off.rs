//! Census row L6-18: the operator's off switch. With the host's
//! `set_off_record_dump_suppression(false)` (the server's
//! `off_record_dump_suppression = false`, or its environment override), an
//! off-record overlay leaves the process dumpable and its core limit as it
//! was, so the owner can attach a debugger or keep a core file. Linux only,
//! as `session_overlay_dump_suppression.rs`; this file is its own test
//! binary, so the switch reaches no other test.
#![cfg(any(target_os = "linux", target_os = "android"))]

use oneiron_store::session_overlay::{
    SessionOverlay, off_record_dump_suppression, set_off_record_dump_suppression,
};
use rustix::process::{
    DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit, setrlimit,
};

#[test]
fn the_operator_switch_leaves_an_off_record_process_dumpable() {
    set_off_record_dump_suppression(false);
    assert!(!off_record_dump_suppression(), "the switch reads back off");
    // Give the soft core limit room to show a change where the host allows
    // a core file.
    let before = getrlimit(Resource::Core);
    if before.maximum != Some(0) {
        setrlimit(
            Resource::Core,
            Rlimit {
                current: before.maximum,
                maximum: before.maximum,
            },
        )
        .expect("raise the soft core limit to the hard one");
    }
    let raised = getrlimit(Resource::Core);

    let _overlay = SessionOverlay::new(4096);

    assert_eq!(
        dumpable_behavior().expect("PR_GET_DUMPABLE"),
        DumpableBehavior::Dumpable,
        "suppression switched off, yet an off-record overlay cleared the dumpable flag"
    );
    assert_eq!(
        getrlimit(Resource::Core),
        raised,
        "suppression switched off, yet an off-record overlay changed the core limit"
    );
}
