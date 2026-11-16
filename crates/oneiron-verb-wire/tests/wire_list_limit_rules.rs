#![cfg(feature = "sync")]
//! UC-13 PR 4c: the limit rules of two wire requests, pinned at limit 0, 1,
//! the default, the maximum and the maximum + 1, and when absent.
//! `HooksReplayRequest::limit()` refuses zero and serves the default when
//! absent; the page cut at `HOOKS_REPLAY_PAGE_MAX` stays in the engine, so
//! this method passes any other ask through uncut.
//! `MeshPathReceiptsRequest::bound()` serves zero as an empty read and cuts
//! at `MESH_PATH_RECEIPTS_READ_MAX`. The same file runs green on main and on
//! the head: the rules move onto `oneiron_base::request_limits` with no
//! change in what a request is served.
//! Run with: `cargo test --locked -p oneiron-verb-wire --all-features
//! --test wire_list_limit_rules`.

use oneiron_contracts::memory::MemoryError;
use oneiron_verb_wire::sync::mesh_path::MESH_PATH_RECEIPTS_READ_MAX;
use oneiron_verb_wire::verbs::host::hooks_replay::{
    HOOKS_REPLAY_LIMIT_DEFAULT, HooksReplayRequest,
};
use oneiron_verb_wire::verbs::mesh::{MESH_PATH_RECEIPTS_DEFAULT, MeshPathReceiptsRequest};

fn hooks_replay(limit: Option<usize>) -> HooksReplayRequest {
    HooksReplayRequest {
        binding: "00000000000000000000000000000001".to_owned(),
        since: None,
        limit,
        cursor: None,
    }
}

#[test]
fn hooks_replay_limit_refuses_zero_with_its_own_text() {
    let refused = hooks_replay(Some(0)).limit();
    assert_eq!(
        refused,
        Err(MemoryError::bad_request_with(
            "limit must be at least 1",
            &["Request one entry or more and continue from next_cursor."],
        )),
    );
}

#[test]
fn hooks_replay_limit_serves_the_default_when_absent() {
    assert_eq!(HOOKS_REPLAY_LIMIT_DEFAULT, 64);
    assert_eq!(hooks_replay(None).limit(), Ok(HOOKS_REPLAY_LIMIT_DEFAULT));
}

#[test]
fn hooks_replay_limit_passes_every_other_ask_through_uncut() {
    for asked in [1, 63, 64, 65, 256, 257, 100_000, usize::MAX] {
        assert_eq!(
            hooks_replay(Some(asked)).limit(),
            Ok(asked),
            "asked {asked}"
        );
    }
}

#[test]
fn mesh_path_receipts_bound_serves_zero_as_an_empty_read() {
    let request = MeshPathReceiptsRequest { limit: Some(0) };
    assert_eq!(request.bound(), 0);
}

#[test]
fn mesh_path_receipts_bound_serves_the_default_when_absent() {
    assert_eq!(MESH_PATH_RECEIPTS_DEFAULT, 100);
    assert_eq!(
        MeshPathReceiptsRequest::default().bound(),
        MESH_PATH_RECEIPTS_DEFAULT
    );
    assert_eq!(
        MeshPathReceiptsRequest { limit: None }.bound(),
        MESH_PATH_RECEIPTS_DEFAULT
    );
}

#[test]
fn mesh_path_receipts_bound_cuts_at_the_read_maximum() {
    assert_eq!(MESH_PATH_RECEIPTS_READ_MAX, 1024);
    let max = MESH_PATH_RECEIPTS_READ_MAX;
    for (asked, served) in [
        (1, 1),
        (MESH_PATH_RECEIPTS_DEFAULT, MESH_PATH_RECEIPTS_DEFAULT),
        (max - 1, max - 1),
        (max, max),
        (max + 1, max),
        (usize::MAX, max),
    ] {
        let request = MeshPathReceiptsRequest { limit: Some(asked) };
        assert_eq!(request.bound(), served, "asked {asked}");
    }
}
