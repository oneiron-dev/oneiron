#![cfg(oneiron_test_support)]
//! `POST /v1/owner/steer`, `POST /v1/owner/inbox/concern/move` and
//! `GET /v1/owner/inbox` answer an engine refusal per its code, as their
//! sibling owner routes do (UC-11, ruling UC11-CLIENT-STATUSES item 2): a
//! malformed request 400, a state that refuses or an authority refusal 409,
//! a missing row 404, and any other code (an engine fault among them) 500,
//! never a 409. No request a test can send makes these engine verbs answer
//! NOT_FOUND or a fault, so the door hands each route's refusal map a
//! refusal by its code. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test owner_refusal_catch_all`.

use oneiron_server::test_doors::catch_all_status::owner_route_statuses;

/// Each engine code and the status all three routes answer it with.
const PINNED: [(&str, u16); 7] = [
    ("BAD_REQUEST", 400),
    ("INVALID_STATE", 409),
    ("FORBIDDEN", 409),
    ("OWNER_BINDING_REQUIRED", 409),
    ("NOT_FOUND", 404),
    ("INTERNAL_SERVER_ERROR", 500),
    ("MODEL_UNAVAILABLE", 500),
];

#[test]
fn owner_routes_answer_per_engine_code() {
    let moved: Vec<String> = PINNED
        .iter()
        .filter_map(|&(code, pinned)| {
            let statuses = owner_route_statuses(code);
            (statuses != [pinned; 3])
                .then(|| format!("{code}: pinned {pinned}, steer/move/inbox answered {statuses:?}"))
        })
        .collect();
    assert!(
        moved.is_empty(),
        "codes answered off their status: {moved:#?}"
    );
}
