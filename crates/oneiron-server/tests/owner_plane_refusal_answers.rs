#![cfg(oneiron_test_support)]
//! The owner plane's refusal maps make the same owner refusal of each engine
//! code before and after they share `OwnerError::from_memory_code` (UC-11
//! PR 4): the variant (and so the status and `state` an owner route
//! answers) and its words, the host failure's context among them. The pins
//! are the answers at the PR's base, each named override included: the
//! cleanup review's missing proposal is changed since review (FIX 10504),
//! and the inbox lens keeps the engine code in its words and answers a state
//! that refuses as refused. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test owner_plane_refusal_answers`.

use oneiron_server::test_doors::catch_all_status::owner_plane_refusals;

/// The maps, in the door's order.
const MAPS: [&str; 7] = [
    "off-record witness",
    "cleanup review",
    "history erase",
    "NOTE tombstone",
    "steer",
    "concern move",
    "inbox lens",
];

/// Each engine code, and what each map makes of it, in the door's order.
const PINNED: [(&str, [&str; 7]); 7] = [
    (
        "BAD_REQUEST",
        [
            "Invalid a pinned refusal",
            "Invalid a pinned refusal",
            "Invalid a pinned refusal",
            "Invalid a pinned refusal",
            "Invalid a pinned refusal",
            "Invalid a pinned refusal",
            "Invalid BAD_REQUEST: a pinned refusal",
        ],
    ),
    (
        "INVALID_STATE",
        [
            "Changed a pinned refusal",
            "Changed a pinned refusal",
            "Changed a pinned refusal",
            "Changed a pinned refusal",
            "Changed a pinned refusal",
            "Changed a pinned refusal",
            "Refused INVALID_STATE: a pinned refusal",
        ],
    ),
    (
        "FORBIDDEN",
        [
            "Refused a pinned refusal",
            "Refused a pinned refusal",
            "Refused a pinned refusal",
            "Refused a pinned refusal",
            "Refused a pinned refusal",
            "Refused a pinned refusal",
            "Refused FORBIDDEN: a pinned refusal",
        ],
    ),
    (
        "OWNER_BINDING_REQUIRED",
        [
            "Host witness into off-record session: a pinned refusal",
            "Host cleanup review: a pinned refusal",
            "Host erase history: a pinned refusal",
            "Host NOTE tombstone: a pinned refusal",
            "Refused a pinned refusal",
            "Refused a pinned refusal",
            "Refused OWNER_BINDING_REQUIRED: a pinned refusal",
        ],
    ),
    (
        "NOT_FOUND",
        [
            "Host witness into off-record session: a pinned refusal",
            "Changed a pinned refusal",
            "NotFound text a pinned refusal",
            "Host NOTE tombstone: a pinned refusal",
            "NotFound task a pinned refusal",
            "NotFound concern_card a pinned refusal",
            "NotFound inbox_lens NOT_FOUND: a pinned refusal",
        ],
    ),
    (
        "INTERNAL_SERVER_ERROR",
        [
            "Host witness into off-record session: a pinned refusal",
            "Host cleanup review: a pinned refusal",
            "Host erase history: a pinned refusal",
            "Host NOTE tombstone: a pinned refusal",
            "Host steer: a pinned refusal",
            "Host concern move: a pinned refusal",
            "Host inbox lens: INTERNAL_SERVER_ERROR: a pinned refusal",
        ],
    ),
    (
        "MODEL_UNAVAILABLE",
        [
            "Host witness into off-record session: a pinned refusal",
            "Host cleanup review: a pinned refusal",
            "Host erase history: a pinned refusal",
            "Host NOTE tombstone: a pinned refusal",
            "Host steer: a pinned refusal",
            "Host concern move: a pinned refusal",
            "Host inbox lens: MODEL_UNAVAILABLE: a pinned refusal",
        ],
    ),
];

#[test]
fn owner_plane_maps_keep_each_answer() {
    let moved: Vec<String> = PINNED
        .iter()
        .flat_map(|&(code, pinned)| {
            let answered = owner_plane_refusals(code);
            MAPS.iter()
                .zip(pinned)
                .zip(answered)
                .filter(|((_, pinned), answered)| answered != pinned)
                .map(move |((map, pinned), answered)| {
                    format!("{map} on {code}: pinned {pinned:?}, answered {answered:?}")
                })
        })
        .collect();
    assert!(moved.is_empty(), "answers off their pins: {moved:#?}");
}
