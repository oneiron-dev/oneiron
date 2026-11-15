#![cfg(oneiron_test_support)]
//! The campaign and saved-query routes answer an engine code their refusal
//! map does not name with 500, as every sibling map does, never 400 (UC-11,
//! ruling UC11-CLIENT-STATUSES item 3). The codes the map names keep their
//! status: a malformed body or a reference the writer cannot resolve 400, a
//! missing row 404, an authority refusal 403, a stale version 409. No
//! request a test can send makes the campaign surface answer an unnamed
//! code, so the door hands the map a refusal by its code. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test campaign_surface_unexpected_code`.

use oneiron_server::test_doors::catch_all_status::campaign_surface_status;

/// Each engine code and the status the campaign surface answers it with.
const PINNED: [(&str, u16); 10] = [
    ("BAD_REQUEST", 400),
    ("INVENTED_REFERENCE", 400),
    ("NOT_FOUND", 404),
    ("FORBIDDEN", 403),
    ("OWNER_BINDING_REQUIRED", 403),
    ("INVALID_STATE", 409),
    ("INTERNAL_SERVER_ERROR", 500),
    ("MODEL_UNAVAILABLE", 500),
    ("IDENTITY_UNSETTLED", 500),
    ("campaign_unnamed_code", 500),
];

#[test]
fn unnamed_codes_answer_500() {
    let moved: Vec<String> = PINNED
        .iter()
        .filter_map(|&(code, pinned)| {
            let status = campaign_surface_status(code);
            (status != pinned).then(|| format!("{code}: pinned {pinned}, answered {status}"))
        })
        .collect();
    assert!(
        moved.is_empty(),
        "codes answered off their status: {moved:#?}"
    );
}
