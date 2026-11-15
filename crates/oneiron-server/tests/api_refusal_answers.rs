#![cfg(oneiron_test_support)]
//! Five core refusal maps keep every answer when they share
//! `ApiError::from_memory_code` (UC-11 PR 5): for each engine code, the
//! status, code, words and suggestions the run control, booking boundary,
//! transcript, scratchpad and message result routes answer. Each pin is
//! built from the public constructors the way the PR's base answers it,
//! each named override included: the booking boundary and the scratchpad
//! keep the engine's suggestions on a malformed request, and the message
//! result read keeps the owner binding refusal's own code and answers a
//! state that refuses as its failure (N4). Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test api_refusal_answers`.

use oneiron_server::error::{ApiError, ApiErrorDetails, EnvelopedApiError};
use oneiron_server::test_doors::api_refusal_answers::api_plane_answers;

/// The routes, in the door's order.
const ROUTES: [&str; 5] = [
    "run control",
    "booking boundary",
    "transcript",
    "scratchpad",
    "message result",
];

/// The engine codes each route is asked about.
const CODES: [&str; 7] = [
    "BAD_REQUEST",
    "INVALID_STATE",
    "FORBIDDEN",
    "OWNER_BINDING_REQUIRED",
    "NOT_FOUND",
    "INTERNAL_SERVER_ERROR",
    "MODEL_UNAVAILABLE",
];

/// The door's refusal words and suggestion.
const WORDS: &str = "a pinned refusal";
const SUGGESTION: &str = "a pinned suggestion";

/// The engine's words and suggestion under `details`.
fn carried(details: ApiErrorDetails) -> ApiError {
    ApiError::new(WORDS, details, [SUGGESTION])
}

fn forbidden() -> ApiError {
    carried(ApiErrorDetails::Forbidden {
        required_scope: None,
    })
}

fn refused_state(state: Option<&str>) -> ApiError {
    carried(ApiErrorDetails::InvalidState {
        state: state.map(str::to_owned),
    })
}

/// Each route's answer to `code`, in the door's order.
fn pinned(code: &str) -> [ApiError; 5] {
    let failed = [
        "core run tree intervene failed",
        "booking boundary failed",
        "transcript read failed",
        "scratchpad failed",
        "message result read failed",
    ];
    match code {
        "BAD_REQUEST" => [
            ApiError::bad_request(WORDS, None),
            carried(ApiErrorDetails::BadRequest { field: None }),
            ApiError::bad_request(WORDS, None),
            carried(ApiErrorDetails::BadRequest { field: None }),
            ApiError::bad_request(WORDS, None),
        ],
        "INVALID_STATE" => [
            refused_state(None),
            refused_state(Some("booking_state")),
            refused_state(Some("transcript_turns_moved")),
            refused_state(Some("scratchpad")),
            ApiError::internal_server_error(failed[4]),
        ],
        "FORBIDDEN" => [
            forbidden(),
            forbidden(),
            forbidden(),
            forbidden(),
            forbidden(),
        ],
        "OWNER_BINDING_REQUIRED" => [
            forbidden(),
            forbidden(),
            forbidden(),
            forbidden(),
            carried(ApiErrorDetails::OwnerBindingRequired {
                required_scope: None,
            }),
        ],
        "NOT_FOUND" => [
            ApiError::not_found("job", None),
            ApiError::not_found("booking", None),
            ApiError::not_found("conversation", None),
            ApiError::not_found("scratchpad", None),
            ApiError::not_found("message_result", None),
        ],
        _ => failed.map(ApiError::internal_server_error),
    }
}

#[test]
fn core_refusal_maps_keep_each_answer() {
    let moved: Vec<String> = CODES
        .iter()
        .flat_map(|&code| {
            let answered = api_plane_answers(code);
            let pinned =
                pinned(code).map(|answer| format!("{:?}", EnvelopedApiError::from(answer)));
            ROUTES
                .iter()
                .zip(pinned)
                .zip(answered)
                .filter(|((_, pinned), answered)| answered != pinned)
                .map(move |((route, pinned), answered)| {
                    format!("{route} on {code}:\n  pinned   {pinned}\n  answered {answered}")
                })
        })
        .collect();
    assert!(moved.is_empty(), "answers off their pins: {moved:#?}");
}
