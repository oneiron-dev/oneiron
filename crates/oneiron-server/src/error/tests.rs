use super::*;

#[test]
fn stale_epoch_error_serializes_contract_shape() {
    let body = serde_json::to_value(ApiError::stale_epoch(7, 4)).unwrap();

    assert_eq!(body["code"], "STALE_EPOCH");
    assert_eq!(body["details"]["code"], "STALE_EPOCH");
    assert_eq!(body["details"]["currentEpoch"], 7);
    assert_eq!(body["details"]["requestedEpoch"], 4);
    assert!(
        body["suggestions"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "suggestions must be actionable and non-empty"
    );
}

#[test]
fn api_error_new_derives_code_from_details() {
    let error = ApiError::new(
        "header is invalid",
        ApiErrorDetails::InvalidHeader {
            header: "Idempotency-Key".to_owned(),
        },
        ["Send a syntactically valid header."],
    );

    assert_eq!(error.code(), ErrorCode::InvalidHeader);
    let body = serde_json::to_value(error).unwrap();
    assert_eq!(body["code"], "INVALID_HEADER");
    assert_eq!(body["details"]["code"], "INVALID_HEADER");
}

#[test]
fn error_code_round_trips_catalog_literals() {
    for code in ErrorCode::ALL {
        let encoded = serde_json::to_string(code).unwrap();
        assert_eq!(encoded, format!("\"{}\"", code.as_str()));
        let decoded: ErrorCode = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, *code);
    }

    let literals = ErrorCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<_>>();
    for required in [
        "STALE_EPOCH",
        "DAILY_BUDGET_EXHAUSTED",
        "NOT_ACCEPTABLE",
        "INVALID_HEADER",
        "4001",
        "4002",
        "4003",
        "4004",
        "4005",
    ] {
        assert!(
            literals.contains(&required),
            "missing required error-code catalog literal {required}"
        );
    }
}

#[test]
fn conflict_errors_have_distinct_codes() {
    let stale = ApiError::stale_epoch(7, 4);
    let replay = ApiError::idempotency_replay_conflict(Some("idem-1"));

    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_ne!(stale.code(), replay.code());

    let stale_body = serde_json::to_value(stale).unwrap();
    let replay_body = serde_json::to_value(replay).unwrap();
    assert_ne!(stale_body["code"], replay_body["code"]);
}

#[test]
fn error_code_schema_matches_catalog_exactly() {
    let schema = error_code_schema();
    let enum_values = schema["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    let catalog = ErrorCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<_>>();

    assert_eq!(enum_values, catalog);
}

#[test]
fn openapi_components_expose_error_code_and_api_error() {
    let components = openapi_error_components();
    assert_eq!(components["ErrorCode"], error_code_schema());
    assert_eq!(components["ApiError"], api_error_schema());
}

#[test]
fn crdt_error_codes_match_protocol_close_code_values() {
    assert_eq!(
        ErrorCode::CrdtAuthExpired.as_str(),
        crate::protocol::close_codes::AUTH_EXPIRED.to_string()
    );
    assert_eq!(
        ErrorCode::CrdtDecodeError.as_str(),
        crate::protocol::close_codes::DECODE_ERROR.to_string()
    );
    assert_eq!(
        ErrorCode::CrdtUnknownTag.as_str(),
        crate::protocol::close_codes::UNKNOWN_TAG.to_string()
    );
    assert_eq!(
        ErrorCode::CrdtFrameTooLarge.as_str(),
        crate::protocol::close_codes::FRAME_TOO_LARGE.to_string()
    );
    assert_eq!(
        ErrorCode::CrdtVersionMismatch.as_str(),
        crate::protocol::close_codes::VERSION_MISMATCH.to_string()
    );
}
