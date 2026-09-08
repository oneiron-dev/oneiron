mod boundary;
mod codebase;
mod email;
#[path = "../expression_preference.rs"]
mod expression_preference;
#[path = "../facade/mod.rs"]
mod facade;
#[path = "../types.rs"]
mod types;
mod vault;

pub use self::email::{channel_identity_email_address, parse_email_inbound_surface_event};
pub use self::vault::NapiVault;
pub use facade::{ActorScopedVault, VaultBridge};

#[cfg(test)]
pub(crate) use self::boundary::{MAX_NAPI_QUERY_BYTES, MAX_NAPI_SEARCH_LIMIT};
pub(crate) use self::boundary::{parse_search_limit, validate_query_len};

#[cfg(test)]
use self::boundary::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn reason<T: std::fmt::Debug>(result: std::result::Result<T, String>) -> String {
        result.expect_err("expected N-API boundary error")
    }

    #[test]
    fn napi_boundary_rejects_created_at_overflow() {
        assert_eq!(parse_created_at(i64::MAX as u64).unwrap(), i64::MAX);

        let overflow = i64::MAX as u64 + 1;
        assert_eq!(
            reason(parse_created_at(overflow)),
            format!("created_at must fit in signed 64-bit integer, got {overflow}")
        );
    }

    #[test]
    fn napi_boundary_rejects_oversized_limit() {
        assert_eq!(
            parse_search_limit(MAX_NAPI_SEARCH_LIMIT).unwrap(),
            MAX_NAPI_SEARCH_LIMIT as usize
        );

        let limit = MAX_NAPI_SEARCH_LIMIT + 1;
        assert_eq!(
            reason(parse_search_limit(limit)),
            format!("limit must be <= {MAX_NAPI_SEARCH_LIMIT}, got {limit}")
        );
    }

    #[test]
    fn napi_boundary_rejects_oversized_query() {
        let ok = "x".repeat(MAX_NAPI_QUERY_BYTES);
        assert!(validate_query_len(&ok).is_ok());

        let too_long = "x".repeat(MAX_NAPI_QUERY_BYTES + 1);
        assert_eq!(
            reason(validate_query_len(&too_long)),
            format!(
                "query must be <= {MAX_NAPI_QUERY_BYTES} bytes, got {}",
                MAX_NAPI_QUERY_BYTES + 1
            )
        );
    }

    #[test]
    fn napi_boundary_rejects_oversized_entity_payload() {
        assert!(validate_entity_payload_len(MAX_NAPI_ENTITY_PAYLOAD_BYTES).is_ok());

        let len = MAX_NAPI_ENTITY_PAYLOAD_BYTES + 1;
        assert_eq!(
            reason(validate_entity_payload_len(len)),
            format!(
                "entity data payload must be <= {MAX_NAPI_ENTITY_PAYLOAD_BYTES} bytes, got {len}"
            )
        );
    }

    #[test]
    fn napi_boundary_rejects_oversized_batch() {
        assert!(validate_batch_size(MAX_NAPI_BATCH_ENTITIES).is_ok());

        let len = MAX_NAPI_BATCH_ENTITIES + 1;
        assert_eq!(
            reason(validate_batch_size(len)),
            format!(
                "batch_put_entities accepts at most {MAX_NAPI_BATCH_ENTITIES} entities, got {len}"
            )
        );
    }

    #[test]
    fn napi_boundary_rejects_wrong_vector_len() {
        assert!(validate_vector_len(4, 4, "query vector").is_ok());

        assert_eq!(
            reason(validate_vector_len(5, 4, "query vector")),
            "query vector length must equal vault dimensions (4), got 5"
        );
    }

    #[test]
    fn napi_boundary_rejects_oversized_dimensions() {
        assert!(validate_dimensions(MAX_NAPI_DIMENSIONS).is_ok());

        let dimensions = MAX_NAPI_DIMENSIONS + 1;
        assert_eq!(
            reason(validate_dimensions(dimensions)),
            format!("dimensions must be <= {MAX_NAPI_DIMENSIONS}, got {dimensions}")
        );
    }
}
