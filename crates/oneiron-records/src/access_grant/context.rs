//! Moved from `crates/oneiron/src/access_grant/context.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccessLimited {
    pub suppressed_count: usize,
    pub required_action: String,
}

/// Written with snake_case field names (its own and `AccessLimited`'s), as the
/// REST replies that flatten it (`POST /v1/core/query`, `POST /v1/core/context-pack`)
/// and their OpenAPI mirror `GrantedDataSchema` name them.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GrantedData<T> {
    pub granted_data: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_limited: Option<AccessLimited>,
}

impl<T> GrantedData<T> {
    /// Only authorized ids belong in this projection. Withheld ids are never disclosed.
    pub fn new(granted_data: Vec<T>, suppressed_count: usize) -> Self {
        Self {
            granted_data,
            access_limited: (suppressed_count > 0).then(|| AccessLimited {
                suppressed_count,
                required_action: "request_access".to_owned(),
            }),
        }
    }
}
