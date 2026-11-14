//! Moved from `crates/oneiron/src/authority/oauth_server/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::authority::oauth_server::clients::OAuthClientRecord;
pub use crate::authority::oauth_server::clients::OAuthClientSource;
use ed25519_dalek::SigningKey;

/// How long an access token stands (CALLS, FIX 4902: an engine call).
pub const OAUTH_ACCESS_TTL_SECS: u64 = 3_600;

/// How long a fetched client ID metadata document stands before the next authorize fetches it
/// again (CALLS, FIX 4902: an engine call).
pub const OAUTH_CIMD_TTL_SECS: u64 = 3_600;
pub mod clients;
pub mod rows;
