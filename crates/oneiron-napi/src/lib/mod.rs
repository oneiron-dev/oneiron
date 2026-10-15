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

pub(crate) use self::boundary::{parse_search_limit, validate_query_len};
