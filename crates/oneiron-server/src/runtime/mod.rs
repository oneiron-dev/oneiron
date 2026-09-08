mod config;
mod defaults;
mod mode;
mod routes;

pub use self::config::RuntimeConfig;
pub use self::defaults::{
    RuntimeConfigOverride, RuntimeRoleDefaultOverrides, RuntimeRoleDefaults, RuntimeRoleTarget,
    RuntimeRoleTargetOverride,
};
pub use self::mode::{RuntimeMode, RuntimeProviderKind, RuntimeRole};
// Test-only caller until row routing lands with 1890 (the fn carries
// expect(dead_code) outside tests); a crate-wide re-export would be an
// unused import in non-test builds.
#[cfg(test)]
pub(crate) use self::routes::resolve_agent_route;
pub use self::routes::{
    RuntimeHealthStatus, RuntimeRoute, RuntimeRouteProvenance, RuntimeRouteReason,
    RuntimeRouteSource, RuntimeRouteState, RuntimeStatus,
};

#[cfg(test)]
mod tests;

// The flat runtime.rs module used to provide these names to the sibling test
// module through `use super::*`. The explicit re-exports above already cover
// every `pub` name the tests use bare; the seam only adds what they do not:
// the `pub(super)` const plus the crate/std imports the tests rely on.
// (Full `child::*` globs would duplicate the explicit re-exports and rustc
// credits those names to the explicit imports, leaving the globs unused.)
#[cfg(test)]
use self::config::DEFAULT_BYO_KEY_ENV;
#[cfg(test)]
use crate::usage::UsageMode;
#[cfg(test)]
use std::ffi::OsString;
