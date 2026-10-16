mod config;
mod gpu;
pub use gpu::{
    GPU_LEASE_SECONDS, GPU_RENEW_SECONDS, GpuHealth, GpuLease, GpuRegistry, GpuRegistryError,
};
mod gpu_pool;
pub use gpu_pool::{GpuDerivationJob, GpuLeaseGuard, GpuPodConfig, GpuPool, GpuPoolConfig};
mod defaults;
mod mode;
mod routes;
mod usage;
pub use usage::VaultUsage;
pub mod seat_login;

pub use self::config::RuntimeConfig;
pub use self::defaults::{
    RuntimeConfigOverride, RuntimeRoleDefaultOverrides, RuntimeRoleDefaults, RuntimeRoleTarget,
    RuntimeRoleTargetOverride,
};
pub use self::mode::{RuntimeMode, RuntimeProviderKind, RuntimeRole};
// Test-only caller until row routing lands with 1890 (the fn carries
// expect(dead_code) outside tests); a crate-wide re-export would be an
// unused import in non-test builds.
pub use self::routes::{
    RuntimeHealthStatus, RuntimeRoute, RuntimeRouteProvenance, RuntimeRouteReason,
    RuntimeRouteSource, RuntimeRouteState, RuntimeStatus,
};

// The flat runtime.rs module used to provide these names to the sibling test
// module through `use super::*`. The explicit re-exports above already cover
// every `pub` name the tests use bare; the seam only adds what they do not:
// the `pub(super)` const plus the crate/std imports the tests rely on.
// (Full `child::*` globs would duplicate the explicit re-exports and rustc
// credits those names to the explicit imports, leaving the globs unused.)
