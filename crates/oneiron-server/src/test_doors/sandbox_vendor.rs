//! Doors for `tests/sandbox_vendor_daytona.rs` and
//! `tests/sandbox_vendor_e2b.rs` (L8-43): the vendor sandboxes this server
//! serves, with the vendor's API at the test's own address.

use std::path::PathBuf;
use std::sync::Arc;

use oneiron::Vault;
use oneiron::code_sandbox::microvm::SandboxBackends;

use crate::sandbox_vendor::{DaytonaEndpoints, E2bEndpoints, ServedSandboxBackends};

/// The served backends of `vault`, reaching Daytona's control API at `api`
/// and its toolbox proxy at `toolbox`, with each run's scratch under
/// `scratch_root`.
pub fn served_backends(
    vault: &Arc<Vault>,
    api: &str,
    toolbox: &str,
    scratch_root: PathBuf,
) -> Arc<dyn SandboxBackends> {
    Arc::new(ServedSandboxBackends::with_daytona(
        vault,
        DaytonaEndpoints {
            api: api.to_owned(),
            toolbox: toolbox.to_owned(),
        },
        scratch_root,
    ))
}

/// The served backends of `vault`, reaching E2B's control API at `api` and
/// each sandbox's daemon at `envd` (with `{sandbox}` standing for its id),
/// with each run's scratch under `scratch_root`.
pub fn served_e2b_backends(
    vault: &Arc<Vault>,
    api: &str,
    envd: &str,
    scratch_root: PathBuf,
) -> Arc<dyn SandboxBackends> {
    Arc::new(ServedSandboxBackends::with_e2b(
        vault,
        E2bEndpoints {
            api: api.to_owned(),
            envd: envd.to_owned(),
        },
        scratch_root,
    ))
}
