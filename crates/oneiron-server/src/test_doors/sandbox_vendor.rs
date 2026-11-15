//! Doors for `tests/sandbox_vendor_daytona.rs` (L8-43): the vendor sandboxes
//! this server serves, with Daytona's API at the test's own address.

use std::path::PathBuf;
use std::sync::Arc;

use oneiron::Vault;
use oneiron::code_sandbox::microvm::SandboxBackends;

use crate::sandbox_vendor::{DaytonaEndpoints, ServedSandboxBackends};

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
