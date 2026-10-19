//! `NativeClient.open_with_host_root` (FIX 5342, the Python half of FIX
//! 4730): `open`, then this install's own machine profile from the vault's
//! host root secret, through the shared client's rooted-only
//! `OneironClient::open_with_host_root`.
//!
//! The secret crosses as its own argument, never a field of the open
//! options, and is borrowed from the caller's immutable `bytes` for this
//! call only: nothing here copies or keeps it. What the open did with it
//! crosses back as JSON, like every DTO of this extension.

use std::path::PathBuf;

use oneiron_remote::{OneironClient, OpenOptions};
use pyo3::prelude::*;
use serde::Serialize;

use crate::{encode, raise};

/// What `open_with_host_root` did with the host root it was given; the
/// `HostRootProfile` dict `__init__.pyi` declares.
#[derive(Serialize)]
struct HostRootProfile {
    /// This open enrolled this install as an `Unanswered` machine; false
    /// when its live profile already stood, and nothing was written.
    enrolled: bool,
    /// The given root is not this vault's settled root, so it went unused:
    /// the handle stands under the settled root as before. Reported, never
    /// refused, so the host can show it or re-key. Never with `enrolled`.
    wrong_root: bool,
}

/// The embedded handle a host-root open returns, its native work run with
/// the interpreter detached. Refusals are the shared client's: an empty
/// secret is `BAD_REQUEST`; a managed or relay posture, or a root the
/// provider holds, is `FORBIDDEN`; a secret that cannot profile the install
/// fails with the engine's reason. A wrong root over a standing profile
/// opens and is reported ([`profile`]).
pub(crate) fn open(
    py: Python<'_>,
    path: Option<PathBuf>,
    host_root_secret: &[u8],
    dimensions: Option<usize>,
) -> PyResult<OneironClient> {
    // Crash output never carries world text: the engine's hook goes in before
    // any vault opens (owner ruling 2026-10-14, fix 6).
    oneiron::panic_report::install_panic_hook();
    let options = OpenOptions { dimensions };
    py.detach(|| OneironClient::open_with_host_root(path.as_deref(), &options, host_root_secret))
        .map_err(raise)
}

/// What the host-root open that made `client` did with its root, as the
/// `HostRootProfile` JSON; `None` on every other handle, one rebound from it
/// included.
pub(crate) fn profile(client: &OneironClient) -> PyResult<Option<String>> {
    client
        .host_root_profile()
        .map(|profile| {
            encode(&HostRootProfile {
                enrolled: profile.enrolled,
                wrong_root: profile.wrong_root,
            })
        })
        .transpose()
}
