//! Doors for `tests/runner_fence_masked_checkout.rs`
//! ([RUNNER-FENCE-MASKED-CHECKOUT]): a masked copy's checkout, bound
//! directly to a copy store at a copy commit standing in for a canonical
//! original, as a lease's selected binding is bound. Reaching it the
//! usual way needs a marked store and its projection records; the
//! checkout's own materialize, inspect and collect are what is under
//! test. Compiled only under `--cfg oneiron_test_support`; never API.

use std::path::{Path, PathBuf};

use crate::Vault;
use crate::git_wire::{GitOid, GitWire, RepoProjectedCheckoutBinding};
use crate::store::checkout_lease::{
    CheckoutLeaseAct, CheckoutResult, CheckoutTeardownInspection, PushedHeadReceipt,
};

/// The wire over `vault` and the binding of the copy store at
/// `copy_root`, pinned at `copy`, to the canonical `original`.
fn bound<'a>(
    vault: &'a Vault,
    copy_root: &Path,
    original: &str,
    copy: &str,
) -> CheckoutResult<(GitWire<'a>, RepoProjectedCheckoutBinding)> {
    let wire = GitWire::new(vault)?;
    let binding = RepoProjectedCheckoutBinding::bind(
        &wire,
        copy_root,
        GitOid::parse_hex(original)?,
        GitOid::parse_hex(copy)?,
    )?;
    Ok((wire, binding))
}

/// Materializes `lease`'s masked copy checkout from the copy store at
/// `copy_root`: the copy commit `copy` for the lease's pinned `original`.
/// The checkout's tree path.
///
/// # Errors
/// A lease not pinned at the original, a copy store that does not hold
/// the copy commit, or a failed git effect.
pub fn materialize_masked_copy_checkout(
    vault: &Vault,
    lease: &CheckoutLeaseAct,
    copy_root: &Path,
    original: &str,
    copy: &str,
) -> CheckoutResult<PathBuf> {
    let (wire, binding) = bound(vault, copy_root, original, copy)?;
    wire.materialize_projected_checkout(lease, &binding)?;
    Ok(wire
        .projected_checkout_handle_dir(lease, &binding)
        .join("tree"))
}

/// Observes `lease`'s masked copy checkout against `receipt`, as its
/// teardown inspection does.
///
/// # Errors
/// A failed read.
pub fn inspect_masked_copy_checkout(
    vault: &Vault,
    lease: &CheckoutLeaseAct,
    copy_root: &Path,
    original: &str,
    copy: &str,
    receipt: &PushedHeadReceipt,
) -> CheckoutResult<CheckoutTeardownInspection> {
    let (wire, binding) = bound(vault, copy_root, original, copy)?;
    wire.inspect_projected_checkout_teardown(lease, &binding, receipt)
}

/// Collects `lease`'s masked copy checkout, as its collection does.
///
/// # Errors
/// A failed git effect, or a handle that survived.
pub fn collect_masked_copy_checkout(
    vault: &Vault,
    lease: &CheckoutLeaseAct,
    copy_root: &Path,
    original: &str,
    copy: &str,
) -> CheckoutResult<()> {
    let (wire, binding) = bound(vault, copy_root, original, copy)?;
    wire.collect_projected_checkout(lease, &binding)
}
