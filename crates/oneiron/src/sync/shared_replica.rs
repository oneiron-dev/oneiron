//! Native materialization of an accepted member's initial shared replica.
//!
//! The caller retains the actual HTTPS source and selected target lifecycle.
//! This door does not turn decoded input into transport provenance.

pub(crate) mod source;
mod wire;
pub use source::{
    SharedReplicaManifest, SharedReplicaManifestRequest, SharedReplicaWindow,
    SharedReplicaWindowRequest,
};

use crate::authority::CapabilitySlip;
use crate::authority::shared_replica_bootstrap::PreparedSharedReplicaAuthority;
use crate::federation::FederationGrantScope;
use crate::{Result, Vault};

use super::WindowKey;
use super::isolated_receiver::PreparedIsolatedWindow;
use super::schema::create_window_doc;
use super::selector::{SyncSelector, check_bootstrap_sources};

/// Materializes the original signed history and all fetched native windows in
/// one real root. The target must still be authority-unstarted on that writer.
/// `proof` is a fresh local holder proof's timestamp, signature and nonce; it
/// must not be a proof already spent by one of the home's HTTP calls.
///
/// `shared_vault_id` is the selected logical shared vault, not the local store
/// id or the home's authority lineage. Native current-grant checks bind it to
/// `selector` after every PERSON and GRANT window has staged.
///
/// Returns the original write result and durable publication independently.
/// In particular, `Err` with `true` is a committed tail error: the caller must
/// preserve the dedicated target. No live sync manager or lane starts here.
pub fn import_shared_replica(
    vault: &Vault,
    history: Vec<Vec<u8>>,
    windows: Vec<(WindowKey, Vec<u8>)>,
    slip: CapabilitySlip,
    proof: (u64, Vec<u8>, Vec<u8>),
    shared_vault_id: u64,
    selector: &SyncSelector,
    lease_vault_id: u64,
) -> (Result<()>, bool) {
    let prepared = (|| -> Result<_> {
        let (timestamp, signature, nonce) = proof;
        let binding_key = slip.claims.binding_key;
        let authority = PreparedSharedReplicaAuthority::prepare(
            history,
            slip,
            timestamp,
            signature,
            nonce,
            selector.member_ref,
            binding_key,
        )?;
        let windows = windows
            .into_iter()
            .map(|(key, update)| {
                let base = create_window_doc("shared-replica", &key);
                Ok((
                    PreparedIsolatedWindow::prepare(vault, key, &base, update, lease_vault_id)?,
                    Vec::new(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((authority, windows))
    })();
    let (authority, windows) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return (Err(error), false),
    };
    let root = PreparedIsolatedWindow::write_batch_root(
        windows,
        vault,
        authority,
        None,
        |txn, verified, history, windows| {
            let sources: Vec<_> = windows
                .iter()
                .map(|(key, _, update, candidate)| (*key, *update, *candidate))
                .collect();
            check_bootstrap_sources(
                vault,
                txn,
                verified,
                FederationGrantScope::vault(shared_vault_id),
                selector,
                history,
                &sources,
            )
        },
    );
    (root.result, root.published.is_some())
}
