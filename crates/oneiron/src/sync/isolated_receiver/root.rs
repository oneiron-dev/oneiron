//! The isolated receiver's real root write and its durable publication.

use std::cell::RefCell;
use std::sync::Arc;

use super::{PreparedIsolatedWindow, PublishedIsolatedWindow};
use crate::authority::VerifiedSlip;
use crate::authority::shared_replica_bootstrap::PreparedSharedReplicaAuthority;
use crate::embed::home_vectors::copy_scope;
use crate::embed::home_vectors::retained_copy::PreparedHomeClaimCopy;
use crate::sync::bridge::EntityImportEffects;
use crate::sync::client::OwnDeviceImport;
use crate::{Error, Result, Vault};

/// The original write-door answer and the publication are independent. A
/// postcommit error cannot turn a durable candidate back into an uncommitted
/// one or authorize its host to delete the destination's files.
pub(in crate::sync) struct IsolatedRootResult {
    pub(in crate::sync) result: Result<()>,
    pub(in crate::sync) published: Option<PublishedIsolatedWindow>,
}

impl PreparedIsolatedWindow {
    /// Imports original signed history, stages the native window and checks
    /// final authority in one root. `read_check` must judge the complete
    /// candidate in this writer. Its arguments retain the original window
    /// key, base, raw update and final candidate: a per-row or final-map check
    /// alone is not authority to persist the whole carried history/metadata.
    ///
    /// This internal write door does not supply that source authorization or
    /// bind an HTTPS acceptance to a target. Its caller must do both before
    /// exposing a bootstrap entrypoint.
    pub(in crate::sync) fn write_root(
        self,
        vault: &Vault,
        mut authority: PreparedSharedReplicaAuthority,
        own_device: Option<&OwnDeviceImport>,
        copies: &[Arc<PreparedHomeClaimCopy>],
        read_check: impl FnOnce(
            &heed::RoTxn<'_>,
            &VerifiedSlip,
            &crate::sync::WindowKey,
            &loro::LoroDoc,
            &[u8],
            &loro::LoroDoc,
        ) -> Result<()>,
    ) -> IsolatedRootResult {
        // A savepoint's success is not the outer writer's commit receipt.
        if crate::store::active_write_txn_depth() != 0 {
            return IsolatedRootResult {
                result: Err(Error::InvariantViolation(
                    "isolated receiver requires its own root write",
                )),
                published: None,
            };
        }
        let key = self.content.key.clone();
        copy_scope::with_home_claim_copies(vault, &key, copies, || {
            let entity_effects = RefCell::new(Some(EntityImportEffects::new()));
            let published = RefCell::new(None);
            let observation = copy_scope::observe_writer(vault, key.as_str());
            // The supplied read callback may retain dependencies the engine
            // cannot audit. This door, not all copy imports, therefore uses
            // the native opaque callback discipline.
            let result = vault.write_txn_door_after_commit(
                crate::store::Callback::Opaque,
                |txn| {
                    authority.stage_history_in_txn(vault, txn)?;
                    let staged = {
                        let mut effects = entity_effects.borrow_mut();
                        self.stage_in_txn(
                            vault,
                            txn,
                            own_device,
                            effects.as_mut().ok_or(Error::InvariantViolation(
                                "isolated entity effects were consumed before commit",
                            ))?,
                        )?
                    };
                    let verified = authority.admit_in_txn(vault, txn)?;
                    read_check(
                        txn,
                        &verified,
                        &staged.content.key,
                        &staged.base,
                        &staged.update,
                        &staged.content.candidate,
                    )?;
                    Ok(staged)
                },
                |staged| {
                    let effects =
                        entity_effects
                            .borrow_mut()
                            .take()
                            .ok_or(Error::InvariantViolation(
                                "isolated entity effects were consumed before publication",
                            ))?;
                    *published.borrow_mut() = Some(staged.publish_after_commit(vault, effects));
                    Ok(())
                },
            );
            if let Some(observation) = observation {
                observation.finish(&result);
            }
            // The write door has returned and its RwTxn is closed. A partial
            // stage or base-commit error still owns the original native
            // outputs; reconciliation never substitutes its count for Err.
            if result.is_err()
                && let Some(effects) = entity_effects.into_inner()
            {
                effects.recover_after_root_error(vault, key.as_str());
            }
            IsolatedRootResult {
                result,
                published: published.into_inner(),
            }
        })
    }
}
