//! The isolated receiver's real root writes and their durable publication.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;

use super::{PreparedIsolatedWindow, PublishedIsolatedWindow};
use crate::authority::VerifiedSlip;
use crate::authority::shared_replica_bootstrap::PreparedSharedReplicaAuthority;
use crate::embed::home_vectors::copy_scope;
use crate::embed::home_vectors::retained_copy::PreparedHomeClaimCopy;
use crate::sync::WindowKey;
use crate::sync::bridge::EntityImportEffects;
use crate::sync::client::OwnDeviceImport;
use crate::{EntityId, Error, Result, Vault};

/// A returned error and a durable publication are independent: a tail error
/// never authorizes deleting an already committed destination.
pub(in crate::sync) struct IsolatedRootResult {
    pub(in crate::sync) result: Result<()>,
    pub(in crate::sync) published: Option<PublishedIsolatedWindow>,
}

pub(in crate::sync) struct IsolatedBatchRootResult {
    pub(in crate::sync) result: Result<()>,
    pub(in crate::sync) published: Option<Vec<PublishedIsolatedWindow>>,
}

impl PreparedIsolatedWindow {
    /// The singleton adapter keeps the original mandatory source-read door.
    pub(in crate::sync) fn write_root(
        self,
        vault: &Vault,
        authority: PreparedSharedReplicaAuthority,
        own_device: Option<&OwnDeviceImport>,
        copies: &[Arc<PreparedHomeClaimCopy>],
        read_check: impl FnOnce(
            &heed::RoTxn<'_>,
            &VerifiedSlip,
            &[(EntityId, Vec<u8>)],
            &WindowKey,
            &loro::LoroDoc,
            &[u8],
            &loro::LoroDoc,
        ) -> Result<()>,
    ) -> IsolatedRootResult {
        let batch = Self::write_batch_root(
            vec![(self, copies.to_vec())],
            vault,
            authority,
            own_device,
            |txn, verified, history, sources| {
                let (key, base, update, candidate) = sources[0];
                read_check(txn, verified, history, key, base, update, candidate)
            },
        );
        IsolatedRootResult {
            result: batch.result,
            published: batch.published.and_then(|mut windows| windows.pop()),
        }
    }

    /// Stages every original window before final grant admission and the one
    /// complete source-read check, all in the same root. Native copy holders
    /// and per-window effects outlive that real writer and its commit.
    /// This internal door supplies no HTTPS provenance or target lifecycle.
    pub(in crate::sync) fn write_batch_root(
        windows: Vec<(Self, Vec<Arc<PreparedHomeClaimCopy>>)>,
        vault: &Vault,
        mut authority: PreparedSharedReplicaAuthority,
        own_device: Option<&OwnDeviceImport>,
        read_check: impl FnOnce(
            &heed::RoTxn<'_>,
            &VerifiedSlip,
            &[(EntityId, Vec<u8>)],
            &[(&WindowKey, &loro::LoroDoc, &[u8], &loro::LoroDoc)],
        ) -> Result<()>,
    ) -> IsolatedBatchRootResult {
        if crate::store::active_write_txn_depth() != 0 {
            return IsolatedBatchRootResult {
                result: Err(Error::InvariantViolation(
                    "isolated receiver requires its own root write",
                )),
                published: None,
            };
        }
        let (windows, copies): (Vec<_>, Vec<_>) = windows.into_iter().unzip();
        let keys: Vec<_> = windows
            .iter()
            .map(|window| window.content.key.clone())
            .collect();
        let mut unique = BTreeSet::new();
        if keys.iter().any(|key| !unique.insert(key.as_str())) {
            return IsolatedBatchRootResult {
                result: Err(Error::InvalidConfig(
                    "duplicate isolated source window".into(),
                )),
                published: None,
            };
        }
        let copy_batch: Vec<_> = keys
            .iter()
            .zip(&copies)
            .map(|(key, copies)| (key, copies.as_slice()))
            .collect();
        copy_scope::with_home_claim_copy_batch(vault, &copy_batch, || {
            let entity_effects: Vec<_> = keys
                .iter()
                .map(|_| RefCell::new(Some(EntityImportEffects::new())))
                .collect();
            let published = RefCell::new(None);
            let observations: Vec<_> = keys
                .iter()
                .filter_map(|key| copy_scope::observe_writer(vault, key.as_str()))
                .collect();
            // Only this caller-supplied read callback needs the native opaque
            // discipline; copy imports in general do not acquire it here.
            let result = vault.write_txn_door_after_commit(
                crate::store::Callback::Opaque,
                |txn| {
                    let original_history = authority.original_history_rows()?;
                    let history_ids = authority.stage_history_in_txn(vault, txn)?;
                    let imported: BTreeSet<_> = history_ids.iter().copied().collect();
                    if original_history.keys().any(|id| !imported.contains(id)) {
                        return Err(Error::InvariantViolation(
                            "isolated authority import omitted a carried row",
                        ));
                    }
                    let history = history_ids
                        .into_iter()
                        .map(|id| {
                            let body = original_history.get(&id).cloned().ok_or(
                                Error::InvariantViolation(
                                    "isolated authority import changed a carried row id",
                                ),
                            )?;
                            Ok((id, body))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let mut staged = Vec::with_capacity(windows.len());
                    for (window, effects) in windows.into_iter().zip(&entity_effects) {
                        let mut effects = effects.borrow_mut();
                        staged.push(window.stage_in_txn(
                            vault,
                            txn,
                            own_device,
                            effects.as_mut().ok_or(Error::InvariantViolation(
                                "isolated entity effects were consumed before commit",
                            ))?,
                        )?);
                    }
                    let verified = authority.admit_in_txn(vault, txn)?;
                    let sources: Vec<_> = staged
                        .iter()
                        .map(|window| {
                            (
                                &window.content.key,
                                &window.base,
                                window.update.as_slice(),
                                &window.content.candidate,
                            )
                        })
                        .collect();
                    read_check(txn, &verified, &history, &sources)?;
                    Ok(staged)
                },
                |staged| {
                    let mut windows = Vec::with_capacity(staged.len());
                    for (staged, effects) in staged.into_iter().zip(&entity_effects) {
                        let effects =
                            effects
                                .borrow_mut()
                                .take()
                                .ok_or(Error::InvariantViolation(
                                    "isolated entity effects were consumed before publication",
                                ))?;
                        windows.push(staged.publish_after_commit(vault, effects));
                    }
                    *published.borrow_mut() = Some(windows);
                    Ok(())
                },
            );
            for observation in observations {
                observation.finish(&result);
            }
            // Every RwTxn is closed before native output reconciliation.
            // Keep the original error and each window's partial-stage effects.
            if result.is_err() {
                for (key, effects) in keys.iter().zip(entity_effects) {
                    if let Some(effects) = effects.into_inner() {
                        effects.recover_after_root_error(vault, key.as_str());
                    }
                }
            }
            IsolatedBatchRootResult {
                result,
                published: published.into_inner(),
            }
        })
    }
}
