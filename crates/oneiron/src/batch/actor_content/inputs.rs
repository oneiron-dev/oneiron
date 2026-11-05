//! Read-only original content-gate inputs from the actual batch frame.

use super::{ContentWriteSet, Scope, SharedContentWriteSet};
use crate::federation::{OwnedSharedVaultWriteInputs, SharedVaultWriteInputs};
use crate::{EntityId, Vault, WriteActor};

/// A view of one actual typed target. Missing observations remain unknown;
/// personal scope comes only from the frame's original creation lookup.
pub(crate) struct ContentWriteInputs<'frame> {
    target: EntityId,
    shared: Option<&'frame SharedContentWriteSet>,
}

impl ContentWriteSet {
    pub(in crate::batch) fn native_inputs(
        &self,
        target: EntityId,
    ) -> Option<ContentWriteInputs<'_>> {
        (self.native_target == Some(target)).then_some(ContentWriteInputs {
            target,
            shared: self.shared.as_ref(),
        })
    }
}

impl ContentWriteInputs<'_> {
    pub(crate) fn target(&self) -> EntityId {
        self.target
    }

    pub(crate) fn shared_vault_id(&self) -> Option<u64> {
        self.shared.map(|shared| shared.vault_id)
    }

    pub(crate) fn previous_scope(&self) -> Option<&Scope> {
        self.shared?.entries.get(&self.target)?.old.as_ref()
    }

    pub(crate) fn before(&self) -> Option<SharedVaultWriteInputs<'_>> {
        Some(
            self.shared?
                .entries
                .get(&self.target)?
                .before_inputs
                .as_ref()?
                .as_borrowed(),
        )
    }

    pub(crate) fn after(&self) -> Option<SharedVaultWriteInputs<'_>> {
        Some(
            self.shared?
                .entries
                .get(&self.target)?
                .after_inputs
                .as_ref()?
                .as_borrowed(),
        )
    }
}

pub(super) fn authorize_content_write(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_id: u64,
    actor: &WriteActor,
    requested: &super::SharedVaultWrite,
    capture: Option<&mut Option<OwnedSharedVaultWriteInputs>>,
) -> crate::error::Result<()> {
    if let Some(capture) = capture {
        let mut observe = |inputs: SharedVaultWriteInputs<'_>| {
            *capture = Some(inputs.into_owned());
        };
        vault.authorize_shared_vault_write_observing_in_txn(
            txn,
            vault_id,
            actor,
            requested,
            Some(&mut observe),
        )
    } else {
        vault.authorize_shared_vault_write_in_txn(txn, vault_id, actor, requested)
    }
}
