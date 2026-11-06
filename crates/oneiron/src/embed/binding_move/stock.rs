use super::{
    BINDING_MOVE, BTreeSet, BindingMoveState, BindingSource, EmbeddingSpace,
    PendingEmbedderBinding, RoTxn, Vault, declare_embedding_space_in_txn, embedding_spaces_in_txn,
    expected_moved_in, invalid, kind_slot_bindings_in_txn, pins,
};
use crate::embed::space_move::stock_move_kinds;
use crate::embed::{InputKind, KindSlotBindings};
use crate::error::Result;
use crate::model_binding::ModelSlot;

fn inputs_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    expected: &PendingEmbedderBinding,
) -> Result<Option<(KindSlotBindings, BTreeSet<InputKind>)>> {
    if !matches!(&expected.source, BindingSource::Offer { .. })
        || expected.state != BindingMoveState::Waiting
        || expected.link.is_some()
        || expected.refill.is_some()
        || expected.binding.slot != ModelSlot::Embedder
        || BINDING_MOVE
            .get(&vault.store, txn, &expected.source.id())?
            .as_ref()
            != Some(expected)
        || expected_moved_in(vault, txn, expected)?
    {
        return Ok(None);
    }
    let bindings = kind_slot_bindings_in_txn(&vault.store, txn)?;
    let serving = bindings
        .text
        .clone()
        .unwrap_or_else(|| vault.text_index_space().id);
    let model = expected.binding.model.as_str();
    if pins(&serving, model) {
        return Ok(None);
    }
    let kinds = stock_move_kinds(&bindings);
    for space in embedding_spaces_in_txn(&vault.store, txn)? {
        if pins(&space.id, model) && kinds.iter().all(|kind| space.admit_binding(*kind).is_ok()) {
            // The ordinary attach path can use it once its kind slots are free.
            return Ok(None);
        }
    }
    Ok(Some((bindings, kinds)))
}

impl Vault {
    /// The incumbent kinds an approved stock binding still needs a declared space for.
    /// An existing compatible pin, a refill, or a changed approval stays on its ordinary path.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn stock_embedder_binding_inputs(
        &self,
        expected: &PendingEmbedderBinding,
    ) -> Result<Option<(KindSlotBindings, BTreeSet<InputKind>)>> {
        let rtxn = self.store.env.read_txn()?;
        inputs_in(self, &rtxn, expected)
    }

    /// Declares a stock binding's observed native width only while its full approval and
    /// incumbent snapshot still stand. The next ordinary pass begins its move.
    ///
    /// # Errors
    ///
    /// Storage errors or an invalid candidate declaration, including a changed native width.
    pub fn declare_staged_stock_embedder_space(
        &self,
        expected: &PendingEmbedderBinding,
        expected_bindings: &KindSlotBindings,
        space: &EmbeddingSpace,
    ) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some((bindings, kinds)) = inputs_in(self, &wtxn, expected)? else {
            return Ok(false);
        };
        if bindings != *expected_bindings {
            return Ok(false);
        }
        if !pins(&space.id, expected.binding.model.as_str())
            || space.accepts != kinds
            || space.query_towers != kinds
        {
            return Err(invalid(
                "a staged stock space must pin its binding and incumbent kinds",
            ));
        }
        declare_embedding_space_in_txn(&self.store, &mut wtxn, space)?;
        let setup = self.publish_embedding_setup_in_txn(&mut wtxn)?;
        wtxn.commit()?;
        self.embedding_setup_committed(setup);
        Ok(true)
    }
}
