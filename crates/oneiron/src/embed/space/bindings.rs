//! The kind slot binding doors (OF-370; ARCH-0019 `#kind-slots`, `#default-bindings`).

use std::collections::BTreeSet;

use super::{
    EMBEDDING_SLOT, InputKind, bind_kind_slot_in_txn, embedding_space_in_txn,
    refuse_moving_slot_in_txn, slot_setup_id,
};
use crate::Vault;
use crate::error::{Error, Result};

impl Vault {
    /// Binds a kind slot to a declared space that accepts that input. Binding text moves text
    /// documents and text queries off the vault's own index onto that space, so the space also
    /// needs a text query tower ([`Self::bind_one_space_for_all`] binds every slot at once).
    /// A slot an open move carries is refused until the move ends.
    pub fn bind_kind_slot(&self, kind: InputKind, space_id: &str) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        bind_kind_slot_in_txn(&self.store, &mut wtxn, kind, space_id)?;
        let owned = BTreeSet::from([slot_setup_id(kind)?]);
        let setup = self.publish_embedding_setup_as_in_txn(&mut wtxn, &owned)?;
        wtxn.commit()?;
        self.embedding_setup_committed(setup);
        Ok(())
    }

    /// The one-space preset (OF-370; ARCH-0019 `#default-bindings`): binds every kind slot
    /// declared space `space_id` accepts to it, text included, in one write. Text documents then
    /// embed into the space through its media embedder ([`Self::reconcile_media_embeddings`]),
    /// and a server searches a text query there through the space's text tower, in place of the
    /// vault's own index. A declaration only: no stored vector moves, and unbinding the text
    /// slot ([`Self::unbind_kind_slot`]) returns text to the vault's index.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the space is undeclared, does not accept text, or has no
    /// text query tower, or an open move carries a slot it would bind.
    pub fn bind_one_space_for_all(&self, space_id: &str) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(space) = embedding_space_in_txn(&self.store, &wtxn, space_id)? else {
            return Err(Error::InvalidConfig(format!(
                "embedding space {space_id} is not declared"
            )));
        };
        space.admit_binding(InputKind::Text)?;
        for kind in &space.accepts {
            refuse_moving_slot_in_txn(&self.store, &wtxn, *kind)?;
        }
        let mut owned = BTreeSet::new();
        for kind in InputKind::ALL {
            if space.accepts.contains(&kind) {
                EMBEDDING_SLOT.put(&self.store, &mut wtxn, &[kind.byte()], &space.id)?;
                owned.insert(slot_setup_id(kind)?);
            }
        }
        let setup = self.publish_embedding_setup_as_in_txn(&mut wtxn, &owned)?;
        wtxn.commit()?;
        self.embedding_setup_committed(setup);
        Ok(())
    }
}
