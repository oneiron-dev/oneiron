//! A standing grant's bound as a seed writes it (DEC-0006): who, which class,
//! which envelope. The wire form holds no authority of its own. It builds a
//! [`GrantBound`] only through the consent constructors, which check it, and
//! a grant only lands through the consent doors: the owner's mint, or an
//! agent's proposal to the owner's widen inbox.
use crate::Vault;
use crate::error::Result;

#[doc(hidden)]
pub use oneiron_verb_wire::vault_shape::grant::ShapeGrantBound;

impl Vault {
    /// The principal ref a grant an actor's apply files is answered under
    /// (FIX 2503). In a rooted vault it is the live owner the root binds as
    /// `human`, as hex: the ref a host-action owner, and an owner whose
    /// principal ref is their entity id, accepts under. The embedded owner
    /// wins when the root binds them, else the first such owner by id. An
    /// embedded vault, and a rooted one that binds no live owner, keep the
    /// embedded owner, as before.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub(super) fn shape_filing_owner_ref(&self) -> Result<String> {
        let embedded = crate::vault::embedded_owner_actor_id()?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        if fold.vault_id.is_none() || fold.vault_root_is_conflicted() {
            return Ok(embedded.to_hex());
        }
        let mut bound = crate::policy_model::owners_in_txn(self, &txn)?;
        bound.retain(|owner| crate::authority::actor_binding_is_active(&fold, owner, "human"));
        bound.sort();
        let owner = if bound.contains(&embedded) {
            embedded
        } else {
            bound.first().copied().unwrap_or(embedded)
        };
        Ok(owner.to_hex())
    }
}
