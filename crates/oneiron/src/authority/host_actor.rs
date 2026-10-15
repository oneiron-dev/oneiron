//! The owner a self-hosted root binds (H149).
//!
//! Owner verbs ask the authority log, not store truth, whether an actor is
//! the owner: a folded active `human` binding. A self-hosted host holds the
//! owner's own key material, so the transaction that roots the vault binds
//! the vault's embedded owner under the root key, and the owner keeps the
//! owner verbs no other PERSON can name itself into. A hosted root is the
//! operator's key, never the owner's, and a relay mints no authority: their
//! roots bind no one, and the owner binds from a device of their own.
use super::*;
use crate::Vault;
use crate::error::Result;

impl Vault {
    /// Binds the embedded owner as `human` under `issuer`, in the transaction
    /// that wrote this vault's genesis. A hard-deleted owner is not brought
    /// back: the vault stays rooted with no owner bound, and owner verbs
    /// refuse.
    pub(super) fn bind_rooted_owner_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
    ) -> Result<()> {
        if self.privacy_posture() != crate::HostingPrivacyPosture::SelfHostLocal {
            return Ok(());
        }
        let owner = crate::vault::embedded_owner_actor_id()?;
        if self.local_hard_delete_marker_exists_in_txn(txn, &owner)? {
            return Ok(());
        }
        let now = self.store.clock.now_recorded_at();
        self.stage_embedded_owner_actor_in_txn(txn, now)?;
        self.append_slip_op_in_txn(
            txn,
            issuer,
            AuthorityOp::BindActor {
                authority_key: issuer.public_key(),
                actor_ref: owner,
                actor_class: ACTOR_CLASS_HUMAN.into(),
                epoch: 1,
            },
        )
    }
}
