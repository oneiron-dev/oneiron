//! The weave Admin's read key (OF-499 A3, L02 seam): the Admin's verified
//! request instrument as every slip key reads it, its Scope set to the
//! Admin's current one, built in the transaction that reads under it.
//!
//! A child of the actor key, so it sets the key's private authority without
//! a general setter. Never the owner key, no owner exemption, no relationship
//! grant: the Admin's Scope is its explicit authority, and the slip's
//! records and channels caveats still bind through its proof. The
//! conversation home binds it as it binds every credential's reader: an Admin
//! who is not the vault's owner reads no stamped claim
//! ([`ScopedReadActorKey::homed_unnamed`]).
use super::super::ScopedRead;
use super::ScopedReadActorKey;
use crate::Vault;
use crate::authority::AuthenticatedWeaveAdmin;
use crate::error::Result;

impl<'v> ScopedRead<'v> {
    /// The lane `admin` reads under in `txn`: its request's slip key, the
    /// slip's Scope and proof copied as every slip key copies them, its
    /// authority the Admin's membership grant met with the request
    /// ([`AuthenticatedWeaveAdmin::read_scope_in_txn`], which revalidates the
    /// proof here). Same transaction only: a frame or a later snapshot never
    /// reads under it; each read builds its own. Its reader is homed in no
    /// conversation of this vault unless `txn` finds the Admin to be the
    /// vault's owner (DEC-0006 `#home-clearance`; RULING
    /// SECREAD-HOME-READ-DOORS = B): an Admin is a person on a membership
    /// grant, never one of the vault's own agents. An owner check that fails
    /// binds the reader.
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof does not
    /// hold in `txn`; a storage fault as itself. `None` only when the slip
    /// builds no read key.
    pub(crate) fn for_weave_admin_in_txn(
        vault: &'v Vault,
        txn: &'v heed::RoTxn<'_>,
        admin: &'v AuthenticatedWeaveAdmin,
    ) -> Result<Option<Self>> {
        let scope = admin.read_scope_in_txn(vault, txn)?;
        let Some(mut key) = ScopedReadActorKey::from_verified_slip(admin.request()) else {
            return Ok(None);
        };
        key.authority = Some(ScopedReadActorKey::read_authority(&scope));
        if !crate::memory::owner_exemption_holds_in_txn(vault, txn, admin.actor()).unwrap_or(false)
        {
            key = key.homed_unnamed();
        }
        Ok(Some(vault.scoped_read(key)))
    }
}
