//! Typed origin and checkout doors (DOOR-139): tested-tree export, the origin
//! authority epoch, publication records and checkout door binding. Each one
//! projects an engine path; registration creates only an empty served
//! repository. None mints a lease, commits a tested tree or forces a
//! publication result.
//!
//! Authority is the owner's live proof alone (`Memory::origin_owner`).
//! Export and binding also take a live checkout lease the owner holds on the
//! served repository, through the same gate every lease-route git request
//! redeems (`credential_door::require_checkout_lease`).

mod operations;
mod setup;
mod types;

pub use types::*;

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::checkout::lease::{CheckoutError, CheckoutLeaseAct};
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::git_wire::GitWire;
use crate::origin::smart_http::origin_repo_dir;

impl Memory<'_> {
    /// The CALL behind every DOOR-139 door: origin and checkout doors are
    /// owner-only setup doors. The proof must be live on this vault and name
    /// this handle's own human actor; an agent never borrows it, and a
    /// request field never stands in for it.
    fn origin_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<EntityId> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.origin_owner_in_txn(owner, &txn)
    }

    fn origin_owner_in_txn(
        &self,
        owner: &AuthenticatedOwner,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<EntityId> {
        let actor = owner.revalidate_in_txn(self.vault, txn)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "origin and checkout setup acts as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(actor)
    }

    /// The live checkout lease `checkout`.`epoch` names, held by the owner's
    /// own principal on the served repository `repo`. The stored lease
    /// decides state, time, holder and repository; the request only names it.
    fn origin_checkout_lease(
        &self,
        owner: &AuthenticatedOwner,
        repo: &str,
        checkout: &str,
        epoch: u64,
    ) -> MemoryResult<CheckoutLeaseAct> {
        let repo_dir = origin_repo_dir(self.vault, repo)?;
        let served = RepoRef::LocalFolder {
            path: repo_dir.to_string_lossy().into_owned(),
            commit: "0".repeat(crate::codebase::CODEBASE_COMMIT_HASH_HEX_LEN),
        };
        let holder = owner.revalidate_principal_ref(self.vault)?;
        let ticket = format!("{checkout}.{epoch}");
        crate::credential_door::require_checkout_lease(self.vault, &ticket, holder, &served)
            .map_err(|error| {
                MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    format!("checkout lease refused: {error}"),
                    &["Name a live lease you hold on this served repository, at its epoch."],
                )
            })
    }

    /// The git wire whose checkout remotes point at `endpoint`. The caller
    /// names the door base explicitly; no Host or forwarded header is read,
    /// and the existing grammar refuses userinfo, queries and plain HTTP off
    /// loopback. The endpoint grants nothing and selects no object store.
    fn origin_door_wire(&self, endpoint: &str) -> MemoryResult<GitWire<'_>> {
        Ok(GitWire::new(self.vault)?.with_checkout_door(endpoint)?)
    }

    /// Where an origin row lists what it derives from: each named row that
    /// still exists. A side-table journal row has no entity of its own.
    fn origin_listed(&self, rows: impl IntoIterator<Item = EntityId>) -> MemoryResult<()> {
        for row in rows {
            if self.vault.get_entity_type(&row)?.is_some() {
                self.produced_from([row]);
            }
        }
        Ok(())
    }

    /// A row the answer is read from, which the caller's credential must read.
    fn origin_readable(&self, id: EntityId) -> MemoryResult<()> {
        self.produced_from([id]);
        if self.get_entity(&id.to_hex())?.value.is_none() {
            return Err(MemoryError::not_found(
                "code revision record is absent or withheld",
            ));
        }
        Ok(())
    }
}

/// A checkout port refusal, as the door's caller reads it.
fn checkout_refusal(error: CheckoutError) -> MemoryError {
    match error {
        CheckoutError::Store(error) => MemoryError::from(error),
        CheckoutError::Invalid(reason) => MemoryError::bad_request(reason),
        CheckoutError::RepoOps(reason) => MemoryError::new(MEMORY_CODE_INVALID_STATE, reason, &[]),
        other => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!("checkout refused: {other:?}"),
            &[],
        ),
    }
}
