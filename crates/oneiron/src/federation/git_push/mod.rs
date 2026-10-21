//! The owner's `git_push` Grant (FIX 6867, owner ruling G1-PUSH = D, as the
//! owner refined it 10-21: "the Grant check IS the policy").
//!
//! Raw git push into this vault's `/git` endpoint is its own Grant
//! capability. The owner holds it implicitly; anyone else holds it only
//! through a GitPush FEDERATION_GRANT he minted (`vault.repo.git_push.mint`,
//! [`Vault::mint_git_push_grant`]) to a live PERSON or a live agent
//! definition he names, on explicitly named repos, until he revokes it
//! (`vault.repo.git_push.revoke`) or it reaches the expiry he set. A vault
//! write grant, top scope included, no longer implies it, and the agent
//! Grant mint never gains its verb.
//!
//! One decision admits every receive-pack, advertisement and RPC alike, on
//! the ordinary and the checkout-lease route:
//! [`Vault::admit_git_receive_pack_in_txn`] answers a sealed
//! [`GitPushAdmission`] (the owner, a GitPush Grant, or an SDK checkout whose
//! run's Grant covers the push) or the typed refusal naming the missing
//! capability. It reads the Grant, never the holder's class. The final
//! intent writer rechecks the same authority before the quarantine is
//! released ([`Vault::recheck_git_push_in_txn`]); once accepted, the journal
//! completes exactly that operation, recovery included (CALLS "FIX 6867
//! git_push acceptance").
//!
//! Each GitPush grant shows in `vault.consent.registry` with its own
//! one-tap revoke ([`GIT_PUSH_REVOKE_COMMAND`]); its signed mint and revoke
//! acts are the authority log's account of the owner's will.

mod admission;
mod caller;
mod mint;
mod registry;

use std::path::Path;

pub use caller::{GitPushAdmission, GitPushCaller, GitPushCredential, GitPushSeal};
pub(crate) use caller::{GitPushRefChange, GitPushStamp, ServedPushRepo};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeStoreRead, EntityStoreRead};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_FEDERATION_GRANT,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::{
    FederationGrant, FederationGrantKind, FederationGrantScope, GitPushBounds, GitPushRepo,
    decode_federation_grant_body, own_device_residence_scope,
};

/// The one-tap revoke command every GitPush grant carries.
pub(crate) const GIT_PUSH_REVOKE_COMMAND: &str = "vault.repo.git_push.revoke";

/// One live GitPush grant as its row holds it.
#[derive(Debug, Clone)]
pub(crate) struct GitPushGrantStanding {
    pub(crate) id: EntityId,
    pub(crate) grant: FederationGrant,
    /// The repos it names.
    pub(crate) bounds: GitPushBounds,
    /// The owner who granted it (the row's `delegated_by`).
    pub(crate) delegated_by: EntityId,
    /// Recording time of the mint (Unix seconds).
    pub(crate) created_at: u64,
}

impl GitPushGrantStanding {
    /// Whether it still stands at `now`: no expiry, or one not reached.
    pub(crate) fn stands_at(&self, now: u64) -> bool {
        self.grant
            .expires_at
            .is_none_or(|expires_at| now < expires_at)
    }
}

impl Vault {
    /// Every live GitPush grant of this vault, in id order. A row that does
    /// not decode, or any Access grant, is none here.
    pub(crate) fn git_push_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<GitPushGrantStanding>> {
        let mut grants = Vec::new();
        for id in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
        {
            if let Some(standing) = self.git_push_grant_in_txn(txn, id?)? {
                grants.push(standing);
            }
        }
        Ok(grants)
    }

    /// The live GitPush grant `id`, read in `txn`; `None` for any other row.
    pub(crate) fn git_push_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> Result<Option<GitPushGrantStanding>> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(None);
        };
        let Ok(grant) = decode_federation_grant_body(&body) else {
            return Ok(None);
        };
        let (FederationGrantKind::GitPush, Some(bounds), Some(delegated_by)) = (
            grant.kind,
            grant.git_push_bounds.clone(),
            grant.delegated_by,
        ) else {
            return Ok(None);
        };
        let created_at = self
            .store
            .port_entity_record(txn, &id)?
            .map_or(0, |row| row.learned_at);
        Ok(Some(GitPushGrantStanding {
            id,
            grant,
            bounds,
            delegated_by,
            created_at,
        }))
    }

    /// The grant scope this vault's own grants carry: the vault's recorded
    /// scope when it is shared, the home's residence scope otherwise.
    pub(crate) fn git_push_grant_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<FederationGrantScope> {
        Ok(self
            .shared_vault_creation_in_txn(txn)?
            .map_or_else(own_device_residence_scope, |shared| {
                FederationGrantScope::vault(shared.vault_id)
            }))
    }

    /// Whether `member` is a holder a Grant can name: a live PERSON or a
    /// live agent definition. A machine, a system principal or a missing
    /// one is no holder. The same predicate holds at mint and at every
    /// admission, so a holder that stopped existing pushes nothing.
    pub(crate) fn git_push_grantee_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
    ) -> Result<bool> {
        if crate::consent::person_is_live_in_txn(self, txn, &member)? {
            return Ok(true);
        }
        Ok(matches!(
            live_entity_row_in_txn(&self.store, txn, &member)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                ..
            }
        ))
    }

    /// The stored repo path of `repo`'s CODE anchor in `txn`: a live
    /// CODE_ARTIFACT whose stored repo_ref is a local repository, with a
    /// `belongs_to` edge to the live PROJECT the repo names. `None` for
    /// anything else, an unreadable body included. The path is the stored
    /// record's, never a caller's; which store it names is the caller's
    /// identity check.
    pub(crate) fn git_push_anchor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        repo: &GitPushRepo,
    ) -> Result<Option<String>> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CODE_ARTIFACT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &repo.repo)?
        else {
            return Ok(None);
        };
        let Some(RepoRef::LocalFolder { path, .. }) =
            crate::code_artifact::decode_code_artifact_body(&body)
                .ok()
                .and_then(|artifact| RepoRef::parse(&artifact.repo_ref).ok())
        else {
            return Ok(None);
        };
        if !live_entity_row_in_txn(&self.store, txn, &repo.project)?.is_live()
            || !crate::workspace_roster::is_project_entity(&self.store, txn, repo.project)?
            || self
                .store
                .port_edge_get(txn, &repo.repo, EdgeKind::BelongsTo, &repo.project)?
                .is_none()
        {
            return Ok(None);
        }
        Ok(Some(path))
    }

    /// The Git object-store identity the stored path `anchor` names, or
    /// `None` when it names no store this host can read.
    pub(crate) fn git_push_store_identity(&self, anchor: &str) -> Option<String> {
        crate::git_wire::GitWire::new(self)
            .ok()?
            .repository_identity(Path::new(anchor))
            .ok()
            .map(|identity| identity.as_hex())
    }
}
