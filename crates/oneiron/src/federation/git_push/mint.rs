//! The owner's mint and revoke of a `git_push` Grant (FIX 6867, G1-PUSH):
//! `vault.repo.git_push.mint` and `.revoke`, owner proof only.
//!
//! A mint lands the owner's signed Grant act and the GitPush
//! FEDERATION_GRANT row in one write transaction, as an agent Grant mint
//! does, through the same signer, fold and op. The writer revalidates the
//! owner and the holder he names: a live PERSON or a live agent definition,
//! whichever he chose; a machine, a system principal or a missing one is no
//! holder a Grant can name. Each repo must be a live CODE anchor in its live
//! PROJECT whose stored repo names a Git store this origin serves. No other
//! grant can make one: a top Access grant does not, and the agent Grant
//! mint never gains the `git_push` verb.
//!
//! A revoke lands his signed revoke act and the row's delete in one writer,
//! and touches GitPush rows only; a repeat the authority log already names
//! changes nothing and signs nothing.

use std::path::Path;

use crate::authority::{ActSurface, AgentGrantAct, AgentGrantActRef};
use crate::batch::{BatchOp, apply_ops};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{TimeRange, Vault};

use super::GitPushGrantStanding;
use crate::federation::grant::git_push_scope;
use crate::federation::{
    FederationGrant, FederationGrantKind, FederationGrantPreset, FederationGrantRole,
    GitPushBounds, decode_federation_grant_body, encode_federation_grant_body,
};

/// The holder is no live PERSON or agent definition.
const NOT_A_HOLDER: &str =
    "a git_push grant names a live person or a live agent definition of this vault";
/// A repo is not a live CODE anchor of a live PROJECT over a served store.
const NOT_A_SERVED_REPO: &str = "each git_push repo names a live CODE_ARTIFACT of the live PROJECT \
                                 named, whose stored repo is a Git store this origin serves";
/// The expiry has already passed.
const ALREADY_EXPIRED: &str = "a git_push grant's expires_at must be later than now";

/// What a mint wrote: the grant and the signed record of the owner's act.
#[derive(Debug, Clone)]
pub(crate) struct GitPushMintOutcome {
    pub(crate) standing: GitPushGrantStanding,
    pub(crate) act: AgentGrantActRef,
}

/// What a revoke did. A repeat changed nothing and signed no act.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GitPushRevokeOutcome {
    /// The holder the revoked grant named; `None` for a repeat.
    pub(crate) member: Option<EntityId>,
    /// The signed record of this revoke; `None` for a repeat.
    pub(crate) act: Option<AgentGrantActRef>,
}

impl Vault {
    /// The owner grants `member` raw git push to the `bounds` repos, until
    /// `expires_at` or, when `None`, until he revokes it. `owner` is
    /// revalidated as the vault's live owner in the writer, which signs his
    /// act (`surface` says where he said so, for its audit only) before it
    /// puts the grant.
    ///
    /// # Errors
    /// An owner refusal; `InvalidConfig` for an empty repo set, a holder
    /// that is no live person or agent definition, an expiry already
    /// passed, or a repo that is no served CODE anchor of its PROJECT;
    /// [`crate::error::RecordError::AuthorityRefused`] when this install
    /// cannot carry the owner's act.
    pub(crate) fn mint_git_push_grant(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        member: EntityId,
        bounds: GitPushBounds,
        expires_at: Option<u64>,
    ) -> Result<GitPushMintOutcome> {
        let serving = crate::origin::smart_http::origin_serving_root(self)?;
        self.with_write_txn_grouped(|txn| {
            let delegated_by = owner.revalidate_in_txn(self, txn)?;
            bounds
                .validate()
                .map_err(|reason| Error::InvalidConfig(reason.into()))?;
            if !self.git_push_grantee_stands_in_txn(txn, member)? {
                return Err(Error::InvalidConfig(NOT_A_HOLDER.into()));
            }
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            if expires_at.is_some_and(|expires_at| expires_at <= now) {
                return Err(Error::InvalidConfig(ALREADY_EXPIRED.into()));
            }
            for repo in &bounds.repos {
                let served = self
                    .git_push_anchor_in_txn(txn, repo)?
                    .is_some_and(|anchor| self.serves_store(&serving, &anchor));
                if !served {
                    return Err(Error::InvalidConfig(NOT_A_SERVED_REPO.into()));
                }
            }
            let grant = FederationGrant {
                authority_scope: git_push_scope(&bounds),
                scope: self.git_push_grant_scope_in_txn(txn)?,
                member_ref: member,
                role: FederationGrantRole::Delegate,
                preset: FederationGrantPreset::Delegate,
                expires_at,
                delegated_by: Some(delegated_by),
                guest: None,
                owner_agent: false,
                repo_bounds: None,
                kind: FederationGrantKind::GitPush,
                git_push_bounds: Some(bounds.clone()),
            };
            // Encoding validates: nothing is signed for a grant that cannot stand.
            let data = encode_federation_grant_body(&grant)?;
            let id = EntityId::now();
            let act = self.append_agent_grant_act_in_txn(
                txn,
                owner,
                surface,
                AgentGrantAct::Mint {
                    grant: id,
                    member,
                    scope: grant.authority_scope.clone(),
                    expires_at,
                    repo_bounds: None,
                    grant_kind: FederationGrantKind::GitPush,
                    git_push_bounds: Some(bounds.clone()),
                },
            )?;
            self.apply_grant_row_op_in_txn(
                txn,
                BatchOp::Put {
                    id,
                    entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                    occurred: TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    data,
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
            )?;
            Ok(GitPushMintOutcome {
                standing: GitPushGrantStanding {
                    id,
                    grant,
                    bounds,
                    delegated_by,
                    created_at: now,
                },
                act,
            })
        })
    }

    /// The owner revokes the GitPush grant `grant_ref`: his signed act,
    /// then the row's delete, in one writer, so no admission counts it
    /// again. A grant already revoked (its revoke act stands in the
    /// authority log) answers unchanged and signs nothing.
    ///
    /// # Errors
    /// An owner refusal; `EntityNotFound` for an id that names no live
    /// FEDERATION_GRANT and no revoked grant, or a live grant that is no
    /// GitPush grant; [`crate::error::RecordError::AuthorityRefused`] when
    /// this install cannot carry the owner's act.
    pub(crate) fn revoke_git_push_grant(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        grant_ref: EntityId,
    ) -> Result<GitPushRevokeOutcome> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let body = match live_entity_row_in_txn(&self.store, txn, &grant_ref)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                    body,
                } => body,
                LiveEntityRow::Live { .. } => return Err(Error::EntityNotFound),
                LiveEntityRow::DeletedShell | LiveEntityRow::Absent
                    if self.revoked_agent_grants_in_txn(txn)?.contains(&grant_ref) =>
                {
                    return Ok(GitPushRevokeOutcome {
                        member: None,
                        act: None,
                    });
                }
                LiveEntityRow::DeletedShell | LiveEntityRow::Absent => {
                    return Err(Error::EntityNotFound);
                }
            };
            let grant = decode_federation_grant_body(&body)
                .ok()
                .filter(|grant| grant.kind == FederationGrantKind::GitPush)
                .ok_or(Error::EntityNotFound)?;
            let act = self.append_agent_grant_act_in_txn(
                txn,
                owner,
                surface,
                AgentGrantAct::Revoke { grant: grant_ref },
            )?;
            // The withdrawal stays known here, in this writer (FIX-LIST 5107).
            crate::authority::mark_withdrawn_grant_in_txn(&self.store, txn, grant_ref)?;
            self.apply_grant_row_op_in_txn(txn, BatchOp::Delete { id: grant_ref })?;
            Ok(GitPushRevokeOutcome {
                member: Some(grant.member_ref),
                act: Some(act),
            })
        })
    }

    /// Applies one grant row op in the caller's writer, as the agent Grant
    /// mint persists its grant.
    fn apply_grant_row_op_in_txn(&self, txn: &mut heed::RwTxn<'_>, op: BatchOp) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![op],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    /// Whether the stored repo path `anchor` names a Git store under this
    /// origin's serving root: an imported working folder is no served
    /// repository, whatever it holds.
    fn serves_store(&self, serving: &Path, anchor: &str) -> bool {
        crate::git_wire::GitWire::new(self)
            .ok()
            .and_then(|wire| {
                let root = Path::new(anchor).canonicalize().ok()?;
                wire.canonical_common_dir(&root).ok()
            })
            .is_some_and(|common| common.starts_with(serving))
    }
}
