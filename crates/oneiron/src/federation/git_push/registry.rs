//! The GitPush grants as `vault.consent.registry` reviews them (FIX 6867,
//! G1-PUSH): one row per live grant, in the registry's existing row shape,
//! with its own one-tap revoke. With `include_revoked`, a revoked grant's
//! deleted row is joined back from the authority log (FIX 7136): its signed
//! mint carries what the row held, and its revoke record, the owner's signed
//! revoke act or the host's signed withdrawal a membership change logged
//! (FIX 7135), says it no longer stands. The registry adds no table.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::authority::{
    AgentGrantChange, AuthorityOp, authority_entry_hash, decode_authority_log_entry_body,
};
use crate::consent::{ConsentDomain, ConsentGrantStatus, ConsentRegistryRow, ConsentRevokeAction};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{FederationGrantKind, GitPushBounds, Scope};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;

use super::{GIT_PUSH_REVOKE_COMMAND, GitPushGrantStanding};

/// The class a GitPush grant's registry row shows.
const GIT_PUSH_GRANT_CLASS: &str = "git_push";

/// One GitPush grant as its registry row reads it: a live row's fields, or a
/// revoked grant's as its signed mint carried them.
struct GitPushRegistryGrant {
    id: EntityId,
    member: EntityId,
    scope: Scope,
    bounds: GitPushBounds,
    /// The owner who granted it.
    delegated_by: EntityId,
    expires_at: Option<u64>,
    /// Recording time of the mint (Unix seconds).
    created_at: u64,
}

impl GitPushRegistryGrant {
    fn live(standing: &GitPushGrantStanding) -> Self {
        Self {
            id: standing.id,
            member: standing.grant.member_ref,
            scope: standing.grant.authority_scope.clone(),
            bounds: standing.bounds.clone(),
            delegated_by: standing.delegated_by,
            expires_at: standing.grant.expires_at,
            created_at: standing.created_at,
        }
    }
}

impl Vault {
    /// The GitPush grants as the registry reviews them: standing ones, or
    /// with `include_revoked` every live one (an expired grant shows as
    /// revoked) and every revoked one the authority log names, as revoked.
    pub(crate) fn git_push_registry_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        include_revoked: bool,
    ) -> Result<Vec<ConsentRegistryRow>> {
        let now = self.instant_in_txn(txn)?.secs();
        let live = self.git_push_grants_in_txn(txn)?;
        let mut rows: Vec<ConsentRegistryRow> = live
            .iter()
            .filter(|standing| include_revoked || standing.stands_at(now))
            .map(|standing| {
                let status = if standing.stands_at(now) {
                    ConsentGrantStatus::Active
                } else {
                    ConsentGrantStatus::Revoked
                };
                registry_row(&GitPushRegistryGrant::live(standing), status)
            })
            .collect();
        if include_revoked {
            let shown: BTreeSet<EntityId> = live.iter().map(|standing| standing.id).collect();
            rows.extend(
                self.revoked_git_push_grants_in_txn(txn)?
                    .iter()
                    .filter(|grant| !shown.contains(&grant.id))
                    .map(|grant| registry_row(grant, ConsentGrantStatus::Revoked)),
            );
        }
        Ok(rows)
    }

    /// The GitPush grants a revoke withdrew, in id order, each as its signed
    /// mint carried it: every GitPush mint act the authority fold counted
    /// whose grant a counted revoke names, the owner's own revoke act or the
    /// host's signed withdrawal (`SlipGrantRevoke`) a membership change
    /// logged. An entry whose body this vault no longer holds (an adopted
    /// checkpoint covers it) names none.
    fn revoked_git_push_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<GitPushRegistryGrant>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let mut mints = BTreeMap::new();
        let mut revoked = BTreeSet::new();
        for id in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)?
        {
            let id = id?;
            let Some(row) = self.store.port_entity_record(txn, &id)? else {
                continue;
            };
            if row.entity_type != ENTITY_TYPE_AUTHORITY_LOG || row.body.is_empty() {
                continue;
            }
            let Ok(entry) = decode_authority_log_entry_body(&row.body) else {
                continue;
            };
            let named = match &entry.op {
                AuthorityOp::AgentGrantAct(record) => match &record.change {
                    AgentGrantChange::Mint {
                        member,
                        scope,
                        expires_at,
                        grant_kind: FederationGrantKind::GitPush,
                        git_push_bounds: Some(bounds),
                        ..
                    } => Some((
                        record.grant,
                        Some(GitPushRegistryGrant {
                            id: record.grant,
                            member: *member,
                            scope: scope.clone(),
                            bounds: bounds.clone(),
                            delegated_by: record.act.owner,
                            expires_at: *expires_at,
                            created_at: row.learned_at,
                        }),
                    )),
                    AgentGrantChange::Mint { .. } => None,
                    AgentGrantChange::Revoke => Some((record.grant, None)),
                },
                AuthorityOp::SlipGrantRevoke { grant_ref } => Some((*grant_ref, None)),
                _ => None,
            };
            let Some((grant, mint)) = named else {
                continue;
            };
            if !fold.valid_entries.contains(&authority_entry_hash(&entry)?) {
                continue;
            }
            match mint {
                Some(mint) => {
                    mints.insert(grant, mint);
                }
                None => {
                    revoked.insert(grant);
                }
            }
        }
        Ok(mints
            .into_values()
            .filter(|mint| revoked.contains(&mint.id))
            .collect())
    }
}

/// One GitPush grant's row: the holder, each repo and its PROJECT, the
/// owner who granted it and its expiry, with the GitPush revoke door as its
/// one-tap revoke, never the consent grant revoke.
fn registry_row(grant: &GitPushRegistryGrant, status: ConsentGrantStatus) -> ConsentRegistryRow {
    let grant_ref = grant.id.to_hex();
    let mut selectors: Vec<String> = grant
        .bounds
        .repos
        .iter()
        .map(|repo| {
            format!(
                "repo:{}@project:{}",
                repo.repo.to_hex(),
                repo.project.to_hex()
            )
        })
        .collect();
    selectors.push(format!("delegated_by:{}", grant.delegated_by.to_hex()));
    selectors.push(grant.expires_at.map_or_else(
        || "expiry:durable".to_owned(),
        |expires_at| format!("expiry:{expires_at}"),
    ));
    ConsentRegistryRow {
        domain: ConsentDomain::Action,
        subject: format!("{}/{GIT_PUSH_GRANT_CLASS}", grant.member.to_hex()),
        class: GIT_PUSH_GRANT_CLASS.to_owned(),
        selectors,
        scope: Some(grant.scope.clone()),
        status,
        created_at: grant.created_at,
        revoke_action: ConsentRevokeAction {
            command: GIT_PUSH_REVOKE_COMMAND.to_owned(),
            grant_ref: grant_ref.clone(),
        },
        grant_ref,
        bypass: None,
        delegation: None,
        agent_grant: None,
    }
}
