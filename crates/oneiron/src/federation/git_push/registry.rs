//! The GitPush grants as `vault.consent.registry` reviews them (FIX 6867,
//! G1-PUSH): one row per live grant, in the registry's existing row shape,
//! with its own one-tap revoke. The signed mint and revoke acts stay the
//! authority audit's; the registry adds no table.

use crate::Vault;
use crate::consent::{ConsentDomain, ConsentGrantStatus, ConsentRegistryRow, ConsentRevokeAction};
use crate::error::Result;

use super::{GIT_PUSH_REVOKE_COMMAND, GitPushGrantStanding};

/// The class a GitPush grant's registry row shows.
const GIT_PUSH_GRANT_CLASS: &str = "git_push";

impl Vault {
    /// The GitPush grants as the registry reviews them: standing ones, or
    /// every live one with `include_revoked` (an expired grant shows as
    /// revoked).
    pub(crate) fn git_push_registry_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        include_revoked: bool,
    ) -> Result<Vec<ConsentRegistryRow>> {
        let now = self.instant_in_txn(txn)?.secs();
        Ok(self
            .git_push_grants_in_txn(txn)?
            .iter()
            .filter(|standing| include_revoked || standing.stands_at(now))
            .map(|standing| registry_row(standing, now))
            .collect())
    }
}

/// One GitPush grant's row: the holder, each repo and its PROJECT, the
/// owner who granted it and its expiry, with the GitPush revoke door as its
/// one-tap revoke, never the consent grant revoke.
fn registry_row(standing: &GitPushGrantStanding, now: u64) -> ConsentRegistryRow {
    let grant = &standing.grant;
    let grant_ref = standing.id.to_hex();
    let mut selectors: Vec<String> = standing
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
    selectors.push(format!("delegated_by:{}", standing.delegated_by.to_hex()));
    selectors.push(grant.expires_at.map_or_else(
        || "expiry:durable".to_owned(),
        |expires_at| format!("expiry:{expires_at}"),
    ));
    ConsentRegistryRow {
        domain: ConsentDomain::Action,
        subject: format!("{}/{GIT_PUSH_GRANT_CLASS}", grant.member_ref.to_hex()),
        class: GIT_PUSH_GRANT_CLASS.to_owned(),
        selectors,
        scope: Some(grant.authority_scope.clone()),
        status: if standing.stands_at(now) {
            ConsentGrantStatus::Active
        } else {
            ConsentGrantStatus::Revoked
        },
        created_at: standing.created_at,
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
