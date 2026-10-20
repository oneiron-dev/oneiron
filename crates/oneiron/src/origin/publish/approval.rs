//! Whether an exact publish request's approval still stands at its dispatch
//! (FIX 6866; CALLS "FIX 6866 approval"): an owner's approval while that
//! person is still a live owner, a Grant's while the very same Grant still
//! admits its approver over the branch and every reviewed path, at a repo
//! anchor verified to be this served repository. Anything else refuses the
//! dispatch with `authority_changed`; a fresh request is approved again.

use std::collections::BTreeSet;

use super::PublishScope;
use super::authority::anchor_serves;
use super::types::{OriginPublishAuthority, OriginPublishForce, OriginPublishRequestView};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::error::Result;

impl Vault {
    /// The anchor the approver's Grant reads, verified against this served
    /// repository; `None` when the approval stands on the owner, or on a
    /// Grant that admits no more.
    pub(super) fn approval_anchor(
        &self,
        scope: &PublishScope<'_>,
        view: &OriginPublishRequestView,
    ) -> Result<Option<RepoRef>> {
        let (Some(approved), Some(code_repo)) = (&view.approved, view.code_repo) else {
            return Ok(None);
        };
        let (OriginPublishAuthority::Grant { .. }, Some(actor)) =
            (&approved.authority, approved.actor)
        else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        let admitted =
            self.admit_repo_member_in_txn(&txn, actor, approved.class.into(), code_repo)?;
        drop(txn);
        Ok(admitted
            .ok()
            .map(|membership| membership.repo_ref)
            .filter(|anchor| anchor_serves(scope, anchor)))
    }

    /// Whether the request's approval still stands in `txn`: its owner is
    /// still a live owner, or the same Grant still admits its approver over
    /// every reviewed path at the verified `anchor`.
    pub(super) fn approval_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        view: &OriginPublishRequestView,
        anchor: Option<&RepoRef>,
        paths: &BTreeSet<String>,
    ) -> Result<bool> {
        let Some(approved) = &view.approved else {
            return Ok(false);
        };
        let Some(actor) = approved.actor else {
            return Ok(false);
        };
        match &approved.authority {
            OriginPublishAuthority::Owner => {
                Ok(crate::policy_model::owners_in_txn(self, txn)?.contains(&actor))
            }
            OriginPublishAuthority::Grant { grant } => {
                let (Some(code_repo), Some(anchor)) = (view.code_repo, anchor) else {
                    return Ok(false);
                };
                let admitted = self.admit_origin_publish_grant_in_txn(
                    txn,
                    actor,
                    approved.class.into(),
                    code_repo,
                    &view.ref_name,
                    paths.clone(),
                    view.force == OriginPublishForce::Rewrite,
                )?;
                Ok(matches!(admitted, Ok(standing)
                    if standing.grant == *grant && &standing.repo_ref == anchor))
            }
        }
    }
}
