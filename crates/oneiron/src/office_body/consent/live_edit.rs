//! Live DOCX/XLSX edit admission and grant lifecycle (FIX 596).

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::super::invalid;
use super::{OFFICE_BODY_EDIT_CLASS, issued_grants};
use crate::Vault;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, BoundClass, BoundEnvelope,
    ComposedEffect, ConsentDecision, EffectFacts, GrantBound, StandingConsentGrant,
    evaluate_consent, load_active_standing_grants, revoke_standing_grant_in_txn,
    standing_grant_row_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The operation a live DOCX/XLSX edit receipts as (FIX 596): the grant class
/// and target stay the office edit scope, so existing grants keep covering,
/// while the use receipt names the live edit rather than a merge.
const OFFICE_LIVE_EDIT_OPERATION: &str = "office.body.live_edit";
/// The scope of office edits to `artifact`: what a standing grant names to
/// land a fork there, and whose holders a waiting member is asked of.
pub(crate) fn office_scope(artifact: &EntityId) -> Result<(ActionClass, ActionEnvelope)> {
    let target = format!("entity:{}", artifact.to_hex());
    Ok((
        ActionClass::new(OFFICE_BODY_EDIT_CLASS)?,
        ActionEnvelope::new([target.clone()])?.with_target(target)?,
    ))
}

pub(crate) fn office_effect_for(
    operation: &str,
    artifact: &EntityId,
    subject: &EntityId,
) -> Result<ComposedEffect> {
    ComposedEffect::new(EffectFacts::new(operation)?)
        .with_action_requirement(office_bound(artifact, subject)?)
}

pub(crate) fn office_bound(artifact: &EntityId, opener: &EntityId) -> Result<GrantBound> {
    let (class, envelope) = office_scope(artifact)?;
    GrantBound::action(ActorBound::new(opener.to_hex())?, class, envelope)
}

/// A live DOCX/XLSX edit by `editor` on `artifact` as the evaluator reads it
/// (FIX 596): the same class-agnostic subject and scope as a merge, receipts
/// under the live-edit operation.
pub(crate) fn live_edit_effect(artifact: &EntityId, editor: &EntityId) -> Result<ComposedEffect> {
    office_effect_for(OFFICE_LIVE_EDIT_OPERATION, artifact, editor)
}

/// The ref of a standing grant that covers a live edit by `editor` on
/// `artifact` (FIX 596), minted by someone outside `excluded`; `None` when
/// none does. The candidate mirrors the merge path exactly, so only
/// class-agnostic `entity.office.edit` grants cover it.
pub(crate) fn covering_live_grant(
    vault: &Vault,
    txn: &RoTxn<'_>,
    grants: &[(StandingConsentGrant, Option<EntityId>)],
    excluded: &BTreeSet<EntityId>,
    artifact: &EntityId,
    editor: &EntityId,
) -> Result<Option<String>> {
    // Live coverage only (FIX 596 review): the issuer must still be a live
    // vault owner. An erased (or otherwise non-live) issuer's grant no
    // longer covers, even though the row is still Active.
    let mut live: Vec<(StandingConsentGrant, Option<EntityId>)> = Vec::new();
    for (grant, issuer) in grants {
        if issuer.is_some_and(|issuer| {
            crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &issuer).unwrap_or(false)
        }) {
            live.push((grant.clone(), *issuer));
        }
    }
    super::covering_grant_for(
        OFFICE_LIVE_EDIT_OPERATION,
        &live,
        excluded,
        artifact,
        editor,
    )
}

/// Whether a live DOCX/XLSX edit by `editor` on `artifact` is admitted
/// (FIX 596): a pure check, recording nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveEditAdmission {
    /// A live vault owner edits freely.
    Owner,
    /// A standing `entity.office.edit` grant covers the editor; its ref, so
    /// the committing writer records its use beside the edit.
    Grant { grant_ref: String },
    /// No owner bypass and no covering grant: the verb raises the owner ask.
    NeedsAsk,
}

/// [`LiveEditAdmission`] in the caller's transaction.
pub(crate) fn live_edit_admission_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    editor: &EntityId,
) -> Result<LiveEditAdmission> {
    if crate::policy_model::is_live_vault_owner_in_txn(vault, txn, editor)? {
        return Ok(LiveEditAdmission::Owner);
    }
    let grants = issued_grants(vault, txn)?;
    // No self-answer: a grant the editor minted never covers their own edit.
    // Vacuous today (only owners mint action grants, and owners bypass), and
    // load-bearing if a non-owner mint path ever appears.
    let excluded = BTreeSet::from([*editor]);
    if let Some(grant_ref) = covering_live_grant(vault, txn, &grants, &excluded, artifact, editor)?
    {
        return Ok(LiveEditAdmission::Grant { grant_ref });
    }
    Ok(LiveEditAdmission::NeedsAsk)
}

/// Mints the standing `entity.office.edit` grant for `editor` on `artifact`
/// as `owner`'s own act answering the live-edit ask (FIX 596): the same
/// class-agnostic subject the live gate checks, revocable like any grant.
pub(crate) fn mint_live_edit_grant_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    owner: &AuthenticatedOwner,
    artifact: &EntityId,
    editor: &EntityId,
) -> Result<crate::consent::ConsentReceipt> {
    vault.create_standing_grant_in_txn(wtxn, owner, office_bound(artifact, editor)?)
}

/// Whether an active grant already carries exactly the bound a live-edit
/// ACCEPT would mint for `editor` on `artifact` (FIX 596, C7): the resolve
/// skips the re-mint, so repeated ACCEPTs never churn the row. Only an
/// issuer outside the editor's lineage counts: a self-minted identical row
/// would not cover the edit and must not wedge the ask.
pub(crate) fn identical_live_edit_grant_active_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    editor: &EntityId,
) -> Result<bool> {
    let bound = office_bound(artifact, editor)?.digest();
    for (grant, issuer) in issued_grants(vault, txn)? {
        // Same live-issuer rule as coverage (FIX 596 review): an erased
        // issuer's identical row must not wedge the ask into a skip.
        let live = issuer.is_some_and(|issuer| {
            crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &issuer).unwrap_or(false)
        });
        if live && issuer.is_some_and(|issuer| issuer != *editor) && grant.bound().digest() == bound
        {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Vault {
    /// Whether a live DOCX/XLSX edit by `editor` on `artifact` is admitted
    /// (FIX 596), for the verb's post-`InvalidConfig` disambiguation: the
    /// same check the committing writer runs, recording nothing.
    pub(crate) fn live_edit_admission(
        &self,
        artifact: &EntityId,
        editor: &EntityId,
    ) -> Result<LiveEditAdmission> {
        let txn = self.store.env.read_txn()?;
        live_edit_admission_in_txn(self, &txn, artifact, editor)
    }
}

/// Admits a live DOCX/XLSX edit by `editor` on `artifact` in the committing
/// writer (FIX 596): the owner proceeds, a covering grant's use is recorded
/// beside the edit, and without either the writer fails fast so the verb
/// raises the owner ask. A grant revoked between the verb's read and this
/// commit fails the commit closed.
pub(crate) fn admit_live_edit_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    editor: &EntityId,
) -> Result<()> {
    match live_edit_admission_in_txn(vault, wtxn, artifact, editor)? {
        LiveEditAdmission::Owner => Ok(()),
        LiveEditAdmission::Grant { grant_ref } => {
            let effect = live_edit_effect(artifact, editor)?;
            vault.record_standing_grant_use_in_txn(wtxn, &grant_ref, effect.digest())?;
            Ok(())
        }
        LiveEditAdmission::NeedsAsk => Err(invalid(&format!(
            "live edits by {} on artifact {} need a standing entity.office.edit grant; the owner is asked",
            editor.to_hex(),
            artifact.to_hex(),
        ))),
    }
}

/// Retires office-edit authority naming an erased issuer, editor or exact
/// artifact target, in the erase's own transaction. A wider target envelope
/// remains available for its other artifacts.
pub(in crate::office_body) fn revoke_office_edit_grants_naming_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let class = BoundClass::Action(ActionClass::new(OFFICE_BODY_EDIT_CLASS)?);
    let actor_ref = entity.to_hex();
    let target = format!("entity:{actor_ref}");
    for grant in load_active_standing_grants(store, wtxn)? {
        let bound = grant.bound();
        if bound.class() != &class {
            continue;
        }
        let editor = bound
            .actor()
            .is_some_and(|actor| actor.actor_ref() == actor_ref.as_str());
        let artifact = match bound.envelope() {
            BoundEnvelope::Action(envelope) => {
                envelope.target() == Some(target.as_str())
                    || (envelope.target().is_none()
                        && envelope.selectors() == std::slice::from_ref(&target))
            }
            BoundEnvelope::Disclosure(_) => false,
        };
        let grant_ref = bound.digest().to_hex();
        let issuer = standing_grant_row_in_txn(store, wtxn, &grant_ref)?
            .is_some_and(|row| row.owner_stamp.actor == *entity);
        if editor || artifact || issuer {
            revoke_standing_grant_in_txn(store, wtxn, &grant_ref)?;
        }
    }
    Ok(())
}
