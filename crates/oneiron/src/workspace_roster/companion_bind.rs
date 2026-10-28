//! The first binding of a member's companion to her principal, and the one
//! check a brought companion passes before any binding names her.
//!
//! A brought companion is bound at the onboarding's Started step, in the
//! transaction that reserves the member's slot, and associated with her
//! work facet later, at the companion step. Both writers run the same
//! check in their own transaction, so no binding stands for a companion
//! her member never brought.

use super::*;
use crate::error::GateError;

/// An unfinished onboarding owns its member slot too. A second id must not
/// create another companion while the first journal is waiting for custody.
/// A brought companion is checked before her binding is written
/// (`authorized_at` is the authorization clock committed for that check); a
/// work companion is born at her own step.
pub(super) fn reserve_member_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    intent: &MemberOnboardingIntent,
    digest: &[u8; 32],
    authorized_at: Option<u64>,
) -> Result<()> {
    let key = MemberIntentKey {
        workspace_ref: intent.workspace.workspace_ref.clone(),
        person_ref: intent.person_ref,
    };
    if let Some(prior) = MEMBER_INTENT.get(&vault.store, txn, &key)?
        && prior != *digest
    {
        return Err(invalid(
            "member already has a different workspace onboarding",
        ));
    }
    // Brought or born, one companion PERSON belongs to one principal.
    let companion = intent.companion.person_ref();
    if let Some(prior) = COMPANION_PRINCIPAL.get(&vault.store, txn, &companion)?
        && prior != intent.person_ref
    {
        return Err(invalid(
            "companion person already belongs to a different principal",
        ));
    }
    if intent.companion.is_bring() {
        let authorized_at = authorized_at.ok_or(Error::InvariantViolation(
            "a brought companion's binding needs its authorization time",
        ))?;
        // A workspace no onboarding has established yet has no policy to
        // read; the companion step reads it again once it does.
        let policy = PRESET
            .get(&vault.store, txn, &intent.workspace.workspace_ref)?
            .map(|row| row.work_companion);
        verify_brought_companion_in_txn(vault, txn, intent, policy, authorized_at)?;
    }
    COMPANION_PRINCIPAL.put(&vault.store, txn, &companion, &intent.person_ref)?;
    MEMBER_INTENT.put(&vault.store, txn, &key, digest)?;
    Ok(())
}

/// A brought companion, as her member brings her: a model-backed PERSON,
/// admitted by the workspace's `work_companion` policy when it has one,
/// brought on her member's own live authenticated consent, her actor
/// anchored to her PERSON, and her member's companion-profile grant over
/// her, person-wide or at the work facet she wears here, already standing.
/// Each is read in `txn`, never taken from the caller.
pub(super) fn verify_brought_companion_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: &MemberOnboardingIntent,
    policy: Option<WorkCompanionPolicy>,
    authorized_at: u64,
) -> Result<()> {
    let CompanionChoice::Bring {
        person,
        actor,
        work_facet,
        proof,
    } = &intent.companion
    else {
        return Err(invalid("only a brought companion is checked here"));
    };
    let now = vault.store.clock.now_recorded_at();
    if crate::subject_model::person_substrate_in_txn(vault, txn, person, now)?
        != Some(crate::subject_model::PersonSubstrate::Model)
    {
        return Err(invalid("a brought companion must be a model-backed PERSON"));
    }
    if policy.is_some_and(|policy| !policy.admits(&intent.companion)) {
        return Err(Error::Record(
            crate::error::RecordError::WorkCompanionRequired,
        ));
    }
    if proof.revalidate_person_in_txn(vault, txn)? != intent.person_ref {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            "a brought companion needs her member's own authenticated consent",
        )));
    }
    let anchor = crate::subject_model::actor_subject_anchor_in_txn(vault, txn, actor, now)?;
    if anchor.is_none_or(|anchor| {
        anchor.subject_ref != *person
            || anchor.subject_kind != crate::subject_model::SubjectKind::Person
    }) {
        return Err(invalid(
            "a brought companion's actor must be anchored to her PERSON",
        ));
    }
    if crate::gate::companion_profile_access_grant(
        &vault.store,
        txn,
        &intent.person_ref,
        person,
        Some(work_facet),
        authorized_at,
    )?
    .is_none()
    {
        return Err(invalid(
            "a brought companion must already be her member's companion",
        ));
    }
    Ok(())
}
