//! The first binding of a member's companion to her principal, and the one
//! check a brought companion passes before any binding names her.
//!
//! A brought companion is bound at the onboarding's Started step, in the
//! transaction that reserves the member's slot, and associated with her
//! work facet later, at the companion step. Both writers run the same
//! check in their own transaction, so no binding stands for a companion
//! her member never brought. The reserve also keeps a member's companion
//! from running an org she belongs to, unless she is the sole owner
//! (COMPANION-LEADER, #companion-split).

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
    require_companion_split_in_txn(vault, txn, intent)
}

/// The refusal [`require_companion_split_in_txn`] returns.
const COMPANION_SPLIT_REFUSAL: &str = "one agent is not both a person's companion and the companion of an org she belongs to; only a sole owner binds them both";

/// COMPANION-LEADER (the owner, 11 Nov; ONEIRON-ARCH-0063 #companion-split):
/// "One agent never serves as both a person's companion and their company's
/// companion by default, because their loyalties can diverge. A sole owner
/// may bind them on purpose."
///
/// A person's companion is the PERSON [`COMPANION_PRINCIPAL`] names her for.
/// Her company's companion is the house of a workspace she belongs to, known
/// by its own model PERSON anchor. The check reads after this reserve's own
/// two rows, so it judges the roster as it would stand: the house of the
/// workspace she joins, and the house of each stored workspace she is
/// already in. Those two rows are written only here and a preset never
/// changes its house, so no other write can make a split stand. The vault's
/// one live owner joining is the sole owner's own act, on purpose, and
/// passes.
fn require_companion_split_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: &MemberOnboardingIntent,
) -> Result<()> {
    let member = intent.person_ref;
    let mut houses = vec![intent.workspace.house_actor_ref];
    for (workspace_ref, row) in PRESET.scan(&vault.store, txn)? {
        let key = MemberIntentKey {
            workspace_ref,
            person_ref: member,
        };
        if MEMBER_INTENT.get(&vault.store, txn, &key)?.is_some() {
            houses.push(row.preset.house_actor_ref);
        }
    }
    let now = vault.store.clock.now_recorded_at();
    for house in houses {
        let Some(anchor) =
            crate::subject_model::actor_subject_anchor_in_txn(vault, txn, &house, now)?
        else {
            continue;
        };
        if anchor.subject_kind != crate::write_envelope::subject_record::SubjectKind::Person
            || COMPANION_PRINCIPAL.get(&vault.store, txn, &anchor.subject_ref)? != Some(member)
        {
            continue;
        }
        if crate::policy_model::owners_in_txn(vault, txn)?.as_slice() == [member] {
            return Ok(());
        }
        return Err(invalid(COMPANION_SPLIT_REFUSAL));
    }
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
        != Some(crate::write_envelope::subject_record::PersonSubstrate::Model)
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
            || anchor.subject_kind != crate::write_envelope::subject_record::SubjectKind::Person
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
