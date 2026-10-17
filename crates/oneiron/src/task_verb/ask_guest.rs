//! Ask-scoped guest authority: reuse a person's owner-stamped bounds.
use super::{TaskAskGuest, TaskAskTarget};
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, BoundEnvelope, BoundSubject,
    DisclosureClass, DisclosureEnvelope, GrantBound, StandingConsentGrant,
};
use crate::error::Result;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

fn invalid() -> crate::Error {
    super::ask_record::invalid()
}

/// A guest's consent counts only as the vault's owner recorded it: a grant a
/// live owner of this vault stamped, read in the ask's own transaction. A
/// native host's proof shows a live person, not their consent, so a grant the
/// guest stamped is none (F18 tier flip).
fn owner_recorded(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &crate::consent::ConsentGrantRow,
) -> Result<bool> {
    crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &row.owner_stamp.actor)
}

/// An answer delegation names its guest: the grant's target is the guest,
/// never unset (an unset target would cover every guest of the companion).
fn names_guest(bound: &GrantBound, person: EntityId) -> bool {
    matches!(
        bound.envelope(),
        BoundEnvelope::Action(envelope) if envelope.target() == Some(person.to_hex().as_str())
    )
}

fn not_recorded() -> crate::Error {
    crate::Error::Gate(crate::error::GateError::ConsentGuestNotRecorded(
        "the owner has not recorded this guest's consent",
    ))
}

/// A guest is never allowed to expand the person's standing disclosure. The
/// bound and its owner stamp are checked at admission AND at answer intake.
pub(super) fn check_disclosure(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    asker: EntityId,
    guest: &TaskAskGuest,
    spec: &super::TaskAskSpec,
) -> Result<BTreeSet<EntityId>> {
    let question = &spec.what;
    let class = question.class_key.as_deref().ok_or_else(invalid)?;
    let refs: BTreeSet<_> = std::iter::once(question.reference.entity_ref())
        .chain(question.context_refs.iter().map(|r| r.entity_ref()))
        .collect();
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let ask_policy = policy.ask_operational_policy().ok_or_else(invalid)?;
    let cap = ask_policy
        .guest_limit_for(
            person,
            spec.class.as_ref().and_then(|row| row.guest_fact_limit),
        )
        .ok_or_else(invalid)?;
    if refs.len() > cap {
        return Err(invalid());
    }
    if refs.is_empty() || guest.companion_ref == person || guest.companion_ref == asker {
        return Err(invalid());
    }
    let row = vault
        .consent_grant_in_txn(txn, &guest.disclosure_grant_ref)?
        .ok_or_else(not_recorded)?;
    if !owner_recorded(vault, txn, &row)? {
        return Err(not_recorded());
    }
    // A row that is no usable disclosure for this ask refuses the same way,
    // so the refusal tells nothing about rows the caller was not given.
    let StandingConsentGrant::Disclosure(parent) = &row.grant else {
        return Err(not_recorded());
    };
    // The owner records the guest's consent: its audience names the guest
    // beside the asker.
    let required = GrantBound::disclosure(
        AudienceBound::new([asker.to_hex(), person.to_hex()])?,
        DisclosureClass::new(class)?,
        DisclosureEnvelope::new(refs.iter().map(EntityId::to_hex))?,
    )?;
    if !row.is_active()
        || row.grant_ref() != guest.disclosure_grant_ref
        || !parent.bound().contains(&required)
    {
        return Err(not_recorded());
    }
    for reference in &refs {
        crate::llm::decision::questions::validate_task_answer_unit(
            vault,
            txn,
            asker,
            guest.companion_ref,
            *reference,
        )?;
    }
    Ok(refs)
}

/// The answer-class delegation is a separate ACTION grant a live owner
/// stamped. A disclosure grant, guest grant or caller-supplied boolean cannot
/// make a hint final. The target is the exact person; the class identifies
/// the ask class.
pub(super) fn delegated_class(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    companion: EntityId,
    class: Option<&str>,
) -> Result<Option<String>> {
    let Some(class) = class else {
        return Ok(None);
    };
    let required = GrantBound::action(
        ActorBound::new(companion.to_hex())?.with_actor_class("agent")?,
        ActionClass::new(format!("ask.answer.{class}"))?,
        ActionEnvelope::new(["answer".to_owned()])?.with_target(person.to_hex())?,
    )?;
    for grant in vault.active_standing_consent_grants_in_txn(txn)? {
        let StandingConsentGrant::Action(action) = &grant else {
            continue;
        };
        if !action.bound().contains(&required) || !names_guest(action.bound(), person) {
            continue;
        }
        if !matches!(action.bound().subject(), BoundSubject::Actor(_)) {
            continue;
        }
        let reference = grant.bound().digest().to_hex();
        let Some(row) = vault.consent_grant_in_txn(txn, &reference)? else {
            continue;
        };
        if row.is_active() && owner_recorded(vault, txn, &row)? {
            return Ok(Some(reference));
        }
    }
    Ok(None)
}

/// Re-check the stored delegation proof without treating a later revocation
/// as retroactive alteration of an answer already admitted before cutoff.
pub(super) fn check_delegation_record(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    companion: EntityId,
    class: Option<&str>,
    reference: &str,
) -> Result<bool> {
    let Some(class) = class else {
        return Ok(false);
    };
    let Some(row) = vault.consent_grant_in_txn(txn, reference)? else {
        return Ok(false);
    };
    let StandingConsentGrant::Action(action) = &row.grant else {
        return Ok(false);
    };
    let required = GrantBound::action(
        ActorBound::new(companion.to_hex())?.with_actor_class("agent")?,
        ActionClass::new(format!("ask.answer.{class}"))?,
        ActionEnvelope::new(["answer".to_owned()])?.with_target(person.to_hex())?,
    )?;
    // Admission took this grant only as a live owner recorded it
    // (`delegated_class`). Like a later revocation, a later change of owners
    // does not reach back into an answer already admitted.
    Ok(row.grant_ref() == reference
        && action.bound().contains(&required)
        && names_guest(action.bound(), person))
}

/// Admit only the exact question facts inside a live owner-stamped bound, then
/// materialize a disjoint guest grant in the same transaction as the ask.
pub(super) fn mint_guest_grants(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group_ref: EntityId,
    asker: EntityId,
    effective: &super::TaskAskSpec,
    now: u64,
) -> Result<std::collections::BTreeMap<EntityId, EntityId>> {
    let mut guest_grants = std::collections::BTreeMap::new();
    if let Some(TaskAskTarget::Guests(guests)) = &effective.who {
        for (person, guest) in guests {
            let refs = check_disclosure(vault, txn, *person, asker, guest, effective)?;
            let grant = crate::federation::FederationGrant::ask_guest(
                group_ref,
                guest.companion_ref,
                *person,
                asker,
                refs,
            )?;
            let grant_id = crate::EntityId::derive(
                crate::entity_id::derived_domains::TASK_ASK_GUEST_GRANT,
                &[group_ref.as_bytes(), person.as_bytes()],
            )?;
            let encoded = crate::federation::encode_federation_grant_body(&grant)?;
            if let Some(raw) = vault.get_raw_in(txn, &grant_id)? {
                if raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) != Some(encoded.as_slice()) {
                    return Err(invalid());
                }
            } else {
                // FEDERATION_GRANT is an engine-authored maintenance kind.
                // This known guest constructor and live parent-bound check
                // are the only minting path; raw public puts stay denied.
                crate::batch::apply_ops(
                    &vault.store,
                    &vault.config,
                    &vault.analyzer,
                    txn,
                    vec![crate::batch::BatchOp::Put {
                        id: grant_id,
                        entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                        occurred: crate::temporal::TimeRange {
                            start: now,
                            end: now,
                        },
                        learned_at: now,
                        data: encoded,
                        allow_maintenance: true,
                        allow_reserved_predicate: false,
                        hub_sync_imported: false,
                    }],
                    vault
                        .text_index_trusted
                        .load(std::sync::atomic::Ordering::Acquire),
                    false,
                    true,
                )?;
            }
            guest_grants.insert(*person, grant_id);
        }
    }
    Ok(guest_grants)
}

/// The FEDERATION_GRANT the ask `group_ref` minted for guest `person`, as its
/// group record holds it (OF-220): none when the ask recorded no such guest.
pub(crate) fn ask_guest_grant_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_ref: EntityId,
    person: EntityId,
) -> Result<Option<EntityId>> {
    Ok(super::ask_record::read_group(vault, txn, group_ref)?
        .and_then(|group| group.guest_grants.get(&person).copied()))
}

pub(super) fn check_companion_answer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &super::ask_record::AskGroup,
    actor: EntityId,
    word: &super::TaskAskWord,
    now: u64,
) -> Result<()> {
    validate_companion_fact(vault, txn, id, group, actor, word)?;
    let person = word.companion_for.ok_or_else(invalid)?;
    let grant_id = group.guest_grants.get(&person).ok_or_else(invalid)?;
    let raw = vault.get_raw_in(txn, grant_id)?.ok_or_else(invalid)?;
    // A deleted guest grant confers nothing, even while its body is stored.
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, grant_id)?.is_live() {
        return Err(invalid());
    }
    let grant = crate::federation::decode_federation_grant_body(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    if !grant.confers_at(now) {
        return Err(invalid());
    }
    let super::TaskAskTarget::Guests(guests) = group.effective.who.as_ref().ok_or_else(invalid)?
    else {
        return Err(invalid());
    };
    let guest = guests.get(&person).ok_or_else(invalid)?;
    check_disclosure(
        vault,
        txn,
        person,
        super::ask_record::entity(&group.owner)?,
        guest,
        &group.effective,
    )?;
    Ok(())
}

/// Replayed companion evidence must still be tied to the exact stored guest
/// allowlist. Revoking the parent later does not rewrite admitted evidence.
pub(super) fn validate_companion_fact(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &super::ask_record::AskGroup,
    actor: EntityId,
    word: &super::TaskAskWord,
) -> Result<()> {
    let person = word.companion_for.ok_or_else(invalid)?;
    let grant_id = group.guest_grants.get(&person).ok_or_else(invalid)?;
    let raw = vault.get_raw_in(txn, grant_id)?.ok_or_else(invalid)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT
        || !crate::vault::live_entity_row_in_txn(&vault.store, txn, grant_id)?.is_live()
    {
        return Err(invalid());
    }
    let grant = crate::federation::decode_federation_grant_body(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    let asker = super::ask_record::entity(&group.owner)?;
    if !grant.allows_ask_fact(
        id,
        actor,
        person,
        asker,
        group.effective.what.reference.entity_ref(),
    ) || !grant.allows_ask_fact(id, actor, person, asker, word.result_ref)
        || word
            .provenance_refs
            .iter()
            .any(|r| !grant.allows_ask_fact(id, actor, person, asker, r.entity_ref()))
    {
        return Err(invalid());
    }
    Ok(())
}
