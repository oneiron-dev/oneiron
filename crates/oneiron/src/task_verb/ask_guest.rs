//! Ask-scoped guest authority: reuse a person's owner-stamped bounds.
use super::{TaskAskGuest, TaskAskTarget};
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, BoundSubject, DisclosureClass,
    DisclosureEnvelope, GrantBound, StandingConsentGrant,
};
use crate::error::Result;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

fn invalid() -> crate::Error {
    super::ask_record::invalid()
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
        .ok_or_else(invalid)?;
    let StandingConsentGrant::Disclosure(parent) = &row.grant else {
        return Err(invalid());
    };
    let required = GrantBound::disclosure(
        AudienceBound::singleton(asker.to_hex())?,
        DisclosureClass::new(class)?,
        DisclosureEnvelope::new(refs.iter().map(EntityId::to_hex))?,
    )?;
    if !row.is_active()
        || row.owner_stamp.actor != person
        || row.grant_ref() != guest.disclosure_grant_ref
        || !parent.bound().contains(&required)
    {
        return Err(invalid());
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

/// The answer-class delegation is a separate owner-stamped ACTION grant. A
/// disclosure grant, guest grant or caller-supplied boolean cannot make a hint
/// final. The target is the exact person; the class identifies the ask class.
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
        if !action.bound().contains(&required) {
            continue;
        }
        if !matches!(action.bound().subject(), BoundSubject::Actor(_)) {
            continue;
        }
        let reference = grant.bound().digest().to_hex();
        let Some(row) = vault.consent_grant_in_txn(txn, &reference)? else {
            continue;
        };
        if row.owner_stamp.actor == person && row.is_active() {
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
    Ok(row.owner_stamp.actor == person
        && row.grant_ref() == reference
        && action.bound().contains(&required))
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
