//! Ordered native entity effects for the private agent-definition setup adapter.

use std::borrow::Cow;

use super::AgentDefinition;
use super::portable_binding::{
    PreparedAgentDefinitionBirth, prepare_agent_definition_birth_in_txn,
};
use crate::batch::PreparedPersonSubstrate;
use crate::context_board::PreparedAgentPerson;
use crate::error::Result;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON,
};
use crate::{EntityId, TimeRange, Vault};

/// A real encoded Put from this setup's preceding native operations. It is a
/// read projection only; the native write still performs all of its checks.
pub(crate) struct SetupEntityPut<'a> {
    pub(crate) id: EntityId,
    pub(crate) entity_type: u8,
    pub(crate) data: Cow<'a, [u8]>,
}

impl<'a> SetupEntityPut<'a> {
    pub(crate) fn borrowed(id: EntityId, entity_type: u8, data: &'a [u8]) -> Self {
        Self {
            id,
            entity_type,
            data: Cow::Borrowed(data),
        }
    }
}

pub(crate) fn setup_entity_type_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    preceding: &[SetupEntityPut<'_>],
) -> Result<Option<u8>> {
    // Present rows (including their faults) retain the native precedence.
    let stored = vault.get_entity_type_in_txn(txn, id)?;
    Ok(stored.or_else(|| {
        preceding
            .iter()
            .rev()
            .find(|put| put.id == *id)
            .map(|put| put.entity_type)
    }))
}

#[derive(Debug)]
pub(crate) struct PreparedSetupOwner {
    person: EntityId,
    body: Vec<u8>,
    substrate: PreparedPersonSubstrate,
    pub(super) before: EntityId,
}

impl PreparedSetupOwner {
    pub(crate) fn is_before(&self, id: EntityId) -> bool {
        self.before == id
    }

    pub(crate) fn matches(&self, id: EntityId, person: EntityId) -> bool {
        self.before == id && self.person == person
    }

    pub(crate) fn into_person_put(self) -> (Vec<u8>, PreparedPersonSubstrate) {
        (self.body, self.substrate)
    }

    fn append_puts(&self, puts: &mut Vec<SetupEntityPut<'_>>) {
        // These two small owned rows keep the ordered projection independent
        // of the growable owner-plan list, not of the native prepared tuples.
        puts.push(SetupEntityPut {
            id: self.person,
            entity_type: ENTITY_TYPE_PERSON,
            data: Cow::Owned(self.body.clone()),
        });
        if let Some((id, body)) = self.substrate.facet_put() {
            puts.push(SetupEntityPut {
                id,
                entity_type: crate::registry::ENTITY_TYPE_FACET,
                data: Cow::Owned(body.to_vec()),
            });
        }
    }
}

pub(crate) fn take_setup_owner_before(
    owners: &mut Vec<PreparedSetupOwner>,
    id: EntityId,
) -> Option<PreparedSetupOwner> {
    let position = owners.iter().position(|owner| owner.is_before(id))?;
    Some(owners.remove(position))
}

/// All of these units were prepared in the caller's writer. No definition,
/// PERSON, credential consumption, or entity effect has been written yet.
pub(crate) struct PreparedAgentSetup {
    pub(super) birth: PreparedAgentDefinitionBirth,
    pub(super) person: Option<PreparedAgentPerson>,
    pub(super) owners: Vec<PreparedSetupOwner>,
    definition_body: Vec<u8>,
    entity_puts: Vec<SetupEntityPut<'static>>,
    occurred: TimeRange,
    learned_at: u64,
}

impl PreparedAgentSetup {
    /// Every encoded native Put, in order, including repeated ids and superseded heads.
    pub(crate) fn entity_puts(&self) -> impl Iterator<Item = (EntityId, u8, &[u8])> + '_ {
        std::iter::once((
            self.birth.id(),
            ENTITY_TYPE_AGENT_DEF,
            self.definition_body.as_slice(),
        ))
        .chain(
            self.entity_puts
                .iter()
                .map(|put| (put.id, put.entity_type, put.data.as_ref())),
        )
    }

    /// Consumes the native setup tuples after the caller's Allow decision.
    /// The caller owns effect admission, credential spending and commit.
    pub(crate) fn apply_after_allow_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        let Self {
            birth,
            person,
            mut owners,
            definition_body,
            entity_puts: _entity_puts,
            occurred,
            learned_at,
        } = self;
        let id = birth.id();
        let source_owner = birth
            .entity_put()
            .and_then(|(source, _)| take_setup_owner_before(&mut owners, source));
        crate::batch::apply_ops_with_gate_mode(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_AGENT_DEF,
                occurred,
                learned_at,
                row_version: None,
                data: definition_body,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            crate::batch::ApplyOpsGateMode::for_agent_setup(birth, source_owner),
        )?;
        if let Some(person) = person {
            person.apply_with_setup_owners(vault, txn, &mut owners)?;
        }
        Ok(())
    }
}

pub(crate) fn prepare_agent_setup_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    definition: &AgentDefinition,
    definition_data: &[u8],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<PreparedAgentSetup> {
    let birth = prepare_agent_definition_birth_in_txn(&vault.store, txn, &id, definition)?;
    let mut preceding = vec![SetupEntityPut::borrowed(
        id,
        ENTITY_TYPE_AGENT_DEF,
        definition_data,
    )];
    let mut owners = Vec::new();
    // The genuine AGENT_DEF create writes its optional source ASSET before
    // ensure_agent_person, so this owner birth must be visible to that read.
    if let Some((asset_id, asset_body)) = birth.entity_put() {
        if let Some(owner) = prepare_owner_before_put(
            vault,
            txn,
            &preceding,
            asset_id,
            ENTITY_TYPE_ASSET,
            asset_body,
            occurred,
            learned_at,
        )? {
            owner.append_puts(&mut preceding);
            owners.push(owner);
        }
        preceding.push(SetupEntityPut::borrowed(
            asset_id,
            ENTITY_TYPE_ASSET,
            asset_body,
        ));
    }
    let person = crate::context_board::prepare_agent_person_after_puts_in_txn(
        vault,
        txn,
        id,
        definition_data,
        definition
            .display_name
            .as_deref()
            .unwrap_or(&definition.agent_id),
        learned_at,
        &preceding,
    )?;
    if let Some(person) = &person {
        preceding.extend(person.person_puts());
        // The model and anchor use distinct predicates. Earlier native
        // AGENT_DEF/ASSET/PERSON/FACET operations add no claim heads, redirects,
        // or vault.default_facet facts, so their captured head sets still hold.
        for head in person.subjects.heads() {
            for (claim, data) in head.encoded_puts()? {
                if let Some(owner) = prepare_owner_before_put(
                    vault,
                    txn,
                    &preceding,
                    claim,
                    ENTITY_TYPE_CLAIM,
                    &data,
                    TimeRange {
                        start: learned_at,
                        end: learned_at,
                    },
                    learned_at,
                )? {
                    owner.append_puts(&mut preceding);
                    owners.push(owner);
                }
                preceding.push(SetupEntityPut {
                    id: claim,
                    entity_type: ENTITY_TYPE_CLAIM,
                    data: Cow::Owned(data),
                });
            }
        }
    }
    let definition_body = definition_data.to_vec();
    let entity_puts = preceding
        .into_iter()
        .skip(1)
        .map(|put| SetupEntityPut {
            id: put.id,
            entity_type: put.entity_type,
            data: Cow::Owned(put.data.into_owned()),
        })
        .collect();
    Ok(PreparedAgentSetup {
        birth,
        person,
        owners,
        definition_body,
        entity_puts,
        occurred,
        learned_at,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "the native trigger retains its row, time and exact earlier-write frontier"
)]
fn prepare_owner_before_put(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    preceding: &[SetupEntityPut<'_>],
    id: EntityId,
    entity_type: u8,
    data: &[u8],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<Option<PreparedSetupOwner>> {
    // These native setup batches have neither a mask, replicated writes nor
    // ASSET_TEXT sources. Do not read the default facet on a no-birth branch.
    let Some(facet) = crate::batch::setup_birth_stamp_target(
        &vault.store,
        txn,
        id,
        entity_type,
        data,
        preceding.iter().map(|put| put.id),
    )?
    else {
        return Ok(None);
    };
    let owner = crate::vault::embedded_owner_actor_id()?;
    if facet != crate::claim::substrate_facet_id(owner)?
        || setup_entity_type_in_txn(vault, txn, &owner, preceding)?.is_some()
    {
        return Ok(None);
    }
    let body = crate::vault::encode_embedded_owner_actor_body()?;
    let substrate = crate::batch::prepare_person_substrate_after_puts(
        &vault.store,
        txn,
        owner,
        occurred,
        learned_at,
        preceding,
    )?;
    Ok(Some(PreparedSetupOwner {
        person: owner,
        body,
        substrate,
        before: id,
    }))
}
