//! Atomic deterministic PERSON substrate masks, including replay and open-time repair.
use super::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use crate::side_table::{self, Raw, SideTable};
use crate::{
    EntityId,
    error::{Error, Result},
    store::Store,
    temporal::TimeRange,
};
use rmpv::Value;

/// One-shot sweep-done markers. Key: `()`.
const SCOPE_STAMP_SWEEP_DONE: SideTable<(), [u8; 1], Raw> =
    SideTable::new(&side_table::SCOPE_STAMP_SWEEP_DONE);
const SCOPE_POLICY_SWEEP_DONE: SideTable<(), [u8; 1], Raw> =
    SideTable::new(&side_table::SCOPE_POLICY_SWEEP_DONE);

pub(crate) fn ensure_person_substrate(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    person: EntityId,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    prepare_person_substrate(store, txn, person, occurred, learned_at)?.apply(store, txn)
}

#[derive(Debug)]
pub(crate) struct PreparedPersonSubstrate {
    person: EntityId,
    facet: EntityId,
    bytes: Option<Vec<u8>>,
    occurred: TimeRange,
    learned_at: u64,
}

pub(crate) fn prepare_person_substrate(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<PreparedPersonSubstrate> {
    prepare_person_substrate_after_puts(store, txn, person, occurred, learned_at, &[])
}

pub(crate) fn prepare_person_substrate_after_puts(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    occurred: TimeRange,
    learned_at: u64,
    preceding: &[crate::agent_def::SetupEntityPut<'_>],
) -> Result<PreparedPersonSubstrate> {
    let facet = crate::write_envelope::claim_body::substrate_facet_id(person)?;
    let exists = match preceding.iter().rev().find(|put| put.id == facet) {
        Some(put) => {
            if put.entity_type != ENTITY_TYPE_FACET || !is_substrate(&put.data, person) {
                return Err(Error::CorruptedIndex("substrate identity collision"));
            }
            true
        }
        None => person_substrate_exists(store, txn, person, facet)?,
    };
    let bytes = if exists {
        None
    } else {
        // A caller can choose the id a PERSON's substrate lands at; an id that
        // has been an agent stays one (H215).
        crate::agent_def::refuse_agent_id_retype_in_txn(store, txn, &facet, ENTITY_TYPE_FACET)?;
        let body = Value::Map(vec![
            ("kind".into(), "substrate".into()),
            (
                "person_ref".into(),
                Value::Binary(person.as_bytes().to_vec()),
            ),
            ("sensitivity".into(), "sensitive".into()),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &body)
            .map_err(|_| Error::InvariantViolation("substrate encoding"))?;
        Some(bytes)
    };
    Ok(PreparedPersonSubstrate {
        person,
        facet,
        bytes,
        occurred,
        learned_at,
    })
}

impl PreparedPersonSubstrate {
    pub(super) fn person(&self) -> EntityId {
        self.person
    }

    pub(crate) fn facet_put(&self) -> Option<(EntityId, &[u8])> {
        self.bytes.as_deref().map(|bytes| (self.facet, bytes))
    }

    pub(crate) fn apply(self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        self.apply_rows_in_txn(store, txn)
    }

    pub(super) fn apply_at_person_projection(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        if person_substrate_exists(store, txn, self.person, self.facet)? {
            return self.apply_has_facet(store, txn);
        }
        if self.bytes.is_none() {
            return ensure_person_substrate(
                store,
                txn,
                self.person,
                self.occurred,
                self.learned_at,
            );
        }
        crate::agent_def::refuse_agent_id_retype_in_txn(
            store,
            txn,
            &self.facet,
            ENTITY_TYPE_FACET,
        )?;
        self.apply_rows_in_txn(store, txn)
    }

    fn apply_rows_in_txn(&self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let facet = self.facet;
        let occurred = self.occurred;
        let learned_at = self.learned_at;
        if let Some(bytes) = self.bytes.as_deref() {
            super::put_apply::stage_entity_body_row(
                store,
                txn,
                &facet,
                ENTITY_TYPE_FACET,
                occurred,
                learned_at,
                0,
                bytes,
            )?;
            super::put_apply::stage_entity_index_rows(
                store,
                txn,
                &facet,
                ENTITY_TYPE_FACET,
                occurred,
                learned_at,
            )?;
            let prefix = store.short_id_prefix(ENTITY_TYPE_FACET)?;
            let plan =
                super::plan_short_id_update(store, txn, &facet, ENTITY_TYPE_FACET, &prefix, bytes)?;
            super::apply_short_id_plan(store, txn, &facet, plan)?;
            store.scope_stamps.stamp_put(
                store,
                txn,
                facet,
                ENTITY_TYPE_FACET,
                bytes,
                crate::batch::row_put::RowPut::Birth,
            )?;
        }
        self.apply_has_facet(store, txn)
    }

    fn apply_has_facet(&self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        super::edge_apply::apply_edge_with_created_at(
            store,
            txn,
            self.person,
            EdgeKind::HasFacet,
            self.facet,
            1.0,
            self.learned_at,
            oneiron_contracts::affect::Vad::NEUTRAL,
            None,
        )?;
        Ok(())
    }
}

fn person_substrate_exists(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    facet: EntityId,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &facet)? else {
        return Ok(false);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("substrate header"))?;
    if header.entity_type != ENTITY_TYPE_FACET
        || !is_substrate(&raw[ENTITY_METADATA_HEADER_LEN..], person)
    {
        return Err(Error::CorruptedIndex("substrate identity collision"));
    }
    Ok(true)
}

fn is_substrate(data: &[u8], person: EntityId) -> bool {
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut &data[..]) else {
        return false;
    };
    entries.len() == 3
        && entries
            .iter()
            .any(|(k, v)| k.as_str() == Some("kind") && v.as_str() == Some("substrate"))
        && entries.iter().any(|(k, v)| {
            k.as_str() == Some("person_ref") && v.as_slice() == Some(person.as_bytes().as_slice())
        })
}
/// Caller-selected ids cannot mint base reality or the default project as records.
pub(super) fn validate_scope_identity(id: EntityId) -> Result<()> {
    if id == oneiron_contracts::claim::base_world_id()
        || id == crate::write_envelope::claim_body::default_project_id()
    {
        return Err(Error::InvalidClaimBody(
            "reserved scope member cannot be minted",
        ));
    }
    Ok(())
}
pub(crate) fn sweep_scope_stamps(store: &Store) -> Result<()> {
    let mut txn = store.env.write_txn()?;
    let scope_done = SCOPE_STAMP_SWEEP_DONE.contains(store, &txn, &())?;
    // Version 3 of the sweep also settles every unstamped TASK in base reality.
    let tasks_done = SCOPE_STAMP_SWEEP_DONE
        .get(store, &txn, &())?
        .is_some_and(|[version]| version >= 3);
    let policy_done = SCOPE_POLICY_SWEEP_DONE.contains(store, &txn, &())?;
    if scope_done && tasks_done && policy_done {
        return Ok(());
    }
    let rows = crate::ports::EntityStoreRead::port_entity_raw_records(store, &txn)?
        .collect::<Result<Vec<_>>>()?;
    for (id, raw) in rows {
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("scope sweep header"))?;
        let occurred = TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        };
        if !policy_done
            && header.entity_type == crate::registry::ENTITY_TYPE_POLICY_MANIFEST
            && let Some(bytes) = store
                .gate_hooks
                .normalize_policy_manifest_scope(&raw[ENTITY_METADATA_HEADER_LEN..])
        {
            // A locally authored manifest keeps its origin across the upgrade;
            // replayed bytes gain no trust stamp from it.
            if store.gate_hooks.manifest_is_trusted(
                store,
                &txn,
                &id,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )? {
                store
                    .gate_hooks
                    .stamp_manifest_origin(store, &mut txn, &id, &bytes, false)?;
            }
            super::put_apply::stage_entity_body_row(
                store,
                &mut txn,
                &id,
                header.entity_type,
                occurred,
                header.learned_at,
                header.row_version,
                &bytes,
            )?;
            // Maintenance grant kinds have no short-id prefix.
            if let Ok(prefix) = store.short_id_prefix(header.entity_type) {
                let plan = super::plan_short_id_update(
                    store,
                    &txn,
                    &id,
                    header.entity_type,
                    &prefix,
                    &bytes,
                )?;
                super::apply_short_id_plan(store, &mut txn, &id, plan)?;
            }
            store.scope_stamps.stamp_put(
                store,
                &mut txn,
                id,
                header.entity_type,
                &bytes,
                crate::batch::row_put::RowPut::Birth,
            )?;
        }
        if !tasks_done && header.entity_type == crate::registry::ENTITY_TYPE_TASK {
            store.scope_stamps.backfill_task_base(
                store,
                &mut txn,
                id,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )?;
        }
        // The policy migration has its own marker: vaults that already ran the
        // claim/identity sweep must still upgrade the fourth grant family.
        if scope_done {
            continue;
        }
        if header.entity_type == ENTITY_TYPE_PERSON {
            ensure_person_substrate(store, &mut txn, id, occurred, header.learned_at)?;
        }
        if matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_ACCESS_GRANT
                | crate::registry::ENTITY_TYPE_FEDERATION_GRANT
        ) {
            let old = &raw[ENTITY_METADATA_HEADER_LEN..];
            let bytes = match header.entity_type {
                crate::registry::ENTITY_TYPE_ACCESS_GRANT => {
                    crate::access_grant::decode_access_grant_body(old)?;
                    old.to_vec()
                }
                _ => crate::federation::encode_federation_grant_body(
                    &crate::federation::decode_federation_grant_body(old)?,
                )?,
            };
            super::put_apply::stage_entity_body_row(
                store,
                &mut txn,
                &id,
                header.entity_type,
                occurred,
                header.learned_at,
                header.row_version,
                &bytes,
            )?;
            // Maintenance grant kinds have no short-id prefix.
            if let Ok(prefix) = store.short_id_prefix(header.entity_type) {
                let plan = super::plan_short_id_update(
                    store,
                    &txn,
                    &id,
                    header.entity_type,
                    &prefix,
                    &bytes,
                )?;
                super::apply_short_id_plan(store, &mut txn, &id, plan)?;
            }
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            crate::ports::claim_order::observe_in_txn(store, &mut txn, header.row_version)?;
            let bytes = crate::claim::upgrade_pre_scope_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let prefix = store.short_id_prefix(header.entity_type)?;
            let plan =
                super::plan_short_id_update(store, &txn, &id, header.entity_type, &prefix, &bytes)?;
            super::put_apply::stage_entity_body_row(
                store,
                &mut txn,
                &id,
                header.entity_type,
                occurred,
                header.learned_at,
                header.row_version,
                &bytes,
            )?;
            super::apply_short_id_plan(store, &mut txn, &id, plan)?;
            store.scope_stamps.stamp_put(
                store,
                &mut txn,
                id,
                header.entity_type,
                &bytes,
                crate::batch::row_put::RowPut::Birth,
            )?;
        }
    }
    SCOPE_STAMP_SWEEP_DONE.put(store, &mut txn, &(), &[3])?;
    SCOPE_POLICY_SWEEP_DONE.put(store, &mut txn, &(), &[1])?;
    txn.commit()?;
    Ok(())
}
