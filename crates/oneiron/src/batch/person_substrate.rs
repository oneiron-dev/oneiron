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
    let facet = crate::claim::substrate_facet_id(person)?;
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &facet)? {
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("substrate header"))?;
        if header.entity_type != ENTITY_TYPE_FACET
            || !is_substrate(&raw[ENTITY_METADATA_HEADER_LEN..], person)
        {
            return Err(Error::CorruptedIndex("substrate identity collision"));
        }
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
        super::put_apply::stage_entity_body_row(
            store,
            txn,
            &facet,
            ENTITY_TYPE_FACET,
            occurred,
            learned_at,
            &bytes,
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
            super::plan_short_id_update(store, txn, &facet, ENTITY_TYPE_FACET, &prefix, &bytes)?;
        super::apply_short_id_plan(store, txn, &facet, plan)?;
        crate::federation::record_scope::stamp_put(
            store,
            txn,
            facet,
            ENTITY_TYPE_FACET,
            &bytes,
            crate::federation::record_scope::RowPut::Birth,
        )?;
    }
    super::edge_apply::apply_edge_with_created_at(
        store,
        txn,
        person,
        EdgeKind::HasFacet,
        facet,
        1.0,
        learned_at,
        crate::affect::Vad::NEUTRAL,
        None,
    )?;
    Ok(())
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
    if id == crate::claim::base_world_id() || id == crate::claim::default_project_id() {
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
            && let Some(bytes) =
                crate::gate::normalize_policy_manifest_scope(&raw[ENTITY_METADATA_HEADER_LEN..])
        {
            // A locally authored manifest keeps its origin across the upgrade;
            // replayed bytes gain no trust stamp from it.
            if crate::gate::manifest_authenticity::manifest_is_trusted(
                store,
                &txn,
                &id,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )? {
                crate::gate::manifest_authenticity::stamp_manifest_origin(
                    store, &mut txn, &id, &bytes, false,
                )?;
            }
            super::put_apply::stage_entity_body_row(
                store,
                &mut txn,
                &id,
                header.entity_type,
                occurred,
                header.learned_at,
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
            crate::federation::record_scope::stamp_put(
                store,
                &mut txn,
                id,
                header.entity_type,
                &bytes,
                crate::federation::record_scope::RowPut::Birth,
            )?;
        }
        if !tasks_done && header.entity_type == crate::registry::ENTITY_TYPE_TASK {
            crate::federation::record_scope::backfill_task_base(
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
                    crate::access_grant::encode_access_grant_body(
                        &crate::access_grant::decode_access_grant_body(old)?,
                    )?
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
                &bytes,
            )?;
            super::apply_short_id_plan(store, &mut txn, &id, plan)?;
            crate::federation::record_scope::stamp_put(
                store,
                &mut txn,
                id,
                header.entity_type,
                &bytes,
                crate::federation::record_scope::RowPut::Birth,
            )?;
        }
    }
    SCOPE_STAMP_SWEEP_DONE.put(store, &mut txn, &(), &[3])?;
    SCOPE_POLICY_SWEEP_DONE.put(store, &mut txn, &(), &[1])?;
    txn.commit()?;
    Ok(())
}
