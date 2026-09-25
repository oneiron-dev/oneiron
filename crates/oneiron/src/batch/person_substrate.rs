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
    let facet = crate::claim::substrate_facet_id(person);
    if let Some(raw) = store.entities.get(txn, facet.as_bytes())? {
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("substrate header"))?;
        if header.entity_type != ENTITY_TYPE_FACET
            || !is_substrate(&raw[ENTITY_METADATA_HEADER_LEN..], person)
        {
            return Err(Error::CorruptedIndex("substrate identity collision"));
        }
    } else {
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
            false,
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
    let policy_done = SCOPE_POLICY_SWEEP_DONE.contains(store, &txn, &())?;
    if scope_done && policy_done {
        return Ok(());
    }
    let rows: Vec<_> = store
        .entities
        .iter(&txn)?
        .map(|row| row.map(|(key, raw)| (key.to_vec(), raw.into_owned())))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (key, raw) in rows {
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("scope sweep header"))?;
        let id = EntityId::from_bytes(
            key.as_slice()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("scope sweep id"))?,
        )?;
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
                false,
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
                | crate::registry::ENTITY_TYPE_OUTBOUND_GRANT
                | crate::registry::ENTITY_TYPE_FEDERATION_GRANT
        ) {
            let old = &raw[ENTITY_METADATA_HEADER_LEN..];
            let bytes = match header.entity_type {
                crate::registry::ENTITY_TYPE_ACCESS_GRANT => {
                    crate::access_grant::encode_access_grant_body(
                        &crate::access_grant::decode_access_grant_body(old)?,
                    )?
                }
                crate::registry::ENTITY_TYPE_OUTBOUND_GRANT => {
                    crate::outbound_grant::encode_standing_outbound_grant_body(
                        &crate::outbound_grant::decode_standing_outbound_grant_body(old)?,
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
        if header.entity_type == crate::companion::ENTITY_TYPE_COMPANION_REGISTER {
            let bytes = upgrade_identity_facet(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let record = crate::companion::decode_companion_record_body(&bytes)?;
            let person = match record.subject {
                crate::companion::CompanionSubject::Persona { persona_ref } => persona_ref,
                crate::companion::CompanionSubject::Relationship { source_ref, .. } => source_ref,
            };
            if store.entities.get(&txn, person.as_bytes())?.is_none() {
                super::put_apply::stage_entity_body_row(
                    store,
                    &mut txn,
                    &person,
                    ENTITY_TYPE_PERSON,
                    occurred,
                    header.learned_at,
                    b"",
                )?;
                super::put_apply::stage_entity_index_rows(
                    store,
                    &mut txn,
                    &person,
                    ENTITY_TYPE_PERSON,
                    occurred,
                    header.learned_at,
                )?;
            }
            ensure_person_substrate(store, &mut txn, person, occurred, header.learned_at)?;
            super::put_apply::delete_entity_index_rows(
                store,
                &mut txn,
                &id,
                header.entity_type,
                occurred,
                header.learned_at,
            )?;
            super::put_apply::stage_entity_body_row(
                store,
                &mut txn,
                &id,
                ENTITY_TYPE_FACET,
                occurred,
                header.learned_at,
                &bytes,
            )?;
            super::put_apply::stage_entity_index_rows(
                store,
                &mut txn,
                &id,
                ENTITY_TYPE_FACET,
                occurred,
                header.learned_at,
            )?;
            let prefix = store.short_id_prefix(ENTITY_TYPE_FACET)?;
            let plan =
                super::plan_short_id_update(store, &txn, &id, ENTITY_TYPE_FACET, &prefix, &bytes)?;
            super::apply_short_id_plan(store, &mut txn, &id, plan)?;
            super::edge_apply::apply_edge_with_created_at(
                store,
                &mut txn,
                person,
                EdgeKind::HasFacet,
                id,
                1.0,
                header.learned_at,
                crate::affect::Vad::NEUTRAL,
                None,
            )?;
            crate::federation::record_scope::stamp_put(
                store,
                &mut txn,
                id,
                ENTITY_TYPE_FACET,
                &bytes,
                false,
            )?;
            super::facet_identity::reconcile_identity_facet(
                store,
                &mut txn,
                id,
                &bytes,
                occurred,
                header.learned_at,
            )?;
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
                false,
            )?;
        }
    }
    SCOPE_STAMP_SWEEP_DONE.put(store, &mut txn, &(), &[2])?;
    SCOPE_POLICY_SWEEP_DONE.put(store, &mut txn, &(), &[1])?;
    txn.commit()?;
    Ok(())
}

fn upgrade_identity_facet(data: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(data);
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidClaimBody("identity migration body"))?
    else {
        return Err(Error::InvalidClaimBody("identity migration map"));
    };
    if cursor.position() != data.len() as u64 {
        return Err(Error::InvalidClaimBody("identity migration trailing bytes"));
    }
    let mut keys = std::collections::BTreeSet::new();
    for (key, value) in &mut entries {
        let name = key
            .as_str()
            .ok_or(Error::InvalidClaimBody("identity migration key"))?;
        if !keys.insert(name.to_owned()) {
            return Err(Error::InvalidClaimBody("identity migration duplicate key"));
        }
        if name == "schema_version" {
            *value = 3u64.into();
        } else if name == "export" {
            *value = match value.as_str() {
                Some("portable") => "public".into(),
                Some("local_only") => "restricted".into(),
                Some("shared_vault") => "private".into(),
                _ => return Err(Error::InvalidClaimBody("identity migration export")),
            };
            *key = "sensitivity".into();
        }
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("identity migration encode"))?;
    Ok(out)
}
