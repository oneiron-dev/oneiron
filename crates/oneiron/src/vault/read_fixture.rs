//! Explicit actor-bound read policy for cross-crate integration fixtures.
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::{Error, Result, TimeRange, Vault, WriteActor};
use rmpv::Value;
use std::sync::atomic::Ordering;

impl Vault {
    /// Installs one read-only, actor/class-bound grant in the stock manifest.
    /// TEST-SUPPORT ONLY: no write ceiling, source permit, or approval is added.
    /// Refuses a missing/customized policy or a missing/class-mismatched actor.
    /// Reads still pass the normal policy, liveness, and record-scope gates.
    #[doc(hidden)]
    pub fn install_read_permit_for_test(&self, actor: WriteActor) -> Result<()> {
        let id = crate::gate::default_policy_manifest_id()?;
        let default = crate::gate::default_policy_manifest();
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut default.as_slice())
            .map_err(|_| Error::InvariantViolation("decode default test policy"))?
        else {
            return Err(Error::InvariantViolation(
                "default test policy is not a map",
            ));
        };
        entries.push((
            "scoped_grants".into(),
            Value::Array(vec![Value::Map(vec![
                ("actor_ref".into(), actor.entity_ref().to_hex().into()),
                (
                    "actor_class".into(),
                    actor.actor_class().gate_actor_class().into(),
                ),
                ("effector".into(), "core:read".into()),
                (
                    "scope".into(),
                    crate::federation::scope_codec::encode_scope_value(
                        &crate::federation::scope_codec::read_preset(),
                    )?,
                ),
                ("receipt_required".into(), false.into()),
            ])]),
        ));
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &Value::Map(entries))
            .map_err(|_| Error::InvariantViolation("encode read test policy"))?;
        self.with_write_txn(|txn| {
            let super::LiveEntityRow::Live { entity_type, .. } =
                super::live_entity_row_in_txn(&self.store, txn, &actor.entity_ref())?
            else {
                return Err(Error::EntityNotFound);
            };
            crate::provenance::validate_actor_class(entity_type, actor.actor_class())?;
            let raw =
                self.store
                    .entities
                    .get(txn, id.as_bytes())?
                    .ok_or(Error::InvariantViolation(
                        "test permit requires a seeded default policy",
                    ))?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("test policy header"))?;
            if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST
                || raw[ENTITY_METADATA_HEADER_LEN..] != default
            {
                return Err(Error::InvariantViolation(
                    "test permit requires an unchanged default policy",
                ));
            }
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                txn,
                vec![BatchOp::Put {
                    id,
                    entity_type: ENTITY_TYPE_POLICY_MANIFEST,
                    occurred: TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    learned_at: header.learned_at,
                    data,
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                self.text_index_trusted.load(Ordering::Acquire),
                true,
                true,
            )
        })
    }
}
