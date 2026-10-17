//! Custody of a verified provider event's body (OF-519). A surface event
//! carries only a `payload_ref`; dispatch never resolves one. A served host
//! that verified a provider webhook keeps the event's provider JSON in the
//! vault as one BLOB artifact per (channel, provider event id), so the body
//! syncs, restores and erases with the vault, and its ref reads it back.
//! A provider retry of the same event appends the same bytes, which is the
//! blob store's own no-op.

use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::entity_id::derived_domains::{
    SURFACE_PROVIDER_EVENT_BLOB, SURFACE_PROVIDER_INBOUND_ACTOR,
};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::{EntityId, TimeRange, Vault, WriteActor};

/// Every provider event ref starts with this: `blob:<artifact hex>@<version>`.
pub const PROVIDER_EVENT_REF_PREFIX: &str = "blob:";

impl Vault {
    /// Archives one verified provider event's body and returns the
    /// `payload_ref` its surface event carries.
    pub fn archive_provider_event(
        &self,
        channel: &str,
        provider_event_id: &str,
        body: &[u8],
        now: u64,
    ) -> Result<String> {
        let artifact_id = EntityId::derive(
            SURFACE_PROVIDER_EVENT_BLOB,
            &[channel.as_bytes(), provider_event_id.as_bytes()],
        )?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        if self.get_blob_artifact(&artifact_id)?.is_none() {
            self.put_blob_artifact(
                &artifact_id,
                &BlobArtifactBody::new(
                    format!("provider-event:{channel}:{provider_event_id}"),
                    "application/json",
                ),
                at,
                now,
            )?;
        }
        let actor = self.ensure_provider_inbound_actor(now)?;
        let version = self.append_blob_artifact_version(
            &artifact_id,
            body,
            &BlobVersionProvenance::AgentRun {
                run_ref: format!("surface:{channel}:{provider_event_id}"),
            },
            WriteActor::new(actor, crate::edge::EdgeActorClass::System),
            at,
            now,
        )?;
        Ok(format!(
            "{PROVIDER_EVENT_REF_PREFIX}{}@{}",
            artifact_id.to_hex(),
            version.version
        ))
    }

    /// The provider event body a `payload_ref` from
    /// [`Self::archive_provider_event`] names; `None` for any other ref or a
    /// body the vault no longer holds.
    pub fn read_provider_event(&self, payload_ref: &str) -> Result<Option<Vec<u8>>> {
        let Some((artifact, version)) = payload_ref
            .strip_prefix(PROVIDER_EVENT_REF_PREFIX)
            .and_then(|rest| rest.split_once('@'))
        else {
            return Ok(None);
        };
        let (Ok(artifact_id), Ok(version)) = (EntityId::from_hex(artifact), version.parse()) else {
            return Ok(None);
        };
        self.read_blob_artifact_version(&artifact_id, version)
    }

    fn ensure_provider_inbound_actor(&self, now: u64) -> Result<EntityId> {
        let id = EntityId::derive(SURFACE_PROVIDER_INBOUND_ACTOR, &[])?;
        if self.get_entity_type(&id)? != Some(ENTITY_TYPE_MACHINE) {
            let mut body = Vec::new();
            rmpv::encode::write_value(
                &mut body,
                &rmpv::Value::Map(vec![(
                    rmpv::Value::from("name"),
                    rmpv::Value::from("provider event inbound"),
                )]),
            )
            .map_err(|_| Error::InvariantViolation("actor body did not encode"))?;
            self.put_entity(
                &id,
                ENTITY_TYPE_MACHINE,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )?;
        }
        Ok(id)
    }
}
