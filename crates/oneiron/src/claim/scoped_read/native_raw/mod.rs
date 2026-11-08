//! The scoped buffer-oriented native readers. The callback owns session
//! composition; this adapter never falls back to an unscoped vault read.

use super::*;
use crate::off_record::{OffRecordSession, SessionRetrievalTelemetry};

mod graph;
mod snapshots;

/// The native raw read surface inside one verified caller/session selection.
/// Obtained only through a vault or Memory credential-read callback. Writes
/// remain on the original handle, never on this read adapter.
pub struct NativeRawRead<'a> {
    lane: ScopedRead<'a>,
    session: Option<&'a OffRecordSession<'a>>,
}

impl<'a> NativeRawRead<'a> {
    pub(crate) fn new(lane: ScopedRead<'a>, session: Option<&'a OffRecordSession<'a>>) -> Self {
        Self {
            lane: lane.with_claim_status(ClaimReadStatus::Recorded),
            session,
        }
    }

    /// The admitted live body, with repo and file secrets projected in the same snapshot.
    pub fn entity_body(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        Ok(self
            .lane
            .read_projected(
                &[PointRead::id(*id)],
                None,
                |txn, rows| -> Result<Option<Vec<u8>>> {
                    let Some(row) = rows.into_iter().next().flatten() else {
                        return Ok(None);
                    };
                    let Some(body) = row.body else {
                        return Ok(None);
                    };
                    let body = if self.lane.actor_key.secret_sight()
                        == crate::secret_custody::SecretSight::Masked
                    {
                        crate::memory::repo_secret_reads::repo_asset_body_known_in_txn(
                            self.lane.vault,
                            txn,
                            id,
                            row.entity_type,
                            &body,
                        )?
                        .unwrap_or(body)
                    } else {
                        body
                    };
                    let body = if row.entity_type == crate::registry::ENTITY_TYPE_ASSET {
                        crate::store::file_key_masks::sighted_bytes_in_txn(
                            &self.lane.vault.store,
                            txn,
                            body,
                            None,
                            self.lane.actor_key.secret_sight(),
                        )?
                    } else {
                        body
                    };
                    Ok(Some(body))
                },
            )?
            .value)
    }

    /// The admitted live entity's stored type byte.
    pub fn entity_type(&self, id: &EntityId) -> Result<Option<u8>> {
        Ok(self
            .lane
            .read(&[PointRead::id(*id)], None)?
            .value
            .into_iter()
            .next()
            .flatten()
            .filter(|row| row.body.is_some())
            .map(|row| row.entity_type))
    }

    /// Whether the lane admits a live entity at this id.
    pub fn entity_exists(&self, id: &EntityId) -> Result<bool> {
        Ok(self.entity_type(id)?.is_some())
    }

    fn retrieval_lane(&self) -> ScopedRead<'_> {
        let lane = match self.lane.session_view {
            Some(view) => self
                .lane
                .vault
                .scoped_read_in_session(self.lane.actor_key.clone(), view),
            None => self.lane.vault.scoped_read(self.lane.actor_key.clone()),
        };
        lane.with_claim_status(ClaimReadStatus::Surfaceable)
    }

    fn retrieval<T>(
        &self,
        read: impl FnOnce(&ScopedRead<'_>, Option<&SessionRetrievalTelemetry<'_>>) -> Result<T>,
    ) -> Result<T> {
        let lane = self.retrieval_lane();
        match self.session {
            Some(session) => {
                let route = session.write_route()?;
                let telemetry = session.retrieval_telemetry(&route)?;
                read(&lane, Some(&telemetry))
            }
            None => read(&lane, None),
        }
    }

    /// BM25 candidates are admitted before ranking and rechecked before return.
    pub fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        self.query(|builder| builder.search_text(query, limit).limit(limit))
    }

    /// Vector candidates are admitted before ranking and rechecked before return.
    pub fn search_vector(&self, query: &[f32], limit: usize) -> Result<Vec<ScoredEntity>> {
        self.query(|builder| builder.search_vector(query, limit).limit(limit))
    }

    /// Executes the configured pipeline under this read's authority and route.
    pub fn query(
        &self,
        configure: impl for<'b> Fn(crate::PipelineBuilder<'b>) -> crate::PipelineBuilder<'b>,
    ) -> Result<Vec<ScoredEntity>> {
        self.retrieval(|lane, telemetry| Ok(lane.native_query(configure, telemetry)?.value))
    }

    /// Filters the configured pack before serialization and run finalization.
    pub fn context_pack(
        &self,
        configure: impl for<'b> Fn(crate::ContextPackBuilder<'b>) -> crate::ContextPackBuilder<'b>,
    ) -> Result<Vec<u8>> {
        self.retrieval(|lane, telemetry| Ok(lane.native_pack(configure, telemetry)?.value))
    }
}

impl crate::Vault {
    /// Runs a native raw read as the actual verified credential subject.
    /// A credential that grants no read never falls back to the host's lane.
    pub fn with_credential_raw_read<T>(
        &self,
        proof: &crate::authority::VerifiedSlip,
        read: impl for<'a> FnOnce(&NativeRawRead<'a>) -> Result<T>,
    ) -> Result<T> {
        let key = self
            .credential_read_key(proof)?
            .ok_or(Error::InvalidClaimBody(
                "the read credential does not grant a read",
            ))?;
        read(&NativeRawRead::new(self.scoped_read(key), None))
    }
}
