use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Highest priority: a pending claim surfaced in user-visible retrieval.
pub const EMBED_PRIORITY_SURFACED_HOT: u8 = 0;
/// Server-originated sync materialization.
pub const EMBED_PRIORITY_SERVER: u8 = 1;
/// Local device write.
pub const EMBED_PRIORITY_DEVICE: u8 = 2;
/// Cold attach-embedder or model backfill.
pub const EMBED_PRIORITY_BACKFILL: u8 = 3;

/// Default pending-embedding lease duration.
#[cfg(feature = "sync")]
pub const DEFAULT_PENDING_EMBEDDING_LEASE_MS: u64 = 30_000;

/// Default lease window for remote-routed embed work (E2: remote rungs get
/// longer lease windows). 4x the local default.
#[cfg(feature = "sync")]
pub const DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS: u64 = 120_000;

/// Where an embedder runs relative to the vault owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmbedderLocality {
    /// Runs on the same device as the vault.
    OnDevice,
    /// Runs on infrastructure controlled by the vault owner.
    OwnerServer,
    /// Runs on a third-party service.
    ThirdParty,
}

/// One pending claim body supplied to a host-injected embedder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEmbeddingInput {
    pub entity_id: EntityId,
    pub claim_body: Vec<u8>,
    pub pending_embedding_token: Vec<u8>,
}

/// Host-injected retrieval embedder.
///
/// The engine owns queueing, leases, and vector storage. Implementations own
/// model execution and any locality-specific policy before returning vectors.
pub trait Embedder: Send + Sync {
    fn model_id(&self) -> &str;
    fn dimensions(&self) -> usize;
    fn locality(&self) -> EmbedderLocality;
    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>>;
}

/// Tri-state PII egress verdict for one pending claim (ONE-EMBED E6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Deny,
    NoVerdict,
}

/// Host-supplied egress gate. The OneiroNER PII head's verdict lives
/// host-side; the engine never knows what PII is. Consulted for EVERY
/// claim routed to a non-OnDevice embedder.
///
/// Host trait impls invoked under a held txn/lock must be non-blocking
/// cached lookups; hosts run arbitrary inference in the async phases the
/// engine exposes for it.
pub trait EgressPredicate: Send + Sync {
    /// Egress verdict for one pending claim. `Deny` and `NoVerdict` both
    /// route the claim to the local (OnDevice) embedder — fail-closed; a
    /// missing verdict can never send bytes off-device and never stalls
    /// the queue.
    ///
    /// Called under a held write transaction: host trait impls invoked
    /// under a held txn/lock must be non-blocking cached lookups; hosts run
    /// arbitrary inference in the async phases the engine exposes for it.
    fn decide(&self, input: &PendingEmbeddingInput) -> EgressDecision;
}

/// A configured non-OnDevice rung.
#[cfg(feature = "sync")]
pub struct RemoteRung {
    pub embedder: std::sync::Arc<dyn Embedder>,
    pub predicate: std::sync::Arc<dyn EgressPredicate>,
    pub lease_duration_ms: u64,
}

#[cfg(feature = "sync")]
impl RemoteRung {
    /// Builds a rung with the default remote lease window
    /// ([`DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS`]).
    #[must_use]
    pub fn new(
        embedder: std::sync::Arc<dyn Embedder>,
        predicate: std::sync::Arc<dyn EgressPredicate>,
    ) -> Self {
        Self {
            embedder,
            predicate,
            lease_duration_ms: DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS,
        }
    }
}

/// Canonical rung-2 INT8-transport receipt: `codes[i] as f32 * scale`.
/// Server sends int8+scale; the HOST dequantizes before returning vectors
/// through `Embedder::embed` (E4: INT8 is transport-only, never stored;
/// the f16 storage conversion is the EMB-3 row format's responsibility).
#[must_use]
pub fn dequantize_int8_embedding(codes: &[i8], scale: f32) -> Vec<f32> {
    codes.iter().map(|c| f32::from(*c) * scale).collect()
}

#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingEmbeddingLease {
    expires_at_ms: u64,
    token: Vec<u8>,
}

/// Which embedder a leased claim was routed to. Never persisted: the lease
/// wire format is unchanged and a crashed pass re-decides on re-drain.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmbedRoute {
    Local,
    Remote,
}

#[cfg(feature = "sync")]
#[derive(Debug, Clone)]
struct LeasedPendingEmbedding {
    input: PendingEmbeddingInput,
    lease_value: Vec<u8>,
    route: EmbedRoute,
}

#[cfg(feature = "sync")]
#[derive(Debug, Default, Clone)]
struct LeaseBatch {
    work: Vec<LeasedPendingEmbedding>,
    active_leases: usize,
    stale_jobs: usize,
    egress_denied: usize,
    egress_no_verdict: usize,
}

/// Summary from one reconciler pass.
#[cfg(feature = "sync")]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PendingEmbeddingReconcileReport {
    pub leased: usize,
    pub active_leases: usize,
    pub stale_jobs: usize,
    pub embedded: usize,
    pub filled: usize,
    pub stale_fills: usize,
    pub routed_remote: usize,
    pub egress_denied: usize,
    pub egress_no_verdict: usize,
    pub remote_failed_fallback_local: usize,
}

/// Per-vault pending-embedding reconciler.
#[cfg(feature = "sync")]
pub struct PendingEmbeddingReconciler {
    vault: std::sync::Arc<crate::Vault>,
    embedder: std::sync::Arc<dyn Embedder>,
    batch_size: usize,
    lease_duration_ms: u64,
    remote_rung: Option<RemoteRung>,
}

#[cfg(feature = "sync")]
impl PendingEmbeddingReconciler {
    #[must_use]
    pub fn new(
        vault: std::sync::Arc<crate::Vault>,
        embedder: std::sync::Arc<dyn Embedder>,
    ) -> Self {
        Self {
            vault,
            embedder,
            batch_size: 32,
            lease_duration_ms: DEFAULT_PENDING_EMBEDDING_LEASE_MS,
            remote_rung: None,
        }
    }

    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    #[must_use]
    pub fn with_lease_duration_ms(mut self, lease_duration_ms: u64) -> Self {
        self.lease_duration_ms = lease_duration_ms.max(1);
        self
    }

    /// Attaches a remote rung (rung 1 = `OwnerServer`, rung 2 = `ThirdParty`;
    /// the rung is `embedder.locality()`). Requires: remote locality !=
    /// `OnDevice`, the PRIMARY embedder locality == `OnDevice`
    /// (fail-closed-to-local needs a local target), and a non-zero lease
    /// window (`lease_duration_ms` is public and feeds expiry math
    /// directly: a 0ms lease is born expired, so every pass re-leases and
    /// re-embeds the same rows). At most one remote rung per reconciler.
    pub fn with_remote_rung(mut self, rung: RemoteRung) -> Result<Self> {
        if rung.embedder.locality() == EmbedderLocality::OnDevice {
            return Err(Error::InvalidConfig(
                "remote rung embedder must not be OnDevice".to_owned(),
            ));
        }
        if self.embedder.locality() != EmbedderLocality::OnDevice {
            return Err(Error::InvalidConfig(
                "remote rung requires an OnDevice primary embedder".to_owned(),
            ));
        }
        if rung.lease_duration_ms == 0 {
            return Err(Error::InvalidConfig(
                "remote rung lease duration must be greater than zero".to_owned(),
            ));
        }
        if self.remote_rung.is_some() {
            return Err(Error::InvalidConfig(
                "a remote rung is already configured".to_owned(),
            ));
        }
        self.remote_rung = Some(rung);
        Ok(self)
    }

    pub fn reconcile_once(&self) -> Result<PendingEmbeddingReconcileReport> {
        self.reconcile_once_at(unix_millis_now())
    }

    fn reconcile_once_at(&self, now_ms: u64) -> Result<PendingEmbeddingReconcileReport> {
        self.validate_embedder_for_vault()?;
        let batch = self.lease_due_jobs(now_ms)?;
        let mut report = PendingEmbeddingReconcileReport {
            leased: batch.work.len(),
            active_leases: batch.active_leases,
            stale_jobs: batch.stale_jobs,
            egress_denied: batch.egress_denied,
            egress_no_verdict: batch.egress_no_verdict,
            ..PendingEmbeddingReconcileReport::default()
        };
        if batch.work.is_empty() {
            return Ok(report);
        }

        let (remote_work, local_work): (Vec<_>, Vec<_>) = batch
            .work
            .into_iter()
            .partition(|work| work.route == EmbedRoute::Remote);

        // Remote batch FIRST: remote-routed rows carry the long (120s)
        // lease window, so a primary failure in the local batch — which
        // aborts the pass, as it always has — must not strand
        // never-attempted remote rows behind those leases. An aborted pass
        // therefore only leaves never-attempted rows behind the SHORT
        // local window.
        if !remote_work.is_empty() {
            let rung = self.remote_rung.as_ref().ok_or(Error::InvariantViolation(
                "remote-routed work without a remote rung",
            ))?;
            let inputs: Vec<PendingEmbeddingInput> =
                remote_work.iter().map(|work| work.input.clone()).collect();
            match rung.embedder.embed(&inputs) {
                Ok(vectors) => {
                    if vectors.len() != remote_work.len() {
                        return Err(Error::InvariantViolation(
                            "embedder returned mismatched vector count",
                        ));
                    }
                    report.routed_remote += remote_work.len();
                    report.embedded += vectors.len();
                    self.fill_batch(&remote_work, &vectors, &mut report)?;
                }
                Err(e) => {
                    tracing::warn!(?e, "remote embed failed; falling back to local");
                    report.remote_failed_fallback_local += remote_work.len();
                    self.embed_and_fill_local(&remote_work, &mut report)?;
                }
            }
        }

        if let Err(error) = self.embed_and_fill_local(&local_work, &mut report) {
            // The pass still fails (pinned: primary errors propagate), but
            // remote work that already completed above must not vanish from
            // observability with the dropped report. Pure-local failures
            // stay silent, exactly as EMB-1 always propagated them.
            if report.routed_remote > 0 || report.remote_failed_fallback_local > 0 {
                tracing::warn!(
                    ?error,
                    routed_remote = report.routed_remote,
                    remote_failed_fallback_local = report.remote_failed_fallback_local,
                    embedded = report.embedded,
                    filled = report.filled,
                    stale_fills = report.stale_fills,
                    "local batch failed after remote work completed; reconcile report dropped"
                );
            }
            return Err(error);
        }

        Ok(report)
    }

    fn embed_and_fill_local(
        &self,
        work: &[LeasedPendingEmbedding],
        report: &mut PendingEmbeddingReconcileReport,
    ) -> Result<()> {
        if work.is_empty() {
            return Ok(());
        }
        let inputs: Vec<PendingEmbeddingInput> =
            work.iter().map(|item| item.input.clone()).collect();
        let vectors = self.embedder.embed(&inputs)?;
        if vectors.len() != work.len() {
            return Err(Error::InvariantViolation(
                "embedder returned mismatched vector count",
            ));
        }
        report.embedded += vectors.len();
        self.fill_batch(work, &vectors, report)
    }

    fn fill_batch(
        &self,
        work: &[LeasedPendingEmbedding],
        vectors: &[Vec<f32>],
        report: &mut PendingEmbeddingReconcileReport,
    ) -> Result<()> {
        for (item, vector) in work.iter().zip(vectors.iter()) {
            if self.complete_leased_work(item, vector)? {
                report.filled += 1;
            } else {
                report.stale_fills += 1;
            }
        }
        Ok(())
    }

    fn validate_embedder_for_vault(&self) -> Result<()> {
        self.validate_one_embedder(self.embedder.as_ref())?;
        if let Some(rung) = &self.remote_rung {
            self.validate_one_embedder(rung.embedder.as_ref())?;
        }
        Ok(())
    }

    fn validate_one_embedder(&self, embedder: &dyn Embedder) -> Result<()> {
        if embedder.dimensions() != self.vault.config.dimensions {
            return Err(Error::DimensionMismatch {
                expected: self.vault.config.dimensions,
                got: embedder.dimensions(),
            });
        }
        let Some(config_model) = self.vault.config.embedding_model.as_deref() else {
            return Err(Error::InvalidConfig(
                "embedding model is required before embedding reconciliation".to_owned(),
            ));
        };
        if config_model != embedder.model_id() {
            return Err(Error::EmbeddingModelChanged {
                stored: config_model.to_owned(),
                requested: embedder.model_id().to_owned(),
            });
        }
        Ok(())
    }

    fn lease_due_jobs(&self, now_ms: u64) -> Result<LeaseBatch> {
        let queue = crate::sync::SyncQueue::new(std::sync::Arc::clone(&self.vault))?;
        let jobs = queue.drain_embed_jobs()?;
        let mut batch = LeaseBatch::default();
        if jobs.is_empty() {
            return Ok(batch);
        }

        self.vault.with_write_txn(|wtxn| {
            for job in jobs {
                if batch.work.len() >= self.batch_size {
                    break;
                }
                let Some(input) = pending_input_in_txn(&self.vault, wtxn, &job.entity_id)? else {
                    crate::sync::queue::delete_embed_job_in_txn(
                        &self.vault.store,
                        wtxn,
                        &job.entity_id,
                    )?;
                    clear_pending_embedding_lease_if_any(&self.vault, wtxn, &job.entity_id)?;
                    batch.stale_jobs += 1;
                    continue;
                };

                let key = pending_embedding_lease_key(&job.entity_id);
                if let Some(existing) = self.vault.store.sync_state.get(wtxn, key.as_str())?
                    && let Some(lease) = decode_pending_embedding_lease(&existing)
                    && lease.token == input.pending_embedding_token
                    && lease.expires_at_ms > now_ms
                {
                    batch.active_leases += 1;
                    continue;
                }

                let (route, lease_duration_ms) = match &self.remote_rung {
                    None => (EmbedRoute::Local, self.lease_duration_ms),
                    Some(rung) => match rung.predicate.decide(&input) {
                        EgressDecision::Allow => (EmbedRoute::Remote, rung.lease_duration_ms),
                        EgressDecision::Deny => {
                            batch.egress_denied += 1;
                            (EmbedRoute::Local, self.lease_duration_ms)
                        }
                        EgressDecision::NoVerdict => {
                            batch.egress_no_verdict += 1;
                            (EmbedRoute::Local, self.lease_duration_ms)
                        }
                    },
                };

                let expires_at_ms = now_ms.saturating_add(lease_duration_ms);
                let lease_value =
                    encode_pending_embedding_lease(expires_at_ms, &input.pending_embedding_token);
                self.vault
                    .store
                    .sync_state
                    .put(wtxn, key.as_str(), lease_value.as_slice())?;
                batch.work.push(LeasedPendingEmbedding {
                    input,
                    lease_value,
                    route,
                });
            }
            Ok(())
        })?;

        Ok(batch)
    }

    fn complete_leased_work(&self, work: &LeasedPendingEmbedding, vector: &[f32]) -> Result<bool> {
        let mut filled_current = false;
        self.vault.with_write_txn(|wtxn| {
            let current_before = self
                .vault
                .store
                .pending_embedding_token_in_txn(wtxn, &work.input.entity_id)?;
            crate::batch::apply_ops(
                &self.vault.store,
                &self.vault.config,
                &self.vault.analyzer,
                wtxn,
                vec![crate::batch::BatchOp::Vector {
                    id: work.input.entity_id,
                    vector: vector.to_vec(),
                    pending_embedding_token: Some(work.input.pending_embedding_token.clone()),
                }],
                self.vault
                    .text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
            let current_after = self
                .vault
                .store
                .pending_embedding_token_in_txn(wtxn, &work.input.entity_id)?;

            clear_pending_embedding_lease_if_matches(
                &self.vault,
                wtxn,
                &work.input.entity_id,
                &work.lease_value,
            )?;

            let token_was_current =
                current_before.as_deref() == Some(work.input.pending_embedding_token.as_slice());
            if current_after.is_none() {
                crate::sync::queue::delete_embed_job_in_txn(
                    &self.vault.store,
                    wtxn,
                    &work.input.entity_id,
                )?;
            }
            filled_current = token_was_current && current_after.is_none();
            Ok(())
        })?;
        Ok(filled_current)
    }
}

/// Re-marks every persisted claim after an embedding-space replacement.
/// Queue replacement deliberately deletes an old row first: queue insertion otherwise
/// preserves a hotter priority that belonged to the old model.
///
/// `priority` is consumed by the sync embed-queue re-push below; the signature
/// stays feature-independent because the base caller (`vault.rs`) supplies it
/// either way.
#[cfg_attr(not(feature = "sync"), allow(unused_variables))]
pub(crate) fn remark_all_claims_pending_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    priority: u8,
) -> Result<usize> {
    let mut claims = Vec::new();
    for row in vault.store.entities.iter(wtxn)? {
        let (key, raw) = row?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            let id = EntityId::from_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("entity id"))?,
            )
            .map_err(|_| Error::CorruptedIndex("entity id"))?;
            claims.push((id, raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec()));
        }
    }
    for (id, body) in &claims {
        vault.store.mark_pending_embedding(wtxn, id, body)?;
        #[cfg(feature = "sync")]
        {
            crate::sync::queue::delete_embed_job_in_txn(&vault.store, wtxn, id)?;
            crate::sync::queue::push_embed_job_in_txn(&vault.store, wtxn, id, priority)?;
            vault
                .store
                .sync_state
                .delete(wtxn, pending_embedding_lease_key(id).as_str())?;
        }
    }
    Ok(claims.len())
}

/// Enqueues background embed jobs for ids that still carry a `pe:` marker.
///
/// **Session content never arrives here (ARCH-0052 K6, ONE-1728).** The rule is
/// encoded as ROUTING, not as a filter in this function: the session write path
/// does not call this verb and writes no `pe:` marker at all — session content
/// embeds inline through the configured embedder at witness time (vector and
/// HNSW rows staged into the overlay), or has no vectors until promote. The
/// generalization is that session flows create ZERO background-job rows
/// (`attempt_records` / `attempt_ready` / `attempt_dedupe`) referencing overlay
/// content, so a job can never outlive the room it names.
///
/// The `debug_assert!` below is the dev-time tripwire proving the routing held,
/// not a production filter — a filter here would silently absorb a routing bug
/// instead of surfacing it. The base-only `PendingEmbeddingReconciler` needs no
/// equivalent: it reads base rows session content never enters.
#[cfg(feature = "sync")]
pub(crate) fn enqueue_pending_embedding_jobs(
    vault: &crate::Vault,
    ids: &[EntityId],
    priority: u8,
) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    debug_assert!(
        !ids.iter().any(|id| vault
            .store
            .off_record_sessions
            .contains_entity(id)
            .unwrap_or(false)),
        "K6: a live-overlay id reached the embed job queue; session content \
         embeds inline and must never enqueue a background job"
    );
    vault.with_write_txn(|wtxn| {
        for id in ids {
            if vault
                .store
                .pending_embedding_token_in_txn(wtxn, id)?
                .is_some()
            {
                crate::sync::queue::push_embed_job_in_txn(&vault.store, wtxn, id, priority)?;
            }
        }
        Ok(())
    })
}

#[cfg(feature = "sync")]
fn pending_input_in_txn(
    vault: &crate::Vault,
    wtxn: &heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<Option<PendingEmbeddingInput>> {
    let Some(token) = vault.store.pending_embedding_token_in_txn(wtxn, id)? else {
        return Ok(None);
    };
    let Some(raw) = vault.store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("entity header"))?;
    let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    // RT-05 (ONE-1687): the epoch-summary keyframe is embeddable alongside
    // CLAIM, and what the embedder (and egress gate) receives is its TEXT: the
    // record's framing keys carry no retrievable meaning. The pending-embedding
    // token still commits to the whole record, so a re-mint invalidates it.
    let embed_body = match header.entity_type {
        crate::registry::ENTITY_TYPE_CLAIM => body.to_vec(),
        crate::registry::ENTITY_TYPE_SUMMARY => {
            // An ordinary witness SUMMARY shares the type byte and is not an
            // epoch record. SKIP it — the same `None` this arm returned for
            // every SUMMARY before RT-05 — which the caller retires as stale.
            let Ok(summary) = crate::compaction::decode_epoch_summary_body(body) else {
                return Ok(None);
            };
            if summary.text.is_empty() {
                return Ok(None);
            }
            summary.text.into_bytes()
        }
        _ => return Ok(None),
    };
    Ok(Some(PendingEmbeddingInput {
        entity_id: *id,
        claim_body: embed_body,
        pending_embedding_token: token,
    }))
}

#[cfg(feature = "sync")]
fn pending_embedding_lease_key(id: &EntityId) -> String {
    format!("pelease:{}", id.to_hex())
}

#[cfg(feature = "sync")]
fn encode_pending_embedding_lease(expires_at_ms: u64, token: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(1 + 8 + token.len());
    value.push(1);
    value.extend_from_slice(&expires_at_ms.to_be_bytes());
    value.extend_from_slice(token);
    value
}

#[cfg(feature = "sync")]
fn decode_pending_embedding_lease(value: &[u8]) -> Option<PendingEmbeddingLease> {
    if value.len() < 9 || value[0] != 1 {
        return None;
    }
    let expires_at_ms = u64::from_be_bytes(value[1..9].try_into().ok()?);
    Some(PendingEmbeddingLease {
        expires_at_ms,
        token: value[9..].to_vec(),
    })
}

#[cfg(feature = "sync")]
fn clear_pending_embedding_lease_if_any(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let key = pending_embedding_lease_key(id);
    vault.store.sync_state.delete(wtxn, key.as_str())
}

#[cfg(feature = "sync")]
fn clear_pending_embedding_lease_if_matches(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    expected: &[u8],
) -> Result<bool> {
    let key = pending_embedding_lease_key(id);
    let Some(current) = vault.store.sync_state.get(wtxn, key.as_str())? else {
        return Ok(false);
    };
    if current != expected {
        return Ok(false);
    }
    vault.store.sync_state.delete(wtxn, key.as_str())
}

#[cfg(feature = "sync")]
fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().min(u128::from(u64::MAX)) as u64)
}

#[cfg(all(test, feature = "sync"))]
mod tests;
