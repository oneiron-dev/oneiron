//! Existing-only open door: `Store::open_existing` and its helpers.

use std::path::Path;
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::{Arc, Mutex, RwLock};

use heed::{Env, RoTxn};

use crate::analyzer::MultilingualAnalyzer;
use crate::config::VaultConfig;
use crate::error::{Error, Result};
use crate::off_record::OffRecordSessionRegistry;
use crate::overlay_db::{OverlayDb, OverlayStrDb};
use crate::store::{
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE, GATE_DECISION_KEY_PREFIX,
    GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord,
    PENDING_GATE_CONSENT_KEY_PREFIX, RawDatabases, Store, StoreCore, StoreOwner,
    decode_pending_gate_consent, gate_decision_upper_bound, load_structural_kind_registry,
    pending_gate_consent_claim_id_from_key, pending_gate_consent_upper_bound,
    seed_default_policy_manifest_in_txn,
};

use super::hnsw_model_gates::migrate_temporal_long_intervals_if_needed;
use super::manifest_storage_gates::{
    OwnedEnv, RegisteredPath, gate_existing_storage_versions, lmdb_database_open_guard,
    open_existing_databases, rekey_short_ids_if_needed_in_txn, validate_db_manifest_set,
    validate_fast_dims, verify_existing_embedding_model, verify_existing_hnsw_config,
};
use super::open_version_keys::{
    ERR_EXISTING_NO_ANALYZER_BYPASS, NEXT_AUTHORITY_CLOCK_DOMAIN, RECEIPT_FAMILY_INDEX_VERSION,
    RECEIPT_FAMILY_INDEX_VERSION_KEY,
};
use super::vault_root_bind::open_existing_environment;

impl Store {
    /// Opens an ALREADY-INITIALIZED store at `path`, or refuses. Never creates.
    ///
    /// [`Self::open`] stays the only creation door and keeps its creation
    /// semantics untouched; the `is_new_vault` branch is unreachable from
    /// here because this path refuses a root that does not already hold both
    /// LMDB environment files.
    ///
    /// Control flow:
    ///
    /// 1. [`open_existing_environment`] binds the root as a directory
    ///    descriptor under the shared root-open guard, validates both LMDB
    ///    entries fd-relative with no symlink following, refuses through those
    ///    same descriptors unless the pair is ALREADY a complete LMDB
    ///    environment, opens the environment THROUGH the bound descriptor —
    ///    the path `mdb_env_open` itself receives is `/proc/self/fd/<dirfd>`,
    ///    never a re-resolved pathname — and asserts the pre-open root
    ///    identity again afterwards. Nothing is created and nothing is
    ///    written.
    /// 2. All 28 manifest databases are opened in a READ transaction — a
    ///    missing one is [`Error::DbManifestMismatch`] — and the storage ABI
    ///    and schema stamps must equal this engine's exactly. Committing that
    ///    read transaction writes nothing; it is how LMDB publishes the
    ///    database handles it opened.
    /// 3. The persisted HNSW shape, the nullable embedding-model identity, and
    ///    the stored analyzer manifest are compared in read transactions.
    ///    Every branch where [`Self::open`] would REPAIR one of those at open
    ///    time is a typed refusal here.
    /// 4. Only once every comparison has passed does
    ///    [`Self::reconcile_existing_open`] take the first write transaction.
    pub(crate) fn open_existing(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        analyzer: &MultilingualAnalyzer,
    ) -> Result<Self> {
        if config.skip_text_index_manifest_check {
            return Err(Error::InvalidConfig(
                ERR_EXISTING_NO_ANALYZER_BYPASS.to_owned(),
            ));
        }
        validate_fast_dims(config)?;

        let (env, registered_path) = open_existing_environment(path.as_ref(), config)?;

        let store = {
            let db_open_guard = lmdb_database_open_guard()?;
            let rtxn = env.read_txn()?;
            let raw = open_existing_databases(&env, &rtxn)?;
            validate_db_manifest_set(&env, &rtxn)?;
            gate_existing_storage_versions(&OverlayDb::canonical(raw.vault_meta), &rtxn)?;
            // A READ transaction's commit writes no page; heed documents it as
            // the way the handles this transaction opened become visible to the
            // environment instead of being dropped with the transaction.
            rtxn.commit()?;
            drop(db_open_guard);
            Self::assemble(env, raw, registered_path)?
        };

        verify_existing_hnsw_config(&store, config)?;
        verify_existing_embedding_model(&store, config.embedding_model.as_deref())?;
        crate::vault::verify_text_index_manifest(&store, analyzer)?;

        store.reconcile_existing_open()?;
        Ok(store)
    }

    /// Builds the [`Store`] handle over an opened environment and its 28 raw
    /// database handles. Shared by both open doors so neither can drift from
    /// the other's handle wiring or drop-order contract.
    pub(super) fn assemble(
        env: OwnedEnv,
        raw: RawDatabases,
        registered_path: RegisteredPath,
    ) -> Result<Self> {
        let vault_meta_view = OverlayDb::canonical(raw.vault_meta);
        let kind_registry = RwLock::new(load_structural_kind_registry(&env, &vault_meta_view)?);

        let authority_clock_domain =
            NEXT_AUTHORITY_CLOCK_DOMAIN.fetch_add(1, AtomicOrdering::Relaxed);
        let shared_env: Env = (*env).clone();
        let core = Arc::new(StoreCore {
            env: shared_env,
            raw,
            kind_registry,
            off_record_sessions: OffRecordSessionRegistry::default(),
            retrieval_blend_tuning_lock: Mutex::new(()),
            authority_clock_domain,
        });
        let owner = StoreOwner {
            core: Arc::downgrade(&core),
            env,
            authority_clock_domain,
            _registered_path: registered_path,
        };
        Ok(Self {
            entities: OverlayDb::canonical(core.raw.entities),
            edges_out: OverlayDb::canonical(core.raw.edges_out),
            edges_in: OverlayDb::canonical(core.raw.edges_in),
            vectors: OverlayDb::canonical(core.raw.vectors),
            hnsw_neighbors: OverlayDb::canonical(core.raw.hnsw_neighbors),
            hnsw_meta: OverlayDb::canonical(core.raw.hnsw_meta),
            text_postings: OverlayDb::canonical(core.raw.text_postings),
            text_meta: OverlayDb::canonical(core.raw.text_meta),
            text_forward: OverlayDb::canonical(core.raw.text_forward),
            text_bm25_field_stats: OverlayDb::canonical(core.raw.text_bm25_field_stats),
            text_doc_field_lengths: OverlayDb::canonical(core.raw.text_doc_field_lengths),
            vault_meta: OverlayDb::canonical(core.raw.vault_meta),
            ppr_cache: OverlayDb::canonical(core.raw.ppr_cache),
            ppr_cache_deps: OverlayDb::canonical(core.raw.ppr_cache_deps),
            type_index: OverlayDb::canonical(core.raw.type_index),
            temporal_occurred_start: OverlayDb::canonical(core.raw.temporal_occurred_start),
            temporal_occurred_end: OverlayDb::canonical(core.raw.temporal_occurred_end),
            temporal_learned: OverlayDb::canonical(core.raw.temporal_learned),
            temporal_long_intervals: OverlayDb::canonical(core.raw.temporal_long_intervals),
            phonetic_index: OverlayDb::canonical(core.raw.phonetic_index),
            phonetic_forward: OverlayDb::canonical(core.raw.phonetic_forward),
            short_ids: OverlayDb::canonical(core.raw.short_ids),
            short_ids_reverse: OverlayDb::canonical(core.raw.short_ids_reverse),
            sync_state: OverlayStrDb::canonical(core.raw.sync_state),
            sync_queue: OverlayDb::canonical(core.raw.sync_queue),
            attempt_records: OverlayDb::canonical(core.raw.attempt_records),
            attempt_ready: OverlayDb::canonical(core.raw.attempt_ready),
            attempt_dedupe: OverlayDb::canonical(core.raw.attempt_dedupe),
            core,
            owner,
        })
    }

    /// The FIRST write phase of an existing-only open, reached only after
    /// every root, storage, HNSW, embedding-model and analyzer comparison has
    /// already passed in a read transaction.
    ///
    /// These are the ordinary existing-vault reconciliations — the same ones
    /// [`Self::open`] performs — not open-time repairs of identity: the
    /// presentation-prefix re-key, the temporal long-interval key migration,
    /// the additive receipt-family sidecars, the empty-ledger claim-index
    /// flag, and the default policy manifest. Suppressing them would hand back
    /// a less capable vault than [`Self::open`] does.
    pub(super) fn reconcile_existing_open(&self) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        rekey_short_ids_if_needed_in_txn(&self.core.raw, &self.vault_meta, &mut wtxn)?;
        wtxn.commit()?;

        migrate_temporal_long_intervals_if_needed(
            &self.env,
            &self.hnsw_meta,
            &self.temporal_long_intervals,
        )?;
        self.ensure_receipt_family_indexes_on_open()?;
        self.ensure_gate_claim_index_flag_on_open()?;
        self.ensure_default_policy_manifest_on_open()
    }

    pub(super) fn ensure_default_policy_manifest_on_open(&self) -> Result<()> {
        // Healthy vaults should not hold the single LMDB writer slot merely to
        // inspect the manifest. Re-check under the writer before mutating.
        {
            let rtxn = self.env.read_txn()?;
            let policy = crate::gate::resolve_policy_manifest(self, &rtxn)?;
            let diagnostics = policy.diagnostics();
            if diagnostics.manifest_count > 0 || diagnostics.loaded_manifest_forces_fail_closed() {
                return Ok(());
            }
        }

        let mut wtxn = self.env.write_txn()?;
        let policy = crate::gate::resolve_policy_manifest(self, &wtxn)?;
        let diagnostics = policy.diagnostics();
        if diagnostics.manifest_count > 0 || diagnostics.loaded_manifest_forces_fail_closed() {
            return Ok(());
        }
        let id = crate::gate::default_policy_manifest_id()?;
        seed_default_policy_manifest_in_txn(
            &self.entities,
            &self.type_index,
            &self.temporal_occurred_start,
            &self.temporal_learned,
            &mut wtxn,
            &id,
        )?;
        let post_write_policy = crate::gate::resolve_policy_manifest(self, &wtxn)?;
        if post_write_policy.diagnostics().manifest_count != 1 || post_write_policy.is_fail_closed()
        {
            return Err(Error::CorruptedIndex("default policy manifest reseed"));
        }
        let read_frontier_hash = post_write_policy.read_frontier_hash()?;
        if read_frontier_hash == [0; 32] {
            return Err(Error::CorruptedIndex("default policy manifest frontier"));
        }
        let receipt = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::now(),
            created_at: crate::unix_seconds_now(),
            outcome: "reseeded_after_loss".to_owned(),
            reason_codes: vec!["gate.policy_manifest.reseeded_after_loss".to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: vec![GateSystemNoticeRecord {
                notice_type: "policy_manifest_reseeded".to_owned(),
                channel: "system".to_owned(),
                voice: "owner".to_owned(),
                audience: "owner".to_owned(),
                body: "Default policy manifest was restored after loss.".to_owned(),
                row_ref: Some(id.to_hex()),
                setting_change_offer: None,
                policy_plane: None,
                policy_version: None,
                docs_url: None,
            }],
            actor_class: "system".to_owned(),
            actor_ref: None,
            content_kind: "policy_manifest".to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: None,
            diff_handle: id.as_bytes().to_vec(),
            read_frontier_hash,
            redacted_at: None,
        };
        self.append_gate_decision_in_txn(&mut wtxn, &receipt)?;
        Ok(wtxn.commit()?)
    }

    /// Builds RCPT-1's additive `vault_meta` sidecars before an opened store
    /// becomes visible.  The marker and every sidecar commit together, so an
    /// interrupted backfill is retried in full on the next open.
    pub(super) fn ensure_receipt_family_indexes_on_open(&self) -> Result<()> {
        {
            let rtxn = self.env.read_txn()?;
            match self
                .vault_meta
                .get(&rtxn, RECEIPT_FAMILY_INDEX_VERSION_KEY)?
            {
                Some(version) if *version == [RECEIPT_FAMILY_INDEX_VERSION] => return Ok(()),
                Some(_) => return Err(Error::CorruptedIndex("receipt family index version")),
                None => {}
            }
        }

        let mut wtxn = self.env.write_txn()?;
        match self
            .vault_meta
            .get(&wtxn, RECEIPT_FAMILY_INDEX_VERSION_KEY)?
        {
            Some(version) if *version == [RECEIPT_FAMILY_INDEX_VERSION] => return Ok(()),
            Some(_) => return Err(Error::CorruptedIndex("receipt family index version")),
            None => {}
        }

        // The group aliases below resolve through the attempt run index, so build
        // it first.  Collect before writing to avoid mutating a DB while its
        // iterator is live.
        let mut attempts = Vec::new();
        for row in self.attempt_records.iter(&wtxn)? {
            let (key, raw) = row?;
            let id = crate::attempt_queue::AttemptId::from_bytes(&key)?;
            attempts.push(crate::attempt_queue::decode_record(&raw, id)?);
        }
        for attempt in &attempts {
            self.put_attempt_run_index_in_txn(
                &mut wtxn,
                attempt.run_id.as_deref(),
                attempt.id.as_bytes(),
            )?;
        }

        // Collect before writing (LMDB forbids mutating a DB while one of its
        // iterators is live), but keep only what the grant-ref index row needs
        // — not the whole decoded ledger.
        let mut grant_refs = Vec::new();
        self.for_each_gate_decision_in_txn(&wtxn, |record| {
            if let Some(grant_ref) = record.grant_ref {
                grant_refs.push((grant_ref, record.decision_id));
            }
            Ok(())
        })?;
        for (grant_ref, decision_id) in &grant_refs {
            self.put_gate_decision_grant_ref_index_row_in_txn(&mut wtxn, grant_ref, *decision_id)?;
        }

        let mut pending = Vec::new();
        let upper = pending_gate_consent_upper_bound();
        for row in self.vault_meta.range(
            &wtxn,
            &(
                std::ops::Bound::Included(PENDING_GATE_CONSENT_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            let claim_id = pending_gate_consent_claim_id_from_key(&key)?;
            let record = decode_pending_gate_consent(&value)?;
            if record.claim_id != claim_id {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            pending.push(record);
        }
        for record in &pending {
            self.put_pending_gate_consent_indexes_in_txn(&mut wtxn, record)?;
        }

        self.vault_meta.put(
            &mut wtxn,
            RECEIPT_FAMILY_INDEX_VERSION_KEY,
            &[RECEIPT_FAMILY_INDEX_VERSION],
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Sets the ERASE-A (ONE-1637) backfill-complete flag for the vaults whose
    /// backfill is trivially empty: a ledger with no rows is, vacuously, fully
    /// indexed. Covers brand-new vaults and existing never-gated ones without a
    /// maintenance run. A populated ledger leaves the flag unset, which costs
    /// discovery speed (scan fallback) and never correctness.
    pub(super) fn ensure_gate_claim_index_flag_on_open(&self) -> Result<()> {
        // One predicate, checked twice: the write txn re-confirms under lock
        // what the optimistic read txn saw.
        let needs_flag = |txn: &RoTxn<'_>| -> Result<bool> {
            Ok(
                !self.gate_decision_claim_index_backfill_complete_in_txn(txn)?
                    && self.gate_decision_ledger_is_empty_in_txn(txn)?,
            )
        };
        {
            let rtxn = self.env.read_txn()?;
            if !needs_flag(&rtxn)? {
                return Ok(());
            }
        }

        let mut wtxn = self.env.write_txn()?;
        if !needs_flag(&wtxn)? {
            return Ok(());
        }
        self.vault_meta.put(
            &mut wtxn,
            GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
            &GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Single cursor seek over the primary ledger range.
    pub(super) fn gate_decision_ledger_is_empty_in_txn(&self, txn: &RoTxn<'_>) -> Result<bool> {
        let upper = gate_decision_upper_bound();
        Ok(self
            .vault_meta
            .range(
                txn,
                &(
                    std::ops::Bound::Included(GATE_DECISION_KEY_PREFIX),
                    std::ops::Bound::Excluded(upper.as_slice()),
                ),
            )?
            .next()
            .transpose()?
            .is_none())
    }
}
