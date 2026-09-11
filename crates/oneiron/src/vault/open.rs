//! Vault open and bootstrap: open doors, privacy posture and live-window attachment.

use super::Vault;
use super::doctor_manifest::{
    discover_analyzer, handshake_text_index_manifest, text_index_is_empty,
    write_text_index_manifest_if_empty,
};
use crate::analyzer::MultilingualAnalyzer;
#[cfg(feature = "test-support")]
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::config::{HostingPrivacyPosture, VaultConfig};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::store::{DefaultPolicySeedMode, Store, VaultWriterLease};
#[cfg(feature = "test-support")]
use crate::temporal::TimeRange;
use std::path::Path;

const MIN_MAP_SIZE_BYTES: usize = 1 << 20;

/// Config preconditions every opener checks before the environment is mapped.
fn validate_open_config(config: &VaultConfig) -> Result<()> {
    // FIRST, before any other gate and before any opener reaches `Store::open`:
    // an unsupported posture/custody pairing must never bring a storage
    // environment into existence. Every door (`open`, `open_existing`,
    // `open_seeded`, and the test-only ABI opener) funnels through here.
    config.privacy.validate()?;
    if config.dimensions == 0 {
        return Err(Error::InvalidConfig(
            "dimensions must be greater than zero".to_owned(),
        ));
    }
    if config.hnsw.m_max_0 == 0 {
        return Err(Error::InvalidConfig(
            "hnsw m_max_0 must be greater than zero".to_owned(),
        ));
    }
    if config.map_size < MIN_MAP_SIZE_BYTES {
        return Err(Error::InvalidConfig(format!(
            "map_size must be at least {MIN_MAP_SIZE_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Namespace the embedded default owner actor's id is derived from
/// (ONE-1441 WIRE-P1).
///
/// Pinned: changing it changes the owner id every embedded vault already
/// carries, which would strand every claim that names the old one.
const EMBEDDED_OWNER_ACTOR_NAMESPACE: &[u8] = b"oneiron 2026-08 embedded-owner-actor v1";

/// `name` of the embedded owner PERSON — the one field the PERSON projection
/// profile reads at every profile level.
const EMBEDDED_OWNER_ACTOR_NAME: &str = "Vault owner";

/// The pinned, namespace-derived id of the embedded default owner actor.
///
/// Derived rather than literal so the derivation is auditable from the
/// namespace above, and stamped with the RFC 9562 version-8 (custom) and
/// variant bits so the value is a well-formed UUID like every other
/// [`EntityId`] — which also guarantees it can never collide with the
/// all-zero/all-`0xFF` reserved sentinels [`EntityId::from_bytes`] rejects.
pub(super) fn embedded_owner_actor_id() -> Result<EntityId> {
    let digest = blake3::hash(EMBEDDED_OWNER_ACTOR_NAMESPACE);
    let mut bytes = [0u8; ENTITY_ID_LEN];
    bytes.copy_from_slice(&digest.as_bytes()[..ENTITY_ID_LEN]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_bytes(bytes)
}

/// Encodes the minimal PERSON body the bootstrap writes.
pub(super) fn encode_embedded_owner_actor_body() -> Result<Vec<u8>> {
    let value = rmpv::Value::Map(vec![(
        rmpv::Value::from("name"),
        rmpv::Value::from(EMBEDDED_OWNER_ACTOR_NAME),
    )]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &value)
        .map_err(|_| Error::InvariantViolation("embedded owner actor body encode"))?;
    Ok(encoded)
}

impl Vault {
    // NOTE (ONE-1133): the bare non-txn `purge_entity_active_store` wrapper
    // was removed — both sync replay surfaces now route through the
    // reason-aware `apply_replayed_tombstone`, and a bare purge entry point
    // would be an invitation to bypass the ARCH-0038 reason semantics.

    // -----------------------------------------------------------------
    // ARCH-0050 R6 L2 code-memory doors (ONE-1608).
    //
    // Every wrapper here opens ONE transaction, delegates to the internal
    // `crate::code_memory` implementation, and commits exactly once on
    // success. None exposes `Store`, `RoTxn`, or `RwTxn`; the public
    // contract suite reaches only these methods.
    // -----------------------------------------------------------------

    // Read/write/list helpers intentionally remain behind `feature = "sync"`
    // instead of `cfg(test)` because the sync bridge regression suite is an
    // integration test crate. Production bridge code still uses direct
    // transactional `sync_state` access when multiple keys must update
    // atomically.

    // ─── Tree Query API ───────────────────────────────────────

    /// Opens or creates a vault at `path`.
    ///
    /// Open-time compatibility gates run in the canonical order documented at
    /// the top of [`crate::store`]: `Store::open` runs the storage gates
    /// (`vault_meta` created first → ABI gate → schema gate → DB-manifest set
    /// → DB opens → HNSW/dimension preflight → embedding-model preflight),
    /// then this function runs the analyzer / BM25F text-index handshake and
    /// the self-contained SKILL content-hash migration against `vault_meta`.
    /// The
    /// [`VaultConfig::skip_text_index_manifest_check`] escape hatch bypasses
    /// only that final handshake (and marks a populated text index untrusted
    /// so text reads/writes fail closed until
    /// [`crate::maintain::MaintenanceBuilder::clear_text_index`] commits).
    ///
    /// Every gate fails closed: the first failing gate returns its typed
    /// [`Error`] and no usable `Vault` handle is constructed.
    ///
    /// This and [`Self::open_owned`] use the create-capable gates, which may
    /// repair an existing vault at open time. Callers that must reopen
    /// an already-initialized vault, and must never bring one into existence,
    /// use [`Self::open_existing`].
    pub fn open(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        // Production open always seeds the default policy manifest — the seed
        // decision is a compile-time `true` here, not a config field, so no
        // consumer build (including `--all-features`) can open a vault that
        // skips the default consent/policy gate.
        Self::open_seeded(path, config, DefaultPolicySeedMode::Required)
    }

    /// Opens a process-owned vault. Server and embedded SDK owners use this
    /// door so the writer lease covers startup, all Arc holders, and shutdown.
    /// Low-level `open` remains available for caller-managed engine lifetimes.
    pub fn open_owned(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        validate_open_config(&config)?;
        std::fs::create_dir_all(path.as_ref())?;
        let canonical = path.as_ref().canonicalize()?;
        let lease = VaultWriterLease::acquire(&canonical)?;
        let store = Store::open_with_writer_lease(&canonical, &config, &lease)?;
        let mut vault = Self::finish_open(store, config, DefaultPolicySeedMode::Required)?;
        vault.writer_lease = Some(lease);
        Ok(vault)
    }

    /// Process ownership, when opened through [`Self::open_owned`].
    #[must_use]
    pub fn writer_lease(&self) -> Option<&VaultWriterLease> {
        self.writer_lease.as_ref()
    }

    /// Opens an ALREADY-INITIALIZED vault at `path`, or refuses.
    ///
    /// [`Self::open`] remains the ONLY door that creates a vault; this one has
    /// no creation branch at all. It binds the root as a directory-descriptor
    /// capability before LMDB sees it, opens the environment through that
    /// descriptor so a renamed or replaced pathname cannot redirect it, and
    /// re-asserts the bound identity afterwards.
    ///
    /// Every comparison — the root, the storage ABI and schema stamps, the
    /// ARCH-0019 database set, the persisted HNSW shape, the nullable
    /// embedding-model identity, and the analyzer manifest — runs in a READ
    /// transaction before the open takes its first write transaction. Each
    /// branch where [`Self::open`] would repair an existing vault at open time
    /// (stamping a missing model id, writing a missing HNSW record, rewriting
    /// the analyzer manifest of an empty text index) is a typed refusal here,
    /// so a disagreeing vault is left byte-identical.
    ///
    /// An absent, empty, incomplete, unrelated, symlinked, aliased,
    /// hard-linked, or replaced root fails closed with no filesystem effect.
    /// Once every comparison passes, the ordinary existing-vault open writes
    /// run exactly as they do for [`Self::open`] — including the idempotent
    /// seeded system-agent roster reconcile — so a verified vault is no less
    /// capable than one opened through the create-capable door.
    pub fn open_existing(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        validate_open_config(&config)?;
        // Discovered from the operator's trusted dictionary roots, never from
        // the vault's own bytes, and passed into the store open so the exact
        // analyzer comparison happens before any write transaction exists.
        let analyzer = discover_analyzer(&config)?;
        let store = Store::open_existing(path, &config, &analyzer)?;
        Self::assemble_open(
            store,
            config,
            analyzer,
            true,
            DefaultPolicySeedMode::Required,
        )
    }

    /// Opens a vault WITHOUT seeding the default policy manifest. TEST-SUPPORT
    /// ONLY — never call this from production code. It is compiled only under
    /// the `test-support` feature (enabled via this crate's own dev-dependency
    /// for the effect-spine integration oracle), hidden from the public docs,
    /// and named so it cannot be reached by accident. The production `open`
    /// above hardcodes seeding, so the normal, default way to open a vault can
    /// never skip the policy/consent gate; this explicit, doc-hidden, test-named
    /// opener is the only way to obtain an unseeded vault, and only when the test
    /// feature is deliberately enabled — the standard Rust `test-util`-feature
    /// pattern (cf. tokio's `test-util`).
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_unseeded_for_test(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        Self::open_seeded(path, config, DefaultPolicySeedMode::TestUnseeded)
    }

    /// Adds one actor-bound Imported source permit to a stock default manifest.
    /// TEST-SUPPORT ONLY: the cap is the unstamped sensitivity floor, with the
    /// required receipt/warning flags. Every other policy field stays unchanged.
    /// Claims still use the normal write gate; this grants no review approval,
    /// actor ceiling, source relabeling, or raw storage access.
    ///
    /// Refuses a missing or already customized default manifest rather than
    /// replacing caller policy. Other installed manifests remain in the fold.
    /// `Vault::open` never calls this, even when `test-support` is enabled.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn install_imported_source_permit_for_test(&self, actor: EntityId) -> Result<()> {
        use crate::batch::{BatchOp, apply_ops};
        use crate::claim::{ClaimSource, UNSTAMPED_CLAIM_SENSITIVITY_BAND};
        use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
        use rmpv::Value;

        let id = crate::gate::default_policy_manifest_id()?;
        let default = crate::gate::default_policy_manifest();
        let mut manifest = rmpv::decode::read_value(&mut std::io::Cursor::new(&default))
            .map_err(|_| Error::InvariantViolation("decode default test policy"))?;
        let Value::Map(entries) = &mut manifest else {
            return Err(Error::InvariantViolation(
                "default test policy is not a map",
            ));
        };
        let Some(Value::Map(rows)) = entries
            .iter_mut()
            .find_map(|(key, value)| (key.as_str() == Some("source_trust")).then_some(value))
        else {
            return Err(Error::InvariantViolation(
                "default test policy has no source trust",
            ));
        };
        if rows
            .iter()
            .any(|(key, _)| key.as_str() == Some(ClaimSource::Imported.as_str()))
        {
            return Err(Error::InvariantViolation(
                "default test policy already covers Imported",
            ));
        }
        rows.push((
            Value::from(ClaimSource::Imported.as_str()),
            Value::Map(vec![
                (Value::from("actor_ref"), Value::from(actor.to_hex())),
                (
                    Value::from("max_auto_sensitivity"),
                    Value::from(u64::from(UNSTAMPED_CLAIM_SENSITIVITY_BAND)),
                ),
                (Value::from("receipted"), Value::Boolean(true)),
                (Value::from("warned"), Value::Boolean(true)),
            ]),
        ));
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &manifest)
            .map_err(|_| Error::InvariantViolation("encode Imported test policy"))?;

        self.with_write_txn(|wtxn| {
            let raw =
                self.store
                    .entities
                    .get(wtxn, id.as_bytes())?
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
            // The test-only capability is confined to this fixed manifest Put.
            // Use the existing maintenance install path, not raw database writes
            // or replicated replay. Index maintenance and structural checks run.
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                wtxn,
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
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                true,
                true,
            )
        })
    }

    /// Rebinds the stock Generated source permit to one test actor.
    /// TEST-SUPPORT ONLY: only `actor_ref` changes; the sensitivity cap,
    /// receipt/warning flags, and every other policy field stay unchanged.
    /// Claims still pass the normal gate and Dreamer validation. This grants
    /// no actor ceiling, review approval, or source relabeling.
    ///
    /// Refuses a missing or customized default manifest. Other installed
    /// manifests remain in the fold. `Vault::open` never calls this helper.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn install_generated_source_permit_for_test(&self, actor: EntityId) -> Result<()> {
        use crate::batch::{BatchOp, apply_ops};
        use crate::claim::ClaimSource;
        use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
        use rmpv::Value;

        let id = crate::gate::default_policy_manifest_id()?;
        let default = crate::gate::default_policy_manifest();
        let mut manifest = rmpv::decode::read_value(&mut std::io::Cursor::new(&default))
            .map_err(|_| Error::InvariantViolation("decode default test policy"))?;
        let Value::Map(entries) = &mut manifest else {
            return Err(Error::InvariantViolation(
                "default test policy is not a map",
            ));
        };
        let Some(Value::Map(rows)) = entries
            .iter_mut()
            .find_map(|(key, value)| (key.as_str() == Some("source_trust")).then_some(value))
        else {
            return Err(Error::InvariantViolation(
                "default test policy has no source trust",
            ));
        };
        let Some(Value::Map(permit)) = rows.iter_mut().find_map(|(key, value)| {
            (key.as_str() == Some(ClaimSource::Generated.as_str())).then_some(value)
        }) else {
            return Err(Error::InvariantViolation(
                "default test policy has no Generated permit",
            ));
        };
        let Some(actor_ref) = permit
            .iter_mut()
            .find_map(|(key, value)| (key.as_str() == Some("actor_ref")).then_some(value))
        else {
            return Err(Error::InvariantViolation(
                "default Generated test permit has no actor binding",
            ));
        };
        *actor_ref = Value::from(actor.to_hex());
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &manifest)
            .map_err(|_| Error::InvariantViolation("encode Generated test policy"))?;

        self.with_write_txn(|wtxn| {
            let raw =
                self.store
                    .entities
                    .get(wtxn, id.as_bytes())?
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
            // One fixed maintenance Put, with the default-policy comparison
            // in the same transaction. No raw storage or replay bypass.
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                wtxn,
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
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                true,
                true,
            )
        })
    }

    fn open_seeded(
        path: impl AsRef<Path>,
        config: VaultConfig,
        seed_mode: DefaultPolicySeedMode,
    ) -> Result<Self> {
        validate_open_config(&config)?;
        let store = match seed_mode {
            DefaultPolicySeedMode::Required => Store::open(path, &config)?,
            #[cfg(feature = "test-support")]
            DefaultPolicySeedMode::TestUnseeded => Store::open_unseeded_for_test(path, &config)?,
        };
        Self::finish_open(store, config, seed_mode)
    }

    /// Opens a vault with `engine_storage_abi` standing in for
    /// [`crate::store::STORAGE_ABI_VERSION`], so a vault stamped at one ABI
    /// version can be reopened by an "engine" carrying another and the
    /// fail-closed handshake observed end to end (ARCH-0052 D9 / ONE-1732).
    ///
    /// TEST-ONLY, and structurally so: `#[cfg(test)]` keeps it out of every
    /// built artifact and `pub(crate)` keeps it inside this crate, so no
    /// production build contains an ABI override at all. [`Vault::open`] and
    /// [`Store::open`] take no ABI argument and always gate on the compiled
    /// constant — there is no caller-supplied path around the gate.
    #[cfg(test)]
    pub(crate) fn open_with_storage_abi_version_for_test(
        path: impl AsRef<Path>,
        config: VaultConfig,
        engine_storage_abi: u16,
    ) -> Result<Self> {
        validate_open_config(&config)?;
        let store =
            Store::open_with_storage_abi_version_for_test(path, &config, engine_storage_abi)?;
        Self::finish_open(store, config, DefaultPolicySeedMode::Required)
    }

    /// Everything after the storage gates: analyzer discovery, the text-index
    /// handshake, first-open seeding, and the pre-handle censuses. Split out of
    /// [`Self::open_seeded`] so the test-only ABI-injection opener above shares
    /// this body instead of duplicating it.
    fn finish_open(
        store: Store,
        config: VaultConfig,
        seed_mode: DefaultPolicySeedMode,
    ) -> Result<Self> {
        let analyzer = discover_analyzer(&config)?;
        let text_index_trusted = if config.skip_text_index_manifest_check {
            // Bypass-on-empty-index is fine — there are no postings under any
            // analyzer manifest yet, so anything we write next will be the
            // first authoritative state. Bypass-on-populated-index leaves the
            // on-disk postings potentially analyzer-incompatible with the
            // in-memory analyzer; mark the index untrusted so search fails
            // closed until `clear_text_index` runs. The same residual-rows
            // check used by the handshake applies — `total_docs == 0` alone
            // can still hide stale postings/forward/length/stats rows.
            let rtxn = store.env.read_txn()?;
            let empty = text_index_is_empty(&store, &rtxn)?;
            drop(rtxn);
            if empty {
                let mut wtxn = store.env.write_txn()?;
                write_text_index_manifest_if_empty(&store, &mut wtxn, &analyzer)?;
                wtxn.commit()?;
            }
            empty
        } else {
            handshake_text_index_manifest(&store, &analyzer)?;
            true
        };
        Self::assemble_open(store, config, analyzer, text_index_trusted, seed_mode)
    }

    /// Everything both open doors share once the text-index state is settled:
    /// the seeded system-agent reconcile, the handle itself, and the
    /// content-hash index backfill. Split out so the existing-only door, whose
    /// analyzer gate already ran read-only inside `Store::open_existing`,
    /// reaches the same post-gate capabilities without a second handshake.
    fn assemble_open(
        store: Store,
        config: VaultConfig,
        analyzer: MultilingualAnalyzer,
        text_index_trusted: bool,
        seed_mode: DefaultPolicySeedMode,
    ) -> Result<Self> {
        // ONE-1890: the seeded system-agent roster reconciles on EVERY seeded
        // open, fresh and existing, in its own write transaction before any
        // caller holds the handle. Missing rows are created with pinned
        // deterministic ids; existing rows are never overwritten, so a user's
        // edits and their `enabled = false` survive every reopen. Test-only
        // unseeded opens skip it and drive the in-transaction seam directly.
        if matches!(seed_mode, DefaultPolicySeedMode::Required) {
            let mut wtxn = store.env.write_txn()?;
            crate::agent_def::seed_system_agent_definitions(
                &store,
                &config,
                &analyzer,
                &mut wtxn,
                text_index_trusted,
            )?;
            wtxn.commit()?;
        }

        // Cloned before `config` moves into the handle: the retained copy is
        // the pairing `validate_open_config` already accepted.
        let privacy = config.privacy.clone();
        let vault = Self {
            store,
            config,
            analyzer,
            writer_lease: None,
            privacy,
            text_index_trusted: std::sync::atomic::AtomicBool::new(text_index_trusted),
            // Every vault opens FULL; only an explicit ctl-driven shed parks
            // it, and only an inbound resume unparks it.
            slim: crate::slim::SlimController::default(),
            #[cfg(feature = "sync")]
            live_window_manager: std::sync::Mutex::new(std::sync::Weak::new()),
            #[cfg(feature = "sync")]
            live_window_manager_attached: std::sync::atomic::AtomicBool::new(false),
        };
        // Rebuilds the content-hash → holder index (import/sync dedup) when it
        // is missing or stale; completes before any caller receives a usable
        // handle. ONE-1741 dropped the verdict-dedup half — scan verdicts now
        // anchor to the content bytes, so only the holder index is rebuilt.
        crate::skill_hub::backfill_content_hash_index_if_needed(&vault)?;
        Ok(vault)
    }

    /// Deployment posture this vault was opened under.
    ///
    /// Read-only and honest: it reports the posture the opener validated, and
    /// there is no posture that claims a hosting operator cannot read a vault
    /// it stores.
    #[must_use]
    pub fn privacy_posture(&self) -> HostingPrivacyPosture {
        self.privacy.posture
    }

    /// Short description of who holds the key for this vault:
    /// `host-readable` when hosted, `owner-held-key` when self-hosted locally.
    #[must_use]
    pub fn privacy_posture_label(&self) -> &'static str {
        self.privacy.honest_label()
    }

    /// True when a hosting operator can read this vault's contents.
    #[must_use]
    pub fn is_host_readable(&self) -> bool {
        self.privacy.host_readable()
    }

    /// This vault's content-free diagnostic counters.
    ///
    /// The counters belong to the vault, not to the process, so a delta read
    /// here is exactly what this vault recorded — a second vault open in the
    /// same process cannot move it.
    #[must_use]
    pub fn diagnostics(&self) -> &crate::store::Diagnostics {
        &self.store.diagnostics
    }

    /// This vault's test seams.
    ///
    /// Same ownership rule as [`Self::diagnostics`]: a test arms the vault it
    /// opened, so a sibling test in the same `cargo test --lib` binary cannot
    /// reach it and neither of them needs a serial lock.
    #[cfg(test)]
    pub(crate) fn test_hooks(&self) -> &crate::store::TestHooks {
        &self.store.test_hooks
    }

    /// Registers the production window manager as the live-window delete
    /// router (M4-10 / ONE-1135). Called by
    /// [`crate::sync::manager::WindowManager::attach_to_vault`].
    #[cfg(feature = "sync")]
    pub(crate) fn attach_live_window_manager(
        &self,
        manager: std::sync::Weak<crate::sync::WindowManager>,
    ) {
        self.live_window_manager_attached
            .store(true, std::sync::atomic::Ordering::Release);
        *self
            .live_window_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = manager;
    }

    /// Returns the registry-owned live window for `key` — paired with the
    /// manager's [`crate::sync::bridge::Materializer`], so the delete path
    /// can serialize its live-doc tombstone commit against Observer B
    /// callbacks — if a manager is attached AND currently has the window
    /// open. Lookup only — never opens a window (a delete must not fault a
    /// month into memory).
    #[cfg(feature = "sync")]
    pub(crate) fn live_window(
        &self,
        key: &crate::sync::WindowKey,
    ) -> Option<(
        std::sync::Arc<crate::sync::window::LoadedWindow>,
        std::sync::Arc<crate::sync::bridge::Materializer>,
        std::sync::Arc<crate::sync::WindowManager>,
    )> {
        let manager = self
            .live_window_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade()?;
        let window = manager.window(key)?;
        Some((
            window,
            std::sync::Arc::clone(manager.materializer()),
            manager,
        ))
    }

    /// Returns every registry-owned live window without faulting any closed
    /// month into memory. Promotion uses this because a newly unfenced target
    /// can release incident edges whose source belongs to another open month.
    #[cfg(feature = "sync")]
    pub(crate) fn live_windows(&self) -> Vec<std::sync::Arc<crate::sync::window::LoadedWindow>> {
        let Some(manager) = self
            .live_window_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade()
        else {
            return Vec::new();
        };
        manager
            .loaded_keys()
            .into_iter()
            .filter_map(|key| manager.window(&key))
            .collect()
    }

    /// Whether `key` is currently unsafe for sweep compaction: registered in
    /// an attached manager OR still retained by an outstanding orphaned
    /// `Arc<LoadedWindow>` after deregistration. A live doc holds the full op
    /// history in memory, and its next full-snapshot persist would rewrite
    /// that history over a shallow-compacted `d:w:` row, so the sweep must
    /// never compact while such a handle may persist.
    #[cfg(feature = "sync")]
    pub(crate) fn live_window_for_sweep(&self, key: &crate::sync::WindowKey) -> bool {
        let attached = self
            .live_window_manager_attached
            .load(std::sync::atomic::Ordering::Acquire);
        let manager = match self.live_window_manager.lock() {
            Ok(manager) => manager,
            Err(_) => return true,
        };
        match manager.upgrade() {
            Some(manager) => manager.window_live_for_sweep(key),
            None => attached,
        }
    }
}
