//! Shared harnesses and fixtures for the memory acceptance tests.

use super::*;

/// A vault wired for the fix-leg 7 publish-boundary regressions: an attached
/// peer channel plus, on the LIVE leg, an open registry window — so both halves
/// of "did this delete publish?" are observable, the shared live doc and the
/// outbound route.
///
/// `window: None` is the TRANSIENT leg (window never opened), where the publish
/// takes the import-merge path instead of the shared doc. It is a genuinely
/// different code path through `write_crdt_tombstone`, so every regression here
/// runs both.
/// Vector width for the orphan-residue fixture. Small and arbitrary — the
/// headerless delete door only cares that a `vectors` row exists.
#[cfg(feature = "sync")]
pub(super) const RESIDUE_VECTOR_DIMS: usize = 4;

#[cfg(feature = "sync")]
pub(super) struct PublishBoundaryHarness {
    _dir: tempfile::TempDir,
    pub(super) vault: std::sync::Arc<crate::Vault>,
    window: Option<std::sync::Arc<crate::sync::window::LoadedWindow>>,
    window_key: crate::sync::WindowKey,
    pub(super) outbound: tokio::sync::mpsc::UnboundedReceiver<crate::sync::types::LocalUpdate>,
    _manager: std::sync::Arc<crate::sync::WindowManager>,
}

#[cfg(feature = "sync")]
impl PublishBoundaryHarness {
    pub(super) fn open(label: &str, live_window: bool) -> Self {
        Self::open_with_config(label, live_window, VaultConfig::default())
    }

    /// [`Self::open`] with an embedding model declared, which
    /// `ensure_model_id_for_vector_write` requires before any vector write —
    /// the only way to build the orphan-vector residue the headerless delete
    /// door needs.
    pub(super) fn open_for_vector_residue(label: &str, live_window: bool) -> Self {
        Self::open_with_config(
            label,
            live_window,
            VaultConfig {
                embedding_model: Some("test/model@v1".to_owned()),
                dimensions: RESIDUE_VECTOR_DIMS,
                ..VaultConfig::default()
            },
        )
    }

    pub(super) fn open_with_config(label: &str, live_window: bool, config: VaultConfig) -> Self {
        use std::sync::Arc;

        use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(crate::Vault::open(dir.path(), config).expect("open vault"));
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            label,
        ));
        let (tx, outbound) = tokio::sync::mpsc::unbounded_channel();
        manager.outbound().attach(tx);
        // Every fixture entity is put at `learned_at = 1`, so this is the window
        // the headerful deletes address.
        let window_key = WindowKey::from_timestamp(1);
        // `open_window` also attaches the manager to the vault, which is what
        // routes deletes at all — the transient leg does that explicitly so its
        // outbound assertions mean something.
        let window = if live_window {
            Some(
                manager
                    .open_window(&window_key)
                    .expect("open live deletion window"),
            )
        } else {
            manager.attach_to_vault();
            None
        };
        Self {
            _dir: dir,
            vault,
            window,
            window_key,
            outbound,
            _manager: manager,
        }
    }

    /// Whether the shared live doc carries a tombstone for `id`. Vacuously
    /// false on the transient leg, which has no live doc to carry one.
    pub(super) fn live_doc_tombstoned(&self, id: &EntityId) -> bool {
        self.window
            .as_ref()
            .is_some_and(|window| window.doc.get_map("tombstones").get(&id.to_hex()).is_some())
    }

    /// Whether the persisted `d:w:` snapshot carries a tombstone for `id`.
    /// A window with no snapshot row yet trivially carries none.
    pub(super) fn snapshot_tombstoned(&self, id: &EntityId) -> bool {
        let Some(snapshot) = self
            .vault
            .sync_state_get(&format!("d:w:{}", self.window_key))
            .expect("read persisted window snapshot")
        else {
            return false;
        };
        crate::sync::loro_support::doc_from_snapshot(&snapshot)
            .expect("persisted snapshot decodes")
            .get_map("tombstones")
            .get(&id.to_hex())
            .is_some()
    }

    /// Whether any pending `u:w:` update row replays a tombstone for `id`.
    pub(super) fn update_rows_tombstoned(&self, id: &EntityId) -> bool {
        self.vault
            .sync_state_keys_with_prefix(&format!("u:w:{}:", self.window_key))
            .expect("read pending update rows")
            .into_iter()
            .any(|update_key| {
                let bytes = self
                    .vault
                    .sync_state_get(&update_key)
                    .expect("read update row")
                    .expect("update row exists");
                let replayed = crate::sync::schema::create_window_doc("probe", &self.window_key);
                crate::sync::loro_support::import_doc(&replayed, &bytes)
                    .expect("update row imports");
                replayed.get_map("tombstones").get(&id.to_hex()).is_some()
            })
    }

    /// Whether any queued `q:` row replays a tombstone for `id`. DRAINS the
    /// queue, so call it once per subject.
    pub(super) fn queue_rows_tombstoned(&self, id: &EntityId) -> bool {
        let queue = crate::sync::SyncQueue::new(std::sync::Arc::clone(&self.vault))
            .expect("open sync queue");
        queue
            .drain_updates()
            .expect("drain queued updates")
            .into_iter()
            .any(|queued| {
                let replayed = crate::sync::schema::create_window_doc("probe", &self.window_key);
                crate::sync::loro_support::import_doc(&replayed, &queued.encoded)
                    .expect("queued update imports");
                replayed.get_map("tombstones").get(&id.to_hex()).is_some()
            })
    }

    /// Whether a `pt:` pending-tombstone marker for `id` survives — the
    /// replayable carrier a refusal must withdraw. Checks BOTH candidate window
    /// labels: the soft arm addresses `learned_at`'s window and the headerless
    /// leg addresses NOW's, and at a month boundary those differ.
    pub(super) fn replayable_pending_marker(&self, id: &EntityId) -> bool {
        [
            self.window_key.as_str().to_owned(),
            crate::deletion::window_label_from_timestamp(crate::unix_seconds_now()),
        ]
        .iter()
        .any(|window_label| {
            self.vault
                .sync_state_get(&crate::deletion::pending_tombstone_key(window_label, id))
                .expect("read pt: marker")
                .is_some()
        })
    }

    /// Every no-publish assertion in one call, for a delete that must have been
    /// refused BEFORE its linearization point.
    pub(super) fn assert_nothing_published(&mut self, id: &EntityId, context: &str) {
        assert!(
            !self.live_doc_tombstoned(id),
            "{context}: a refused delete must not leave a tombstone in the shared live doc"
        );
        assert!(
            self.outbound.try_recv().is_err(),
            "{context}: a refused delete must not route an outbound update to the peer"
        );
        assert!(
            !self.snapshot_tombstoned(id),
            "{context}: the refused tombstone must not reach the d:w: snapshot"
        );
        assert!(
            !self.update_rows_tombstoned(id),
            "{context}: the refused tombstone must not reach a u:w: carrier"
        );
        assert!(
            !self.queue_rows_tombstoned(id),
            "{context}: the refused tombstone must not reach a delete-bearing q: row"
        );
        assert!(
            !self.replayable_pending_marker(id),
            "{context}: the refused tombstone must not survive as a replayable pt: marker"
        );
    }
}

/// Parks a gated delete at `step`, commits `revoke` while it waits, and returns
/// the delete's result. The two-phase shape is forced: the steps around these
/// seams take the LMDB write lock themselves, so the revocation cannot be
/// pre-staged in a held txn — the deleter must announce while holding nothing.
///
/// The rendezvous belongs to `vault`, so this needs no serial lock: a sibling
/// test running in the same binary armed a different vault.
pub(super) fn safe_delete_with_revocation_at(
    vault: &std::sync::Arc<crate::Vault>,
    owner: EntityId,
    target: EntityId,
    reason: SafeDeleteReason,
    step: crate::deletion::DeleteRendezvous,
    revoke: crate::authority::AuthorityLogEntry,
) -> MemoryResult<DeleteReceipt> {
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
    vault
        .test_hooks()
        .install_delete_rendezvous(step, target, arrived_tx, resume_rx);

    std::thread::scope(|scope| {
        let vault_ref = vault.as_ref();
        let deleter =
            scope.spawn(move || facade_for(vault_ref, owner).safe_delete(&target.to_hex(), reason));
        arrived_rx
            .recv()
            .expect("the deleter must reach the installed rendezvous");
        vault
            .put_authority_log_entries(&[(revoke, test_time(3), 3)])
            .expect("commit the revocation while the deleter is parked");
        resume_tx.send(()).expect("release the deleter");
        deleter.join().expect("deleter thread must not panic")
    })
}

/// Every durable artifact a REFUSED sync-disabled delete must not leave behind,
/// in one call. Distinct from `PublishBoundaryHarness::assert_nothing_published`,
/// which pins the CRDT carriers a `sync` build could leak; without the feature
/// there are no such carriers, and the whole surface is local:
///
/// - `pt:{window}:{id}` — the pending-tombstone marker. THE one that matters:
///   it holds the verbatim 25 B tombstone wire value, and
///   `sync::window::replay_pending_tombstones` turns it into a published
///   tombstone on the next sync-enabled boot. A revoked owner leaving one behind
///   has published an unauthorized deletion, just deferred.
/// - `dt:{id}` — the permanent local hard-delete marker. It is
///   presence-consulted by the materialization gates, so a stray one bricks the
///   id against every future write.
/// - `h:` sweep rows + REDACTION_AUDIT receipts — a refused delete audits no
///   erasure, because none happened.
/// - gate decisions — the authority ledger must not record an `allow` for a
///   deletion the authority refused.
///
/// Both window labels are probed for `pt:`: the headerful arms address
/// `learned_at`'s window and the headerless leg addresses NOW's, and at a month
/// boundary those differ.
#[cfg(not(feature = "sync"))]
pub(super) fn assert_no_local_delete_artifacts(vault: &crate::Vault, id: &EntityId, context: &str) {
    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;

    let rtxn = vault.store.env.read_txn().expect("read txn");
    for window_label in [
        crate::deletion::window_label_from_timestamp(1),
        crate::deletion::window_label_from_timestamp(crate::unix_seconds_now()),
    ] {
        assert!(
            vault
                .store
                .sync_state
                .get(
                    &rtxn,
                    &crate::deletion::pending_tombstone_key(&window_label, id)
                )
                .expect("read pt: marker")
                .is_none(),
            "{context}: a refused delete must leave no replayable pt: marker \
             (a sync-enabled boot would replay it into the very publication the \
             refusal denied)"
        );
    }
    assert!(
        !vault
            .local_hard_delete_marker_exists_in_txn(&rtxn, id)
            .expect("read dt: marker"),
        "{context}: a refused delete must write no dt: local hard-delete marker"
    );
    assert!(
        vault
            .store
            .sync_queue
            .prefix_iter(&rtxn, crate::deletion::HARD_ERASE_SWEEP_PREFIX)
            .expect("iter sweep rows")
            .next()
            .is_none(),
        "{context}: a refused delete must queue no h: hard-erase sweep row"
    );
    drop(rtxn);
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("list receipts")
            .is_empty(),
        "{context}: a refused delete must mint no REDACTION_AUDIT receipt"
    );
    assert!(
        vault
            .gate_decisions(50)
            .expect("gate decisions")
            .iter()
            .all(|decision| decision.content_kind != "deletion"),
        "{context}: a refused delete must append no allow-gate deletion decision"
    );
}

/// A vault with vectors enabled, for the non-publishing delete regressions that
/// need vector residue as rollback evidence.
#[cfg(not(feature = "sync"))]
pub(super) fn open_nonpublishing_delete_vault() -> (tempfile::TempDir, crate::Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(
        dir.path(),
        VaultConfig {
            embedding_model: Some("test/model@v1".to_owned()),
            dimensions: 4,
            ..VaultConfig::default()
        },
    )
    .expect("open vault");
    (dir, vault)
}

/// Whether ANY `pt:` marker exists for `id`, in any window.
///
/// Prefix-scanned rather than keyed: the headerful arms address the entity's own
/// `learned_at` window, and a helper that guessed one label would silently pass
/// its "no marker" assertion for a marker written under a different one — the
/// failure mode that hides exactly the leak these regressions hunt.
#[cfg(not(feature = "sync"))]
pub(super) fn first_txn_pending_tombstone_exists(vault: &crate::Vault, id: &EntityId) -> bool {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let suffix = format!(":{}", id.to_hex());
    vault
        .store
        .sync_state
        .prefix_iter(&rtxn, crate::deletion::PENDING_TOMBSTONE_PREFIX)
        .expect("iter pt: markers")
        .any(|row| row.expect("pt: row").0.ends_with(&suffix))
}

/// Every per-entry first-seen sidecar key currently stored.
pub(super) fn authority_first_seen_sidecar_keys(vault: &crate::Vault) -> Vec<String> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let keys = vault
        .store
        .sync_state
        .iter(&rtxn)
        .expect("iter sync_state")
        .map(|row| row.expect("sync_state row").0.into_owned())
        .filter(|key| {
            key.starts_with("authlog:first_seen:")
                && key != crate::authority::authority_first_seen_clock_sync_key()
                && key != crate::authority::authority_first_seen_backfill_sync_key()
        })
        .collect();
    drop(rtxn);
    keys
}

/// Rewinds a vault to the pre-migration shape: sidecars gone, marker unset.
pub(super) fn strip_authority_first_seen_state(vault: &crate::Vault) {
    let mut keys = authority_first_seen_sidecar_keys(vault);
    assert!(!keys.is_empty(), "fixture must have written sidecars");
    keys.push(crate::authority::authority_first_seen_backfill_sync_key().to_owned());
    vault
        .with_write_txn(|wtxn| {
            for key in &keys {
                vault.store.sync_state.delete(wtxn, key.as_str())?;
            }
            Ok(())
        })
        .expect("strip first-seen state");
}
