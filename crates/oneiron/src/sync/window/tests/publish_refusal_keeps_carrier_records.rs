use super::*;

use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{
    DeleteReceipt, MEMORY_CODE_OWNER_BINDING_REQUIRED, Memory, MemoryResult, SafeDeleteReason,
};
use crate::temporal::TimeRange;

struct CarrierRefusalHarness {
    _dir: tempfile::TempDir,
    vault: std::sync::Arc<crate::Vault>,
    window: Option<std::sync::Arc<crate::sync::window::LoadedWindow>>,
    window_key: crate::sync::WindowKey,
    outbound: tokio::sync::mpsc::UnboundedReceiver<crate::sync::types::LocalUpdate>,
    manager: std::sync::Arc<crate::sync::WindowManager>,
}

impl CarrierRefusalHarness {
    fn open(label: &str, live_window: bool) -> Self {
        Self::open_with_config(label, live_window, VaultConfig::default())
    }

    fn open_with_config(label: &str, live_window: bool, config: VaultConfig) -> Self {
        use std::sync::Arc;

        use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(crate::Vault::open(dir.path(), config).expect("open vault"));
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            label,
        ));
        let (tx, outbound) = tokio::sync::mpsc::unbounded_channel();
        manager.outbound().attach(tx);
        let window_key = WindowKey::from_timestamp(1);
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
            manager,
        }
    }

    fn live_doc_tombstoned(&self, id: &EntityId) -> bool {
        self.window
            .as_ref()
            .is_some_and(|window| window.doc.get_map("tombstones").get(&id.to_hex()).is_some())
    }

    fn snapshot_tombstoned(&self, id: &EntityId) -> bool {
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

    fn update_rows_tombstoned(&self, id: &EntityId) -> bool {
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

    fn queue_rows_tombstoned(&self, id: &EntityId) -> bool {
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

    fn replayable_pending_marker(&self, id: &EntityId) -> bool {
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

    fn assert_nothing_published(&mut self, id: &EntityId, context: &str) {
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

fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn put_owner(vault: &crate::Vault) -> EntityId {
    vault.ensure_embedded_owner_actor().expect("embedded owner")
}

fn facade_for(vault: &crate::Vault, actor: EntityId) -> Memory<'_> {
    vault.memory(actor, EdgeActorClass::Human)
}

fn authority_root(
    seed: u8,
) -> (
    crate::authority::AuthorityLogEntry,
    ed25519_dalek::SigningKey,
) {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
    };
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(10); 32],
            recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
        overlay_seed: None,
    };
    entry.overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&entry.op)
        .expect("authority overlay seed");
    (sign_authority(entry, &signing), signing)
}

fn sign_authority(
    mut entry: crate::authority::AuthorityLogEntry,
    key: &ed25519_dalek::SigningKey,
) -> crate::authority::AuthorityLogEntry {
    use ed25519_dalek::Signer;
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

fn root_binding_with_pending_revocation(
    vault: &crate::Vault,
    seed: u8,
    actor: EntityId,
) -> crate::authority::AuthorityLogEntry {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (genesis, signing) = authority_root(seed);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let genesis_hash = crate::authority::authority_entry_hash(&genesis).expect("genesis hash");
    let owner_entry = |seq: u64, op: AuthorityOp, parents: Vec<[u8; 32]>| {
        let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
            .expect("authority overlay seed");
        sign_authority(
            AuthorityLogEntry {
                schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                parent_hashes: parents,
                op,
                overlay_seed,
                signer: AuthoritySignature {
                    suite: key.suite(),
                    public_key: key.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: 100 + seq,
            },
            &signing,
        )
    };
    let bind = owner_entry(
        1,
        AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: actor,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        vec![genesis_hash],
    );
    let bind_hash = crate::authority::authority_entry_hash(&bind).expect("bind hash");
    vault
        .put_authority_log_entries(&[(genesis, test_time(1), 1), (bind, test_time(2), 2)])
        .expect("root + bind");
    owner_entry(
        2,
        AuthorityOp::RevokeActor {
            authority_key: key.clone(),
            epoch: 1,
        },
        vec![bind_hash],
    )
}

fn put_message_row(vault: &crate::Vault, id: &EntityId) -> Result<()> {
    let body = crate::gate::canonical_witness_message_body_for_test(
        "user",
        "dialogue",
        "a carrier a refused publication keeps",
        true,
        0,
    )?;
    vault
        .batch()
        .put_canonical_message_for_test(id, test_time(1), 1, &body)
        .commit()
}

fn safe_delete_with_revocation_at(
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

fn live_carrier_bytes(harness: &CarrierRefusalHarness, id: &EntityId) -> Vec<u8> {
    let window = harness.window.as_ref().expect("live window open");
    crate::sync::loro_support::map_get_bytes(&window.doc.get_map("entities"), &id.to_hex())
        .expect("the live doc carries the MESSAGE")
}

fn peer_origin_names_carrier(
    harness: &CarrierRefusalHarness,
    id: &EntityId,
    carrier: &[u8],
) -> Result<bool> {
    let mut wtxn = harness.vault.store.env.write_txn()?;
    let names = crate::sync::ingest::peer_row_in_txn(
        harness.vault.as_ref(),
        &mut wtxn,
        harness.window_key.as_str(),
        id,
        carrier,
    )?;
    drop(wtxn);
    Ok(names)
}

fn writer_record_names_carrier(
    harness: &CarrierRefusalHarness,
    id: &EntityId,
    carrier: &[u8],
) -> Result<bool> {
    use crate::side_table::{HexId, Raw, SideTable};

    let written = SideTable::<HexId, Vec<u8>, Raw>::new(&crate::side_table::SYNC_MESSAGE_WRITER);
    let rtxn = harness.vault.store.env.read_txn()?;
    let record = written.get(&harness.vault.store, &rtxn, &HexId(*id))?;
    drop(rtxn);
    let wanted = blake3::hash(carrier);
    Ok(record.is_some_and(|held| held.get(..32) == Some(&wanted.as_bytes()[..])))
}

/// A refused publication keeps the peer and writer records of its carrier: a MESSAGE whose window carrier a peer origin record and a writer record both name is hard-deleted through a revocation racing its publish, and after the refusal both records still name the carrier's exact bytes, on the live and the transient leg. The hard arm leaves the row whole until its publication, so both records are the publication's to keep; the soft arm's scrub tears the writer record with the body before it publishes (FIX 12113, `deletion/derived_rows.rs`). Red at `610f54397651` because the publication dropped both records in `mark_removed_carriers_first`, committed before its publish transaction refused.
#[test]
fn a_refused_publication_keeps_the_peer_and_writer_records_of_its_carrier() -> Result<()> {
    for live_window in [true, false] {
        let leg = if live_window { "live" } else { "transient" };
        let mut harness = CarrierRefusalHarness::open("carrier-record-refusal", live_window);
        let owner = put_owner(&harness.vault);
        let subject = EntityId::from_bytes([0x2A; 16])?;
        put_message_row(&harness.vault, &subject)?;
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2B, owner);

        let carrier = if live_window {
            crate::sync::window::reverse_rematerialize(
                harness.vault.as_ref(),
                &harness.window.as_ref().expect("live window").doc,
                &harness.window_key,
            )?;
            live_carrier_bytes(&harness, &subject)
        } else {
            let staged = harness.manager.open_window(&harness.window_key)?;
            let bytes = crate::sync::loro_support::map_get_bytes(
                &staged.doc.get_map("entities"),
                &subject.to_hex(),
            )
            .expect("the opened window carries the MESSAGE");
            drop(staged);
            assert!(
                harness.manager.unload_window(&harness.window_key)?,
                "{leg}: the staging window unloads back to transient"
            );
            bytes
        };
        let digest = blake3::hash(&carrier);
        crate::sync::ingest::record_peer_rows(
            harness.vault.as_ref(),
            harness.window_key.as_str(),
            &[(subject, digest.as_bytes().to_vec())],
        )?;
        harness.vault.with_write_txn(|wtxn| {
            crate::sync::note_message_put_in_txn(&harness.vault.store, wtxn, &subject, false, None)
        })?;
        assert!(
            peer_origin_names_carrier(&harness, &subject, &carrier)?,
            "{leg}: the peer record names the carrier before the delete"
        );
        assert!(
            writer_record_names_carrier(&harness, &subject, &carrier)?,
            "{leg}: the writer record names the carrier before the delete"
        );
        while harness.outbound.try_recv().is_ok() {}

        let warmup = EntityId::from_bytes([0x2C; 16])?;
        put_message_row(&harness.vault, &warmup)?;
        facade_for(&harness.vault, owner)
            .safe_delete(&warmup.to_hex(), SafeDeleteReason::UserHardDelete)
            .expect("control: a bound owner hard-deletes a MESSAGE");
        if live_window {
            assert!(
                harness.live_doc_tombstoned(&warmup),
                "{leg} control: the live doc must carry the warmup tombstone"
            );
            assert!(
                harness.outbound.try_recv().is_ok(),
                "{leg} control: the peer receives the warmup tombstone"
            );
        }
        while harness.outbound.try_recv().is_ok() {}

        let err = safe_delete_with_revocation_at(
            &harness.vault,
            owner,
            subject,
            SafeDeleteReason::UserHardDelete,
            crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
            revoke,
        )
        .expect_err("a revocation landing before the publish commit must refuse");
        assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{leg}");
        harness.assert_nothing_published(&subject, leg);
        assert!(
            peer_origin_names_carrier(&harness, &subject, &carrier)?,
            "{leg}: a refused publication keeps the peer record of the carrier it did not remove"
        );
        assert!(
            writer_record_names_carrier(&harness, &subject, &carrier)?,
            "{leg}: a refused publication keeps the writer record of the carrier it did not remove"
        );
    }
    Ok(())
}
