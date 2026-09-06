#![allow(clippy::unwrap_used)]

use super::subscriptions::*;
use super::*;
use loro::{CommitOptions, LoroDoc, VersionVector};
use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const WORLD_A: &str = "11111111111111111111111111111111";
const WORLD_B: &str = "22222222222222222222222222222222";

#[derive(Default)]
struct Source {
    doc: LoroDoc,
    values: Mutex<BTreeMap<String, u64>>,
    expired: AtomicBool,
    refused: AtomicBool,
}

impl Source {
    fn write(&self, world: &str, value: u64) {
        self.values.lock().unwrap().insert(world.to_owned(), value);
        self.doc
            .get_map("values")
            .insert(world, value as i64)
            .unwrap();
        self.doc.commit();
    }
}

impl LiveQuerySource for Source {
    fn derive(&self, view: &ScopedView, _: Channel) -> Result<DerivedView, AppError> {
        if self.refused.load(Ordering::SeqCst) {
            return Err(AppError::unauthorized());
        }
        let world = view.world_ref.as_deref().unwrap_or("base");
        Ok(DerivedView {
            value: json!(self.values.lock().unwrap().get(world).copied().unwrap_or(0)),
            cursor: Cursor {
                document: "fixture".to_owned(),
                version_vector: self.doc.oplog_vv().encode(),
                batch: 0,
            },
            dependencies: BTreeSet::from([format!("world/{world}")]),
        })
    }
    fn can_resume(&self, cursor: &Cursor) -> Result<bool, AppError> {
        if self.refused.load(Ordering::SeqCst) {
            return Err(AppError::unauthorized());
        }
        if cursor.document != "fixture" {
            return Err(AppError::bad_request("wrong document", Some("cursor")));
        }
        if self.expired.load(Ordering::SeqCst) {
            return Ok(false);
        }
        export_since(&self.doc, cursor)
    }
}

fn view(world: &str) -> ScopedView {
    ScopedView {
        world_ref: Some(world.to_owned()),
        ..Default::default()
    }
}

fn notify(tier: &LiveQueries, world: &str, by: OriginMark) {
    let path = format!("world/{world}");
    tier.on_materialized(
        &path,
        &MaterializedDiffSummary {
            containers: vec![path.clone()],
            bytes: 1,
        },
        &by,
    );
    tier.refresh().unwrap();
}

#[test]
fn empty_rpc_is_one_terminal_frame_and_ids_do_not_cross_talk() {
    let source = Arc::new(Source::default());
    let tier = LiveQueries::new(1, source);
    let opened = tier
        .open(7, view(WORLD_A), Channel::View, None, None)
        .unwrap();
    let rpc = rpc_result(7, json!([])).unwrap();
    assert_eq!(rpc[0], TAG_RPC);
    let value: Value = serde_json::from_slice(&rpc[1..]).unwrap();
    assert_eq!(value, json!({"requestId":7,"result":[],"last":true}));
    let sub = opened[0].encode().unwrap();
    assert_eq!(sub[0], TAG_SUB);
    let value: Value = serde_json::from_slice(&sub[1..]).unwrap();
    assert_eq!(value["subscriptionId"], 7);
    assert!(value.get("requestId").is_none());
    tier.reconnect(2).unwrap();
    assert!(
        tier.open(
            7,
            view(WORLD_A),
            Channel::View,
            Some(&opened[0].cursor),
            None
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn own_origin_is_filtered_but_second_client_and_world_are_independent() {
    let source = Arc::new(Source::default());
    let first = LiveQueries::new(1, source.clone());
    let second = LiveQueries::new(2, source.clone());
    for tier in [&first, &second] {
        let opened = tier
            .open(1, view(WORLD_A), Channel::View, None, None)
            .unwrap();
        tier.ack(1, &opened[0].cursor).unwrap();
    }
    source.write(WORLD_B, 1);
    notify(&first, WORLD_B, OriginMark::default());
    notify(&second, WORLD_B, OriginMark::default());
    assert!(first.pending(1).unwrap().is_empty());
    assert!(second.pending(1).unwrap().is_empty());
    source.write(WORLD_A, 1);
    for tier in [&first, &second] {
        notify(
            tier,
            WORLD_A,
            OriginMark {
                conn_id: Some(1),
                origin: Some("conn:1".to_owned()),
            },
        );
    }
    assert!(first.pending(1).unwrap().is_empty());
    assert_eq!(second.pending(1).unwrap().len(), 1);
    assert_eq!(second.pending(1).unwrap()[0].result, Some(json!(1)));
}

#[test]
fn optimistic_origin_and_dependency_membership_invalidate_empty_views() {
    let source = Arc::new(Source::default());
    let tier = LiveQueries::new(1, source.clone());
    let opened = tier
        .open(
            1,
            view(WORLD_A),
            Channel::View,
            None,
            Some("optimistic-1".to_owned()),
        )
        .unwrap();
    tier.ack(1, &opened[0].cursor).unwrap();
    source.write(WORLD_A, 1);
    notify(
        &tier,
        WORLD_A,
        OriginMark {
            conn_id: None,
            origin: Some("optimistic-1".to_owned()),
        },
    );
    assert!(tier.pending(1).unwrap().is_empty());
    source.write(WORLD_A, 2);
    notify(&tier, WORLD_A, OriginMark::default());
    assert_eq!(tier.pending(1).unwrap()[0].result, Some(json!(2)));
}

#[test]
fn reconnect_replays_only_missed_subscription_frames_after_cumulative_ack() {
    let source = Arc::new(Source::default());
    let tier = LiveQueries::new(1, source.clone());
    let opened = tier
        .open(9, view(WORLD_A), Channel::Receipts, None, None)
        .unwrap();
    tier.ack(9, &opened[0].cursor).unwrap();
    for n in 1..=3 {
        source.write(WORLD_A, n);
        notify(&tier, WORLD_A, OriginMark::default());
    }
    let pending = tier.pending(9).unwrap();
    tier.ack(9, &pending[1].cursor).unwrap();
    tier.ack(9, &pending[1].cursor).unwrap();
    tier.reconnect(22).unwrap();
    let replay = tier
        .open(
            9,
            view(WORLD_A),
            Channel::Receipts,
            Some(&pending[1].cursor),
            None,
        )
        .unwrap();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].cursor, pending[2].cursor);
    assert_eq!(replay[0].result, Some(json!(3)));
    let mut future = replay[0].cursor.clone();
    future.batch += 100;
    assert!(tier.ack(9, &future).is_err());
    assert_eq!(tier.pending(9).unwrap().len(), 1);
}

#[test]
fn overflow_is_one_cursor_gap_and_reopen_is_explicit_full_state() {
    let source = Arc::new(Source::default());
    let tier = LiveQueries::new(1, source.clone());
    let opened = tier
        .open(1, view(WORLD_A), Channel::View, None, None)
        .unwrap();
    tier.ack(1, &opened[0].cursor).unwrap();
    for n in 0..=LIVEQUERY_RING_CAPACITY {
        source.write(WORLD_A, (n + 1) as u64);
        notify(&tier, WORLD_A, OriginMark::default());
    }
    let pending = tier.pending(1).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].kind, "gap");
    VersionVector::decode(&pending[0].cursor.version_vector).unwrap();
    source.write(WORLD_A, 9000);
    notify(&tier, WORLD_A, OriginMark::default());
    assert_eq!(tier.pending(1).unwrap().len(), 1);
    let resync = tier
        .open(
            1,
            view(WORLD_A),
            Channel::View,
            Some(&opened[0].cursor),
            None,
        )
        .unwrap();
    assert_eq!(
        resync.iter().map(|p| p.kind).collect::<Vec<_>>(),
        ["gap", "snapshot"]
    );
    assert_eq!(resync[1].result, Some(json!(9000)));
}

#[test]
fn retention_expiry_and_source_refusal_never_silently_resume() {
    let source = Arc::new(Source::default());
    let tier = LiveQueries::new(1, source.clone());
    let opened = tier
        .open(1, view(WORLD_A), Channel::PendingConsent, None, None)
        .unwrap();
    source.expired.store(true, Ordering::SeqCst);
    let replay = tier
        .open(
            1,
            view(WORLD_A),
            Channel::PendingConsent,
            Some(&opened[0].cursor),
            None,
        )
        .unwrap();
    assert_eq!(replay[0].kind, "gap");
    assert_eq!(replay[1].kind, "snapshot");
    source.refused.store(true, Ordering::SeqCst);
    assert!(tier.pending(1).is_err());
    assert!(
        tier.open(
            1,
            view(WORLD_A),
            Channel::PendingConsent,
            Some(&replay[1].cursor),
            None
        )
        .is_err()
    );
}

#[test]
fn reserved_channels_and_unknown_verbs_are_not_aliased() {
    let tier = LiveQueries::new(1, Arc::new(Source::default()));
    for channel in [Channel::MemoryBoard, Channel::Gap] {
        assert!(tier.open(1, view(WORLD_A), channel, None, None).is_err());
    }
    assert!(!read_method("put"));
    assert!(!read_method("commit"));
    assert!(
        serde_json::from_value::<SubRequest>(json!({"method":"sub.write","subscriptionId":1}))
            .is_err()
    );
}

#[test]
fn loro_resume_exports_real_updates_and_rejects_malformed_or_future_vv() {
    let doc = LoroDoc::new();
    doc.set_peer_id(8).unwrap();
    let mut cursor = Cursor {
        document: "fixture".to_owned(),
        version_vector: doc.oplog_vv().encode(),
        batch: 0,
    };
    doc.get_map("data").insert("one", 1).unwrap();
    doc.commit();
    assert!(export_since(&doc, &cursor).unwrap());
    cursor.version_vector = vec![255];
    assert!(export_since(&doc, &cursor).is_err());
    let mut future = doc.oplog_vv();
    future.insert(8, 10000);
    cursor.version_vector = future.encode();
    assert!(export_since(&doc, &cursor).is_err());
}

#[test]
fn frozen_observer_entrypoint_and_none_tee_materialize_identically() {
    use oneiron::sync::bridge::{Materializer, register_observer_b, register_observer_b_with_tee};
    type Frozen = fn(
        &LoroDoc,
        &Arc<oneiron::Vault>,
        &Arc<Materializer>,
        &str,
    ) -> (loro::Subscription, loro::Subscription, loro::Subscription);
    let frozen: Frozen = register_observer_b;
    let mut values = Vec::new();
    for use_tee_entrypoint in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let doc = LoroDoc::new();
        let materializer = Arc::new(Materializer::new());
        let _subs = if use_tee_entrypoint {
            register_observer_b_with_tee(&doc, &vault, &materializer, "2026-03", None)
        } else {
            frozen(&doc, &vault, &materializer, "2026-03")
        };
        let id = oneiron::EntityId::from_hex(WORLD_A).unwrap();
        doc.get_map("entities")
            .insert(&id.to_hex(), entity_blob(b"body").as_slice())
            .unwrap();
        doc.commit();
        values.push(vault.get(&id).unwrap());
    }
    assert_eq!(values, vec![Some(b"body".to_vec()), Some(b"body".to_vec())]);
}

fn entity_blob(body: &[u8]) -> Vec<u8> {
    let mut blob = vec![1];
    for _ in 0..3 {
        blob.extend_from_slice(&1_772_000_000u64.to_be_bytes());
    }
    blob.extend_from_slice(body);
    blob
}

#[test]
fn tee_observes_committed_lmdb_once_per_container_batch_and_preserves_origin() {
    use oneiron::sync::bridge::{Materializer, register_observer_b_with_tee};
    struct Tee {
        vault: Arc<oneiron::Vault>,
        seen: Mutex<Vec<OriginMark>>,
    }
    impl LiveQueryTee for Tee {
        fn on_materialized(&self, path: &str, diff: &MaterializedDiffSummary, by: &OriginMark) {
            assert_eq!(path, "w:2026-03/entities");
            assert_eq!(diff.containers.len(), 2);
            for hex in [WORLD_A, WORLD_B] {
                assert_eq!(
                    self.vault
                        .get(&oneiron::EntityId::from_hex(hex).unwrap())
                        .unwrap(),
                    Some(b"body".to_vec())
                );
            }
            self.seen.lock().unwrap().push(by.clone());
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let tee = Arc::new(Tee {
        vault: vault.clone(),
        seen: Mutex::new(Vec::new()),
    });
    let doc = LoroDoc::new();
    let _subs = register_observer_b_with_tee(
        &doc,
        &vault,
        &Arc::new(Materializer::new()),
        "2026-03",
        Some(tee.clone()),
    );
    for hex in [WORLD_A, WORLD_B] {
        doc.get_map("entities")
            .insert(hex, entity_blob(b"body").as_slice())
            .unwrap();
    }
    doc.commit_with(CommitOptions::new().origin("conn:17"));
    let seen = tee.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].conn_id, Some(17));
    assert_eq!(seen[0].origin.as_deref(), Some("conn:17"));
}

#[test]
fn shallow_loro_history_requires_full_state_for_an_old_cursor() {
    let doc = LoroDoc::new();
    let old = Cursor {
        document: "fixture".to_owned(),
        version_vector: doc.oplog_vv().encode(),
        batch: 0,
    };
    doc.get_map("data").insert("first", 1).unwrap();
    doc.commit();
    doc.get_map("data").insert("second", 2).unwrap();
    doc.commit();
    let frontiers = doc.state_frontiers();
    let bytes = doc
        .export(loro::ExportMode::shallow_snapshot(&frontiers))
        .unwrap();
    let shallow = LoroDoc::new();
    shallow.import(&bytes).unwrap();
    assert!(!export_since(&shallow, &old).unwrap());
}

#[test]
fn tee_defers_facade_work_until_the_subscription_loop_runs() {
    let source = Arc::new(Source::default());
    let tier = LiveQueries::new(1, source.clone());
    let opened = tier
        .open(1, view(WORLD_A), Channel::View, None, None)
        .unwrap();
    tier.ack(1, &opened[0].cursor).unwrap();
    source.write(WORLD_A, 1);
    let path = format!("world/{WORLD_A}");
    tier.on_materialized(
        &path,
        &MaterializedDiffSummary {
            containers: vec![],
            bytes: 0,
        },
        &OriginMark::default(),
    );
    assert!(tier.pending(1).unwrap().is_empty());
    tier.refresh().unwrap();
    assert_eq!(tier.pending(1).unwrap()[0].result, Some(json!(1)));
}

#[test]
fn deferred_own_write_does_not_hide_a_later_foreign_write() {
    let source = Arc::new(Source::default());
    let tier = LiveQueries::new(1, source.clone());
    let opened = tier
        .open(1, view(WORLD_A), Channel::View, None, None)
        .unwrap();
    tier.ack(1, &opened[0].cursor).unwrap();
    let path = format!("world/{WORLD_A}");
    for (conn, value) in [(1, 1), (2, 2)] {
        source.write(WORLD_A, value);
        tier.on_materialized(
            &path,
            &MaterializedDiffSummary {
                containers: vec![],
                bytes: 0,
            },
            &OriginMark {
                conn_id: Some(conn),
                origin: None,
            },
        );
    }
    tier.refresh().unwrap();
    assert_eq!(tier.pending(1).unwrap()[0].result, Some(json!(2)));
}
