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
    fn derive(&self, view: &ScopedView, channel: Channel) -> Result<DerivedView, AppError> {
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
            dependencies: BTreeSet::from([if channel == Channel::OwnerFeed {
                "owner-feed".to_owned()
            } else {
                format!("world/{world}")
            }]),
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

            revision_events: Vec::new(),
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
    assert_eq!(rpc.len(), 1);
    assert_eq!(rpc[0][0], TAG_RPC);
    let value = test_wire::reply(&rpc);
    assert_eq!(value["requestId"], json!(7));
    assert_eq!(value["result"], json!([]));
    assert_eq!(value["last"], json!(true));
    let sub = opened[0].encode().unwrap();
    assert_eq!(sub[0][0], TAG_SUB);
    let value: wire::Envelope<serde::de::IgnoredAny> = wire::decode(&sub[0][1..]).unwrap();
    assert_eq!(value.id, 7);
    assert_eq!(value.kind, "sub.snapshot");
    assert_eq!(opened[1].kind, "eose");
    tier.reconnect(2).unwrap();
    assert!(
        tier.open(
            7,
            view(WORLD_A),
            Channel::View,
            Some(&opened[0].cursor),
            None,
        )
        .unwrap()
        .is_empty()
    );
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
        ["gap", "snapshot", "eose"]
    );
    assert_eq!(resync[1].result, Some(json!(9000)));
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
            let entities: std::collections::BTreeSet<_> = diff
                .containers
                .iter()
                .filter_map(|path| path.strip_prefix("e:"))
                .collect();
            assert_eq!(
                entities,
                std::collections::BTreeSet::from([WORLD_A, WORLD_B])
            );
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
fn owner_feed_poll_keeps_delayed_ack_after_body_coalescing() {
    let source = Arc::new(Source::default());
    let tier = LiveQueries::new(1, source.clone());
    let initial = tier
        .open(4, ScopedView::default(), Channel::OwnerFeed, None, None)
        .unwrap();
    tier.ack(4, &initial.last().unwrap().cursor).unwrap();
    source.write("base", 1);
    tier.owner_feed_poll_now();
    tier.refresh().unwrap();
    let c1 = tier.buffered().unwrap().last().unwrap().cursor.clone();
    source.write("base", 2);
    tier.owner_feed_poll_now();
    tier.refresh().unwrap();
    let pending = tier.buffered().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].result, Some(json!(2)));
    let c2 = pending[0].cursor.clone();
    tier.ack(4, &c1).expect("issued C1 remains ACKable");
    let pending = tier.buffered().unwrap();
    assert_eq!(pending.len(), 1, "ACK C1 cannot discard C2");
    assert_eq!(pending[0].cursor, c2);
    tier.ack(4, &c2).expect("latest C2 ACK");
    assert!(tier.buffered().unwrap().is_empty());
    let mut invented = c2;
    invented.batch += 1_000;
    assert_eq!(
        serde_json::to_value(tier.ack(4, &invented).unwrap_err()).unwrap()["code"],
        "BAD_REQUEST"
    );
}
