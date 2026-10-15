use super::*;
use crate::api::ReactiveChange;
use crate::broadcast::{BroadcastError, BroadcastSubscriber, ReactiveChangeSubscriber};
use crate::protocol::{SyncMessage, parse_message};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

#[tokio::test(flavor = "current_thread")]
async fn document_relay_gap_requests_resync_and_preserves_later_edits() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let first = EntityId::now();
    let next = EntityId::now();
    for id in [first, next] {
        vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                b"document owner",
            )
            .unwrap();
    }
    let manager = Arc::new(WindowManager::new(
        vault,
        Arc::new(oneiron::sync::bridge::Materializer::new()),
        "relay-test",
    ));
    let (tx, _) = broadcast::channel(1024);
    let mut peer = BroadcastSubscriber::new(1, &tx);
    let mut query = ReactiveChangeSubscriber::new(&tx);
    spawn_local_change_producer(&manager, &tx);
    let document = manager.documents().open(first).unwrap();
    // No async yield: overflow the bounded producer receiver deterministically.
    for _ in 0..300 {
        document.edit_text(0, 0, "x").unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        assert!(matches!(peer.recv().await, Err(BroadcastError::Lagged(_))));
        assert!(matches!(query.recv().await, Some(ReactiveChange::InvalidateAll { .. })));
        manager.documents().open(next).unwrap().edit_text(0, 0, "after gap").unwrap();
        // The relay must still deliver the next document, not terminate on the gap.
        loop {
            let frame = peer.recv().await.unwrap().unwrap();
            if matches!(parse_message(&frame).unwrap(), SyncMessage::Doc { entity, .. } if entity == next) {
                break;
            }
        }
    }).await.expect("document relay must recover after notification loss");
}
