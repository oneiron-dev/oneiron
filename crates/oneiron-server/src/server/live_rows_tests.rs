#![allow(clippy::unwrap_used)]
//! Rule five at the vault's live rows as this server sets them from
//! `[limits]` (census rows 45 and 57): past a row the next message stream or
//! live document waits its turn and is served, and the crossing asks this
//! server's question.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::memory::{StreamCancelReason, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::{EdgeActorClass, EntityId, TimeRange};

use crate::admission::Crossing;
use crate::config::{LimitsConfig, SyncServerConfig};
use crate::server::SyncServer;
use crate::wire_telemetry::LimitRow;

fn server(limits: LimitsConfig) -> (tempfile::TempDir, SyncServer) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            limits,
            ..SyncServerConfig::default()
        },
    )
    .unwrap();
    (dir, server)
}

fn put(server: &SyncServer, kind: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    server
        .vault()
        .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, body)
        .unwrap();
    id
}

fn turn() -> WitnessTurn {
    WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        occurred_at: 1,
        messages: vec![WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: String::new(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    }
}

/// Holds one piece of `row`'s live work while `callers` more queue behind
/// it, then lets go. Returns how many were refused.
fn queue_behind_one<H: Send>(
    server: &SyncServer,
    row: LimitRow,
    callers: usize,
    open: impl Fn(usize) -> Result<H, String> + Sync,
    release: impl Fn(H) + Sync,
) -> usize {
    let first = open(0).unwrap();
    std::thread::scope(|scope| {
        let waiters: Vec<_> = (1..=callers)
            .map(|n| {
                let (open, release) = (&open, &release);
                scope.spawn(move || open(n).map(release))
            })
            .collect();
        // The first waiter crosses the row and asks; then the first lets go.
        let deadline = Instant::now() + Duration::from_secs(30);
        while server
            .wire_telemetry
            .limit_questions()
            .latest(row)
            .is_none()
        {
            assert!(Instant::now() < deadline, "{} never asked", row.key());
            std::thread::sleep(Duration::from_millis(5));
        }
        release(first);
        waiters
            .into_iter()
            .filter(|waiter| waiter.join().unwrap().is_err())
            .count()
    })
}

/// Crosses `limits.message_streams` set to one, on one actor.
pub(crate) fn cross_the_streams(callers: usize) -> Crossing {
    let (_dir, server) = server(LimitsConfig {
        message_streams: 1,
        ..LimitsConfig::default()
    });
    let actor = put(&server, oneiron::registry::ENTITY_TYPE_PERSON, b"person");
    let memory = || server.vault().memory(actor, EdgeActorClass::Human);
    let refused = queue_behind_one(
        &server,
        LimitRow::MessageStreams,
        callers,
        |_| {
            memory()
                .begin_message_stream(&turn(), None)
                .map_err(|error| error.to_string())
        },
        |handle| {
            memory()
                .cancel_stream(handle, StreamCancelReason::UserInterrupted)
                .unwrap();
        },
    );
    Crossing {
        refused,
        asked: server
            .wire_telemetry
            .limit_questions()
            .latest(LimitRow::MessageStreams)
            .is_some(),
    }
}

/// Crosses `limits.live_documents` set to one, on one opener.
pub(crate) fn cross_the_documents(callers: usize) -> Crossing {
    let (_dir, server) = server(LimitsConfig {
        live_documents: 1,
        ..LimitsConfig::default()
    });
    let documents: Vec<_> = (0..=callers)
        .map(|_| {
            put(
                &server,
                oneiron::registry::ENTITY_TYPE_TURN,
                b"ledger pointer",
            )
        })
        .collect();
    let refused = queue_behind_one(
        &server,
        LimitRow::LiveDocuments,
        callers,
        |n| {
            server
                .reassert_manager
                .documents()
                .open_for(documents[n], b"one opener")
                .map_err(|error| error.to_string())
        },
        drop,
    );
    Crossing {
        refused,
        asked: server
            .wire_telemetry
            .limit_questions()
            .latest(LimitRow::LiveDocuments)
            .is_some(),
    }
}

/// Done-means (rule 5, rows 45 and 57): the server sets the vault's rows
/// from `[limits]`, and past each the next opener waits and is served while
/// the row asks this server's question.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_vault_rows_wait_their_turn_and_ask_the_server() {
    for cross in [cross_the_streams, cross_the_documents] {
        assert_eq!(
            tokio::task::spawn_blocking(move || cross(3)).await.unwrap(),
            Crossing {
                refused: 0,
                asked: true
            }
        );
    }
}
