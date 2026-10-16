//! Rule 5 over the engine's live rows: past its row the next opener waits
//! its turn and is served, or meets its deadline as a typed timeout; a
//! crossing asks once; nothing is refused for the count.
use super::*;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{
    MessageStreamError, MessageStreamHandle, StreamCancelReason, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use std::sync::atomic::{AtomicU64, Ordering};

/// One vault with the live work of every row at hand.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    actors: Vec<EntityId>,
    #[cfg(feature = "sync")]
    manager: Arc<crate::sync::WindowManager>,
    #[cfg(feature = "sync")]
    documents: Vec<EntityId>,
    crossings: Arc<AtomicU64>,
}

/// One piece of live work holding its turn.
enum Held {
    Stream(EntityId, MessageStreamHandle),
    #[cfg(feature = "sync")]
    Document(Arc<crate::sync::documents::EntityDocument>),
}

impl Fixture {
    fn new() -> Arc<Self> {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
        let actors: Vec<_> = (0..4).map(|_| EntityId::now()).collect();
        for actor in &actors {
            vault
                .put_entity(
                    actor,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"person",
                )
                .unwrap();
        }
        #[cfg(feature = "sync")]
        let documents: Vec<_> = (0..4)
            .map(|_| {
                let id = EntityId::now();
                vault
                    .put_entity(
                        &id,
                        crate::registry::ENTITY_TYPE_TURN,
                        TimeRange { start: 1, end: 1 },
                        1,
                        b"ledger pointer",
                    )
                    .unwrap();
                id
            })
            .collect();
        let crossings = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&crossings);
        vault.set_live_row_crossing(Some(Arc::new(move |_, _, _| {
            counted.fetch_add(1, Ordering::SeqCst);
        })));
        Arc::new(Self {
            #[cfg(feature = "sync")]
            manager: Arc::new(crate::sync::WindowManager::new(
                Arc::clone(&vault),
                Arc::new(crate::sync::bridge::Materializer::new()),
                "live-rows",
            )),
            _dir: dir,
            vault,
            actors,
            #[cfg(feature = "sync")]
            documents,
            crossings,
        })
    }

    /// Opens the `n`th piece of `row`'s live work. `Err` is a wait that met
    /// its deadline; any other refusal fails the test.
    fn open(&self, row: LiveRow, n: usize) -> Result<Held, ()> {
        match row {
            LiveRow::MessageStreams => {
                let actor = self.actors[n];
                match self
                    .vault
                    .memory(actor, EdgeActorClass::Human)
                    .begin_message_stream(&turn(), None)
                {
                    Ok(handle) => Ok(Held::Stream(actor, handle)),
                    Err(MessageStreamError::WaitedOut(waited)) => {
                        assert_eq!(waited.row, row);
                        Err(())
                    }
                    Err(error) => panic!("{row:?} refused: {error}"),
                }
            }
            #[cfg(feature = "sync")]
            LiveRow::LiveDocuments => match self
                .manager
                .documents()
                .open_for(self.documents[n], self.actors[n].as_bytes())
            {
                Ok(doc) => Ok(Held::Document(doc)),
                Err(crate::Error::Sync(crate::error::SyncError::LiveDocumentWaitedOut)) => Err(()),
                Err(error) => panic!("{row:?} refused: {error}"),
            },
            #[cfg(not(feature = "sync"))]
            LiveRow::LiveDocuments => Err(()),
        }
    }

    fn release(&self, held: Held) {
        match held {
            Held::Stream(actor, handle) => self
                .vault
                .memory(actor, EdgeActorClass::Human)
                .cancel_stream(handle, StreamCancelReason::UserInterrupted)
                .map(drop)
                .unwrap(),
            #[cfg(feature = "sync")]
            Held::Document(doc) => drop(doc),
        }
    }

    fn waiting(&self, row: LiveRow) -> usize {
        match row {
            LiveRow::MessageStreams => self.vault.message_streams.waiting(),
            #[cfg(feature = "sync")]
            LiveRow::LiveDocuments => self.manager.documents().waiting(),
            #[cfg(not(feature = "sync"))]
            LiveRow::LiveDocuments => 0,
        }
    }

    fn wait_for(&self, row: LiveRow, waiting: usize) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.waiting(row) != waiting {
            assert!(
                Instant::now() < deadline,
                "{row:?}: never {waiting} waiting"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn crossings(&self) -> u64 {
        self.crossings.load(Ordering::SeqCst)
    }
}

fn turn() -> WitnessTurn {
    WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        occurred_at: 10,
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

fn rows(row: LiveRow, bound: usize, wait: Duration) -> LiveRows {
    let mut rows = LiveRows {
        wait,
        ..LiveRows::default()
    };
    match row {
        LiveRow::MessageStreams => rows.message_streams = bound,
        LiveRow::LiveDocuments => rows.live_documents = bound,
    }
    rows
}

/// The code's own list of live rows: each one, set to one, makes the next
/// opener wait and serves it at its turn, asks once for the crossing however
/// many wait, and ends a wait at its deadline with the typed timeout.
#[test]
fn past_its_row_live_work_waits_its_turn_and_is_never_refused_for_count() {
    for row in LiveRow::ALL {
        if cfg!(not(feature = "sync")) && row == LiveRow::LiveDocuments {
            continue;
        }
        let fixture = Fixture::new();
        fixture
            .vault
            .set_live_rows(rows(row, 1, Duration::from_secs(60)));
        let first = fixture.open(row, 0).unwrap();
        let second = std::thread::spawn({
            let fixture = Arc::clone(&fixture);
            move || fixture.open(row, 1)
        });
        fixture.wait_for(row, 1);
        let third = std::thread::spawn({
            let fixture = Arc::clone(&fixture);
            move || fixture.open(row, 2)
        });
        fixture.wait_for(row, 2);
        assert_eq!(fixture.crossings(), 1, "{row:?}: one crossing asks once");
        fixture.release(first);
        let second = second.join().unwrap().expect("served at its turn");
        fixture.release(second);
        let third = third.join().unwrap().expect("served at its turn");
        fixture
            .vault
            .set_live_rows(rows(row, 1, Duration::from_millis(50)));
        assert!(
            fixture.open(row, 3).is_err(),
            "{row:?}: a wait ends at its deadline"
        );
        assert_eq!(fixture.crossings(), 2, "{row:?}: a new crossing asks again");
        fixture.release(third);
        assert!(
            fixture.open(row, 3).is_ok(),
            "{row:?}: a free turn is taken"
        );
    }
}

/// Waiters are served round-robin across keys, so one key that queued
/// first and most never holds back another key's single waiter.
#[cfg(feature = "sync")]
#[test]
fn waiters_take_turns_across_keys_not_in_one_queue() {
    let row = LiveRow::LiveDocuments;
    let fixture = Fixture::new();
    fixture
        .vault
        .set_live_rows(rows(row, 1, Duration::from_secs(60)));
    let served = Arc::new(Mutex::new(Vec::new()));
    let open = |document: usize, key: usize| {
        let fixture = Arc::clone(&fixture);
        let served = Arc::clone(&served);
        std::thread::spawn(move || {
            let doc = fixture
                .manager
                .documents()
                .open_for(fixture.documents[document], fixture.actors[key].as_bytes())
                .unwrap();
            served.lock().unwrap().push(document);
            // Each holds its turn until the test lets the next one go.
            doc
        })
    };
    let first = fixture.open(row, 0).unwrap();
    // Key 1 waits twice, then key 2 once.
    let a1 = open(1, 1);
    fixture.wait_for(row, 1);
    let a2 = open(2, 1);
    fixture.wait_for(row, 2);
    let b1 = open(3, 2);
    fixture.wait_for(row, 3);
    fixture.release(first);
    drop(a1.join().unwrap());
    drop(b1.join().unwrap());
    drop(a2.join().unwrap());
    assert_eq!(*served.lock().unwrap(), vec![1, 3, 2]);
}
