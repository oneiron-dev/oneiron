//! The owner's outbox read (FIX 3966): what one of the owner's machines still
//! owes its home. Each row is a queued update its home has not durably
//! acknowledged, with the digest of the raw row and the home's answer to its
//! latest send. The read drains nothing, and a receipt shows only beside the
//! bytes the home answered.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test sync_outbox`.
#![cfg(feature = "sync")]
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::{SyncClient, SyncClientConfig};
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::manager::WindowManager;
use oneiron::test_doors::sync_outbox::{clear_residence_acks, note_residence_ack};
use oneiron::verbs::{SyncOutboxReceipt, SyncOutboxRow};
use oneiron::{EntityId, Vault, VaultConfig};

fn machine_id() -> EntityId {
    EntityId::from_bytes([
        0x01, 0x9a, 0x72, 0x18, 0x24, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ])
    .expect("fixture machine id")
}

fn open_manager() -> (tempfile::TempDir, Arc<WindowManager>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    let manager = Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "owen",
    ));
    (dir, manager)
}

fn open_connection(manager: &Arc<WindowManager>) -> SyncConnection {
    SyncConnection::new(Arc::clone(manager), ConnectionConfig::default()).expect("connection")
}

fn open_client(manager: &Arc<WindowManager>) -> SyncClient {
    SyncClient::new(Arc::clone(manager), SyncClientConfig::default())
        .expect("client")
        .0
}

fn assert_row(row: &SyncOutboxRow, seq: u64, bytes: &[u8], receipt: Option<SyncOutboxReceipt>) {
    assert_eq!(row.seq, seq);
    assert_eq!(
        row.digest,
        blake3::hash(bytes).to_hex().to_string(),
        "row {seq}: the digest is the BLAKE3 hex of the raw queued row"
    );
    assert_eq!(row.bytes, bytes.len() as u64);
    assert_eq!(row.receipt, receipt);
}

#[test]
fn outbox_lists_owed_rows_by_window_with_digest_and_size() {
    let (_dir, manager) = open_manager();
    let conn = open_connection(&manager);
    let machine = machine_id();

    let first: &[u8] = b"owen-first-device-write";
    let second: &[u8] = b"owen-second-device-write";
    let third: &[u8] = b"owen-third-device-write";
    let fourth: &[u8] = b"owen-fourth-device-write";
    let seq1 = conn.queue().push("2026-04", first).expect("queue row 1");
    let seq2 = conn.queue().push("2026-03", second).expect("queue row 2");
    let seq3 = conn.queue().push("2026-04", third).expect("queue row 3");
    let seq4 = conn.queue().push("2026-03", fourth).expect("queue row 4");

    let outbox = conn.outbox(machine).expect("outbox");
    assert_eq!(outbox.machine, machine);
    assert_eq!(outbox.owed, 4);
    assert_eq!(outbox.windows.len(), 2);
    assert_eq!(outbox.windows[0].window_key, "2026-04");
    assert_eq!(outbox.windows[1].window_key, "2026-03");
    assert_eq!(outbox.windows[0].rows.len(), 2);
    assert_eq!(outbox.windows[1].rows.len(), 2);
    assert_row(&outbox.windows[0].rows[0], seq1, first, None);
    assert_row(&outbox.windows[0].rows[1], seq3, third, None);
    assert_row(&outbox.windows[1].rows[0], seq2, second, None);
    assert_row(&outbox.windows[1].rows[1], seq4, fourth, None);

    let queued = conn.queue().drain_updates().expect("queue");
    assert_eq!(
        queued.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![seq1, seq2, seq3, seq4],
        "the read drains nothing: every row is still queued"
    );
}

#[test]
fn outbox_shows_the_home_answer_only_for_the_bytes_it_answered() {
    let (_dir, manager) = open_manager();
    let conn = open_connection(&manager);
    let mut client = open_client(&manager);
    let machine = machine_id();

    // One window: the first row stays unacknowledged, so it holds back its
    // window and every later row stays queued while the clear refreshes the
    // home's answers.
    let unacked: &[u8] = b"owen-unacked-row";
    let durable: &[u8] = b"owen-durable-row";
    let held: &[u8] = b"owen-held-row";
    let stale: &[u8] = b"owen-stale-row";
    let seq1 = conn.queue().push("2026-03", unacked).expect("queue row 1");
    let seq2 = conn.queue().push("2026-03", durable).expect("queue row 2");
    let seq3 = conn.queue().push("2026-03", held).expect("queue row 3");
    let seq4 = conn.queue().push("2026-03", stale).expect("queue row 4");
    note_residence_ack(&mut client, seq2, *blake3::hash(durable).as_bytes(), true);
    note_residence_ack(&mut client, seq3, *blake3::hash(held).as_bytes(), false);
    note_residence_ack(
        &mut client,
        seq4,
        *blake3::hash(b"owen-other-bytes").as_bytes(),
        true,
    );

    clear_residence_acks(&conn, &mut client).expect("production clear");

    let outbox = conn.outbox(machine).expect("outbox");
    assert_eq!(outbox.owed, 4);
    assert_eq!(outbox.windows.len(), 1);
    assert_eq!(outbox.windows[0].window_key, "2026-03");
    let rows = &outbox.windows[0].rows;
    assert_eq!(rows.len(), 4);
    assert_row(&rows[0], seq1, unacked, None);
    assert_row(&rows[1], seq2, durable, Some(SyncOutboxReceipt::Durable));
    assert_row(&rows[2], seq3, held, Some(SyncOutboxReceipt::Held));
    assert_row(&rows[3], seq4, stale, None);

    assert_eq!(
        conn.queue().drain_updates().expect("queue").len(),
        4,
        "the clear retired nothing: every row is still queued"
    );
}
