//! Door for `tests/sync_outbox.rs`, mounted inside `sync::connection` so it
//! drives the production acknowledgment clear without changing that clear's
//! visibility. Reached as `oneiron::test_doors::sync_outbox` (re-exported
//! there); compiled only under `oneiron_test_support`.

use crate::sync::SyncClient;
use crate::sync::client::ResidenceReceipt;
use crate::sync::connection::SyncConnection;

/// Stands the home's acknowledgment of queued row `seq` in `client`, as the
/// residence exchange holds it once the home answers that send: `digest` is
/// the BLAKE3 of the raw row the home answered, and `durable` whether the
/// home persisted it (a `Held` answer arrives without retiring its row).
pub fn note_residence_ack(client: &mut SyncClient, seq: u64, digest: [u8; 32], durable: bool) {
    let ack = if durable {
        ResidenceReceipt::Durable(digest)
    } else {
        ResidenceReceipt::Held(digest)
    };
    client.residence_acks.insert(seq, ack);
}

/// Runs the production acknowledgment clear over `conn`'s queue, as the
/// residence handshake runs it once the home answers: durably acknowledged
/// rows retire window by window, and the home's answers to the rows still
/// owed are noted for the outbox read.
///
/// # Errors
///
/// The clear's fault, told as text: a digest the home bound to other bytes
/// than the queued row holds, or a queue read or retire that failed here.
pub fn clear_residence_acks(conn: &SyncConnection, client: &mut SyncClient) -> Result<(), String> {
    conn.clear_residence_acks(client)
        .map_err(|fault| fault.to_string())
}
