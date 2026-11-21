//! A machine's report to its home of the items each board it delivered showed (lead ruling
//! PREDICTED-BOARD-SEED-SIGNAL = A, 21 Nov): the home records them in its touch log as prefetch
//! seeds of this machine's prediction (ARCH-0023b #predicted-residence). Every board producer
//! here reports once its board is delivered, whoever ran it, an agent included: the HTTP board,
//! the MCP setup and board verbs, and a native run's board verbs. The report goes over this
//! machine's own sync connection, which proves the machine to the home; a host that runs none,
//! the elected home among them, reports nothing. It is best effort and never holds the board back:
//! a home that is down, or a refused report, leaves no seed and nothing owed.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::sync::residence::BOARD_SEEDS_MAX;

use crate::server::SyncServer;

/// The first [`BOARD_SEEDS_MAX`] distinct items of `rows`, in board order.
fn board_seeds(rows: impl IntoIterator<Item = EntityId>) -> Vec<EntityId> {
    let mut seeds = Vec::new();
    for row in rows {
        if seeds.len() == BOARD_SEEDS_MAX {
            break;
        }
        if !seeds.contains(&row) {
            seeds.push(row);
        }
    }
    seeds
}

/// Reports the first [`BOARD_SEEDS_MAX`] distinct items of a delivered board's `rows` to this
/// machine's home, in a task of its own.
pub(crate) fn report_delivered_board(
    server: &SyncServer,
    rows: impl IntoIterator<Item = EntityId>,
) {
    let seeds = board_seeds(rows);
    // Set once a device link this process runs over the vault opened: serve's, managed serve's
    // or the macOS app's. A host with none has no home to report to.
    let linked = server
        .device_link_opened
        .load(std::sync::atomic::Ordering::Relaxed);
    if seeds.is_empty() || !linked {
        return;
    }
    let vault = Arc::clone(&server.vault);
    tokio::spawn(async move {
        let machine = match tokio::task::spawn_blocking(move || vault.local_machine()).await {
            Ok(Ok(Some(machine))) => machine.id,
            Ok(Ok(None)) => return,
            Ok(Err(error)) => {
                tracing::debug!(%error, "a board's report found no machine to name");
                return;
            }
            Err(error) => {
                tracing::debug!(%error, "a board's report found no machine to name");
                return;
            }
        };
        let Some(connection) = crate::residence_machines::connection(&machine) else {
            return;
        };
        if let Err(error) = connection.report_board_seeds(&seeds).await {
            tracing::debug!(%error, "a board's report left no seed at the home");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes_unchecked([byte; 16])
    }

    #[test]
    fn a_report_names_each_item_once_in_board_order_and_at_most_the_cap() {
        assert_eq!(
            board_seeds([id(2), id(1), id(2), id(3)]),
            vec![id(2), id(1), id(3)]
        );
        let many: Vec<EntityId> = (0..=u8::MAX).map(id).collect();
        let seeds = board_seeds(many.iter().copied());
        assert_eq!(seeds.len(), BOARD_SEEDS_MAX);
        assert_eq!(seeds.as_slice(), &many[..BOARD_SEEDS_MAX]);
    }
}
