//! Residence queue acknowledgments during the initial exchange.

use std::collections::BTreeSet;

use futures_util::{SinkExt, StreamExt};
use tokio::time::Duration;
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::SyncClient;
use crate::sync::queue::QueuedUpdate;

use super::super::SyncConnection;
use super::super::session::{WsSink, WsSource};

impl SyncConnection {
    /// A home acknowledgment is sent only after persistence. A missing ACK
    /// leaves every unconfirmed queue row intact for the next reconnect. The
    /// wait ends once every row of `sent` is answered or cleared. A Held
    /// reply answers without retiring its row or later rows of that window;
    /// other windows still finish. A row never sent is never acknowledged.
    pub(super) async fn wait_residence_acks(
        &self,
        write: &mut WsSink,
        read: &mut WsSource,
        client: &mut SyncClient,
        sent: &[QueuedUpdate],
    ) -> Result<(), String> {
        let sent: BTreeSet<u64> = sent.iter().map(|update| update.seq).collect();
        let budgets = self
            .manager
            .vault()
            .residence_operation_budgets()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "residence policy unavailable".to_string())?;
        // Rows a device-only world keeps here were never sent.
        self.clear_residence_acks(client)?;
        tokio::time::timeout(Duration::from_millis(budgets.ack_timeout_ms), async {
            while self
                .queue
                .drain_updates()
                .map_err(|e| e.to_string())?
                .iter()
                .any(|update| {
                    sent.contains(&update.seq) && !client.residence_acks.contains_key(&update.seq)
                })
            {
                let message = read
                    .next()
                    .await
                    .ok_or_else(|| "home closed before residence ACK".to_string())?
                    .map_err(|e| e.to_string())?;
                if let Message::Binary(data) = message {
                    for response in client
                        .handle_server_message(&data)
                        .map_err(|e| e.to_string())?
                        .into_iter()
                        .filter(|frame| !client.frame_withheld(frame))
                    {
                        write
                            .send(Message::Binary(response.into()))
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    self.clear_residence_acks(client)?;
                }
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "home residence acknowledgment timed out".to_string())?
    }
}
