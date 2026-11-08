//! Residence queue acknowledgments during the initial exchange, and the queue
//! clear they drive.

use std::collections::{BTreeSet, HashSet};

use futures_util::StreamExt;
use tokio::time::Duration;
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::SyncClient;
use crate::sync::queue::QueuedUpdate;
use crate::sync::window::UpdateVerdict;

use super::super::SyncConnection;
use super::super::session::{SessionFault, WsSink, WsSource};

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
    ) -> Result<(), SessionFault> {
        let sent: BTreeSet<u64> = sent.iter().map(|update| update.seq).collect();
        let budgets = self
            .manager
            .vault()
            .residence_operation_budgets()
            .map_err(SessionFault::local)?
            .ok_or_else(|| SessionFault::local("residence policy unavailable"))?;
        // Rows a device-only world keeps here were never sent.
        self.clear_residence_acks(client)?;
        tokio::time::timeout(Duration::from_millis(budgets.ack_timeout_ms), async {
            while self
                .queue
                .drain_updates()
                .map_err(SessionFault::local)?
                .iter()
                .any(|update| {
                    sent.contains(&update.seq) && !client.residence_acks.contains_key(&update.seq)
                })
            {
                let message = read
                    .next()
                    .await
                    .ok_or_else(|| SessionFault::remote("home closed before residence ACK"))?
                    .map_err(SessionFault::remote)?;
                if let Message::Binary(data) = message {
                    for response in client
                        .handle_server_message(&data)
                        .map_err(|e| SessionFault::of_frame(&e, e.to_string()))?
                        .into_iter()
                        .filter(|frame| !client.frame_withheld(frame))
                    {
                        self.send_document_response(write, client, response)
                            .await
                            .map_err(|exit| {
                                SessionFault::remote(
                                    super::super::document_response::response_error(exit),
                                )
                            })?;
                    }
                    self.clear_residence_acks(client)?;
                }
            }
            Ok::<(), SessionFault>(())
        })
        .await
        .map_err(|_| SessionFault::remote("home residence acknowledgment timed out"))?
    }

    /// Clear the queued updates whose bytes the home has durably
    /// acknowledged, window by window. In each window only the contiguous
    /// acknowledged rows clear: a different digest fails the clear, and a
    /// missing earlier ACK or a Held reply retains the rest of that window's
    /// rows, delete markers included. Windows are separate documents, so a row the home
    /// never acknowledged (a window it refused to grant again, say) holds
    /// back only its own window. A row a device-only world keeps here is
    /// never sent, so never acknowledged: it clears, and its operations stay
    /// in the window's durable doc for the promoted vector exchange once the
    /// flag clears. A row that cannot be judged is retained like an
    /// unacknowledged one. A different digest is the home's fault, a failed
    /// queue read or retire this machine's own (FIX 22107).
    pub(in crate::sync::connection) fn clear_residence_acks(
        &self,
        client: &mut SyncClient,
    ) -> Result<(), SessionFault> {
        let mut held_back = HashSet::new();
        let mut confirmed = Vec::new();
        let mut retained = HashSet::new();
        for queued in self.queue.drain_updates().map_err(SessionFault::local)? {
            if held_back.contains(&queued.window_key) {
                retained.insert(queued.seq);
                continue;
            }
            let Some(ack) = client.residence_acks.get(&queued.seq) else {
                if client.update_verdict(&queued.window_key, &queued.encoded)
                    == UpdateVerdict::Withheld
                {
                    confirmed.push(queued.seq);
                    continue;
                }
                retained.insert(queued.seq);
                held_back.insert(queued.window_key);
                continue;
            };
            if ack.digest() != blake3::hash(&queued.encoded).as_bytes() {
                return Err(SessionFault::remote(
                    "home residence acknowledgment digest mismatch",
                ));
            }
            if !ack.is_durable()
                && client.update_verdict(&queued.window_key, &queued.encoded)
                    != UpdateVerdict::Withheld
            {
                retained.insert(queued.seq);
                held_back.insert(queued.window_key);
                continue;
            }
            confirmed.push(queued.seq);
        }
        if !confirmed.is_empty() {
            self.queue
                .retire_confirmed(&confirmed)
                .map_err(SessionFault::local)?;
        }
        client
            .residence_acks
            .retain(|seq, _| retained.contains(seq));
        Ok(())
    }
}
