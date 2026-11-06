//! The preference/degrade ladder belongs to this host, never the engine.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

use oneiron::context_board::{BoardStreamFrame, WakeEnvelope, wake_batch_opener};

use super::board_stream::BoardDelivery;
use super::{AdapterCommand, Instance, WakeBatch, wall_clock_ms};

/// A stalled helper must let the next configured adapter try.
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);

/// The only text a tmux pane is ever typed: this prefix, then the hex TASK
/// id of each wake (a review wake's `diary-read:<agent>:<request>` handle,
/// both hex ids), space separated, then Enter. No label, title, frame or
/// other body text reaches the pane, so nothing a remote author wrote can
/// run there. The batch itself goes to the helper on stdin, or stays in the
/// inbox for `wake inbox`; a pane is nudged only for wakes the inbox took
/// (FIX 6187).
const PANE_NUDGE_PREFIX: &str = "oneiron wake pending";

/// One wake offered to this host's adapters, and whether it entered the
/// inbox, where `wake inbox` finds its batch (FIX 6187). A pane nudge names
/// only a wake that did: the nudge carries ids, never a batch.
struct OfferedWake {
    wake: WakeEnvelope,
    queued: bool,
}

/// The frames and the opener a batch of `offered` wakes was handed over
/// with: what each batch an adapter takes is cut from.
struct Handoff {
    offered: usize,
    frames: Vec<BoardStreamFrame>,
    opener: Option<String>,
}

impl Handoff {
    /// `wakes`, a selection of the handed-over wakes in their order, as one
    /// batch: the frames of their own TASK rows, and the opener the batch
    /// came with when the selection is all of it, else one rendered now for
    /// the wakes it carries (FIX 15011, FIX 6187).
    fn batch(&self, wakes: Vec<WakeEnvelope>) -> BoardDelivery {
        let opener = if wakes.len() == self.offered {
            self.opener.clone()
        } else {
            wake_batch_opener(&wakes, wall_clock_ms())
        };
        let mut batch = BoardDelivery {
            wakes,
            frames: self.frames.clone(),
            opener,
        };
        batch.retain_frames();
        batch
    }
}

impl Instance {
    /// Hands `delivery` to this host's adapters and returns the wakes none
    /// of them took, for the bridge's wake pump to offer again (FIX 6187).
    ///
    /// Each wake meets the inbox first. One it already holds or acknowledged
    /// was handed over and leaves the batch; an enabled inbox is the adapter
    /// of each wake it takes. The rest go down the ladder: the helper takes
    /// them as one batch on stdin, and its zero exit acknowledges those the
    /// inbox holds, never a failed inbox write; a tmux pane is nudged only
    /// with those the inbox took, whose batch `wake inbox` hands over; the
    /// boot command takes what is left as one batch. A wake whose inbox write
    /// failed has no batch for a nudge to point at, so only the helper or the
    /// boot command takes it. One neither took is returned, with its frames
    /// and no opener; a queued wake no adapter took stays in the inbox. The
    /// TASK in the vault stays the durable source: the returned batch is the
    /// bridge's process-local retry, not a crash-durable inbox.
    pub(crate) async fn deliver(
        &self,
        delivery: BoardDelivery,
        credential_env: &[String],
    ) -> BoardDelivery {
        let BoardDelivery {
            wakes,
            frames,
            opener,
        } = delivery;
        let handoff = Handoff {
            offered: wakes.len(),
            frames,
            opener,
        };
        let mut pending = Vec::with_capacity(handoff.offered);
        for wake in wakes {
            match self.inbox.enqueue(&wake) {
                Ok(false) => {}
                Ok(true) if self.config.inbox => {}
                Ok(true) => pending.push(OfferedWake { wake, queued: true }),
                Err(error) => {
                    tracing::warn!(instance = %self.key, %error, "wake inbox failed; reoffering to a full-batch host adapter");
                    pending.push(OfferedWake {
                        wake,
                        queued: false,
                    });
                }
            }
        }
        if pending.is_empty() {
            return BoardDelivery::default();
        }
        if let Some(helper) = &self.config.helper {
            let batch = handoff.batch(pending.iter().map(|offered| offered.wake.clone()).collect());
            match self.send_batch(helper, &batch, credential_env, true).await {
                Ok(()) => {
                    // The helper's zero exit is its acknowledgement of these
                    // occurrence ids, not of any later failure of the TASK.
                    for offered in pending.iter().filter(|offered| offered.queued) {
                        if let Err(error) = self.inbox.acknowledge(&offered.wake.event_ref) {
                            tracing::warn!(instance = %self.key, %error, "wake delivered; local acknowledgement could not be saved");
                        }
                    }
                    return BoardDelivery::default();
                }
                Err(error) => {
                    tracing::warn!(instance = %self.key, %error, "wake helper failed; reoffering to terminal");
                }
            }
        }
        if let Some(target) = &self.config.tmux_target {
            let queued: Vec<WakeEnvelope> = pending
                .iter()
                .filter(|offered| offered.queued)
                .map(|offered| offered.wake.clone())
                .collect();
            if !queued.is_empty() {
                match pane_nudge(target, &queued, credential_env).await {
                    Ok(()) => pending.retain(|offered| !offered.queued),
                    Err(error) => {
                        tracing::warn!(instance = %self.key, %error, "wake pane nudge failed; reoffering to boot command");
                    }
                }
            }
        }
        if pending.is_empty() {
            return BoardDelivery::default();
        }
        if let Some(boot) = &self.config.boot {
            let batch = handoff.batch(pending.iter().map(|offered| offered.wake.clone()).collect());
            match self.send_batch(boot, &batch, credential_env, false).await {
                Ok(()) => return BoardDelivery::default(),
                Err(error) => {
                    tracing::warn!(instance = %self.key, %error, "wake boot command failed");
                }
            }
        }
        let queued = pending.iter().filter(|offered| offered.queued).count();
        let mut undelivered = BoardDelivery {
            wakes: pending
                .into_iter()
                .filter(|offered| !offered.queued)
                .map(|offered| offered.wake)
                .collect(),
            frames: handoff.frames,
            opener: None,
        };
        undelivered.retain_frames();
        tracing::warn!(instance = %self.key, queued, undelivered = undelivered.wakes.len(), "wake adapters exhausted; TASKs remain in the vault, queued notices in the local inbox, and the rest are offered again at the next poll");
        undelivered
    }

    /// `batch` whole on `adapter`'s stdin, as `send_command` sends it.
    async fn send_batch(
        &self,
        adapter: &AdapterCommand,
        batch: &BoardDelivery,
        credential_env: &[String],
        wait_for_ack: bool,
    ) -> anyhow::Result<()> {
        let body = serde_json::to_vec(&WakeBatch {
            instance_key: &self.key,
            wakes: &batch.wakes,
            frames: &batch.frames,
            opener: batch.opener.as_deref(),
        })?;
        send_command(adapter, &body, credential_env, wait_for_ack).await
    }
}

fn command(program: &std::path::Path, credential_env: &[String]) -> tokio::process::Command {
    let mut command: tokio::process::Command = oneiron_spawn::command(program).into();
    command.stdout(Stdio::null()).stderr(Stdio::null());
    for name in credential_env.iter().map(String::as_str).chain([
        "ONEIRON_SECRET",
        "ONEIRON_TOKEN",
        "ONEIRON_BINDING_KEY",
        "ONEIRON_AUTH_SECRET",
    ]) {
        command.env_remove(name);
    }
    command
}

async fn send_command(
    adapter: &AdapterCommand,
    body: &[u8],
    credential_env: &[String],
    wait_for_ack: bool,
) -> anyhow::Result<()> {
    let mut command = command(&adapter.program, credential_env);
    command
        .args(&adapter.args)
        .stdin(Stdio::piped())
        .kill_on_drop(wait_for_ack);
    let mut child = command.spawn()?;
    let sent = tokio::time::timeout(HELPER_TIMEOUT, async {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("wake command has no stdin"))?;
        stdin.write_all(body).await?;
        stdin.write_all(b"\n").await?;
        stdin.shutdown().await?;
        drop(stdin);
        if wait_for_ack {
            anyhow::ensure!(
                child.wait().await?.success(),
                "wake helper refused the batch"
            );
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    match sent {
        Ok(Ok(())) if !wait_for_ack => {
            // A booted harness outlives this bridge. Reap it without holding
            // delivery open, and do not kill it when the bridge goes away.
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            Ok(())
        }
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let _ = child.kill().await;
            Err(error)
        }
        Err(_) => {
            let _ = child.kill().await;
            Err(anyhow::anyhow!("wake command timed out"))
        }
    }
}

/// The fixed pane line: the prefix and each hex TASK id, a review wake's
/// handle rebuilt from its two hex ids, or a room wake's room and turn
/// (FIX 15647). An id that is not plain hex is left out of the line, never
/// typed.
fn pane_line(wakes: &[WakeEnvelope]) -> String {
    let is_hex = |id: &str| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_hexdigit());
    let mut line = String::from(PANE_NUDGE_PREFIX);
    for wake in wakes {
        if let Some(request) = &wake.review_ref {
            if is_hex(&wake.actor_ref) && is_hex(request) {
                line.push_str(" diary-read:");
                line.push_str(&wake.actor_ref);
                line.push(':');
                line.push_str(request);
            }
            continue;
        }
        if let (Some(room), Some(turn)) = (&wake.room_ref, &wake.turn_ref) {
            if is_hex(room) && is_hex(turn) {
                line.push_str(" room:");
                line.push_str(room);
                line.push(':');
                line.push_str(turn);
            }
            continue;
        }
        let hex =
            !wake.task_ref.is_empty() && wake.task_ref.bytes().all(|byte| byte.is_ascii_hexdigit());
        if hex {
            line.push(' ');
            line.push_str(&wake.task_ref);
        }
    }
    line
}

async fn pane_nudge(
    target: &str,
    wakes: &[WakeEnvelope],
    credential_env: &[String],
) -> anyhow::Result<()> {
    let line = pane_line(wakes);
    for args in [
        vec!["send-keys", "-t", target, "-l", "--", line.as_str()],
        vec!["send-keys", "-t", target, "Enter"],
    ] {
        let mut command = command(std::path::Path::new("tmux"), credential_env);
        command.args(args).stdin(Stdio::null()).kill_on_drop(true);
        let mut child = command.spawn()?;
        let status = tokio::time::timeout(HELPER_TIMEOUT, child.wait()).await??;
        anyhow::ensure!(status.success(), "tmux refused wake delivery");
    }
    Ok(())
}
