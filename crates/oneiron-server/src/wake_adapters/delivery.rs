//! The preference/degrade ladder belongs to this host, never the engine.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

use super::board_stream::BoardDelivery;
use super::{AdapterCommand, Instance, WakeBatch};

/// A stalled helper must let the next configured adapter try.
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);

impl Instance {
    pub(crate) async fn deliver(&self, mut delivery: BoardDelivery, credential_env: &[String]) {
        delivery.wakes.retain(|wake| match self.inbox.enqueue(wake) {
            Ok(false) => false,
            Ok(true) => !self.config.inbox,
            Err(error) => {
                tracing::warn!(instance = %self.key, %error, "wake inbox failed; reoffering to a host adapter");
                true
            }
        });
        delivery.retain_frames();
        if delivery.wakes.is_empty() {
            return;
        }
        let batch = WakeBatch {
            instance_key: &self.key,
            wakes: &delivery.wakes,
            frames: &delivery.frames,
        };
        let body = match serde_json::to_vec(&batch) {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(instance = %self.key, %error, "wake batch could not be encoded");
                return;
            }
        };
        if let Some(helper) = &self.config.helper {
            match send_command(helper, &body, credential_env, true).await {
                Ok(()) => {
                    // The helper's zero exit is its acknowledgement of these
                    // occurrence ids, not of any later failure of the TASK.
                    for wake in &delivery.wakes {
                        if let Err(error) = self.inbox.acknowledge(&wake.event_ref) {
                            tracing::warn!(instance = %self.key, %error, "wake delivered; local acknowledgement could not be saved");
                        }
                    }
                    return;
                }
                Err(error) => {
                    tracing::warn!(instance = %self.key, %error, "wake helper failed; reoffering to terminal");
                }
            }
        }
        if let Some(target) = &self.config.tmux_target {
            match terminal(target, &body, credential_env).await {
                Ok(()) => return,
                Err(error) => {
                    tracing::warn!(instance = %self.key, %error, "wake terminal delivery failed; reoffering to boot command");
                }
            }
        }
        if let Some(boot) = &self.config.boot {
            match send_command(boot, &body, credential_env, false).await {
                Ok(()) => return,
                Err(error) => {
                    tracing::warn!(instance = %self.key, %error, "wake boot command failed");
                }
            }
        }
        tracing::warn!(instance = %self.key, count = delivery.wakes.len(), "wake adapters exhausted; TASKs remain in the vault and notices in the local inbox when writable");
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

async fn terminal(target: &str, body: &[u8], credential_env: &[String]) -> anyhow::Result<()> {
    let literal = String::from_utf8(body.to_vec())?;
    for args in [
        vec!["send-keys", "-t", target, "-l", "--", literal.as_str()],
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
