//! Owner-signing recovery (FIX 5260): the vault's proof, on its supervisor's
//! `recover_owner_signing` challenge, that it still holds its spawn token.
//!
//! The proof goes to the supervisor socket the wake ledger already pushes to,
//! on a connection of its own: one `owner_signing_recovery` line with the
//! vault's name, its spawn token and the challenge, and one ack line back.
//! The ctl reply carries only whether the supervisor acked. The token rides
//! no other channel and nothing here stores it. One attempt per challenge:
//! the supervisor asks again if it needs to, and this side never retries.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use oneiron_vault_contract::{
    MAX_CTL_LINE, OWNER_SIGNING_RECOVERY_OP, OwnerSigningRecovery, OwnerSigningRecoveryAck,
    TokenHex,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

/// How long one proof (connect, write and the supervisor's ack) may take
/// before it is abandoned. The supervisor's own ctl call waits longer, so a
/// proof that runs out still ends in an answer on ctl.
const PROOF_TIMEOUT: Duration = Duration::from_secs(2);

/// Sends the proof for `challenge` to `socket` and reads the supervisor's
/// ack: `Ok(true)` when it signs for the owner again, `Ok(false)` when it
/// answered no. The whole attempt runs under [`PROOF_TIMEOUT`].
pub(super) async fn prove(
    socket: &Path,
    vault: &str,
    token: &TokenHex,
    challenge: &str,
) -> anyhow::Result<bool> {
    tokio::time::timeout(PROOF_TIMEOUT, attempt(socket, vault, token, challenge))
        .await
        .map_err(|_elapsed| {
            anyhow::anyhow!("the supervisor did not answer within {PROOF_TIMEOUT:?}")
        })?
}

/// The attempt itself, with no deadline of its own: [`prove`] is the only
/// caller and it is what bounds this.
async fn attempt(
    socket: &Path,
    vault: &str,
    token: &TokenHex,
    challenge: &str,
) -> anyhow::Result<bool> {
    let proof = OwnerSigningRecovery {
        op: OWNER_SIGNING_RECOVERY_OP.to_owned(),
        vault: vault.to_owned(),
        token: token.clone(),
        challenge: challenge.to_owned(),
    };
    // A proof this side's supervisor would refuse to read is one this side
    // must refuse to send.
    proof.validate().context("refused to send the proof")?;
    // The line carries the token, so it is wiped once it is written.
    let line = Zeroizing::new(serde_json::to_string(&proof).context("encode the proof")?);
    anyhow::ensure!(
        line.len() <= MAX_CTL_LINE,
        "the proof is {} bytes, over the {MAX_CTL_LINE}-byte line cap",
        line.len()
    );

    let stream = UnixStream::connect(socket)
        .await
        .context("connect to the supervisor socket")?;
    let (reader, mut writer) = stream.into_split();
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader.take(MAX_CTL_LINE as u64 + 2));
    let mut ack_line = String::new();
    reader.read_line(&mut ack_line).await?;
    let ack: OwnerSigningRecoveryAck =
        serde_json::from_str(ack_line.trim_end_matches(['\r', '\n']))
            .context("the supervisor's ack is malformed")?;
    Ok(ack.recovered)
}
