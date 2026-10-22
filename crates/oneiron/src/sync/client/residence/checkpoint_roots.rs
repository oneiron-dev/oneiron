//! Checkpoint root attestations between this machine and its home (FIX
//! 4882), on the steady pass after the authority catch-up. Either end may
//! hold a root of the vault's counted policy while the other wrote the image
//! that awaits it, and this machine is always the end that dials:
//!
//! - A root this machine holds attests the home's head. The machine asks
//!   which roots the head awaits (`residence.authority.checkpoint.roots`),
//!   reads the image a part at a time (`residence.authority.checkpoint`),
//!   checks it against its own fold and signs it
//!   ([`Vault::attest_home_checkpoint_as_root`]), then delivers the
//!   attestation to the home's intake (`residence.authority.checkpoint.attest`).
//!   A hosted node, which never dials, has its images attested this way.
//! - A root the home holds attests this machine's head. When the home signs
//!   as a root this machine's head awaits, the machine sends the image a
//!   part at a time (`residence.authority.checkpoint.countersign`); the home
//!   checks it against its own fold and signs it, and this machine's own
//!   intake takes what it made ([`Vault::import_device_checkpoint_attestation`]).
//!   A host that enrolled with the founding install has its images attested
//!   this way.
//!
//! Neither end trusts the other's fold: each signs only what its own fold
//! rebuilds, and each intake verifies the root again. A wait or a refusal
//! is logged, and the image waits for the next pass. What a root held here
//! signed for the home's head is kept until the home reports it accepted,
//! so a failed delivery goes again with no new read or signature (FIX 5109,
//! [`Vault::checkpoint_root_deliveries`]).

use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::authority::fetch_authority_checkpoint;
use super::{ResidenceRpc, refused, residence_budgets};
use crate::Vault;
use crate::authority::{
    AUTHORITY_CHECKPOINT_COUNTERSIGN_PART_MAX, AuthorityCheckpointAttestation, AuthorityKey,
    CheckpointRootSigner, PeerMachine, RootCheckpointAttest,
};
use crate::sync::client::SyncClientConfig;
use crate::sync::transport::TransportError;

/// The home's checkpoint head and the roots on either side of it.
#[derive(Deserialize)]
struct RootsReply {
    /// The head image's id in base64; absent when the home keeps none.
    #[serde(default)]
    checkpoint: Option<String>,
    /// The roots the head still awaits.
    #[serde(default)]
    awaiting: Vec<AuthorityKey>,
    /// The roots the home signs as.
    #[serde(default)]
    signs: Vec<AuthorityKey>,
}

/// What the home's roots made of this machine's image.
#[derive(Deserialize)]
struct CountersignReply {
    #[serde(default)]
    attestations: Vec<AuthorityCheckpointAttestation>,
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

fn stopped() -> TransportError {
    TransportError::Storage("checkpoint root work stopped".into())
}

/// One exchange with the home: see the module notes. Returns how many
/// attestations an intake kept. Without a root signer held here and with no
/// root this machine's head awaits, it dials nothing.
pub(crate) async fn exchange_checkpoint_roots(
    vault: &Arc<Vault>,
    config: &SyncClientConfig,
) -> Result<usize, TransportError> {
    let signers = vault.checkpoint_root_signers();
    let own = own_awaited_head(vault);
    if signers.is_empty() && own.is_none() {
        return Ok(0);
    }
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Ok(0);
    };
    let home = match rpc
        .call("residence.authority.checkpoint.roots", json!({}))
        .await?
    {
        Ok(reply) => serde_json::from_value::<RootsReply>(reply).map_err(|_| refused())?,
        // A home that does not hold this machine as linked, or that predates
        // the exchange, has nothing to trade.
        Err(_) => return Ok(0),
    };
    let head = home
        .checkpoint
        .as_deref()
        .map(|checkpoint| {
            base64::engine::general_purpose::STANDARD
                .decode(checkpoint)
                .ok()
                .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                .ok_or_else(refused)
        })
        .transpose()?;
    // What roots held here signed for this home, against what it names now.
    settle_kept(vault, rpc.home, head, home.awaiting.clone()).await?;
    let mut kept = 0;
    if let Some(id) = head {
        for signer in &signers {
            if home.awaiting.contains(&signer.root()) {
                kept += attest_home_head(vault, &mut rpc, id, signer).await?;
            }
        }
    }
    if let Some((image, awaited)) = own
        && awaited.iter().any(|root| home.signs.contains(root))
    {
        kept += ask_home_countersign(vault, &mut rpc, image).await?;
    }
    Ok(kept)
}

/// This machine's head and the roots it awaits, when it awaits any.
fn own_awaited_head(vault: &Vault) -> Option<([u8; 32], Vec<AuthorityKey>)> {
    let roots = vault.authority_checkpoint_roots().ok().flatten()?;
    let awaited: Vec<AuthorityKey> = roots.awaited().cloned().collect();
    (!awaited.is_empty()).then_some((roots.image, awaited))
}

/// Settles what roots held here signed for the home against what it names
/// now, its head `head` and the roots `awaiting` it (FIX 5109). A failure is
/// logged: the rows are a delivery cache.
async fn settle_kept(
    vault: &Arc<Vault>,
    home: PeerMachine,
    head: Option<[u8; 32]>,
    awaiting: Vec<AuthorityKey>,
) -> Result<(), TransportError> {
    let vault = Arc::clone(vault);
    let settled =
        tokio::task::spawn_blocking(move || vault.settle_root_attestations(home, head, &awaiting))
            .await
            .map_err(|_| stopped())?;
    if let Err(error) = settled {
        tracing::warn!(kind = ?error.kind(), "the kept root attestations did not settle");
    }
    Ok(())
}

/// `signer`'s root attests the home's head `id`, and the attestation goes to
/// the home's intake. One this root made on an earlier pass and kept goes
/// again as it was signed (FIX 5109); otherwise the image is read from the
/// home and signed here. Returns 1 once the home kept it.
async fn attest_home_head(
    vault: &Arc<Vault>,
    rpc: &mut ResidenceRpc,
    id: [u8; 32],
    signer: &Arc<dyn CheckpointRootSigner>,
) -> Result<usize, TransportError> {
    let home = rpc.home;
    let root = signer.root();
    let kept = vault
        .kept_root_attestation(home, &root, id)
        .unwrap_or_else(|error| {
            tracing::warn!(kind = ?error.kind(), "a kept root attestation was not read");
            None
        });
    let attestation = match kept {
        Some(attestation) => attestation,
        None => match sign_home_head(vault, rpc, id, signer).await? {
            Some(attestation) => attestation,
            None => return Ok(0),
        },
    };
    let attestation = serde_json::to_value(attestation).map_err(|_| refused())?;
    match rpc
        .call(
            "residence.authority.checkpoint.attest",
            json!({
                "checkpoint": base64::engine::general_purpose::STANDARD.encode(id),
                "attestation": attestation,
            }),
        )
        .await?
    {
        Ok(_) => {
            let vault = Arc::clone(vault);
            let delivered = tokio::task::spawn_blocking(move || {
                vault.root_attestation_delivered(home, &root, id)
            })
            .await
            .map_err(|_| stopped())?;
            if let Err(error) = delivered {
                tracing::warn!(kind = ?error.kind(), "a delivered root attestation was not marked");
            }
            Ok(1)
        }
        Err(_) => {
            tracing::warn!("the home refused this machine's root attestation of its checkpoint");
            Ok(0)
        }
    }
}

/// `signer`'s root signs the home's head `id`, read from the home, and keeps
/// what it made until the home's intake has it
/// ([`Vault::attest_home_checkpoint_as_root`]). `None` when it does not sign
/// it now.
async fn sign_home_head(
    vault: &Arc<Vault>,
    rpc: &mut ResidenceRpc,
    id: [u8; 32],
    signer: &Arc<dyn CheckpointRootSigner>,
) -> Result<Option<AuthorityCheckpointAttestation>, TransportError> {
    let Some((image, _)) = fetch_authority_checkpoint(rpc, &id).await? else {
        return Ok(None);
    };
    let home = rpc.home;
    let attest = {
        let vault = Arc::clone(vault);
        let signer = Arc::clone(signer);
        tokio::task::spawn_blocking(move || {
            vault.attest_home_checkpoint_as_root(home, id, &image, signer.as_ref())
        })
        .await
        .map_err(|_| stopped())?
    };
    match attest {
        Ok(RootCheckpointAttest::Attested { image, attestation }) if image == id => {
            Ok(Some(*attestation))
        }
        Ok(RootCheckpointAttest::Attested { .. }) => {
            tracing::warn!("the home served other bytes than the checkpoint it named");
            Ok(None)
        }
        Ok(RootCheckpointAttest::Waiting(reason)) => {
            tracing::debug!(
                reason,
                "the home's checkpoint waits for this machine's root"
            );
            Ok(None)
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "the home's checkpoint was not attested here");
            Ok(None)
        }
    }
}

/// Asks the home's roots to attest this machine's head `image`, sent a
/// part at a time, and takes what they made, answered on the last part,
/// through this machine's own intake, with the home as the delivering peer.
/// Returns how many it kept.
async fn ask_home_countersign(
    vault: &Arc<Vault>,
    rpc: &mut ResidenceRpc,
    image: [u8; 32],
) -> Result<usize, TransportError> {
    let Some(bundle) = vault.authority_checkpoint_bundle(&image).map_err(storage)? else {
        return Ok(0);
    };
    let total = bundle.image.len() as u64;
    let mut offset = 0_u64;
    let mut last = None;
    for part in bundle
        .image
        .chunks(AUTHORITY_CHECKPOINT_COUNTERSIGN_PART_MAX)
    {
        let reply = rpc
            .call(
                "residence.authority.checkpoint.countersign",
                json!({
                    "checkpoint": base64::engine::general_purpose::STANDARD.encode(image),
                    "total": total,
                    "offset": offset,
                    "part": base64::engine::general_purpose::STANDARD.encode(part),
                }),
            )
            .await?;
        let Ok(reply) = reply else {
            return Ok(0);
        };
        offset += part.len() as u64;
        last = Some(reply);
    }
    let Some(reply) = last else {
        return Ok(0);
    };
    // Every attestation the home returns is verified on its own: a quorum
    // may name more roots than any fixed count (FIX 8090).
    let reply: CountersignReply = serde_json::from_value(reply).map_err(|_| refused())?;
    let home = rpc.home;
    let vault = Arc::clone(vault);
    tokio::task::spawn_blocking(move || {
        let mut kept = 0;
        for attestation in &reply.attestations {
            match vault.import_device_checkpoint_attestation(home, image, attestation) {
                Ok(_) => kept += 1,
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "the home's root attestation of this machine's checkpoint was refused"
                ),
            }
        }
        kept
    })
    .await
    .map_err(|_| stopped())
}
