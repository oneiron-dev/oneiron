//! Checkpoint root attestations between this machine and its home (FIX
//! 4882), on the steady pass after the authority catch-up. Either end may
//! hold a root of the vault's counted policy while the other wrote the image
//! that awaits it, and this machine is always the end that dials:
//!
//! - A root this machine holds attests the home's head. The machine asks
//!   which roots the head awaits (`residence.authority.checkpoint.roots`),
//!   reads the image a part at a time (`residence.authority.checkpoint`),
//!   checks it against its own fold and signs it
//!   ([`Vault::attest_checkpoint_image_as_root`]), then delivers the
//!   attestation to the home's intake (`residence.authority.checkpoint.attest`).
//!   A hosted node, which never dials, has its images attested this way.
//! - A root the home holds attests this machine's head. When the home signs
//!   as a root this machine's head awaits, the machine sends the image whole
//!   (`residence.authority.checkpoint.countersign`); the home checks it
//!   against its own fold and signs it, and this machine's own intake takes
//!   what it made ([`Vault::import_device_checkpoint_attestation`]). A host
//!   that enrolled with the founding install has its images attested this
//!   way.
//!
//! Neither end trusts the other's fold: each signs only what its own fold
//! rebuilds, and each intake verifies the root again. A wait or a refusal
//! is logged, and the image waits for the next pass.

use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::authority::fetch_authority_checkpoint;
use super::{ResidenceRpc, refused, residence_budgets};
use crate::Vault;
use crate::authority::{
    AUTHORITY_CHECKPOINT_COUNTERSIGN_MAX, AuthorityCheckpointAttestation, AuthorityKey,
    CheckpointRootSigner, RootCheckpointAttest,
};
use crate::sync::client::SyncClientConfig;
use crate::sync::transport::TransportError;

/// The most attestations one countersign reply carries: one for each root
/// the home holds.
const COUNTERSIGN_REPLY_MAX: usize = 16;

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
    let mut kept = 0;
    if let Some(checkpoint) = home.checkpoint.as_deref() {
        let id = base64::engine::general_purpose::STANDARD
            .decode(checkpoint)
            .ok()
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
            .ok_or_else(refused)?;
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

/// `signer`'s root attests the home's head `id`, read from the home, and the
/// attestation goes to the home's intake. Returns 1 once the home kept it.
async fn attest_home_head(
    vault: &Arc<Vault>,
    rpc: &mut ResidenceRpc,
    id: [u8; 32],
    signer: &Arc<dyn CheckpointRootSigner>,
) -> Result<usize, TransportError> {
    let Some((image, _)) = fetch_authority_checkpoint(rpc, &id).await? else {
        return Ok(0);
    };
    let attest = {
        let vault = Arc::clone(vault);
        let signer = Arc::clone(signer);
        tokio::task::spawn_blocking(move || {
            vault.attest_checkpoint_image_as_root(&image, signer.as_ref())
        })
        .await
        .map_err(|_| stopped())?
    };
    let attestation = match attest {
        Ok(RootCheckpointAttest::Attested { image, attestation }) if image == id => attestation,
        Ok(RootCheckpointAttest::Attested { .. }) => {
            tracing::warn!("the home served other bytes than the checkpoint it named");
            return Ok(0);
        }
        Ok(RootCheckpointAttest::Waiting(reason)) => {
            tracing::debug!(
                reason,
                "the home's checkpoint waits for this machine's root"
            );
            return Ok(0);
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "the home's checkpoint was not attested here");
            return Ok(0);
        }
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
        Ok(_) => Ok(1),
        Err(_) => {
            tracing::warn!("the home refused this machine's root attestation of its checkpoint");
            Ok(0)
        }
    }
}

/// Asks the home's roots to attest this machine's head `image`, sent whole,
/// and takes what they made through this machine's own intake, with the home
/// as the delivering peer. Returns how many it kept. An image past one
/// request waits for a root that reads it here.
async fn ask_home_countersign(
    vault: &Arc<Vault>,
    rpc: &mut ResidenceRpc,
    image: [u8; 32],
) -> Result<usize, TransportError> {
    let Some(bundle) = vault.authority_checkpoint_bundle(&image).map_err(storage)? else {
        return Ok(0);
    };
    if bundle.image.len() > AUTHORITY_CHECKPOINT_COUNTERSIGN_MAX {
        tracing::debug!(
            bytes = bundle.image.len(),
            "this machine's checkpoint is past one countersign request"
        );
        return Ok(0);
    }
    let reply = match rpc
        .call(
            "residence.authority.checkpoint.countersign",
            json!({ "image": base64::engine::general_purpose::STANDARD.encode(bundle.image) }),
        )
        .await?
    {
        Ok(reply) => serde_json::from_value::<CountersignReply>(reply).map_err(|_| refused())?,
        Err(_) => return Ok(0),
    };
    if reply.attestations.len() > COUNTERSIGN_REPLY_MAX {
        return Err(refused());
    }
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
