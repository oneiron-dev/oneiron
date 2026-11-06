//! Fetch and materialize from the actual accepted HTTPS home and holder.

use oneiron::authority::{CapabilitySlip, holder_proof};
use oneiron::memory::MemoryError;
use oneiron::sync::WindowKey;
use oneiron::task_verb::sdk::{
    SharedReplicaManifest, SharedReplicaManifestRequest, SharedReplicaWindow,
    SharedReplicaWindowRequest,
};
use oneiron::{EntityId, Vault};

use super::HttpsSharedInvitationAcceptance;
use crate::Backend;
use crate::error::transport_error;

impl HttpsSharedInvitationAcceptance {
    /// Imports into the caller's selected, still-unstarted dedicated target.
    /// Every fetch reuses this actual acceptance's HTTPS home, original Wire,
    /// member credential and local holder key. The receipt stays on `self`
    /// even if fetching or materialization fails. This starts no live lane.
    ///
    /// The returned error and committed publication are independent. The
    /// caller must retain committed files on a tail error, drop all candidate
    /// handles, and obtain the real registry insertion result before success.
    pub fn bootstrap_replica_into(
        &self,
        target: &Vault,
        lease_vault_id: u64,
    ) -> (Result<(), MemoryError>, bool) {
        let fetched = (|| -> Result<_, MemoryError> {
            let client = self.member_client()?;
            let Backend::Remote(remote) = &client.backend else {
                return Err(transport_error(
                    "accepted member has no original HTTPS wire",
                ));
            };
            let slip = CapabilitySlip::from_token(&self.reply.credential.slip)?;
            let grant = slip
                .claims
                .grant_ref
                .as_deref()
                .ok_or_else(|| transport_error("accepted member credential names no grant"))?;
            let grant = EntityId::from_hex(grant)
                .map_err(|_| transport_error("accepted member credential has an invalid grant"))?;
            let member = EntityId::from_hex(&slip.claims.holder_ref)
                .map_err(|_| transport_error("accepted member credential has an invalid holder"))?;
            let manifest: SharedReplicaManifest = remote.call(
                "vault.members.replica_manifest",
                &SharedReplicaManifestRequest {
                    vault_id: self.request.vault_id,
                    grant: grant.to_hex(),
                },
            )?;
            let selector = manifest.decode_selector()?;
            if EntityId::from_hex(&manifest.grant)
                .map_err(|_| transport_error("replica source returned an invalid grant"))?
                != grant
                || selector.grant_id != grant
                || selector.member_ref != member
            {
                return Err(transport_error(
                    "replica source changed the accepted member or grant",
                ));
            }
            let history = manifest.decode_history()?;
            let mut windows = Vec::with_capacity(manifest.windows.len());
            for raw_key in &manifest.windows {
                let key = WindowKey::try_new(raw_key.clone()).ok_or_else(|| {
                    transport_error("replica source returned an invalid native window key")
                })?;
                let window: SharedReplicaWindow = remote.call(
                    "vault.members.replica_window",
                    &SharedReplicaWindowRequest {
                        vault_id: self.request.vault_id,
                        grant: grant.to_hex(),
                        window: raw_key.clone(),
                        selector: manifest.selector.clone(),
                    },
                )?;
                if window.window != *raw_key {
                    return Err(transport_error(
                        "replica source changed the requested window",
                    ));
                }
                windows.push((key, window.decode_update()?));
            }
            // HOME already spent a different proof for each HTTP call. This
            // fresh proof is signed locally for the TARGET's own admission.
            let timestamp = crate::unix_seconds_now();
            let proof = holder_proof(&slip, &self.holder_key, timestamp)?;
            let signature = proof
                .get("signature")
                .and_then(|value| value.as_str())
                .ok_or_else(|| transport_error("native holder proof has no signature"))?;
            let signature = signature
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let hex = std::str::from_utf8(pair)
                        .map_err(|_| transport_error("native holder signature is not hex"))?;
                    u8::from_str_radix(hex, 16)
                        .map_err(|_| transport_error("native holder signature is not hex"))
                })
                .collect::<Result<Vec<_>, MemoryError>>()?;
            let nonce = proof
                .get("nonce")
                .and_then(|value| value.as_str())
                .ok_or_else(|| transport_error("native holder proof has no nonce"))?
                .as_bytes()
                .to_vec();
            Ok((
                history,
                windows,
                slip,
                (timestamp, signature, nonce),
                selector,
            ))
        })();
        let (history, windows, slip, proof, selector) = match fetched {
            Ok(fetched) => fetched,
            Err(error) => return (Err(error), false),
        };
        let (result, committed) = oneiron::sync::shared_replica::import_shared_replica(
            target,
            history,
            windows,
            slip,
            proof,
            self.request.vault_id,
            &selector,
            lease_vault_id,
        );
        (result.map_err(MemoryError::from), committed)
    }
}
