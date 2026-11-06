//! The live host's selected-target consumer of an actual HTTPS acceptance.

use std::sync::Arc;

use oneiron::{EntityId, Vault};
use oneiron_remote::HttpsSharedInvitationAcceptance;

use super::{SharedEnvRegistry, SharedEnvSpec};
use crate::commands::credential_file::PairedCredentialFile;
use crate::config::{ServeConfig, SharedEnvConfig};

impl crate::server::SyncServer {
    /// Materializes an accepted membership into its explicitly selected target
    /// and opens that same target in this serving host's existing registry.
    /// `target_serve` is the dedicated target's config, not the personal vault's.
    /// Its vault path must name `entry.path`; its page seal resolves there only.
    /// The credential file already holds the invitee's paired key. On success
    /// its token is replaced by the original acceptance's member token.
    ///
    /// The caller retains the original acceptance and complete receipt. An
    /// outer error is setup/task failure, not a statement about publication.
    /// Once import answers, the inner result and native committed flag stay
    /// separate, including on a tail error. No outcome deletes target files.
    /// A successful inner result is the actual registry-held vault, not a
    /// receipt or a claim that a remote live sync round has completed.
    pub async fn bootstrap_shared_env(
        &self,
        acceptance: &Arc<HttpsSharedInvitationAcceptance>,
        entry: &SharedEnvConfig,
        target_serve: &ServeConfig,
    ) -> anyhow::Result<(anyhow::Result<Arc<Vault>>, bool)> {
        let registry = self
            .shared_envs
            .get()
            .ok_or_else(|| anyhow::anyhow!("this host has no installed shared-env registry"))?;
        registry
            .bootstrap_one(acceptance, entry, target_serve)
            .await
    }
}

impl SharedEnvRegistry {
    async fn bootstrap_one(
        &self,
        acceptance: &Arc<HttpsSharedInvitationAcceptance>,
        entry: &SharedEnvConfig,
        target_serve: &ServeConfig,
    ) -> anyhow::Result<(anyhow::Result<Arc<Vault>>, bool)> {
        let stopped = self.inner.stopped.lock().await;
        anyhow::ensure!(!*stopped, "the shared-env registry has stopped");
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("the shared-env registry has no host wiring"))?;
        let spec = SharedEnvSpec::from_config(entry)?;
        anyhow::ensure!(
            self.get(spec.vault_id, &spec.member).is_none(),
            "shared env membership is already open"
        );
        anyhow::ensure!(
            target_serve.vault_path == spec.path,
            "the dedicated target config must name the selected shared-env path"
        );
        anyhow::ensure!(
            acceptance.request().vault_id == spec.vault_id,
            "the acceptance names a different shared vault"
        );
        let slip =
            oneiron::authority::CapabilitySlip::from_token(&acceptance.reply().credential.slip)?;
        anyhow::ensure!(
            EntityId::from_hex(&slip.claims.holder_ref)?.to_hex() == spec.member,
            "the acceptance names a different member"
        );
        let mut expected_home = reqwest::Url::parse(acceptance.home_url())?;
        expected_home
            .set_scheme("wss")
            .map_err(|()| anyhow::anyhow!("the accepted HTTPS home has no sync scheme"))?;
        let expected_home = expected_home.join("ws")?;
        anyhow::ensure!(
            reqwest::Url::parse(&spec.home_url)? == expected_home,
            "the selected sync endpoint is not the accepted HTTPS home's endpoint"
        );
        let _admitted =
            (runtime.admission)().ok_or_else(|| anyhow::anyhow!("the host is frozen for reap"))?;
        let lease_vault_id = runtime.lease_vault_id;
        let accepted = Arc::clone(acceptance);
        let target_config = target_serve.clone();
        let candidate_config = target_config.clone();
        let (imported, committed, path) = tokio::task::spawn_blocking(move || {
            paired_key(&spec.credential_file, &accepted)?;
            let candidate = crate::commands::replica_target::open(&candidate_config)?;
            let path = candidate.path().to_owned();
            let (imported, committed) = accepted.bootstrap_replica_into(&candidate, lease_vault_id);
            // No candidate Vault, Arc, manager or connection crosses this
            // boundary: registry insertion reopens it with a new writer lease.
            drop(candidate);
            let imported = imported.map_err(anyhow::Error::from);
            let credential = if committed {
                (|| {
                    // Re-read after HTTP work; do not overwrite a different
                    // holder key a caller installed while that work ran.
                    let mut paired = paired_key(&spec.credential_file, &accepted)?;
                    paired.token = accepted.reply().credential.slip.clone();
                    crate::commands::credential_file::replace(
                        &spec.credential_file,
                        paired.credential().as_bytes(),
                    )
                })()
            } else {
                Ok(())
            };
            // A later credential failure must not replace the original import
            // error. Either way committed data stays, with its real flag.
            Ok::<_, anyhow::Error>((imported.and(credential), committed, path))
        })
        .await??;
        if let Err(error) = imported {
            return Ok((Err(error), committed));
        }
        let inserted = self
            .insert(
                entry,
                &target_config,
                lease_vault_id,
                runtime.admission.clone(),
                runtime.freeze.clone(),
            )
            .await
            .map_err(anyhow::Error::msg)
            .and_then(|vault| {
                let held = self.get(entry.vault_id, &entry.member.trim().to_ascii_lowercase());
                anyhow::ensure!(
                    vault.path() == path
                        && held.as_ref().is_some_and(|held| Arc::ptr_eq(held, &vault)),
                    "shared-env insertion did not retain the selected target"
                );
                Ok(vault)
            });
        Ok((inserted, committed))
    }
}

/// The caller's own file supplies only the key; native import still proves
/// the returned token against the imported history and current grant.
fn paired_key(
    path: &std::path::Path,
    acceptance: &HttpsSharedInvitationAcceptance,
) -> anyhow::Result<PairedCredentialFile> {
    let paired = PairedCredentialFile::read(path)?;
    anyhow::ensure!(
        paired.signing_key()?.verifying_key().to_bytes() == acceptance.recipient_binding_key(),
        "the selected credential file does not hold the accepting member's key"
    );
    Ok(paired)
}
