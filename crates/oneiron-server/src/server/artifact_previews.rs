//! Host-authenticated process declarations and their existing private preview leases.

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::artifact_hosting::door_types::*;
use oneiron::artifact_hosting::preview::PreviewSessionManifest;
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_LEASE_REQUIRED, MemoryError, MemoryResult,
};
use oneiron_vault_contract::host::PreviewPortHost;
use tokio::sync::Mutex;

use crate::managed::ManagedShutdown;
use crate::managed::preview::{LocalPreviewHost, PreviewLease, PreviewProcess};

#[derive(Default)]
pub(crate) struct ArtifactPreviews {
    held: Mutex<BTreeMap<(String, String), HostedPreview>>,
}

struct HostedPreview {
    manifest: PreviewSessionManifest,
    host: LocalPreviewHost,
    lease: Option<PreviewLease>,
}

impl super::SyncServer {
    /// The trusted session runtime installs its verified process, connector
    /// and stop signal. No HTTP input can install or replace a connector.
    pub async fn install_artifact_preview_process(
        &self,
        process: Arc<dyn PreviewProcess>,
        stop: ManagedShutdown,
    ) -> MemoryResult<()> {
        let manifest = process.manifest().clone();
        manifest
            .validate(oneiron_vault_contract::now_ts())
            .map_err(MemoryError::bad_request)?;
        let key = (manifest.session_ref.clone(), manifest.lease_ref.clone());
        let mut held = self.artifact_previews.held.lock().await;
        if held.contains_key(&key) {
            return Err(MemoryError::bad_request(
                "preview lease is already installed",
            ));
        }
        held.insert(
            key,
            HostedPreview {
                manifest,
                host: LocalPreviewHost::new(process, stop),
                lease: None,
            },
        );
        Ok(())
    }
}

impl ArtifactPreviews {
    pub(crate) async fn register(
        &self,
        manifest: PreviewSessionManifest,
    ) -> MemoryResult<ArtifactPreviewView> {
        let mut held = self.held.lock().await;
        let key = (manifest.session_ref.clone(), manifest.lease_ref.clone());
        let entry = held.get_mut(&key).ok_or_else(unbound)?;
        if manifest != entry.manifest {
            return Err(MemoryError::bad_request(
                "preview manifest does not match the runtime declaration",
            ));
        }
        if entry.lease.is_none() {
            entry.lease = Some(
                entry
                    .host
                    .open_preview(manifest.clone())
                    .await
                    .map_err(preview_error)?,
            );
        }
        view(
            entry.lease.as_ref().ok_or_else(unbound)?,
            &manifest.owner_ref,
        )
    }

    pub(crate) async fn read(
        &self,
        principal: &str,
        input: ArtifactPreviewRequest,
    ) -> MemoryResult<Option<ArtifactPreviewView>> {
        let held = self.held.lock().await;
        let Some(lease) = held
            .get(&(input.session_ref, input.lease_ref))
            .and_then(|entry| entry.lease.as_ref())
            .filter(|lease| lease.is_live())
        else {
            return Ok(None);
        };
        view(lease, principal).map(Some)
    }

    pub(crate) async fn close(
        &self,
        owner: &str,
        input: ArtifactPreviewRequest,
    ) -> MemoryResult<ArtifactPreviewClosed> {
        let mut held = self.held.lock().await;
        let key = (input.session_ref, input.lease_ref);
        let Some(entry) = held.get(&key) else {
            return Ok(ArtifactPreviewClosed { closed: false });
        };
        if entry.manifest.owner_ref != owner {
            return Err(preview_error("preview owner action refused"));
        }
        // Dropping the existing lease ends all tokens, streams and upgrades.
        let closed = held.remove(&key).is_some();
        Ok(ArtifactPreviewClosed { closed })
    }

    pub(crate) async fn invitation(
        &self,
        owner: &str,
        input: ArtifactPreviewInviteRequest,
        invite: bool,
    ) -> MemoryResult<ArtifactPreviewInvitation> {
        let held = self.held.lock().await;
        let lease = lease(&held, &(input.session_ref, input.lease_ref))?;
        let principal = input.principal_ref.to_hex();
        if invite {
            lease.invite(owner, &principal).map_err(preview_error)?;
        } else {
            lease
                .revoke_invite(owner, &principal)
                .map_err(preview_error)?;
        }
        Ok(ArtifactPreviewInvitation {
            principal_ref: input.principal_ref,
            invited: invite,
        })
    }

    pub(crate) async fn share(
        &self,
        owner: &str,
        input: ArtifactPreviewRequest,
        share: bool,
    ) -> MemoryResult<ArtifactPreviewShare> {
        let held = self.held.lock().await;
        let lease = lease(&held, &(input.session_ref, input.lease_ref))?;
        let access_url = if share {
            Some(lease.share_url(owner).map_err(preview_error)?.to_string())
        } else {
            lease.revoke_share(owner).map_err(preview_error)?;
            None
        };
        Ok(ArtifactPreviewShare { access_url })
    }
}

fn lease<'a>(
    held: &'a BTreeMap<(String, String), HostedPreview>,
    key: &(String, String),
) -> MemoryResult<&'a PreviewLease> {
    held.get(key)
        .and_then(|entry| entry.lease.as_ref())
        .filter(|lease| lease.is_live())
        .ok_or_else(unbound)
}

fn view(lease: &PreviewLease, principal: &str) -> MemoryResult<ArtifactPreviewView> {
    let access_url = lease
        .access_url(principal)
        .map_err(preview_error)?
        .to_string();
    let endpoint = lease.endpoint();
    Ok(ArtifactPreviewView {
        session_ref: endpoint.session_ref.clone(),
        lease_ref: endpoint.lease_ref.clone(),
        local_url: endpoint.local_url.clone(),
        stage: ArtifactPreviewStage::Draft,
        private: true,
        expires_at: endpoint.expires_at,
        access_url,
    })
}

fn unbound() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_LEASE_REQUIRED,
        "no live, host-declared preview lease is bound",
        &["Use a process and lease installed by the session runtime."],
    )
}

fn preview_error(error: impl std::fmt::Display) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        error.to_string(),
        &["Use the live lease's owner, invitation or sharing URL."],
    )
}
