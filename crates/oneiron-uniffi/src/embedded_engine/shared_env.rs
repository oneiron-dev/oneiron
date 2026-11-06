//! Original-value shared invitation acceptance and native embedded bootstrap.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron_remote::HttpsSharedInvitationAcceptance;
use oneiron_server::config::SharedEnvConfig;
use oneiron_server::embedded::{embedded_serve_config, engine_memory_error};

use super::{EmbeddedEngine, engine_failure};
use crate::codec::{self, Lower};
use crate::{
    Oneiron, OneironError, OpenOptions, SharedInvitationAcceptWithCredentialRequest,
    SharedInvitationAcceptedWithCredential, WireJson,
};

/// A successful acceptance on the connected HTTPS home, kept as the native
/// value. Receipt records cannot construct this object or supply its provenance.
#[derive(uniffi::Object)]
pub struct SharedInvitationAcceptance {
    inner: Arc<HttpsSharedInvitationAcceptance>,
}

#[uniffi::export]
impl SharedInvitationAcceptance {
    /// The normalized HTTPS home the acceptance selected.
    pub fn home_url(&self) -> String {
        self.inner.home_url().to_owned()
    }

    /// The exact facade URL the original acceptance used.
    pub fn acceptance_url(&self) -> String {
        self.inner.acceptance_url().to_owned()
    }

    /// The original request; reading it does not create another acceptance.
    pub fn request(&self) -> Result<SharedInvitationAcceptWithCredentialRequest, OneironError> {
        codec::lift_record("accept_shared_invitation_https", self.inner.request())
    }

    /// The complete original receipt and member credential, available even
    /// after member-client creation or native bootstrap fails.
    pub fn reply(&self) -> Result<SharedInvitationAcceptedWithCredential, OneironError> {
        codec::lift_record("accept_shared_invitation_https", self.inner.reply())
    }

    /// A remote member handle on the same HTTPS home and original HTTP wire.
    /// Each request still passes the home's ordinary admission checks.
    pub fn member_client(&self) -> Result<Arc<Oneiron>, OneironError> {
        let inner = self.inner.member_client()?;
        Ok(Arc::new(Oneiron {
            inner,
            engine: None,
        }))
    }
}

#[uniffi::export]
impl Oneiron {
    /// Accepts through this connected HTTPS handle with its own holder key.
    /// An in-process or cleartext handle raises the native refusal. Keep the
    /// returned object for bootstrap; a decoded receipt is not a substitute.
    pub fn accept_shared_invitation_https(
        &self,
        request: SharedInvitationAcceptWithCredentialRequest,
    ) -> Result<Arc<SharedInvitationAcceptance>, OneironError> {
        let request = codec::lower_record("accept_shared_invitation_https", request)?;
        let accepted = self.inner.accept_shared_invitation_https(request)?;
        Ok(Arc::new(SharedInvitationAcceptance {
            inner: Arc::new(accepted),
        }))
    }

    /// Retries a pending HTTPS acceptance under its original invocation.
    /// Pass the refusal's pending payload and the same request, not a decoded
    /// generic retry reply: only the native HTTPS call produces this object.
    pub fn retry_shared_invitation_https(
        &self,
        pending: WireJson,
        request: SharedInvitationAcceptWithCredentialRequest,
    ) -> Result<Arc<SharedInvitationAcceptance>, OneironError> {
        let pending = codec::decode("retry_shared_invitation_https", &pending)?;
        let request = codec::lower_record("retry_shared_invitation_https", request)?;
        let accepted = self
            .inner
            .retry_shared_invitation_https(&pending, request)?;
        Ok(Arc::new(SharedInvitationAcceptance {
            inner: Arc::new(accepted),
        }))
    }
}

/// The explicitly selected dedicated environment, not the personal vault.
/// These are the same inputs as one native SharedEnvConfig entry.
#[derive(Clone, uniffi::Record)]
pub struct SharedEnvEntry {
    pub path: String,
    pub vault_id: u64,
    pub member: String,
    pub home_url: String,
    pub credential_file: String,
}

/// The native import result and committed flag, retained independently.
/// An outer setup/task failure raises from bootstrap_shared_env instead.
#[derive(uniffi::Object)]
pub struct SharedEnvBootstrapOutcome {
    imported: anyhow::Result<Arc<oneiron::Vault>>,
    committed: bool,
}

#[uniffi::export]
impl SharedEnvBootstrapOutcome {
    /// The native publication flag, including when a later step failed.
    pub fn committed(&self) -> bool {
        self.committed
    }

    /// The actual registry-held vault's path on success. A failed import,
    /// credential update or insertion raises its native error instead; it
    /// never returns an empty or fabricated successful path.
    pub fn vault_path(&self) -> Result<String, OneironError> {
        match &self.imported {
            Ok(vault) => Ok(vault.path().to_string_lossy().into_owned()),
            Err(error) => match error.downcast_ref::<oneiron::MemoryError>() {
                Some(error) => Err(error.clone().into()),
                None => Err(engine_memory_error(error).into()),
            },
        }
    }
}

#[uniffi::export]
impl EmbeddedEngine {
    /// Imports the original acceptance into entry.path and opens that same
    /// target in this engine's current shared-env registry. The explicit
    /// target config resolves as start does, never from the personal vault.
    /// The credential file must already hold the accepting invitee's key.
    ///
    /// Outer setup/task failures raise here. Once import answers, its native
    /// result and committed flag remain separate on the returned object. Keep
    /// the acceptance for its complete receipt regardless of either result.
    /// This call does not persist the entry in host configuration.
    pub fn bootstrap_shared_env(
        &self,
        acceptance: Arc<SharedInvitationAcceptance>,
        entry: SharedEnvEntry,
        options: Option<OpenOptions>,
        config_file: Option<String>,
    ) -> Result<Arc<SharedEnvBootstrapOutcome>, OneironError> {
        let dimensions: Option<usize> = options.and_then(|options| options.dimensions).lower()?;
        let entry = SharedEnvConfig {
            path: PathBuf::from(entry.path),
            vault_id: entry.vault_id,
            member: entry.member,
            home_url: entry.home_url,
            credential_file: PathBuf::from(entry.credential_file),
        };
        let target = embedded_serve_config(
            &entry.path,
            dimensions,
            config_file.as_deref().map(Path::new),
        )
        .map_err(engine_failure)?;
        let (imported, committed) = self
            .engine
            .bootstrap_shared_env(&acceptance.inner, &entry, &target)
            .map_err(engine_failure)?;
        Ok(Arc::new(SharedEnvBootstrapOutcome {
            imported,
            committed,
        }))
    }
}
