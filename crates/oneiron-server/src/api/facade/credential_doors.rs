//! A holder appends a narrowing to the exact credential this call presented.
//! No host issuer or owner fallback participates in attenuation or transfer.
use std::sync::Arc;

use oneiron::authority::InvocationSlipBinding;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{CredentialAttenuated, CredentialAttenuationRequest};

use super::host_doors::support::{Listed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(super) fn holder(auth: &CoreAuth) -> MemoryResult<&InvocationSlipBinding> {
    auth.invocation_slip()
        .filter(|_| auth.verified_slip().is_some())
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "credential attenuation requires the caller's own holder-bound slip",
                &["Present the paired caller credential and its holder proof."],
            )
        })
}

pub(crate) async fn self_credential_attenuate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CredentialAttenuationRequest,
) -> Listed<CredentialAttenuated> {
    let binding = match holder(auth) {
        Ok(binding) => binding.clone(),
        Err(error) => return (Err(error), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        let slip = server.vault().attenuate_invocation_slip(
            &binding,
            input.caveat.into_engine(),
            &input.holder_seed,
            input.next_binding_key,
        )?;
        Ok(CredentialAttenuated {
            token: slip.to_token()?,
            binding_key: slip
                .caveats
                .last()
                .expect("attenuation appended a caveat")
                .next_binding_key,
        })
    })
    .await
    .unwrap_or_else(|_| Err(internal("self.credential.attenuate")));
    (answer, Vec::new())
}
