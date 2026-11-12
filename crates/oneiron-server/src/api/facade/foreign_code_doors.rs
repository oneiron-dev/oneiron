//! The foreign `execute_code` projection. A request keeps its own credential
//! and the existing code-host permit; no owner or actor-only fallback is used.
//! The host's type-feedback service is lent to the run as it is, never
//! loaded or waited on here (FIX 10389); a failed run's refusal keeps its
//! program's feedback beside it ([`SourceListed`]).
use std::sync::Arc;

use oneiron::code_sandbox::foreign::ForeignCodeArtifact;
use oneiron::memory::foreign_code::{ForeignCodeRunRequest, ForeignCodeRunResult};
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};

use super::host_doors::support::{SourceListed, credential_source_listing, source_refused};
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

const FOREIGN_COMPONENT: &[u8] =
    include_bytes!("../../../../../components/code-run-quickjs/artifacts/quickjs-foreign.wasm");
const COMPONENT_MANIFEST: &str =
    include_str!("../../../../../components/code-run-quickjs/artifacts/manifest.json");

pub(super) fn foreign_code_admits(server: &SyncServer, auth: &CoreAuth) -> MemoryResult<()> {
    let denied = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "execute_code requires this caller's own read and propose credential",
            &[],
        )
    };
    auth.require_granted(CoreScope::Read)
        .map_err(|_| denied())?;
    if !auth.has_scope(CoreScope::Write) {
        auth.require_granted(CoreScope::Propose)
            .map_err(|_| denied())?;
    }
    let proof = auth.verified_slip().ok_or_else(denied)?;
    if !auth.credential_is_live(server.vault())
        || server.vault().credential_read_key(proof)?.is_none()
    {
        return Err(denied());
    }
    Ok(())
}

pub(crate) async fn execute_code(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: ForeignCodeRunRequest,
) -> SourceListed<ForeignCodeRunResult> {
    if let Err(error) = foreign_code_admits(server, auth) {
        return source_refused(error);
    }
    if session.is_some() {
        return source_refused(MemoryError::new(
            oneiron::memory::MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
            "foreign code receipts require canonical storage",
            &[],
        ));
    }
    let Some(host) = server
        .code_execution_host()
        .and_then(|host| host.engine_native())
        .filter(|host| host.provider().production_runtime_available())
    else {
        return source_refused(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "no verified code host is bound",
            &[],
        ));
    };
    let type_feedback = host.provider().code_check().cloned();
    let permit = match host.runs().admit(auth.idempotency_principal()).await {
        Ok(permit) => permit,
        Err(_) => {
            return source_refused(MemoryError::new(
                oneiron::memory::MEMORY_CODE_INVALID_STATE,
                "foreign code waited out before admission",
                &[],
            ));
        }
    };
    let caller = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return source_refused(error.into_memory_error()),
    };
    // The guest's proposed files spool on the server's one disk floor, the
    // one its uploads keep (FIX 7650).
    let spool: Arc<dyn oneiron::code_sandbox::ProposalSpoolFloor> =
        Arc::new(server.transfers.disk.clone());
    credential_source_listing(server, auth, caller, "execute_code", move |_, _, memory| {
        let _permit = permit;
        let manifest: serde_json::Value = serde_json::from_str(COMPONENT_MANIFEST)
            .map_err(|_| super::host_doors::support::internal("execute_code"))?;
        let pin = manifest["artifacts"]["foreign"]["sha256"]
            .as_str()
            .filter(|pin| pin.len() == 64 && pin.is_ascii())
            .ok_or_else(|| super::host_doors::support::internal("execute_code"))?;
        let mut sha256 = [0; 32];
        for (index, byte) in sha256.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&pin[index * 2..index * 2 + 2], 16)
                .map_err(|_| super::host_doors::support::internal("execute_code"))?;
        }
        memory.execute_foreign_code(
            input,
            ForeignCodeArtifact {
                component: FOREIGN_COMPONENT,
                sha256,
            },
            oneiron::code_sandbox::microvm::ExecutionBudget::default(),
            spool,
            type_feedback.as_ref(),
        )
    })
    .await
}
