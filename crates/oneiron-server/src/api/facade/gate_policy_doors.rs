//! Owner policy and checker host doors. HTTP, SDK and MCP use the same
//! unattenuated owner credential as the neighboring setting doors; a policy
//! put also admits a person holding the policy power (FIX 8177).
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::policy_manifest_doors::{
    self, GateCheckerReceipt, GateCheckerSet, GateCheckerView, PolicyManifestPut,
    PolicyManifestRead, PolicyManifestReceipt, PolicyManifestsView,
};
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::{Listed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = super::owner_binding::facade_owner(server, auth, verb)?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || act(&server, &owner).map_err(MemoryError::from))
        .await
        .map_err(|_| internal(verb))?
}

pub(crate) async fn vault_gate_policy_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PolicyManifestRead,
) -> Listed<PolicyManifestsView> {
    let answer = as_owner(
        server,
        auth,
        "vault.gate.policy.get",
        move |server, owner| {
            policy_manifest_doors::policy_manifests_as_owner(server.vault(), owner, &input)
        },
    )
    .await;
    let rows = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |view| {
            view.manifests
                .iter()
                .filter_map(|row| EntityId::from_hex(&row.manifest_ref).ok())
                .collect()
        },
    );
    (answer, rows)
}

/// Who puts a gate policy manifest (FIX 8177): the owner under its proof,
/// as before (`true`), or a person on their own verified slip holding the
/// policy power (`false`), checked read-only here so a powerless person's
/// pre-hooks never fire (FIX 8516) and found again by the manifest writer
/// in its own write transaction; neither an Admin nor a Delegate label
/// admits anyone by itself. Anyone else, a powerless person included,
/// keeps the owner refusal it had.
pub(super) fn policy_putter(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<(AuthenticatedOwner, bool)> {
    super::owner_binding::facade_owner(server, auth, verb)
        .map(|owner| (owner, true))
        .or_else(|refusal| {
            let person = super::shared_act_doors::person(server, auth, verb)
                .ok()
                .filter(|person| {
                    policy_manifest_doors::holder_has_policy_power(server.vault(), person)
                        .unwrap_or(false)
                });
            person.map(|person| (person, false)).ok_or(refusal)
        })
}

pub(crate) async fn vault_gate_policy_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PolicyManifestPut,
) -> Listed<PolicyManifestReceipt> {
    const VERB: &str = "vault.gate.policy.put";
    let answer = match policy_putter(server, auth, VERB) {
        Err(refusal) => Err(refusal),
        Ok((proof, owner)) => {
            let server = Arc::clone(server);
            super::clock_ingress::run_blocking(move || {
                let vault = server.vault();
                let put = if owner {
                    policy_manifest_doors::put_policy_manifest_as_owner(vault, &proof, input)
                } else {
                    policy_manifest_doors::put_policy_manifest_as_holder(vault, &proof, input)
                };
                put.map_err(MemoryError::from)
            })
            .await
            .unwrap_or_else(|_| Err(internal(VERB)))
        }
    };
    let rows = answer
        .as_ref()
        .ok()
        .and_then(|receipt| EntityId::from_hex(&receipt.manifest.manifest_ref).ok())
        .into_iter()
        .collect();
    (answer, rows)
}

pub(crate) async fn vault_gate_checker_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<GateCheckerView> {
    (
        as_owner(
            server,
            auth,
            "vault.gate.checker.get",
            move |server, owner| {
                policy_manifest_doors::gate_checker_as_owner(server.vault(), owner)
            },
        )
        .await,
        Vec::new(),
    )
}

pub(crate) async fn vault_gate_checker_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GateCheckerSet,
) -> Listed<GateCheckerReceipt> {
    (
        as_owner(
            server,
            auth,
            "vault.gate.checker.set",
            move |server, owner| {
                policy_manifest_doors::set_gate_checker_as_owner(server.vault(), owner, input)
            },
        )
        .await,
        Vec::new(),
    )
}
