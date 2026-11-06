//! A published app's own pairing identity, without engine-action grants.

use super::{CodebaseForkHash, EntityId, Error, Result, Vault};
use crate::agent_dispatch::CommReach;
use crate::authority::{HostSlipIssuer, PairingLink, PairingPrincipal};
use crate::consent::AuthenticatedOwner;
use crate::federation::{Scope, ScopeAxis};
use serde::Serialize;

/// The app redeems this link with its own binding key through the normal
/// pairing door. The artifact fields identify the selected code; they are
/// not an action grant or proof that a backend process has been started.
#[derive(Serialize)]
pub struct ArtifactBackendPairing {
    pub artifact: String,
    pub fork_hash: String,
    pub code_artifact_ref: String,
    pub principal_ref: String,
    pub link: PairingLink,
}

#[derive(serde::Deserialize, Serialize)]
struct BackendPrincipalBody {
    name: String,
    artifact_backend: BackendPrincipalBinding,
}

#[derive(serde::Deserialize, Serialize)]
struct BackendPrincipalBinding {
    artifact: String,
    fork_hash: String,
    code_artifact_ref: EntityId,
}

/// Recognizes the fresh app actor's native identity, not an action grant.
/// The owner grant writer first checks that this is a live PERSON row.
pub(crate) fn is_backend_principal(principal: EntityId, body: &[u8]) -> bool {
    let Ok(body) = rmp_serde::from_slice::<BackendPrincipalBody>(body) else {
        return false;
    };
    let binding = body.artifact_backend;
    if super::validate_artifact_id(&binding.artifact).is_err() {
        return false;
    }
    let Ok(fork_hash) = super::parse_codebase_fork_hash_hex(&binding.fork_hash) else {
        return false;
    };
    let prefix = format!(
        "artifact-backend:{}:{}:{}:",
        binding.artifact,
        super::artifact_hex(&fork_hash),
        binding.code_artifact_ref.to_hex(),
    );
    let Some(nonce) = body.name.strip_prefix(&prefix) else {
        return false;
    };
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }
    EntityId::derive(
        crate::entity_id::derived_domains::AGENT_PRINCIPAL,
        &[body.name.as_bytes()],
    )
    .is_ok_and(|expected| expected == principal)
}

impl Vault {
    /// Matches the app's native identity to the exact code this session staged.
    /// The caller must authenticate separately; this grants no action or read.
    pub fn artifact_backend_principal_matches(
        &self,
        principal: EntityId,
        source: &super::ArtifactBackendSource,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            body,
        } = crate::vault::live_entity_row_in_txn(&self.store, &txn, &principal)?
        else {
            return Ok(false);
        };
        if !is_backend_principal(principal, &body) {
            return Ok(false);
        }
        let Ok(body) = rmp_serde::from_slice::<BackendPrincipalBody>(&body) else {
            return Ok(false);
        };
        Ok(body.artifact_backend.artifact == source.pointer.artifact
            && body.artifact_backend.fork_hash == super::artifact_hex(&source.fork_hash)
            && body.artifact_backend.code_artifact_ref == source.code_artifact_ref)
    }

    /// Creates a fresh app actor and an owner-recorded pairing link with no
    /// engine-action verbs. It neither grants the actor a standing ceiling
    /// nor admits a connector. A backend can compute without either.
    pub fn create_artifact_backend_pairing(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        artifact: &str,
        fork_hash: &CodebaseForkHash,
        lifetime_secs: u64,
        comm: CommReach,
    ) -> Result<ArtifactBackendPairing> {
        let (principal, code_artifact) = self.try_with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let snapshot = self
                .resolve_artifact_snapshot_by_fork_in_txn(txn, artifact, fork_hash)?
                .ok_or(Error::EntityNotFound)?;
            // Never adopt a named agent's existing identity or its grants.
            let (principal, name) = loop {
                let mut nonce = [0_u8; 32];
                crate::world_keys::os_fill(&mut nonce)?;
                let name = format!(
                    "artifact-backend:{artifact}:{}:{}:{}",
                    super::artifact_hex(fork_hash),
                    snapshot.code_artifact_id.to_hex(),
                    super::artifact_hex(&nonce),
                );
                let principal = EntityId::derive(
                    crate::entity_id::derived_domains::AGENT_PRINCIPAL,
                    &[name.as_bytes()],
                )?;
                if self.get_entity_type_in_txn(txn, &principal)?.is_none()
                    && !self.local_hard_delete_marker_exists_in_txn(txn, &principal)?
                {
                    break (principal, name);
                }
            };
            let body = rmp_serde::to_vec_named(&BackendPrincipalBody {
                name,
                artifact_backend: BackendPrincipalBinding {
                    artifact: artifact.to_owned(),
                    fork_hash: super::artifact_hex(fork_hash),
                    code_artifact_ref: snapshot.code_artifact_id,
                },
            })
            .map_err(|_| Error::InvariantViolation("artifact backend principal body encode"))?;
            let now = self.store.clock.now_recorded_at();
            self.batch_in()
                .put(
                    &principal,
                    crate::registry::ENTITY_TYPE_PERSON,
                    crate::TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .apply(txn)?;
            Ok::<_, Error>((principal, snapshot.code_artifact_id))
        })?;
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(Default::default());
        // This second native writer revalidates the owner and issuer. A
        // failed issue can leave an actor row, never a credential or grant.
        let link = self.issue_owner_pairing_link(
            issuer,
            owner,
            scope,
            lifetime_secs,
            PairingPrincipal {
                holder_ref: Some(principal.to_hex()),
                actor_class: Some("agent".to_owned()),
                org_ref: None,
                write_facet: None,
                comm: Some(comm),
            },
        )?;
        Ok(ArtifactBackendPairing {
            artifact: artifact.to_owned(),
            fork_hash: super::artifact_hex(fork_hash),
            code_artifact_ref: code_artifact.to_hex(),
            principal_ref: principal.to_hex(),
            link,
        })
    }
}
