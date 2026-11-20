//! A published app's own pairing identity, without engine-action grants.

use super::{CodebaseForkHash, EntityId, Error, Result, Vault};
use crate::agent_dispatch::CommReach;
use crate::authority::{HostSlipIssuer, PairingLink, PairingPrincipal};
use crate::consent::AuthenticatedOwner;
use crate::federation::{Scope, ScopeAxis};
use serde::Serialize;

/// The name prefix of a published app's backend principal: the PERSON
/// [`Vault::create_artifact_backend_pairing`] derives. Agent naming does not
/// reserve it, so an agent the owner names with it reads as a backend and
/// takes no verb-bearing link without a Grant row (FIX
/// [ARTIFACT-BACKEND-NAME-PREFIX-UNRESERVED]).
const ARTIFACT_BACKEND_NAME_PREFIX: &str = "artifact-backend:";

/// Whether `name`, a named agent PERSON's recorded name, is a published app's
/// backend principal's.
pub(crate) fn is_artifact_backend_name(name: &str) -> bool {
    name.starts_with(ARTIFACT_BACKEND_NAME_PREFIX)
}

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

impl Vault {
    /// Whether `holder` is a published app's backend principal in `txn`: a
    /// live named agent's PERSON whose name
    /// [`Self::create_artifact_backend_pairing`] gave it.
    ///
    /// # Errors
    /// A store failure reading the row.
    pub(crate) fn is_artifact_backend_principal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
    ) -> Result<bool> {
        Ok(self
            .live_named_agent_name_in_txn(txn, holder)?
            .is_some_and(|name| is_artifact_backend_name(&name)))
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
                    "{ARTIFACT_BACKEND_NAME_PREFIX}{artifact}:{}:{}",
                    super::artifact_hex(fork_hash),
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
            let mut body = Vec::new();
            rmpv::encode::write_value(
                &mut body,
                &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
            )
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
        // A later link that names verbs for this actor is refused until the
        // owner mints its Grant row (APP-BACKEND-LINK-GRANT = A).
        let link = self.issue_owner_pairing_link_without_grant(
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
