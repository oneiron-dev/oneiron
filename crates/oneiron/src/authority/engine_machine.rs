//! Host-provisioned software identities for the engine's own MACHINE writers.
//!
//! The engine's background writers are MACHINE actors (ARCH-0034: MACHINE
//! admits only actor class system), and the host that runs the engine holds
//! the trust root (identity.md, host-rooted authority). The host enrolls one
//! software Ed25519 key per engine writer through the authority log, as
//! ARCH-0053 seeds system actors through the registry at bootstrap, and keeps
//! each writer's signer on this vault handle. Every key derives from the
//! host's retained root secret, so the host stores no new key material. Each
//! writer holds its own key, so the owner can revoke one writer without
//! touching the host. An actor that already has a binding is never enrolled
//! again, so a revocation stays terminal.

use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::{EntityId, Vault};

use super::slip_vault::require_host;
use super::{ActorBindingStatus, AuthorityKey, HostSlipIssuer, invalid_authority};

const ENGINE_MACHINE_KEY_DOMAIN: &str = "oneiron/engine-machine-authority/v1";
/// Engine writers are bootstrap seeds: a row this module births carries the
/// seed time, as the seeded owner PERSON and agent definitions do, so a host
/// open never reads as vault activity.
const ENGINE_MACHINE_SEED_TIME: u64 = 0;
const ENGINE_MACHINE_TRANSPORT_DOMAIN: &str = "oneiron/engine-machine-transport/v1";

fn engine_machine_signing_key(
    issuer: &HostSlipIssuer,
    vault_id: &[u8; 32],
    machine: EntityId,
) -> SigningKey {
    let mut hasher = blake3::Hasher::new_derive_key(ENGINE_MACHINE_KEY_DOMAIN);
    hasher.update(vault_id);
    hasher.update(machine.as_bytes());
    hasher.update(issuer.secret());
    let seed = Zeroizing::new(*hasher.finalize().as_bytes());
    SigningKey::from_bytes(&seed)
}

impl Vault {
    /// Enroll and retain a signer for every engine MACHINE writer. The host
    /// calls this after `ensure_host_root_slip` each time it opens the vault:
    /// the first call enrolls, later calls only retain the signers, and an
    /// existing vault gets its engine keys before its first engine write.
    pub fn provision_engine_machine_identities(&self, issuer: &HostSlipIssuer) -> Result<()> {
        let seed = ENGINE_MACHINE_SEED_TIME;
        let machines = [
            self.ensure_commitment_projection_machine(seed)?,
            crate::calendar::ingest::ensure_ics_import_actor(self, seed)?,
            crate::calendar::transcript::file_drop_import_actor(self, seed)?,
            self.ensure_esign_artifact_machine(seed)?,
        ];
        for machine in machines {
            self.provision_host_machine_identity(issuer, machine)?;
        }
        Ok(())
    }

    /// Give one stored MACHINE a software key derived from the host root and
    /// retain its signer on this handle. Enrollment happens only while no key
    /// was ever bound to the actor; a revoked or foreign binding leaves the
    /// actor without a signer, so its writes stay refused.
    pub fn provision_host_machine_identity(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
    ) -> Result<()> {
        let fold = self.authority_fold()?;
        require_host(&fold, issuer)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let signing = engine_machine_signing_key(issuer, &vault_id, machine);
        let public_key = signing.verifying_key().to_bytes();
        let key = AuthorityKey::Ed25519(public_key);
        let fold = if fold
            .actor_bindings
            .values()
            .any(|binding| binding.actor_ref == machine)
        {
            self.retain_machine_history_issuer(issuer)?;
            fold
        } else {
            let transport = blake3::derive_key(ENGINE_MACHINE_TRANSPORT_DOMAIN, &public_key);
            self.enroll_machine_identity(issuer, machine, public_key, transport, |transcript| {
                Ok(signing.sign(transcript).to_bytes())
            })?;
            self.authority_fold()?
        };
        let live = fold.actor_bindings.get(&key).is_some_and(|binding| {
            binding.status == ActorBindingStatus::Active && binding.actor_ref == machine
        }) && fold.roster.get(&key).is_some_and(|device| !device.revoked);
        if live {
            self.retain_machine_write_signer(machine, public_key, move |transcript| {
                Ok(signing.sign(transcript).to_bytes())
            })?;
        }
        Ok(())
    }

    fn ensure_commitment_projection_machine(&self, now: u64) -> Result<EntityId> {
        let machine = crate::commitment_schedule::commitment_projection_actor().entity_ref();
        match self.get_entity_type(&machine)? {
            Some(crate::registry::ENTITY_TYPE_MACHINE) => {}
            Some(_) => return Err(invalid_authority()),
            None => {
                let mut body = Vec::new();
                rmpv::encode::write_value(
                    &mut body,
                    &rmpv::Value::Map(vec![(
                        rmpv::Value::from("name"),
                        rmpv::Value::from("commitment projector"),
                    )]),
                )
                .map_err(|_| crate::Error::InvariantViolation("actor body did not encode"))?;
                self.put_entity(
                    &machine,
                    crate::registry::ENTITY_TYPE_MACHINE,
                    crate::TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )?;
            }
        }
        Ok(machine)
    }

    fn ensure_esign_artifact_machine(&self, now: u64) -> Result<EntityId> {
        self.with_write_txn(|txn| {
            Ok(crate::blob_artifact::esign::artifact_machine(self, txn, now)?.entity_ref())
        })
    }
}
