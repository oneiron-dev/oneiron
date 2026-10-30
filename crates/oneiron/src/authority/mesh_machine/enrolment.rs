//! The mesh binding a machine link's redemption makes for the machine it
//! enrols (FIX 3374, L02 04:5x). The joining machine sends its endpoint key
//! and both binding proofs with its enrolment request; in the redemption's
//! own transaction the host checks that they name exactly the MACHINE and
//! machine key the redemption enrols and that both proofs verify, before it
//! mints anything. Then, in one savepoint of that transaction, it mints a
//! pairing slip held by that MACHINE under its machine key and carrying the
//! one ALPN alone, binds the endpoint on it and grants the ALPN: all of them
//! land with the pairing, or none do. A binding refused at any step leaves
//! the pairing as it would stand without one, with the reason.
//!
//! A removed MACHINE's binding admits nothing (`mesh_pairing_live`), and
//! [`Vault::revoke_removed_machine_mesh`] revokes its pairing and grants in
//! the log.

use super::super::slip_vault::{random_slip_id, require_host};
use super::super::{AuthorityOp, MachineEnrolmentRequest, SlipClaims, strong_ed25519_key};
use super::doors::MESH_GRANT_MAX_SECS;
use super::*;

/// Why a redemption's mesh binding was not made. The pairing stands, and no
/// part of the binding was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshBindRefusal {
    /// The identity names another MACHINE or key than the one the redemption
    /// enrols.
    NotTheEnrolledMachine,
    /// A proof does not verify under its key.
    BadProof,
    /// The binding or its grant was refused where it would land: an endpoint
    /// another MACHINE holds, a deleted holder, a binding already revoked.
    BindRefused,
}

/// What a redemption's mesh binding did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshEnrolment {
    /// Bound and granted the ALPN with the pairing, on a fresh pairing slip.
    Bound {
        machine: EntityId,
        endpoint_key: [u8; 32],
        pairing_slip_id: [u8; 32],
    },
    /// The endpoint's binding stood from an earlier pairing, and the ALPN was
    /// granted on it again.
    Regranted {
        machine: EntityId,
        endpoint_key: [u8; 32],
    },
    /// The endpoint already held a live grant on the ALPN; nothing new.
    AlreadyGranted {
        machine: EntityId,
        endpoint_key: [u8; 32],
    },
    Refused(MeshBindRefusal),
}

/// Whether any chain of `machine` removed it: removal is terminal.
pub(super) fn machine_removed(machine: &crate::authority::FoldedMachine) -> bool {
    machine.chains().any(|(_, chain)| chain.removed)
}

impl Vault {
    /// Binds `identity`'s endpoint for the machine `request` enrols and grants
    /// it `alpn`, in the caller's redemption transaction.
    pub(in crate::authority) fn bind_enrolled_mesh_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        request: &MachineEnrolmentRequest,
        identity: &MeshBindingIdentity,
        alpn: &[u8],
    ) -> MeshEnrolment {
        let (machine, endpoint_key) = (request.machine, identity.endpoint_key);
        if identity.machine != machine || identity.device_key != request.machine_key {
            return MeshEnrolment::Refused(MeshBindRefusal::NotTheEnrolledMachine);
        }
        let transcript = binding_transcript(machine, endpoint_key);
        let proven = [
            (identity.device_key, identity.device_proof.as_slice()),
            (endpoint_key, identity.transport_proof.as_slice()),
        ]
        .into_iter()
        .all(|(key, proof)| {
            strong_ed25519_key(&key).is_ok_and(|key| {
                Signature::from_slice(proof)
                    .is_ok_and(|proof| key.verify_strict(&transcript, &proof).is_ok())
            })
        });
        if !proven {
            return MeshEnrolment::Refused(MeshBindRefusal::BadProof);
        }
        if self
            .mesh_grant_permits_in_txn(txn, machine, endpoint_key, alpn)
            .unwrap_or(false)
        {
            return MeshEnrolment::AlreadyGranted {
                machine,
                endpoint_key,
            };
        }
        match self.bind_enrolled_in_savepoint(txn, issuer, request, identity, alpn) {
            Ok(Some(pairing_slip_id)) => MeshEnrolment::Bound {
                machine,
                endpoint_key,
                pairing_slip_id,
            },
            Ok(None) => MeshEnrolment::Regranted {
                machine,
                endpoint_key,
            },
            Err(_) => MeshEnrolment::Refused(MeshBindRefusal::BindRefused),
        }
    }

    /// The pairing slip, the binding and the grant, in one savepoint of `txn`
    /// that lands only whole, and the new pairing slip's id. A binding that
    /// stands from an earlier pairing takes the grant alone, as the owner's
    /// grant door gives it (`None`). The slip runs no longer than a grant may.
    fn bind_enrolled_in_savepoint(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        request: &MachineEnrolmentRequest,
        identity: &MeshBindingIdentity,
        alpn: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        let (machine, endpoint_key) = (request.machine, identity.endpoint_key);
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let grant = MeshAlpnGrant {
            machine,
            endpoint_key,
            alpn: alpn.to_vec(),
            allow: true,
        };
        if MESH_AUTHORITY.contains(&self.store, &savepoint, &HexId(machine))? {
            self.set_mesh_alpn_grant_in_txn(&mut savepoint, issuer, grant)?;
            savepoint.commit()?;
            return Ok(None);
        }
        let now = self.instant_in_txn(&savepoint)?.secs();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([mesh_verb(alpn)]));
        let pairing = self.mint_slip_in_txn(
            &mut savepoint,
            issuer,
            SlipClaims {
                slip_id: random_slip_id(),
                vault_id: request.vault_id,
                parent_id: None,
                holder_ref: machine.to_hex(),
                binding_key: request.machine_key,
                scope,
                issued_at: now,
                expires_at: now.saturating_add(MESH_GRANT_MAX_SECS),
                ttl_secs: MESH_GRANT_MAX_SECS,
                single_use: false,
                records: Default::default(),
                channels: Default::default(),
                actor_class: None,
                org_ref: None,
                grant_ref: None,
                invitation_ref: None,
                delegation: None,
                comm: None,
            },
        )?;
        let pairing_slip_id = pairing.claims.slip_id;
        let count = self.bind_mesh_machine_in_txn(
            &mut savepoint,
            issuer,
            MeshMachineBinding {
                machine,
                address: MeshMachineAddress {
                    endpoint_key,
                    direct_addrs: Vec::new(),
                    relay_url: None,
                },
                device_key: request.machine_key,
                pairing_slip_id,
                device_proof: identity.device_proof.clone(),
                transport_proof: identity.transport_proof.clone(),
            },
        )?;
        self.set_mesh_alpn_grant_in_txn(&mut savepoint, issuer, grant)?;
        savepoint.commit()?;
        count.finish(self);
        Ok(Some(pairing_slip_id))
    }

    /// Revokes, for a MACHINE the owner removed, the pairing its mesh binding
    /// stands on and every ALPN grant it holds, and marks the binding revoked;
    /// `false` when the MACHINE is not removed or holds no binding this host
    /// signed. Removal already left the binding admitting nothing; this
    /// writes the revocations to the log.
    pub fn revoke_removed_machine_mesh(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        if !fold.machine(machine).is_some_and(machine_removed) {
            return Ok(false);
        }
        let Some(signed) = MESH_AUTHORITY.get(&self.store, &txn, &HexId(machine))? else {
            return Ok(false);
        };
        let mut claims = signed.claims;
        if claims.machine != machine || claims.host_key != issuer.binding_key() || claims.revoked {
            return Ok(false);
        }
        let held: Vec<[u8; 32]> = claims
            .alpns
            .values()
            .copied()
            .chain([claims.pairing_slip_id])
            .filter(|id| fold.slip_is_live(id))
            .collect();
        for slip_id in held {
            self.append_slip_op_in_txn(&mut txn, issuer, AuthorityOp::SlipRevoke { slip_id })?;
        }
        claims.revoked = true;
        claims.alpns.clear();
        self.write_mesh_authority_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        self.store.notify_credential_revocations();
        Ok(true)
    }
}
