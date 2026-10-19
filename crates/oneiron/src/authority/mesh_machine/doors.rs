//! Public mesh setup inputs and owner-bound doors over the host's existing
//! binding, ALPN and terminal revocation operations.
use super::super::slip_vault::{random_slip_id, require_host};
use super::super::{AuthorityOp, SlipClaims, strong_ed25519_key};
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::ports::{EntityRecord, TombstoneStoreRead};
use crate::scan_check::EngineScan;
use crate::temporal::TimeRange;
use ed25519_dalek::{Signer, SigningKey};

/// A paired MACHINE's address and proofs of both keys over its binding.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshMachineBinding {
    pub machine: EntityId,
    pub address: MeshMachineAddress,
    pub device_key: [u8; 32],
    pub pairing_slip_id: [u8; 32],
    /// Ed25519 signature by the key that paired.
    pub device_proof: Vec<u8>,
    /// Ed25519 signature by the derived transport key, on the same transcript.
    pub transport_proof: Vec<u8>,
}

/// Allow or revoke exactly one ALPN for a bound MACHINE and endpoint key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshAlpnGrant {
    pub machine: EntityId,
    pub endpoint_key: [u8; 32],
    pub alpn: Vec<u8>,
    pub allow: bool,
}

/// Public install identity and possession proofs; never either signing seed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshBindingIdentity {
    pub machine: EntityId,
    pub device_key: [u8; 32],
    pub endpoint_key: [u8; 32],
    pub device_proof: Vec<u8>,
    pub transport_proof: Vec<u8>,
}

impl Vault {
    /// This install's public keys and binding proofs, for its owner to submit
    /// to a paired host. Does not mint an identity or grant any access.
    pub fn mesh_binding_identity_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<MeshBindingIdentity> {
        let (machine, seed) = self.mesh_transport_seed()?.ok_or_else(invalid_authority)?;
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        if crate::identity::read_machine_id_in_txn(self, &txn)? != Some(machine) {
            return Err(invalid_authority());
        }
        let device = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(invalid_authority)?;
        let transport = SigningKey::from_bytes(&seed);
        let endpoint_key = transport.verifying_key().to_bytes();
        let transcript = binding_transcript(machine, endpoint_key);
        Ok(MeshBindingIdentity {
            machine,
            device_key: device.verifying_key().to_bytes(),
            endpoint_key,
            device_proof: device.sign(&transcript).to_bytes().to_vec(),
            transport_proof: transport.sign(&transcript).to_bytes().to_vec(),
        })
    }

    /// Host binding: both pairing and transport keys prove the same binding.
    /// Address and authority commit atomically, initially with no ALPN grants.
    pub fn bind_mesh_machine(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        address: MeshMachineAddress,
        device_key: [u8; 32],
        pairing_slip_id: [u8; 32],
        proofs: [&[u8]; 2],
    ) -> Result<()> {
        self.bind_mesh_machine_with(
            issuer,
            None,
            MeshMachineBinding {
                machine,
                address,
                device_key,
                pairing_slip_id,
                device_proof: proofs[0].to_vec(),
                transport_proof: proofs[1].to_vec(),
            },
        )
    }

    /// The caller's own owner proof is rechecked in the binding's writer.
    pub fn bind_mesh_machine_as_owner(
        &self,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        input: MeshMachineBinding,
    ) -> Result<()> {
        self.bind_mesh_machine_with(issuer, Some(owner), input)
    }

    fn bind_mesh_machine_with(
        &self,
        issuer: &HostSlipIssuer,
        owner: Option<&AuthenticatedOwner>,
        input: MeshMachineBinding,
    ) -> Result<()> {
        let MeshMachineBinding {
            machine,
            address,
            device_key,
            pairing_slip_id,
            device_proof,
            transport_proof,
        } = input;
        let mut txn = self.store.env.write_txn()?;
        if let Some(owner) = owner {
            owner.revalidate_in_txn(self, &txn)?;
        }
        let transcript = binding_transcript(machine, address.endpoint_key);
        for (key, proof) in [
            (device_key, device_proof.as_slice()),
            (address.endpoint_key, transport_proof.as_slice()),
        ] {
            strong_ed25519_key(&key)?
                .verify_strict(
                    &transcript,
                    &Signature::from_slice(proof).map_err(|_| invalid_authority())?,
                )
                .map_err(|_| invalid_authority())?;
        }
        let encoded = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(address.clone()))
            .map_err(|_| invalid_authority())?;
        parse_address(&encoded).ok_or_else(invalid_authority)?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let claims = MeshAuthorityClaims {
            version: 1,
            machine,
            endpoint_key: address.endpoint_key,
            device_key,
            pairing_slip_id,
            alpns: BTreeMap::new(),
            revoked: false,
            host_key: issuer.binding_key(),
        };
        if !self.mesh_pairing_live(&fold, &txn, &claims)?
            || MESH_AUTHORITY.contains(&self.store, &txn, &HexId(machine))?
        {
            return Err(invalid_authority());
        }
        let visibility = TombstoneStoreRead::port_deletion_state(&self.store, &txn, &machine)?;
        if visibility.deleted || visibility.archived || visibility.stale {
            return Err(invalid_authority());
        }
        // Public pairing requires an existing live holder. Its host-approved
        // binding replaces the prior MACHINE body with the typed address envelope.
        // Never overwrite another kind, a deleted/stale holder, or a different
        // endpoint already tagged as this MACHINE's mesh identity.
        if let Some(existing) = EntityStoreRead::port_entity_record(&self.store, &txn, &machine)? {
            if existing.entity_type != ENTITY_TYPE_MACHINE
                || EntityStore::port_entity_get(self, &txn, &machine)?.is_none()
            {
                return Err(invalid_authority());
            }
            if let Ok(prior) = rmp_serde::from_slice::<MeshMachineAddressEnvelope>(&existing.body)
                && prior.domain == DOMAIN
                && (prior.version != 1
                    || parse_address(&existing.body).is_none()
                    || prior.address.endpoint_key != address.endpoint_key)
            {
                return Err(invalid_authority());
            }
        }
        let mut count = ScanCount::start(&self.store, &txn, EngineScan::MachineRows, &[])?;
        if self
            .mesh_machine_by_endpoint_in_txn(&txn, address.endpoint_key, Some(&mut count))?
            .is_some_and(|(id, _)| id != machine)
        {
            return Err(invalid_authority());
        }
        let now = self.instant_in_txn(&txn)?.secs();
        EntityStore::port_entity_put(
            self,
            &mut txn,
            &machine,
            &EntityRecord {
                entity_type: ENTITY_TYPE_MACHINE,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                body: encoded,
            },
        )?;
        self.write_mesh_authority_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        count.finish(self);
        Ok(())
    }

    /// Authorized ALPN grant or revocation. A revoked MACHINE stays revoked.
    pub fn set_mesh_alpn_grant(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        endpoint_key: [u8; 32],
        alpn: &[u8],
        allow: bool,
    ) -> Result<()> {
        self.set_mesh_alpn_grant_with(
            issuer,
            None,
            MeshAlpnGrant {
                machine,
                endpoint_key,
                alpn: alpn.to_vec(),
                allow,
            },
        )
    }

    /// The owner's grant or revocation, revalidated in its writing transaction.
    pub fn set_mesh_alpn_grant_as_owner(
        &self,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        input: MeshAlpnGrant,
    ) -> Result<()> {
        self.set_mesh_alpn_grant_with(issuer, Some(owner), input)
    }

    fn set_mesh_alpn_grant_with(
        &self,
        issuer: &HostSlipIssuer,
        owner: Option<&AuthenticatedOwner>,
        input: MeshAlpnGrant,
    ) -> Result<()> {
        let MeshAlpnGrant {
            machine,
            endpoint_key,
            alpn,
            allow,
        } = input;
        let alpn = alpn.as_slice();
        let mut txn = self.store.env.write_txn()?;
        if let Some(owner) = owner {
            owner.revalidate_in_txn(self, &txn)?;
        }
        if !valid_alpn(alpn) {
            return Err(invalid_authority());
        }
        require_host(&self.authority_fold_readonly_in_txn(&txn)?, issuer)?;
        let mut claims = self
            .mesh_authority_in_txn(&txn, machine)?
            .ok_or_else(invalid_authority)?;
        if claims.revoked
            || claims.host_key != issuer.binding_key()
            || claims.endpoint_key != endpoint_key
            || self
                .mesh_machine_in_txn(&txn, machine)?
                .is_none_or(|row| row.endpoint_key != endpoint_key)
        {
            return Err(invalid_authority());
        }
        if let Some(previous) = claims.alpns.remove(alpn) {
            self.append_slip_op_in_txn(
                &mut txn,
                issuer,
                AuthorityOp::SlipRevoke { slip_id: previous },
            )?;
        }
        if allow {
            let fold = self.authority_fold_readonly_in_txn(&txn)?;
            let pair = &fold
                .slips
                .mints
                .get(&claims.pairing_slip_id)
                .ok_or_else(invalid_authority)?
                .action
                .claims;
            let now = self.instant_in_txn(&txn)?.secs();
            let expires_at = pair.expires_at.min(now.saturating_add(365 * 24 * 60 * 60));
            if expires_at <= now {
                return Err(invalid_authority());
            }
            let mut scope = Scope::top();
            scope.verbs = ScopeAxis::Some(BTreeSet::from([mesh_verb(alpn)]));
            if !scope.is_narrowing_of(&pair.scope) {
                return Err(invalid_authority());
            }
            let grant = SlipClaims {
                slip_id: random_slip_id(),
                vault_id: pair.vault_id,
                parent_id: None,
                holder_ref: machine.to_hex(),
                binding_key: endpoint_key,
                scope,
                issued_at: now,
                expires_at,
                ttl_secs: expires_at - now,
                single_use: false,
                records: Default::default(),
                channels: Default::default(),
                actor_class: None,
                org_ref: None,
                grant_ref: None,
                invitation_ref: None,
                delegation: None,
                comm: None,
            };
            let slip = self.mint_slip_in_txn(&mut txn, issuer, grant)?;
            claims.alpns.insert(alpn.to_vec(), slip.claims.slip_id);
        }
        if claims.alpns.len() > MAX_ALPNS {
            return Err(invalid_authority());
        }
        self.write_mesh_authority_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(())
    }

    /// Irreversible local revoke. Reenrollment needs a new MACHINE/pairing.
    pub fn revoke_mesh_machine(&self, issuer: &HostSlipIssuer, machine: EntityId) -> Result<()> {
        self.revoke_mesh_machine_with(issuer, None, machine)
    }

    /// The owner's terminal revoke, revalidated in its writing transaction.
    pub fn revoke_mesh_machine_as_owner(
        &self,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        machine: EntityId,
    ) -> Result<()> {
        self.revoke_mesh_machine_with(issuer, Some(owner), machine)
    }

    fn revoke_mesh_machine_with(
        &self,
        issuer: &HostSlipIssuer,
        owner: Option<&AuthenticatedOwner>,
        machine: EntityId,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        if let Some(owner) = owner {
            owner.revalidate_in_txn(self, &txn)?;
        }
        require_host(&self.authority_fold_readonly_in_txn(&txn)?, issuer)?;
        let mut claims = self
            .mesh_authority_in_txn(&txn, machine)?
            .ok_or_else(invalid_authority)?;
        if claims.host_key != issuer.binding_key() {
            return Err(invalid_authority());
        }
        claims.revoked = true;
        for id in claims.alpns.values() {
            self.append_slip_op_in_txn(&mut txn, issuer, AuthorityOp::SlipRevoke { slip_id: *id })?;
        }
        claims.alpns.clear();
        self.write_mesh_authority_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(())
    }
}
