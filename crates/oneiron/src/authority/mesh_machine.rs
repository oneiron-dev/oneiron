//! Local host-authorized mesh binding and grants, distinct from address hints.
//! A MACHINE row is public-writable address data. The host-signed local binding
//! selects exact ALPN slips in AUTHORITY_LOG; it cannot grant permission itself.
//! The host, pairing slip, logged grant and current MACHINE key are rechecked together.
use super::slip_vault::{random_slip_id, require_host};
use super::{
    AuthorityFold, AuthorityKey, AuthorityOp, HostSlipIssuer, SlipClaims, invalid_authority,
    roster_has_live_owner,
};
use crate::{
    EntityId, Vault,
    error::Result,
    federation::{Scope, ScopeAxis},
    ports::{EntityRecord, EntityStore, EntityStoreRead},
    registry::ENTITY_TYPE_MACHINE,
    temporal::TimeRange,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};

const DOMAIN: &str = "oneiron/mesh-machine/v1";
const AUTH_DOMAIN: &[u8] = b"oneiron/mesh-authority/v1\0";
const BIND_DOMAIN: &[u8] = b"oneiron/mesh-machine-binding/v1\0";
const MAX_MACHINES: usize = 1024;
const MAX_ALPNS: usize = 32;

/// Address hints. This structure has no authority by itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshMachineAddress {
    pub endpoint_key: [u8; 32],
    pub direct_addrs: Vec<SocketAddr>,
    pub relay_url: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshMachineAddressEnvelope {
    pub domain: String,
    pub version: u8,
    pub address: MeshMachineAddress,
}
impl MeshMachineAddressEnvelope {
    pub const DOMAIN: &'static str = DOMAIN;
    pub fn new(address: MeshMachineAddress) -> Self {
        Self {
            domain: DOMAIN.into(),
            version: 1,
            address,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeshAuthorityClaims {
    version: u8,
    machine: EntityId,
    endpoint_key: [u8; 32],
    device_key: [u8; 32],
    pairing_slip_id: [u8; 32],
    alpns: BTreeMap<Vec<u8>, [u8; 32]>,
    revoked: bool,
    host_key: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedMeshAuthority {
    claims: MeshAuthorityClaims,
    signature: Vec<u8>,
}
fn authority_key(machine: EntityId) -> String {
    format!("authority:mesh-machine:v1:{}", machine.to_hex())
}
fn transcript(claims: &MeshAuthorityClaims) -> Result<Vec<u8>> {
    let mut bytes = AUTH_DOMAIN.to_vec();
    bytes.extend(rmp_serde::to_vec_named(claims).map_err(|_| invalid_authority())?);
    Ok(bytes)
}
fn binding_transcript(machine: EntityId, key: [u8; 32]) -> Vec<u8> {
    let mut bytes = BIND_DOMAIN.to_vec();
    bytes.extend_from_slice(machine.as_bytes());
    bytes.extend_from_slice(&key);
    bytes
}
fn valid_alpn(alpn: &[u8]) -> bool {
    !alpn.is_empty() && alpn.len() <= 255
}
fn mesh_verb(alpn: &[u8]) -> String {
    format!(
        "mesh:alpn:{}",
        alpn.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
fn parse_address(body: &[u8]) -> Result<Option<MeshMachineAddress>> {
    let Ok(envelope) = rmp_serde::from_slice::<MeshMachineAddressEnvelope>(body) else {
        return Ok(None);
    };
    if envelope.domain != DOMAIN || envelope.version != 1 {
        return Ok(None);
    }
    if envelope.address.direct_addrs.len() > 32
        || VerifyingKey::from_bytes(&envelope.address.endpoint_key).is_err()
        || envelope
            .address
            .relay_url
            .as_ref()
            .is_some_and(|url| url.len() > 2048)
    {
        return Err(invalid_authority());
    }
    Ok(Some(envelope.address))
}
impl Vault {
    fn mesh_machine_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
    ) -> Result<Option<MeshMachineAddress>> {
        let Some(row) = EntityStore::port_entity_get(self, txn, &machine)? else {
            return Ok(None);
        };
        if row.entity_type != ENTITY_TYPE_MACHINE {
            return Ok(None);
        }
        parse_address(&row.body)
    }
    /// One snapshot for type, liveness and address; never guesses a header offset.
    pub fn mesh_machine(&self, machine: EntityId) -> Result<Option<MeshMachineAddress>> {
        let txn = self.store.env.read_txn()?;
        self.mesh_machine_in_txn(&txn, machine)
    }
    /// Resolve against a single snapshot, including the type index and all bodies.
    pub fn mesh_machine_by_endpoint(
        &self,
        key: [u8; 32],
    ) -> Result<Option<(EntityId, MeshMachineAddress)>> {
        let txn = self.store.env.read_txn()?;
        let mut found = None;
        let mut seen = 0;
        for id in
            EntityStoreRead::port_entity_ids_by_type(&self.store, &txn, ENTITY_TYPE_MACHINE, None)?
        {
            seen += 1;
            if seen > MAX_MACHINES {
                return Err(invalid_authority());
            }
            let id = id?;
            if let Some(row) = self.mesh_machine_in_txn(&txn, id)?
                && row.endpoint_key == key
            {
                if found.is_some() {
                    return Err(invalid_authority());
                }
                found = Some((id, row));
            }
        }
        Ok(found)
    }
    fn mesh_authority_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
    ) -> Result<Option<MeshAuthorityClaims>> {
        let Some(raw) = self.store.sync_state.get(txn, &authority_key(machine))? else {
            return Ok(None);
        };
        let signed: SignedMeshAuthority =
            rmp_serde::from_slice(&raw).map_err(|_| invalid_authority())?;
        let claims = signed.claims;
        if claims.version != 1
            || claims.machine != machine
            || claims.alpns.len() > MAX_ALPNS
            || claims.alpns.keys().any(|alpn| !valid_alpn(alpn))
        {
            return Err(invalid_authority());
        }
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold.vault_root_is_conflicted()
            || !roster_has_live_owner(&fold.roster, &AuthorityKey::Ed25519(claims.host_key))
        {
            return Ok(None);
        }
        let host = VerifyingKey::from_bytes(&claims.host_key).map_err(|_| invalid_authority())?;
        let sig = Signature::from_slice(&signed.signature).map_err(|_| invalid_authority())?;
        host.verify(&transcript(&claims)?, &sig)
            .map_err(|_| invalid_authority())?;
        if !self.mesh_pairing_live(&fold, txn, &claims)? {
            return Ok(None);
        }
        Ok(Some(claims))
    }
    fn mesh_pairing_live(
        &self,
        fold: &AuthorityFold,
        txn: &heed::RoTxn<'_>,
        claims: &MeshAuthorityClaims,
    ) -> Result<bool> {
        let Some(mint) = fold.slips.mints.get(&claims.pairing_slip_id) else {
            return Ok(false);
        };
        let now = self.instant_in_txn(txn)?.secs();
        let pair = &mint.action.claims;
        Ok(fold.slip_is_live(&claims.pairing_slip_id)
            && now >= pair.issued_at
            && now < pair.expires_at
            && pair.holder_ref == claims.machine.to_hex()
            && pair.binding_key == claims.device_key
            && pair.parent_id.is_none()
            && fold.vault_id == Some(pair.vault_id))
    }
    /// A fresh, single-snapshot check of signed grant, live pairing and current row.
    pub fn mesh_grant_permits(
        &self,
        machine: EntityId,
        endpoint_key: [u8; 32],
        alpn: &[u8],
    ) -> Result<bool> {
        if !valid_alpn(alpn) {
            return Ok(false);
        }
        let txn = self.store.env.read_txn()?;
        let Some(row) = self.mesh_machine_in_txn(&txn, machine)? else {
            return Ok(false);
        };
        if row.endpoint_key != endpoint_key {
            return Ok(false);
        }
        let Some(claims) = self.mesh_authority_in_txn(&txn, machine)? else {
            return Ok(false);
        };
        if claims.revoked || claims.endpoint_key != endpoint_key {
            return Ok(false);
        }
        let Some(grant_id) = claims.alpns.get(alpn) else {
            return Ok(false);
        };
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let Some(mint) = fold.slips.mints.get(grant_id) else {
            return Ok(false);
        };
        let grant = &mint.action.claims;
        let now = self.instant_in_txn(&txn)?.secs();
        Ok(fold.slip_is_live(grant_id)
            && now >= grant.issued_at
            && now < grant.expires_at
            && fold.vault_id == Some(grant.vault_id)
            && mint.signer == AuthorityKey::Ed25519(claims.host_key)
            && grant.parent_id.is_none()
            && grant.binding_key == endpoint_key
            && grant.holder_ref == machine.to_hex()
            && grant.scope.verbs == ScopeAxis::Some(BTreeSet::from([mesh_verb(alpn)]))
            && grant.scope.worlds == ScopeAxis::All
            && grant.scope.facets == ScopeAxis::All
            && grant.scope.bands == ScopeAxis::All
            && grant.scope.audience == ScopeAxis::All
            && grant.actor_class.is_none()
            && grant.org_ref.is_none())
    }
    fn write_mesh_authority_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        claims: MeshAuthorityClaims,
    ) -> Result<()> {
        let signature = issuer.sign_mesh(&transcript(&claims)?);
        let bytes = rmp_serde::to_vec_named(&SignedMeshAuthority {
            claims: claims.clone(),
            signature: signature.to_vec(),
        })
        .map_err(|_| invalid_authority())?;
        self.store
            .sync_state
            .put(txn, &authority_key(claims.machine), &bytes)?;
        Ok(())
    }
    /// Enroll a paired device. Both pairing and transport keys prove the same binding.
    /// Address and host-signed binding projection commit atomically, with NO ALPN grants.
    pub fn bind_mesh_machine(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        address: MeshMachineAddress,
        device_key: [u8; 32],
        pairing_slip_id: [u8; 32],
        proofs: [&[u8]; 2],
    ) -> Result<()> {
        let transcript = binding_transcript(machine, address.endpoint_key);
        for (key, proof) in [(device_key, proofs[0]), (address.endpoint_key, proofs[1])] {
            VerifyingKey::from_bytes(&key)
                .map_err(|_| invalid_authority())?
                .verify(
                    &transcript,
                    &Signature::from_slice(proof).map_err(|_| invalid_authority())?,
                )
                .map_err(|_| invalid_authority())?;
        }
        let encoded = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(address.clone()))
            .map_err(|_| invalid_authority())?;
        parse_address(&encoded)?.ok_or_else(invalid_authority)?;
        let mut txn = self.store.env.write_txn()?;
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
            || self
                .store
                .sync_state
                .get(&txn, &authority_key(machine))?
                .is_some()
            || EntityStoreRead::port_entity_record(&self.store, &txn, &machine)?.is_some()
        {
            return Err(invalid_authority());
        }
        if self
            .mesh_machine_by_endpoint(address.endpoint_key)?
            .is_some()
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
        Ok(())
    }
    /// Authorized ALPN grant or revocation. A revoked MACHINE cannot be re-enabled.
    pub fn set_mesh_alpn_grant(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        endpoint_key: [u8; 32],
        alpn: &[u8],
        allow: bool,
    ) -> Result<()> {
        if !valid_alpn(alpn) {
            return Err(invalid_authority());
        }
        let mut txn = self.store.env.write_txn()?;
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
    /// Irreversible local MACHINE admission revoke. Reenrollment needs a new row/pairing.
    pub fn revoke_mesh_machine(&self, issuer: &HostSlipIssuer, machine: EntityId) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
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

#[cfg(test)]
mod tests {
    use super::super::pairing_binding_transcript;
    use super::*;
    use crate::{VaultConfig, authority::HostSlipIssuer};
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (
        tempfile::TempDir,
        Vault,
        HostSlipIssuer,
        EntityId,
        MeshMachineAddress,
        [u8; 32],
    ) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        let host = HostSlipIssuer::from_secret(b"mesh grant host root").unwrap();
        vault.ensure_host_root_slip(&host).unwrap();
        let machine = EntityId::now();
        let device = SigningKey::from_bytes(&[31; 32]);
        let transport = SigningKey::from_bytes(&blake3::derive_key(
            "oneiron/mesh-transport-ed25519/v1",
            device.as_bytes(),
        ));
        let address = MeshMachineAddress {
            endpoint_key: transport.verifying_key().to_bytes(),
            direct_addrs: vec![],
            relay_url: None,
        };
        let link = vault.issue_pairing_link(&host, Scope::top(), 3600).unwrap();
        let key = device.verifying_key().to_bytes();
        let proof = device
            .sign(&pairing_binding_transcript(&link.code, &key, &machine.to_hex()).unwrap())
            .to_bytes();
        let pair = vault
            .redeem_pairing_link(&host, &link.code, &machine.to_hex(), key, &proof)
            .unwrap();
        let transcript = binding_transcript(machine, address.endpoint_key);
        vault
            .bind_mesh_machine(
                &host,
                machine,
                address.clone(),
                key,
                pair.claims.slip_id,
                [
                    &device.sign(&transcript).to_bytes(),
                    &transport.sign(&transcript).to_bytes(),
                ],
            )
            .unwrap();
        (dir, vault, host, machine, address, pair.claims.slip_id)
    }
    #[test]
    fn paired_binding_is_not_a_grant_and_revoke_is_terminal() {
        let (_dir, vault, host, machine, address, _) = fixture();
        let key = address.endpoint_key;
        assert_eq!(
            vault.mesh_machine_by_endpoint(key).unwrap().unwrap().0,
            machine
        );
        assert!(
            !vault
                .mesh_grant_permits(machine, key, b"mesh/test")
                .unwrap()
        );
        vault
            .set_mesh_alpn_grant(&host, machine, key, b"mesh/test", true)
            .unwrap();
        assert!(
            vault
                .mesh_grant_permits(machine, key, b"mesh/test")
                .unwrap()
        );
        assert!(
            !vault
                .mesh_grant_permits(machine, key, b"mesh/other")
                .unwrap()
        );
        assert!(
            !vault
                .mesh_grant_permits(machine, [8; 32], b"mesh/test")
                .unwrap()
        );
        vault
            .set_mesh_alpn_grant(&host, machine, key, b"mesh/test", false)
            .unwrap();
        assert!(
            !vault
                .mesh_grant_permits(machine, key, b"mesh/test")
                .unwrap()
        );
        vault
            .set_mesh_alpn_grant(&host, machine, key, b"mesh/test", true)
            .unwrap();
        assert!(
            vault
                .mesh_grant_permits(machine, key, b"mesh/test")
                .unwrap()
        );
        vault.revoke_mesh_machine(&host, machine).unwrap();
        assert!(
            !vault
                .mesh_grant_permits(machine, key, b"mesh/test")
                .unwrap()
        );
        assert!(
            vault
                .set_mesh_alpn_grant(&host, machine, key, b"mesh/test", true)
                .is_err()
        );
    }
    #[test]
    fn public_machine_rewrite_never_widens_and_pair_revoke_closes_grant() {
        let (_dir, vault, host, machine, address, pair_id) = fixture();
        let key = address.endpoint_key;
        vault
            .set_mesh_alpn_grant(&host, machine, key, b"mesh/test", true)
            .unwrap();
        let wrong = MeshMachineAddress {
            endpoint_key: SigningKey::from_bytes(&[66; 32]).verifying_key().to_bytes(),
            direct_addrs: vec![],
            relay_url: None,
        };
        vault
            .put_entity(
                &machine,
                ENTITY_TYPE_MACHINE,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(wrong)).unwrap(),
            )
            .unwrap();
        assert!(
            !vault
                .mesh_grant_permits(machine, key, b"mesh/test")
                .unwrap()
        );
        vault
            .put_entity(
                &machine,
                ENTITY_TYPE_MACHINE,
                TimeRange { start: 1, end: 1 },
                2,
                &rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(address)).unwrap(),
            )
            .unwrap();
        assert!(
            vault
                .mesh_grant_permits(machine, key, b"mesh/test")
                .unwrap()
        );
        vault.revoke_capability_slip(&host, pair_id).unwrap();
        assert!(
            !vault
                .mesh_grant_permits(machine, key, b"mesh/test")
                .unwrap()
        );
    }
}
