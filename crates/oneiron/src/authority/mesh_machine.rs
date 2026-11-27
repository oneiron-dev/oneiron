//! Local host-authorized mesh binding and grants, distinct from address hints.
//! A MACHINE row is public-writable address data. The host-signed local binding
//! selects exact ALPN slips in AUTHORITY_LOG; it cannot grant permission itself.
//! The host, pairing slip, logged grant and current MACHINE key are rechecked together.
use super::{
    AuthorityFold, AuthorityKey, HostSlipIssuer, invalid_authority, roster_has_live_owner,
};
use crate::scan_check::ScanCount;
use crate::{
    EntityId, Vault,
    error::Result,
    ports::{EntityStore, EntityStoreRead},
    registry::ENTITY_TYPE_MACHINE,
    side_table::{self, HexId, Named, SideTable},
};
use ed25519_dalek::Signature;
use oneiron_authority::federation::{Scope, ScopeAxis};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use crate::temporal::TimeRange;

mod doors;
mod endpoint_index;
mod enrolment;
mod replication;
pub use doors::{MeshAlpnGrant, MeshBindingIdentity, MeshMachineBinding};
pub(crate) use endpoint_index::reindex_mesh_machine_endpoint;
pub use enrolment::{MeshBindRefusal, MeshEnrolment, MeshEnrolmentAsk};
pub use replication::{
    MESH_AUTHORITY_PAGE_MAX, MESH_AUTHORITY_PART_MAX, MESH_AUTHORITY_ROW_MAX, MeshAuthorityImport,
    MeshAuthorityPage, MeshAuthorityPart, MeshAuthorityRow, MeshAuthorityRowJoin,
    MeshAuthorityRowRef,
};
use replication::{mesh_transport_seed_of, verified_mesh_authority};

const DOMAIN: &str = "oneiron/mesh-machine/v1";
const AUTH_DOMAIN: &[u8] = b"oneiron/mesh-authority/v1\0";
const BIND_DOMAIN: &[u8] = b"oneiron/mesh-machine-binding/v1\0";
/// MACHINE rows a lookup any endpoint key can make walks before it refuses,
/// when the endpoint index cannot serve it (its open rebuild failed or never
/// ran): a stranger's work stays bounded. The index reads only the rows that
/// name the key ([`endpoint_index`], census L3-28B).
const MAX_LOOKUP_MACHINES: usize = 1024;

#[doc(hidden)]
pub use oneiron_verb_wire::authority::mesh_machine::MeshMachineAddress;

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
    /// One more than the row this host held for the MACHINE before, counted
    /// at each write, so a replica takes a row only over an older one
    /// (MESH-AUTHORITY-REPLICATION, REVIEW-10536 P1). A row written before
    /// the count holds none: the signed bytes leave it out while it is zero,
    /// so such a row still verifies.
    #[serde(default, skip_serializing_if = "revision_unset")]
    revision: u64,
}
/// Whether a binding's `revision` is unset (a row written before the count).
fn revision_unset(revision: &u64) -> bool {
    *revision == 0
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedMeshAuthority {
    claims: MeshAuthorityClaims,
    signature: Vec<u8>,
}
/// Host-signed authority projection. The key is the MACHINE's lower-case hex id.
const MESH_AUTHORITY: SideTable<HexId, SignedMeshAuthority, Named> =
    SideTable::new(&side_table::AUTHORITY_MESH_MACHINE);
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
/// The claims of the pairing slip a binding stands on, when it stands for
/// that binding at any time: minted and not revoked in `fold`, a root slip of
/// this vault held by the binding's MACHINE under its machine key, and the
/// MACHINE not removed. Whether it is live now is its lifetime's question
/// ([`Vault::mesh_pairing_live`]).
fn mesh_pairing_standing<'f>(
    fold: &'f AuthorityFold,
    claims: &MeshAuthorityClaims,
) -> Option<&'f super::SlipClaims> {
    let pair = &fold.slips.mints.get(&claims.pairing_slip_id)?.action.claims;
    (fold.slip_is_live(&claims.pairing_slip_id)
        && pair.holder_ref == claims.machine.to_hex()
        && pair.binding_key == claims.device_key
        && pair.parent_id.is_none()
        && fold.vault_id == Some(pair.vault_id)
        // A removed MACHINE's binding admits nothing (FIX 3374).
        && !fold.machine(claims.machine).is_some_and(|folded| {
            enrolment::machine_removed(folded, fold.pinned_root.as_ref())
        }))
    .then_some(pair)
}
/// The address a MACHINE body carries, every direct address in it: a
/// binding is never refused or read as absent for how many it names (Phase2
/// A, FIX 7922). Its key, relay and envelope checks stay; a stranger's lookup
/// stays bounded by its row count ([`MAX_LOOKUP_MACHINES`]).
fn parse_address(body: &[u8]) -> Option<MeshMachineAddress> {
    let envelope = rmp_serde::from_slice::<MeshMachineAddressEnvelope>(body).ok()?;
    if envelope.domain != DOMAIN
        || envelope.version != 1
        || super::strong_ed25519_key(&envelope.address.endpoint_key).is_err()
        || envelope
            .address
            .relay_url
            .as_ref()
            .is_some_and(|url| url.len() > 2048)
    {
        return None;
    }
    Some(envelope.address)
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
        Ok(parse_address(&row.body))
    }
    /// One snapshot for type, liveness and address; never guesses a header offset.
    pub fn mesh_machine(&self, machine: EntityId) -> Result<Option<MeshMachineAddress>> {
        let txn = self.store.env.read_txn()?;
        self.mesh_machine_in_txn(&txn, machine)
    }
    /// Resolve against a single snapshot: the endpoint index, else the type
    /// index and all bodies. Any key may ask, so this read raises no owner check.
    pub fn mesh_machine_by_endpoint(
        &self,
        key: [u8; 32],
    ) -> Result<Option<(EntityId, MeshMachineAddress)>> {
        let txn = self.store.env.read_txn()?;
        self.mesh_machine_by_endpoint_in_txn(&txn, key, None)
    }
    /// The endpoint index answers whenever it can, for the owner and a
    /// stranger alike: it reads only the MACHINE rows that name `key`
    /// (census L3-28B). On any doubt the walk below answers: the owner's
    /// bind reads every MACHINE, however many the owner keeps (rule 5), and
    /// counts them in `count`; a lookup any endpoint key can make (`count`
    /// is `None`) is a stranger's work and stays bounded.
    fn mesh_machine_by_endpoint_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: [u8; 32],
        count: Option<&mut ScanCount>,
    ) -> Result<Option<(EntityId, MeshMachineAddress)>> {
        if let Some(answer) = endpoint_index::indexed_machine_by_endpoint_in_txn(self, txn, key) {
            return answer;
        }
        self.walk_machines_by_endpoint_in_txn(txn, key, count)
    }
    /// Every MACHINE row's body, read for the one that names `key`.
    fn walk_machines_by_endpoint_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: [u8; 32],
        mut count: Option<&mut ScanCount>,
    ) -> Result<Option<(EntityId, MeshMachineAddress)>> {
        let mut found = None;
        for (seen, id) in
            EntityStoreRead::port_entity_ids_by_type(&self.store, txn, ENTITY_TYPE_MACHINE, None)?
                .enumerate()
        {
            match count.as_deref_mut() {
                Some(count) => count.row(),
                None if seen >= MAX_LOOKUP_MACHINES => return Err(invalid_authority()),
                None => {}
            }
            let id = id?;
            if let Some(row) = self.mesh_machine_in_txn(txn, id)?
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
        let Some((fold, claims)) = self.mesh_authority_signed_in_txn(txn, machine)? else {
            return Ok(None);
        };
        if !self.mesh_pairing_live(&fold, txn, &claims)? {
            return Ok(None);
        }
        Ok(Some(claims))
    }
    /// `machine`'s binding row as a live owner host signed it, with the fold
    /// it was checked against: [`Self::mesh_authority_in_txn`] without its
    /// check that the binding's pairing is live.
    fn mesh_authority_signed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
    ) -> Result<Option<(AuthorityFold, MeshAuthorityClaims)>> {
        let Some(signed) = MESH_AUTHORITY
            .get(&self.store, txn, &HexId(machine))
            .map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid_authority()
                } else {
                    error
                }
            })?
        else {
            return Ok(None);
        };
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        Ok(verified_mesh_authority(&fold, machine, &signed)?.map(|claims| (fold, claims)))
    }
    /// Whether the pairing a binding stands on is live on this vault now: it
    /// stands ([`mesh_pairing_standing`]) and has not expired. Its start is
    /// its presence in the home's signed fold, not a reading of this vault's
    /// clock. The home mints a pairing on its own authority clock, and a
    /// replica's clock stops while its vault is closed or its host sleeps, so
    /// a replica behind the home would read a fresh pairing as not yet begun
    /// and refuse every bind on it until its own clock caught up
    /// (MESH-PAIRING-REPLICA-CLOCK = A, Engine 25 Nov 11:55). For the same
    /// reason its end is judged no earlier than the newest time a live owner
    /// signed into the fold, so a replica that slept does not keep a pairing
    /// past its expiry for the time it was closed (MESH-REPLICA-CLOCK-LIFETIMES
    /// = A, Engine 25 Nov 19:45). A grant is judged alike
    /// (`mesh_grant_permits_in_txn`).
    fn mesh_pairing_live(
        &self,
        fold: &AuthorityFold,
        txn: &heed::RoTxn<'_>,
        claims: &MeshAuthorityClaims,
    ) -> Result<bool> {
        let Some(pair) = mesh_pairing_standing(fold, claims) else {
            return Ok(false);
        };
        if self.instant_in_txn(txn)?.secs() >= pair.expires_at {
            return Ok(false);
        }
        let signed = super::readonly_fold::newest_owner_signed_ts_in_txn(
            &self.store,
            self.privacy_posture(),
            txn,
            fold,
        )?;
        Ok(signed.is_none_or(|signed| signed < pair.expires_at))
    }
    /// A fresh, single-snapshot check of signed grant, live pairing and current row.
    pub fn mesh_grant_permits(
        &self,
        machine: EntityId,
        endpoint_key: [u8; 32],
        alpn: &[u8],
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.mesh_grant_permits_in_txn(&txn, machine, endpoint_key, alpn)
    }
    /// Whether this vault's grants admit the MACHINE `machine` on `alpn`
    /// under its current address key, read in `txn`: the one-machine form of
    /// [`Self::mesh_machines_granted`], for a write that judges the grant in
    /// its own transaction. A row whose grant does not check out answers
    /// `false`, never an error.
    pub(crate) fn mesh_machine_granted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
        alpn: &[u8],
    ) -> Result<bool> {
        let Some(row) = self.mesh_machine_in_txn(txn, machine)? else {
            return Ok(false);
        };
        Ok(self
            .mesh_grant_permits_in_txn(txn, machine, row.endpoint_key, alpn)
            .unwrap_or(false))
    }

    /// Every MACHINE this vault's grants admit on `alpn` under its current
    /// address key, in one snapshot, as a caller picks a peer to dial. A
    /// row whose grant does not check out is left out, never an error.
    pub fn mesh_machines_granted(&self, alpn: &[u8]) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let mut granted = Vec::new();
        for id in
            EntityStoreRead::port_entity_ids_by_type(&self.store, &txn, ENTITY_TYPE_MACHINE, None)?
        {
            let id = id?;
            let Some(row) = self.mesh_machine_in_txn(&txn, id)? else {
                continue;
            };
            if self
                .mesh_grant_permits_in_txn(&txn, id, row.endpoint_key, alpn)
                .unwrap_or(false)
            {
                granted.push(id);
            }
        }
        Ok(granted)
    }
    /// Until when, in vault seconds, `machine` holds a live grant on `alpn` under its current
    /// address key, as [`Self::mesh_grant_permits`] judges it now: the earlier of the grant's
    /// expiry and its pairing's. `None` when no grant permits it now. The `vault_machine`
    /// connector's live recheck reads it before each dispatch (pass 33 section 8.2: no grant may
    /// end inside the submit window and the staging limit).
    pub(crate) fn mesh_grant_live_until_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
        alpn: &[u8],
    ) -> Result<Option<u64>> {
        let Some(row) = self.mesh_machine_in_txn(txn, machine)? else {
            return Ok(None);
        };
        if !self.mesh_grant_permits_in_txn(txn, machine, row.endpoint_key, alpn)? {
            return Ok(None);
        }
        let Some(claims) = self.mesh_authority_in_txn(txn, machine)? else {
            return Ok(None);
        };
        let Some(grant_id) = claims.alpns.get(alpn) else {
            return Ok(None);
        };
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let expires_at = |slip: &[u8; 32]| {
            fold.slips
                .mints
                .get(slip)
                .map(|mint| mint.action.claims.expires_at)
        };
        Ok(expires_at(grant_id)
            .zip(expires_at(&claims.pairing_slip_id))
            .map(|(grant, pairing)| grant.min(pairing)))
    }
    /// This install's MACHINE id and the seed of its mesh transport key, or
    /// `None` before it has a machine id (OF-535). The seed is derived from the
    /// machine key, the key a mesh binding pairs and a machine proof signs
    /// with, under the transport domain `oneiron-mesh-transport` derives
    /// with (`oneiron/mesh-transport-ed25519/v1`); the machine key never
    /// leaves the engine.
    pub fn mesh_transport_seed(&self) -> Result<Option<(EntityId, zeroize::Zeroizing<[u8; 32]>)>> {
        self.load_install_signing_if_minted()?;
        let txn = self.store.env.read_txn()?;
        let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let Some(key) = crate::identity::read_machine_signing_key_in_txn(self, &txn)? else {
            return Ok(None);
        };
        Ok(Some((machine, mesh_transport_seed_of(&key))))
    }
    /// The physical machine behind an authenticated mesh endpoint, in one
    /// snapshot: the endpoint names the MACHINE, the host-signed binding and
    /// grant admit it, and the key the machine stands on here is the very key
    /// that paired. The profile lives in the authority log, so the address bind
    /// that rewrote the row keeps it.
    pub fn mesh_peer_machine(
        &self,
        endpoint_key: [u8; 32],
        alpn: &[u8],
    ) -> Result<super::PeerMachine> {
        let txn = self.store.env.read_txn()?;
        let Some((machine, _)) = self.mesh_machine_by_endpoint_in_txn(&txn, endpoint_key, None)?
        else {
            return Ok(super::PeerMachine::Unknown);
        };
        let paired = self
            .mesh_authority_in_txn(&txn, machine)?
            .map(|claims| claims.device_key);
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        match fold.machine_proof_key(machine) {
            Some(key)
                if paired == Some(key)
                    && self.mesh_grant_permits_in_txn(&txn, machine, endpoint_key, alpn)? =>
            {
                Ok(super::PeerMachine::Proven { machine, key })
            }
            _ => Ok(super::PeerMachine::Unknown),
        }
    }
    /// Whether `machine`'s grant of `alpn` was ended by an act this vault
    /// folded, and not by time alone: the grant withdrawn or its slip
    /// revoked, the machine's binding revoked or gone, its pairing revoked,
    /// or the machine removed. A grant or a pairing that only expired is not
    /// withdrawn, and neither is a grant whose mint this replica has not
    /// folded yet: that is unknown here (pass 33 EN-4 A: a revoke stops what
    /// it authorised; an expiry does not).
    pub fn mesh_grant_withdrawn(&self, machine: EntityId, alpn: &[u8]) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let Some((fold, claims)) = self.mesh_authority_signed_in_txn(&txn, machine)? else {
            return Ok(true);
        };
        // The pairing's standing apart from its lifetime: a revoke or the
        // MACHINE's removal ends it, its expiry does not.
        if claims.revoked || mesh_pairing_standing(&fold, &claims).is_none() {
            return Ok(true);
        }
        let Some(grant_id) = claims.alpns.get(alpn) else {
            return Ok(true);
        };
        Ok(fold.slips.mints.get(grant_id).is_some() && !fold.slip_is_live(grant_id))
    }
    fn mesh_grant_permits_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
        endpoint_key: [u8; 32],
        alpn: &[u8],
    ) -> Result<bool> {
        if !valid_alpn(alpn) {
            return Ok(false);
        }
        let Some(row) = self.mesh_machine_in_txn(txn, machine)? else {
            return Ok(false);
        };
        if row.endpoint_key != endpoint_key {
            return Ok(false);
        }
        let Some(claims) = self.mesh_authority_in_txn(txn, machine)? else {
            return Ok(false);
        };
        if claims.revoked || claims.endpoint_key != endpoint_key {
            return Ok(false);
        }
        let Some(grant_id) = claims.alpns.get(alpn) else {
            return Ok(false);
        };
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let Some(mint) = fold.slips.mints.get(grant_id) else {
            return Ok(false);
        };
        // A removed MACHINE admits nothing, however its removal arrived:
        // the owner's door, another door, or a sync (FIX 3374, L02 05:3x).
        if fold
            .machine(machine)
            .is_some_and(|folded| enrolment::machine_removed(folded, fold.pinned_root.as_ref()))
        {
            return Ok(false);
        }
        let grant = &mint.action.claims;
        // Its start is its presence in the signed fold and its end is judged
        // no earlier than the newest owner-signed time, as for its pairing: a
        // replica proves peers on the home's grants (REVIEW-10536 round 2).
        let now = self.instant_in_txn(txn)?.secs();
        let signed = super::readonly_fold::newest_owner_signed_ts_in_txn(
            &self.store,
            self.privacy_posture(),
            txn,
            &fold,
        )?;
        Ok(fold.slip_is_live(grant_id)
            && now.max(signed.unwrap_or(0)) < grant.expires_at
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
        mut claims: MeshAuthorityClaims,
    ) -> Result<()> {
        // One up from the row held, so every replica orders this host's
        // writes of the MACHINE; a row that does not decode counts as none.
        let held = match MESH_AUTHORITY.get(&self.store, txn, &HexId(claims.machine)) {
            Ok(held) => held.map_or(0, |held| held.claims.revision),
            Err(error) if error.kind() == crate::error::ErrorKind::SideTableRow => 0,
            Err(error) => return Err(error),
        };
        claims.revision = held.saturating_add(1);
        let signature = issuer.sign_mesh(&transcript(&claims)?);
        MESH_AUTHORITY.put(
            &self.store,
            txn,
            &HexId(claims.machine),
            &SignedMeshAuthority {
                claims,
                signature: signature.to_vec(),
            },
        )?;
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
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        let host = HostSlipIssuer::from_secret(b"mesh grant host root").unwrap();
        vault.ensure_host_root_slip(&host).unwrap();
        let machine = EntityId::now();
        vault
            .put_entity(
                &machine,
                ENTITY_TYPE_MACHINE,
                TimeRange { start: 1, end: 1 },
                1,
                b"paired machine actor",
            )
            .unwrap();
        assert!(vault.get(&machine).unwrap().is_some()); // the public pairing route's holder precondition
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
        assert_eq!(
            vault.mesh_machine(machine).unwrap().unwrap().endpoint_key,
            address.endpoint_key
        );
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
            vault
                .bind_mesh_machine(&host, machine, address, [1; 32], [2; 32], [&[], &[]])
                .is_err()
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
    #[test]
    fn binding_refuses_wrong_kind_deleted_duplicate_and_repeat() {
        use crate::registry::ENTITY_TYPE_PERSON;
        let (_dir, vault, host, bound, address, pair_id) = fixture();
        let device = SigningKey::from_bytes(&[31; 32]);
        let transport = SigningKey::from_bytes(&blake3::derive_key(
            "oneiron/mesh-transport-ed25519/v1",
            device.as_bytes(),
        ));
        let key = device.verifying_key().to_bytes();
        let bind = |machine: EntityId, slip_id: [u8; 32]| {
            let transcript = binding_transcript(machine, address.endpoint_key);
            vault.bind_mesh_machine(
                &host,
                machine,
                address.clone(),
                key,
                slip_id,
                [
                    &device.sign(&transcript).to_bytes(),
                    &transport.sign(&transcript).to_bytes(),
                ],
            )
        };
        assert!(bind(bound, pair_id).is_err()); // an existing binding cannot be reminted
        for (kind, deleted) in [
            (ENTITY_TYPE_PERSON, false),
            (ENTITY_TYPE_MACHINE, true),
            (ENTITY_TYPE_MACHINE, false),
        ] {
            let machine = EntityId::now();
            vault
                .put_entity(&machine, kind, TimeRange { start: 1, end: 1 }, 1, b"holder")
                .unwrap();
            let link = vault.issue_pairing_link(&host, Scope::top(), 3600).unwrap();
            let proof = device
                .sign(&pairing_binding_transcript(&link.code, &key, &machine.to_hex()).unwrap())
                .to_bytes();
            let slip = vault
                .redeem_pairing_link(&host, &link.code, &machine.to_hex(), key, &proof)
                .unwrap();
            if deleted {
                assert!(vault.delete_entity(&machine).unwrap());
            }
            assert!(
                bind(machine, slip.claims.slip_id).is_err(),
                "wrong kind, deleted holder, or duplicate endpoint must refuse binding"
            );
        }
        assert_eq!(
            vault
                .mesh_machine_by_endpoint(address.endpoint_key)
                .unwrap()
                .unwrap()
                .0,
            bound
        );
    }
}
