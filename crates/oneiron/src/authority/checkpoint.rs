//! Quorum-signed authority roster checkpoints, linked to exact signed history.
//! Checkpoints are verified hints, never substitute trust roots; raw history is retained.
use super::history_transfer::history_in_txn;
use super::*;
use crate::side_table::{self, Raw, SideTable};
use crate::{Vault, error::Result};
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

pub const AUTHORITY_CHECKPOINT_DOMAIN: &[u8] = b"oneiron/authority/checkpoint/v1";

/// Content hash of the current head of the local authority-checkpoint chain. Key: ().
const CHECKPOINT_HEAD: SideTable<(), AuthorityEntryHash, Raw> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_HEAD);
/// One durable, quorum-signed authority checkpoint (hand-rolled MessagePack map). Key: hash32.
const CHECKPOINT_ROW: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_ROW);

/// A signed roster summary at a closed authority-history horizon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityCheckpoint {
    pub vault_id: AuthorityVaultId,
    /// Number of signed entries covered; includes rejected signed forks.
    pub horizon: u64,
    pub entry_hashes: Vec<AuthorityEntryHash>,
    /// Content hashes of prior checkpoints, not caller-supplied trust roots.
    pub parent_hashes: Vec<AuthorityEntryHash>,
    pub roster: BTreeMap<AuthorityKey, FoldedDevice>,
    pub tier_floor: AuthorityTier,
    pub signatures: Vec<AuthoritySignature>,
}

fn body_value(checkpoint: &AuthorityCheckpoint) -> Value {
    Value::Map(vec![
        (Value::from("schema_version"), Value::from(1)),
        (Value::from("vault_id"), binary_value(checkpoint.vault_id)),
        (Value::from("horizon"), Value::from(checkpoint.horizon)),
        (
            Value::from("entry_hashes"),
            Value::Array(
                checkpoint
                    .entry_hashes
                    .iter()
                    .copied()
                    .map(binary_value)
                    .collect(),
            ),
        ),
        (
            Value::from("parent_hashes"),
            Value::Array(
                checkpoint
                    .parent_hashes
                    .iter()
                    .copied()
                    .map(binary_value)
                    .collect(),
            ),
        ),
        (
            Value::from("tier_floor"),
            Value::from(checkpoint.tier_floor.as_str()),
        ),
        (
            Value::from("roster"),
            Value::Array(
                checkpoint
                    .roster
                    .values()
                    .map(|device| {
                        Value::Map(vec![
                            (Value::from("key"), key_value(&device.key)),
                            (Value::from("tier"), Value::from(device.tier.as_str())),
                            (Value::from("roles"), Value::from(device.roles)),
                            (Value::from("revoked"), Value::from(device.revoked)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}
fn shape(checkpoint: &AuthorityCheckpoint) -> Result<()> {
    if checkpoint.vault_id == [0; 32]
        || checkpoint.horizon == 0
        || checkpoint.horizon != checkpoint.entry_hashes.len() as u64
        || checkpoint.parent_hashes.len() > MAX_PARENTS
        || checkpoint.signatures.is_empty()
        || checkpoint.signatures.len() > MAX_COSIGNS + 1
        || checkpoint
            .entry_hashes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || checkpoint
            .parent_hashes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || checkpoint
            .signatures
            .windows(2)
            .any(|pair| pair[0].public_key >= pair[1].public_key)
        || checkpoint
            .roster
            .iter()
            .any(|(key, device)| key != &device.key)
    {
        return Err(invalid_authority());
    }
    for signature in &checkpoint.signatures {
        signature.validate()?;
    }
    Ok(())
}
/// Canonical signature transcript. Quorum key selection is signed too.
pub fn authority_checkpoint_transcript(checkpoint: &AuthorityCheckpoint) -> Result<Vec<u8>> {
    shape(checkpoint)?;
    let value = Value::Map(vec![
        (Value::from("body"), body_value(checkpoint)),
        (
            Value::from("signer_keys"),
            Value::Array(
                checkpoint
                    .signatures
                    .iter()
                    .map(|s| key_value(&s.public_key))
                    .collect(),
            ),
        ),
    ]);
    let mut bytes = AUTHORITY_CHECKPOINT_DOMAIN.to_vec();
    bytes.extend(encode_value(&value)?);
    Ok(bytes)
}
/// Strict canonical checkpoint wire encoding.
pub fn encode_authority_checkpoint(checkpoint: &AuthorityCheckpoint) -> Result<Vec<u8>> {
    shape(checkpoint)?;
    encode_value(&Value::Map(vec![
        (Value::from("body"), body_value(checkpoint)),
        (
            Value::from("signatures"),
            Value::Array(checkpoint.signatures.iter().map(signature_value).collect()),
        ),
    ]))
}
/// Strict decoding only. Call `Vault::verify_authority_checkpoint` before trusting a summary.
pub fn decode_authority_checkpoint(bytes: &[u8]) -> Result<AuthorityCheckpoint> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(invalid_authority());
    }
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_authority())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_authority());
    }
    let outer = map_entries(&value)?;
    validate_keys(outer, &["body", "signatures"])?;
    let body = map_entries(required(outer, "body")?)?;
    validate_keys(
        body,
        &[
            "schema_version",
            "vault_id",
            "horizon",
            "entry_hashes",
            "parent_hashes",
            "tier_floor",
            "roster",
        ],
    )?;
    if required(body, "schema_version")?.as_u64() != Some(1) {
        return Err(invalid_authority());
    }
    let mut roster = BTreeMap::new();
    for value in required(body, "roster")?
        .as_array()
        .ok_or_else(invalid_authority)?
    {
        let row = map_entries(value)?;
        validate_keys(row, &["key", "tier", "roles", "revoked"])?;
        let key = decode_key(required(row, "key")?)?;
        let device = FoldedDevice {
            key: key.clone(),
            tier: decode_tier(required(row, "tier")?)?,
            roles: u16::try_from(
                required(row, "roles")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
            )
            .map_err(|_| invalid_authority())?,
            revoked: required(row, "revoked")?
                .as_bool()
                .ok_or_else(invalid_authority)?,
        };
        if roster.insert(key, device).is_some() {
            return Err(invalid_authority());
        }
    }
    let checkpoint = AuthorityCheckpoint {
        vault_id: decode_hash(required(body, "vault_id")?)?,
        horizon: required(body, "horizon")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
        entry_hashes: decode_hash_array(required(body, "entry_hashes")?)?,
        parent_hashes: decode_hash_array(required(body, "parent_hashes")?)?,
        tier_floor: decode_tier(required(body, "tier_floor")?)?,
        roster,
        signatures: decode_signature_array(required(outer, "signatures")?)?,
    };
    if encode_authority_checkpoint(&checkpoint)? != bytes {
        return Err(invalid_authority());
    }
    Ok(checkpoint)
}
/// Content address for chain linkage and durable storage.
pub fn authority_checkpoint_hash(checkpoint: &AuthorityCheckpoint) -> Result<AuthorityEntryHash> {
    Ok(*blake3::hash(&encode_authority_checkpoint(checkpoint)?).as_bytes())
}
impl Vault {
    fn checkpoint_fold(
        &self,
        txn: &heed::RoTxn<'_>,
        checkpoint: &AuthorityCheckpoint,
    ) -> Result<AuthorityFold> {
        let history = history_in_txn(self, txn)?;
        let mut entries = Vec::new();
        let mut seen = BTreeMap::new();
        let included: BTreeSet<_> = checkpoint.entry_hashes.iter().copied().collect();
        for hash in &checkpoint.entry_hashes {
            let (_, entry) = history.get(hash).ok_or_else(invalid_authority)?;
            if entry
                .parent_hashes
                .iter()
                .any(|parent| !included.contains(parent))
            {
                return Err(invalid_authority());
            }
            if let Some(time) = AUTHORITY_FIRST_SEEN.get_lenient(
                &self.store,
                txn,
                &authority_first_seen_sidecar_key(hash),
            )? {
                seen.insert(*hash, time);
            }
            entries.push(entry.clone());
        }
        let floor = AUTHORITY_FIRST_SEEN
            .get_lenient(&self.store, txn, &authority_first_seen_clock_key())?
            .unwrap_or(0);
        let now =
            authority_observation_secs(&self.store, floor, self.store.clock.now_recorded_at());
        let peers = crate::federation::admitted_peer_consent_roots_in_txn(self, txn)?;
        Ok(fold_authority_log_for_posture(
            &entries,
            &seen,
            now,
            &peers,
            self.privacy_posture(),
        ))
    }
    fn verify_checkpoint_one(
        &self,
        txn: &heed::RoTxn<'_>,
        checkpoint: &AuthorityCheckpoint,
    ) -> Result<()> {
        shape(checkpoint)?;
        let fold = self.checkpoint_fold(txn, checkpoint)?;
        if fold.vault_id != Some(checkpoint.vault_id)
            || fold.roster != checkpoint.roster
            || fold.tier_floor != Some(checkpoint.tier_floor)
            || !fold.pending_widens.is_empty()
            || fold
                .authority_forks
                .iter()
                .any(|fork| fork.status == AuthorityForkStatus::Quarantined)
        {
            return Err(invalid_authority());
        }
        let transcript = authority_checkpoint_transcript(checkpoint)?;
        let mut consent = false;
        for signature in &checkpoint.signatures {
            let device = fold
                .roster
                .get(&signature.public_key)
                .filter(|device| !device.revoked && device.roles != 0)
                .ok_or_else(invalid_authority)?;
            if !tier_meets_floor(device.tier, checkpoint.tier_floor) {
                return Err(invalid_authority());
            }
            consent |= if self.privacy_posture() == crate::HostingPrivacyPosture::Hosted {
                folded_host_device_can_consent(device)
            } else {
                folded_device_can_authority_consent(device)
            };
            if !verify_authority_signature(signature, &transcript) {
                return Err(invalid_authority());
            }
        }
        let active = fold
            .roster
            .values()
            .filter(|device| !device.revoked && device.roles != 0)
            .count();
        if !consent || checkpoint.signatures.len() < active.min(2) {
            return Err(invalid_authority());
        }
        Ok(())
    }
    fn verify_checkpoint_chain(
        &self,
        txn: &heed::RoTxn<'_>,
        checkpoint: &AuthorityCheckpoint,
    ) -> Result<()> {
        let mut pending = vec![checkpoint.clone()];
        let mut visited = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if !visited.insert(authority_checkpoint_hash(&current)?) {
                continue;
            }
            self.verify_checkpoint_one(txn, &current)?;
            for hash in &current.parent_hashes {
                let bytes = CHECKPOINT_ROW
                    .get(&self.store, txn, hash)?
                    .ok_or_else(invalid_authority)?;
                let parent = decode_authority_checkpoint(&bytes)?;
                if authority_checkpoint_hash(&parent)? != *hash
                    || parent.vault_id != current.vault_id
                    || parent.horizon >= current.horizon
                    || parent
                        .entry_hashes
                        .iter()
                        .any(|entry| current.entry_hashes.binary_search(entry).is_err())
                {
                    return Err(invalid_authority());
                }
                pending.push(parent);
            }
        }
        Ok(())
    }
    /// Verifies quorum, exact replay summary, horizon closure and every parent link.
    pub fn verify_authority_checkpoint(&self, checkpoint: &AuthorityCheckpoint) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        self.verify_checkpoint_chain(&txn, checkpoint)
    }
    /// Appends a new checkpoint after the current head. Concurrent writers retry;
    /// neither a stale signature nor an unknown parent silently starts another chain.
    pub fn write_authority_checkpoint<S>(
        &self,
        mut signer_keys: Vec<AuthorityKey>,
        mut sign: S,
    ) -> Result<AuthorityCheckpoint>
    where
        S: FnMut(&AuthorityKey, &[u8]) -> Result<Vec<u8>>,
    {
        self.authority_fold()?; // establish local observation sidecars before taking the signing snapshot
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let history = history_in_txn(self, &txn)?;
        let head: Option<AuthorityEntryHash> = CHECKPOINT_HEAD.get(&self.store, &txn, &())?;
        let parent_hashes = head.map_or_else(Vec::new, |hash| vec![hash]);
        signer_keys.sort();
        signer_keys.dedup();
        let mut checkpoint = AuthorityCheckpoint {
            vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
            horizon: history.len() as u64,
            entry_hashes: history.keys().copied().collect(),
            parent_hashes,
            roster: fold.roster,
            tier_floor: fold.tier_floor.ok_or_else(invalid_authority)?,
            signatures: signer_keys
                .into_iter()
                .map(|public_key| AuthoritySignature {
                    suite: public_key.suite(),
                    public_key,
                    signature: vec![0; 64],
                })
                .collect(),
        };
        drop(txn);
        let transcript = authority_checkpoint_transcript(&checkpoint)?;
        for signature in &mut checkpoint.signatures {
            signature.signature = sign(&signature.public_key, &transcript)?;
        }
        let mut txn = self.store.env.write_txn()?;
        if CHECKPOINT_HEAD.get(&self.store, &txn, &())? != head {
            return Err(invalid_authority());
        }
        self.verify_checkpoint_chain(&txn, &checkpoint)?;
        let hash = authority_checkpoint_hash(&checkpoint)?;
        let bytes = encode_authority_checkpoint(&checkpoint)?;
        CHECKPOINT_ROW.put(&self.store, &mut txn, &hash, &bytes)?;
        CHECKPOINT_HEAD.put(&self.store, &mut txn, &(), &hash)?;
        txn.commit()?;
        Ok(checkpoint)
    }
    /// A checkpoint is never returned as trusted state without chain and quorum verification.
    pub fn read_authority_checkpoint(
        &self,
        hash: &AuthorityEntryHash,
    ) -> Result<Option<AuthorityCheckpoint>> {
        let txn = self.store.env.read_txn()?;
        let Some(bytes) = CHECKPOINT_ROW.get(&self.store, &txn, hash)? else {
            return Ok(None);
        };
        let checkpoint = decode_authority_checkpoint(&bytes)?;
        if authority_checkpoint_hash(&checkpoint)? != *hash {
            return Err(invalid_authority());
        }
        self.verify_checkpoint_chain(&txn, &checkpoint)?;
        Ok(Some(checkpoint))
    }
}
