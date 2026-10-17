//! OF-422 Phase 1 (ARCH-0069 `#custody-seal-planned`): a portable credential
//! syncs again, but only as an owner-signed custody transition.
//!
//! The custody record stays sealed from every replicated door, as before: a
//! peer's custody body proves nothing about who wrote it. What travels
//! instead is a transition: the record at one generation with its value taken
//! out, the value sealed to each machine mine here, and a signature by a
//! machine mine here under the pinned root, or by the pinned root's owner
//! anchor. A receiver judges the signer against its own folded roster as it
//! stands at receipt, and writes the record through the local custody door
//! only when its own machine opens the value. A host that is not one of the
//! owner's machines holds the transition unread and forwards it.
//!
//! A device-bound, cross-vault or "this device only" record never makes one:
//! that material stays on the device that holds it.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, OpenKey, OpenPolicy, Purpose, SealKey,
    SealParams, SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use super::codec::{decode_secret_custody_body, encode_secret_custody_body, invalid_body};
use super::doors::bind_synced_name_in_txn;
use super::types::{CustodyClass, SecretCustodyRecord, SecretCustodyStatus};
use crate::Vault;
use crate::authority::{AuthorityFold, WrapRecipient};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, HexId, Raw, SideTable};

/// The latest transition this vault holds of each portable credential, signed
/// here or taken from a window, by record id. The sync layer mirrors each into
/// the window of its signing month.
const TRANSITIONS: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_TRANSITION);

const MAGIC: &[u8; 4] = b"OCT1";
const SIGNATURE_DOMAIN: &[u8] = b"oneiron/custody-transition/v1";
const VALUE_LABEL: &[u8] = b"oneiron/custody-value/v1";
const KEY_ID_LABEL: &[u8] = b"custody";
const VALUE_EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The largest transition a door writes or a receiver decodes.
pub(crate) const MAX_TRANSITION_BYTES: usize = 4 << 20;
/// The most machines one transition seals the value to.
const MAX_RECIPIENTS: usize = 64;

/// One owner-signed transition of a portable credential.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CustodyTransition {
    /// The custody record's id.
    pub(crate) id: EntityId,
    /// The record's rotation generation.
    pub(crate) generation: u32,
    pub(crate) status: SecretCustodyStatus,
    /// Unix seconds at signing.
    pub(crate) signed_at: u64,
    /// The record in the body codec, its value taken out.
    body: Vec<u8>,
    /// The value sealed to each recipient machine; none once revoked.
    sealed: Vec<(EntityId, Vec<u8>)>,
    /// The Ed25519 key that signed.
    pub(crate) signer: [u8; 32],
    signature: [u8; 64],
}

// Never print the sealed value or the body.
impl std::fmt::Debug for CustodyTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustodyTransition")
            .field("id", &self.id)
            .field("generation", &self.generation)
            .field("status", &self.status)
            .field("signed_at", &self.signed_at)
            .field("recipients", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

/// Whether `record` may leave this device: custody-portable with its "this
/// device only" dial off.
pub(crate) fn custody_portable(record: &SecretCustodyRecord) -> bool {
    record.class == CustodyClass::CustodyPortable && !record.device_only
}

/// Whether `signer` signs for the owner under `fold`: the pinned root's owner
/// anchor, or a machine mine under the pin.
fn owner_signer(fold: &AuthorityFold, signer: &[u8; 32]) -> bool {
    fold.pinned_root
        .as_ref()
        .is_some_and(|root| root.anchor_key == *signer)
        || fold.mine_machine_by_key(signer).is_some()
}

/// Signs the transition of record `id` as it stands in `record`, with
/// `signing`, this machine's install key or the owner anchor, its value
/// sealed to every machine mine under `fold`'s pin. `None` when the record
/// must stay here: it is not portable, the vault has no authority genesis, or
/// `signing` is neither the pinned root's anchor nor a machine mine under the
/// pin.
pub(crate) fn sign_custody_transition(
    fold: &AuthorityFold,
    signing: &SigningKey,
    id: EntityId,
    record: &SecretCustodyRecord,
    signed_at: u64,
) -> Result<Option<CustodyTransition>> {
    let signer = signing.verifying_key().to_bytes();
    let Some(vault_id) = fold.vault_id else {
        return Ok(None);
    };
    if !custody_portable(record) || !owner_signer(fold, &signer) {
        return Ok(None);
    }
    let mut bare = record.clone();
    bare.value_bytes = Vec::new();
    let body = encode_secret_custody_body(&bare)?;
    let mut sealed = Vec::new();
    if record.status != SecretCustodyStatus::Revoked {
        for (machine, public) in seal_recipients(fold) {
            let envelope = seal_value(
                &vault_id,
                id,
                record.rotation_generation,
                machine,
                &public,
                &record.value_bytes,
            )?;
            sealed.push((machine, envelope));
        }
        if sealed.is_empty() || sealed.len() > MAX_RECIPIENTS {
            return Ok(None);
        }
    }
    let mut transition = CustodyTransition {
        id,
        generation: record.rotation_generation,
        status: record.status,
        signed_at,
        body,
        sealed,
        signer,
        signature: [0; 64],
    };
    transition.signature = signing.sign(&transition.transcript(&vault_id)).to_bytes();
    if transition.encode().len() > MAX_TRANSITION_BYTES {
        return Ok(None);
    }
    Ok(Some(transition))
}

/// The machines a transition seals its value to under `fold`: each machine
/// mine under the pin whose encryption key imports.
fn seal_recipients(fold: &AuthorityFold) -> Vec<(EntityId, HybridPublicKey)> {
    fold.machines
        .keys()
        .filter_map(|machine| {
            let trusted = fold.trusted_machine(*machine)?;
            // A profile whose key does not import could open nothing.
            let public = HybridPublicKey::from_bytes(&trusted.profile.encryption_key.key).ok()?;
            Some((*machine, public))
        })
        .collect()
}

/// Signs and stores, in the door's own write transaction, the transition of
/// record `id` as `record` now stands. Nothing is written when the record must
/// stay here: it is not portable, this install has no machine key loaded, or
/// it is not a machine mine under a pinned root. Returns the transition
/// written.
pub(crate) fn write_custody_transition_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    record: &SecretCustodyRecord,
    at: u64,
) -> Result<Option<CustodyTransition>> {
    if !custody_portable(record) {
        return Ok(None);
    }
    let Some(machine) = crate::identity::read_machine_id_in_txn(vault, wtxn)? else {
        return Ok(None);
    };
    let Ok(Some(signing)) = crate::identity::read_machine_signing_key_in_txn(vault, wtxn) else {
        return Ok(None);
    };
    let fold = vault.authority_view_readonly_in_txn(wtxn)?;
    let mine = fold.pinned_root.is_some()
        && fold.trusted_machine(machine).is_some_and(|trusted| {
            trusted.profile.machine_key == signing.verifying_key().to_bytes()
        });
    if !mine {
        return Ok(None);
    }
    let Some(transition) = sign_custody_transition(&fold, &signing, id, record, at)? else {
        return Ok(None);
    };
    TRANSITIONS.put(&vault.store, wtxn, &HexId(id), &transition.encode())?;
    Ok(Some(transition))
}

/// Keeps `transition` as this vault's latest of its record when it supersedes
/// the one held. A machine that took a peer's transition can then seal it
/// again for a machine the roster gains, and drop the carrier it supersedes
/// from the window that carrier rides. Returns whether it kept it.
pub(crate) fn remember_custody_transition_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    transition: &CustodyTransition,
) -> Result<bool> {
    let key = HexId(transition.id);
    let held = TRANSITIONS.get(&vault.store, wtxn, &key)?;
    if held
        .and_then(|held| CustodyTransition::decode(&held).ok())
        .is_some_and(|held| !transition.supersedes(&held))
    {
        return Ok(false);
    }
    TRANSITIONS.put(&vault.store, wtxn, &key, &transition.encode())?;
    Ok(true)
}

/// Seals again, in `wtxn`, the latest transition of each portable record this
/// vault holds whose value a machine now mine under the pin cannot open: the
/// record at the same generation and status, its value sealed to every
/// machine mine now, signed at `at` and never before the transition it
/// replaces. A machine with no record writes it; one that holds the record
/// finds it stale. Nothing is signed when this install is not a machine mine
/// under the pin. Returns the transitions written.
pub(crate) fn reseal_custody_transitions_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    at: u64,
) -> Result<Vec<CustodyTransition>> {
    let mine: Vec<EntityId> = {
        let fold = vault.authority_view_readonly_in_txn(wtxn)?;
        seal_recipients(&fold)
            .into_iter()
            .map(|(machine, _)| machine)
            .collect()
    };
    let mut due = Vec::new();
    for (_, carrier) in TRANSITIONS.scan(&vault.store, wtxn)? {
        let Ok(held) = CustodyTransition::decode(&carrier) else {
            continue;
        };
        if held.status != SecretCustodyStatus::Revoked
            && mine
                .iter()
                .any(|machine| !held.sealed.iter().any(|(to, _)| to == machine))
        {
            due.push(held);
        }
    }
    let mut written = Vec::new();
    for held in due {
        let Some(record) = super::read_secret_custody_in_txn(&vault.store, wtxn, &held.id)? else {
            continue;
        };
        if (record.rotation_generation, status_rank(record.status)) != held.order() {
            continue;
        }
        let signed_at = at.max(held.signed_at.saturating_add(1));
        if let Some(transition) =
            write_custody_transition_in_txn(vault, wtxn, held.id, &record, signed_at)?
        {
            written.push(transition);
        }
    }
    Ok(written)
}

/// Every transition this vault holds, by record id.
pub(crate) fn custody_transitions(vault: &Vault) -> Result<Vec<(EntityId, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(TRANSITIONS
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(HexId(id), carrier)| (id, carrier))
        .collect())
}

impl CustodyTransition {
    /// Where this transition stands among the record's: its generation, then
    /// its status (active, suspended, revoked).
    pub(crate) fn order(&self) -> (u32, u8) {
        (self.generation, status_rank(self.status))
    }

    /// Whether this carrier replaces `other`, of the same record: a later
    /// [`Self::order`], or the same one signed later, as a re-seal is. Two
    /// carriers signed in the same second settle on the greater bytes, the
    /// same on every machine.
    pub(crate) fn supersedes(&self, other: &Self) -> bool {
        match (self.order(), self.signed_at).cmp(&(other.order(), other.signed_at)) {
            std::cmp::Ordering::Equal => self.encode() > other.encode(),
            later => later.is_gt(),
        }
    }

    /// What the signature covers: the vault and every field but the
    /// signature itself.
    fn transcript(&self, vault_id: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + self.body.len() + 128);
        out.extend_from_slice(SIGNATURE_DOMAIN);
        out.extend_from_slice(vault_id);
        self.encode_unsigned(&mut out);
        out
    }

    fn encode_unsigned(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(status_byte(self.status));
        out.extend_from_slice(&self.signed_at.to_be_bytes());
        put_bytes(out, &self.body);
        out.extend_from_slice(&(self.sealed.len() as u16).to_be_bytes());
        for (machine, envelope) in &self.sealed {
            out.extend_from_slice(machine.as_bytes());
            put_bytes(out, envelope);
        }
        out.extend_from_slice(&self.signer);
    }

    /// The carrier bytes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_unsigned(&mut out);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decodes carrier bytes strictly: every length exact, nothing after the
    /// signature. Decoding proves nothing; [`Self::verify`] does.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TRANSITION_BYTES {
            return Err(malformed());
        }
        let mut read = Reader(bytes);
        if read.take(MAGIC.len())? != MAGIC {
            return Err(malformed());
        }
        let id = EntityId::from_bytes(read.array::<16>()?)?;
        let generation = u32::from_be_bytes(read.array()?);
        let status = status_from_byte(read.array::<1>()?[0])?;
        let signed_at = u64::from_be_bytes(read.array()?);
        let body = read.bytes()?.to_vec();
        let count = usize::from(u16::from_be_bytes(read.array()?));
        if count > MAX_RECIPIENTS {
            return Err(malformed());
        }
        let mut sealed = Vec::with_capacity(count);
        for _ in 0..count {
            let machine = EntityId::from_bytes(read.array::<16>()?)?;
            sealed.push((machine, read.bytes()?.to_vec()));
        }
        let signer = read.array()?;
        let signature = read.array()?;
        if !read.0.is_empty() {
            return Err(malformed());
        }
        Ok(Self {
            id,
            generation,
            status,
            signed_at,
            body,
            sealed,
            signer,
            signature,
        })
    }

    /// Whether this transition stands under `fold` as it is now: whole
    /// ([`Self::verify_signed`]) and signed by a machine mine under the pin,
    /// or by the pinned root's owner anchor.
    pub(crate) fn verify(&self, fold: &AuthorityFold) -> Result<()> {
        self.verify_signed(&fold.vault_id.ok_or_else(unsigned)?)?;
        if !owner_signer(fold, &self.signer) {
            return Err(unsigned());
        }
        Ok(())
    }

    /// Whether this transition is whole: signed for `vault_id` by the key it
    /// names, over a portable record that agrees with it, its value sealed to
    /// distinct machines exactly when it is not revoked. Who signed is
    /// [`Self::verify`]'s question, asked where the record is written: a
    /// window keeps relaying a transition whose signer the roster later
    /// drops.
    pub(crate) fn verify_signed(&self, vault_id: &[u8; 32]) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.signer).map_err(|_| unsigned())?;
        key.verify_strict(
            &self.transcript(vault_id),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| unsigned())?;
        let record = decode_secret_custody_body(&self.body)?;
        if !custody_portable(&record)
            || !record.value_bytes.is_empty()
            || record.status != self.status
            || record.rotation_generation != self.generation
        {
            return Err(malformed());
        }
        let revoked = self.status == SecretCustodyStatus::Revoked;
        if revoked != self.sealed.is_empty() {
            return Err(malformed());
        }
        let mut machines: Vec<_> = self.sealed.iter().map(|(machine, _)| *machine).collect();
        machines.sort_unstable();
        machines.dedup();
        if machines.len() != self.sealed.len() {
            return Err(malformed());
        }
        Ok(())
    }

    /// The record this transition carries, value still out.
    pub(crate) fn record(&self) -> Result<SecretCustodyRecord> {
        decode_secret_custody_body(&self.body)
    }

    /// The value sealed to `machine`, opened with its secret. `None` when the
    /// transition holds no envelope for it or the envelope does not open.
    pub(crate) fn open_value(
        &self,
        vault_id: &[u8; 32],
        machine: EntityId,
        secret: &HybridSecretKey,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let (_, envelope) = self.sealed.iter().find(|(to, _)| *to == machine)?;
        let envelope = Envelope::parse(envelope).ok()?;
        let key_id = value_key_id(self.id, self.generation);
        let recipient = WrapRecipient::Machine(machine).envelope_recipient();
        let policy = OpenPolicy {
            purpose: Purpose::SecretFile,
            vault_id,
            recipient: &recipient,
            key_id: &key_id,
            wraps: &[WrapType::HybridCapsule],
            aead_suites: &[AEAD],
            kem_suites: &[KEM],
            min_epoch: VALUE_EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let payload = envelope.open(OpenKey::Hybrid(secret), &policy).ok()?;
        let value = payload.strip_prefix(VALUE_LABEL)?;
        Some(Zeroizing::new(value.to_vec()))
    }
}

impl Vault {
    /// Signs the current transition of the portable record `secret_ref` names
    /// with the owner anchor of `seed`, the recovery root this vault pins: the
    /// owner's door for an install that cannot sign as one of the owner's
    /// machines (ARCH-0069: a transition comes from the owner anchor or from a
    /// live machine mine under the pin). The record keeps its generation,
    /// status and value; the value is sealed to every machine mine now.
    /// Returns whether it wrote one: none for a record that stays here (device
    /// bound, cross-vault or "this device only") or a value no machine mine
    /// here could open.
    ///
    /// # Errors
    /// A remote origin; a proof that is no longer the live vault owner's; a
    /// seed whose root is not the root this vault pins; a name no record
    /// holds; storage errors.
    pub fn sign_custody_with_anchor(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        origin: crate::authority::EditOrigin,
        seed: &crate::world_keys::RecoveryRootSeed,
        secret_ref: &str,
        at: u64,
    ) -> Result<bool> {
        if !matches!(origin, crate::authority::EditOrigin::ThisMachine) {
            return Err(Error::InvalidConfig(
                "a remote request never signs with the owner anchor".into(),
            ));
        }
        let vault_id = {
            let rtxn = self.store.env.read_txn()?;
            self.authority_view_readonly_in_txn(&rtxn)?
                .vault_id
                .ok_or_else(unsigned)?
        };
        // The anchor is derived before the write transaction opens.
        let root = seed.public(&vault_id)?;
        let anchor = seed.anchor();
        let transition = self.with_write_txn(|wtxn| {
            owner.revalidate_as_vault_owner_in_txn(self, wtxn)?;
            let fold = self.authority_view_readonly_in_txn(wtxn)?;
            if fold.vault_id != Some(vault_id)
                || fold
                    .pinned_root
                    .as_ref()
                    .is_none_or(|pin| pin.id != root.id || pin.anchor_key != root.anchor_key)
            {
                return Err(Error::InvalidConfig(
                    "the seed's root is not the root this vault pins".into(),
                ));
            }
            let id = super::resolve_secret_ref_in_txn(&self.store, wtxn, secret_ref)?.ok_or_else(
                || {
                    Error::Secret(crate::error::SecretError::SecretRefNotFound {
                        name: secret_ref.to_owned(),
                    })
                },
            )?;
            let Some(record) = super::read_secret_custody_in_txn(&self.store, wtxn, &id)? else {
                return Ok(None);
            };
            // A transition of the same generation and status is replaced, so
            // this one is signed after it.
            let order = (record.rotation_generation, status_rank(record.status));
            let signed_at = TRANSITIONS
                .get(&self.store, wtxn, &HexId(id))?
                .and_then(|held| CustodyTransition::decode(&held).ok())
                .filter(|held| held.order() == order)
                .map_or(at, |held| at.max(held.signed_at.saturating_add(1)));
            let Some(transition) = sign_custody_transition(&fold, &anchor, id, &record, signed_at)?
            else {
                return Ok(None);
            };
            Ok(remember_custody_transition_in_txn(self, wtxn, &transition)?.then_some(transition))
        })?;
        #[cfg(feature = "sync")]
        if transition.is_some() {
            self.refresh_custody_in_live_windows();
        }
        Ok(transition.is_some())
    }
}

/// What a transition did to this vault's custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyApplied {
    /// The record was written at the transition's generation and status.
    Written,
    /// This vault holds the record at that generation and status, or later.
    Stale,
    /// The record stays as this vault holds it: it is local here (device
    /// bound, cross-vault or "this device only"), revoked, its name belongs to
    /// another live record, or its bindings are wider than this vault's floor.
    Kept,
    /// This machine holds no value the transition sealed to it.
    Unopened,
}

/// Writes a verified `transition` into this vault's custody, with `value` the
/// one this machine opened from it. A generation never goes back, a revoked
/// record never comes back, and a record this vault keeps local never takes a
/// peer's transition. A revocation also revokes the record's leases here.
pub(crate) fn apply_custody_transition_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    transition: &CustodyTransition,
    value: Option<&[u8]>,
    at: u64,
) -> Result<CustodyApplied> {
    let mut record = transition.record()?;
    let held = super::read_secret_custody_in_txn(&vault.store, wtxn, &transition.id)?.map(|held| {
        (
            custody_portable(&held),
            held.status,
            held.rotation_generation,
        )
    });
    if let Some((portable, status, generation)) = held {
        if !portable || status == SecretCustodyStatus::Revoked {
            return Ok(CustodyApplied::Kept);
        }
        if (transition.generation, status_rank(transition.status))
            <= (generation, status_rank(status))
        {
            return Ok(CustodyApplied::Stale);
        }
    }
    if transition.status == SecretCustodyStatus::Revoked {
        if held.is_none() {
            return Ok(CustodyApplied::Stale);
        }
        crate::secret_rotation::revoke_custody_in_txn(vault, wtxn, &transition.id, at)?;
        return Ok(CustodyApplied::Written);
    }
    let Some(value) = value else {
        return Ok(CustodyApplied::Unopened);
    };
    record.value_bytes = value.to_vec();
    if super::refuse_bindings_wider_than_live_floor(&vault.store, wtxn, &record).is_err()
        || !bind_synced_name_in_txn(
            &vault.store,
            wtxn,
            &record.name,
            &transition.id,
            transition.generation,
        )?
    {
        return Ok(CustodyApplied::Kept);
    }
    super::put_secret_custody_in_txn(vault, wtxn, &transition.id, &record, at)?;
    Ok(CustodyApplied::Written)
}

fn seal_value(
    vault_id: &[u8; 32],
    id: EntityId,
    generation: u32,
    machine: EntityId,
    public: &HybridPublicKey,
    value: &[u8],
) -> Result<Vec<u8>> {
    let key_id = value_key_id(id, generation);
    let recipient = WrapRecipient::Machine(machine).envelope_recipient();
    let mut payload = Zeroizing::new(Vec::with_capacity(VALUE_LABEL.len() + value.len()));
    payload.extend_from_slice(VALUE_LABEL);
    payload.extend_from_slice(value);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::SecretFile,
        epoch: VALUE_EPOCH,
        key_id: &key_id,
        recipient: &recipient,
        vault_id,
    };
    seal(
        &params,
        SealKey::Hybrid {
            recipient: public,
            kem_suite: KEM,
        },
        &payload,
        &mut SysRng,
    )
    .map(|envelope| envelope.to_bytes())
    .map_err(|_| invalid_body("sealing a custody value failed"))
}

/// The envelope key id of one record's value at one generation.
fn value_key_id(id: EntityId, generation: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_ID_LABEL.len() + 20);
    out.extend_from_slice(KEY_ID_LABEL);
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    out
}

/// Active, then suspended, then revoked: a status only moves forward within a
/// generation.
fn status_rank(status: SecretCustodyStatus) -> u8 {
    status_byte(status)
}

fn status_byte(status: SecretCustodyStatus) -> u8 {
    match status {
        SecretCustodyStatus::Active => 0,
        SecretCustodyStatus::Suspended => 1,
        SecretCustodyStatus::Revoked => 2,
    }
}

fn status_from_byte(byte: u8) -> Result<SecretCustodyStatus> {
    Ok(match byte {
        0 => SecretCustodyStatus::Active,
        1 => SecretCustodyStatus::Suspended,
        2 => SecretCustodyStatus::Revoked,
        _ => return Err(malformed()),
    })
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n).ok_or_else(malformed)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("length taken"))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = u32::from_be_bytes(self.array()?);
        self.take(usize::try_from(len).map_err(|_| malformed())?)
    }
}

fn malformed() -> Error {
    invalid_body("malformed custody transition")
}

fn unsigned() -> Error {
    invalid_body("custody transition is not signed by the owner here")
}
