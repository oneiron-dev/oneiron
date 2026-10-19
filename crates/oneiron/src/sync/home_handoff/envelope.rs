//! The sealed handoff and its ack. The source signs a header (the move and
//! the digest of its sections) with its install key; the hash of the signed
//! header is the handoff's id. The manifest (that signed header, the
//! predecessor's signed header and the sections) is sealed to the target
//! machine's encryption key under `Purpose::HomeHandoff`, bound to the vault,
//! the id and the target machine. The target opens and verifies all of it
//! before any transaction, and signs an ack of the id, the sealed bytes'
//! digest, the generation and itself.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, OpenKey, OpenPolicy, Purpose, SealKey, SealParams,
    SuiteId, WrapType, seal,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{HandoffId, HomeGeneration, HomeIdentity, HomeMove, refused};
use crate::Vault;
use crate::authority::{AuthorityFold, AuthorityView};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{Named, SideCodec};

const HEADER_DOMAIN: &[u8] = b"oneiron/home-handoff/header/v1\0";
const SECTIONS_DOMAIN: &[u8] = b"oneiron/home-handoff/sections/v1\0";
const ACK_DOMAIN: &[u8] = b"oneiron/home-handoff/ack/v1\0";
/// The envelope epoch a handoff seals and opens at.
const HANDOFF_EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;

/// One registered table's rows in a manifest. A table with no rows still
/// has its section, so a missing section never reads as "nothing to carry".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct TableSection {
    pub(super) table_id: String,
    pub(super) schema_version: u16,
    #[serde(with = "super::bin")]
    pub(super) rows: Vec<u8>,
}

/// What the source signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HandoffHeader {
    pub(super) movement: HomeMove,
    /// The digest of the encoded sections.
    pub(super) sections: [u8; 32],
}

/// A header as its source signed it: the exact bytes and the signature. A
/// later move carries its predecessor's, so a target new to the lineage can
/// check how the source came to hold the state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SignedHeader {
    #[serde(with = "super::bin")]
    header: Vec<u8>,
    #[serde(with = "super::bin")]
    signature: Vec<u8>,
}

impl SignedHeader {
    fn sign(header: &HandoffHeader, key: &SigningKey) -> Result<Self> {
        let bytes = encode(header)?;
        let signature = key.sign(&transcript(HEADER_DOMAIN, &bytes)).to_bytes();
        Ok(Self {
            header: bytes,
            signature: signature.to_vec(),
        })
    }

    /// The handoff's id: the hash of the signed header bytes.
    pub(super) fn id(&self) -> HandoffId {
        *blake3::hash(&transcript(HEADER_DOMAIN, &self.header)).as_bytes()
    }

    /// The header, when its source is one of the owner's machines here and
    /// that machine's key signed exactly these bytes.
    fn verify(&self, fold: &AuthorityFold) -> Result<HandoffHeader> {
        let header: HandoffHeader = decode(&self.header)?;
        machine_key(fold, header.movement.source.machine)?
            .verify_strict(
                &transcript(HEADER_DOMAIN, &self.header),
                &signature(&self.signature)?,
            )
            .map_err(|_| refused("a handoff header's signature does not verify"))?;
        Ok(header)
    }
}

/// The sealed plaintext.
#[derive(Serialize, Deserialize)]
struct Manifest {
    signed: SignedHeader,
    lineage: Option<SignedHeader>,
    /// The encoded sections, kept as the bytes the header's digest covers.
    #[serde(with = "super::bin")]
    sections: Vec<u8>,
}

/// A frozen handoff as its source sealed it: what C2 delivers in parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SealedHandoff {
    pub(super) id: HandoffId,
    pub(super) digest: [u8; 32],
    pub(super) movement: HomeMove,
    pub(super) sealed: Vec<u8>,
}

impl SealedHandoff {
    pub(crate) fn id(&self) -> HandoffId {
        self.id
    }

    /// The hash of the sealed bytes; the ack names it.
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn movement(&self) -> &HomeMove {
        &self.movement
    }

    pub(crate) fn sealed(&self) -> &[u8] {
        &self.sealed
    }
}

/// A handoff that opened here and whose every signature and digest
/// verified. Only [`open_handoff`] makes one.
pub(crate) struct VerifiedHandoff {
    pub(super) id: HandoffId,
    pub(super) digest: [u8; 32],
    pub(super) signed: SignedHeader,
    pub(super) header: HandoffHeader,
    /// The predecessor's id and header, when the handoff carries them.
    pub(super) lineage: Option<(HandoffId, HandoffHeader)>,
    pub(super) sections: Vec<TableSection>,
}

impl VerifiedHandoff {
    pub(crate) fn id(&self) -> HandoffId {
        self.id
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn movement(&self) -> &HomeMove {
        &self.header.movement
    }
}

/// The target's signed ack of one adopted handoff.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HomeAck {
    pub(crate) id: HandoffId,
    pub(crate) digest: [u8; 32],
    pub(crate) generation: HomeGeneration,
    pub(crate) target: HomeIdentity,
    #[serde(with = "super::bin")]
    pub(crate) signature: Vec<u8>,
}

/// An ack the target machine's key here signed. Only [`verify_ack`] makes one.
pub(crate) struct VerifiedHomeAck(HomeAck);

impl VerifiedHomeAck {
    pub(crate) fn ack(&self) -> &HomeAck {
        &self.0
    }
}

/// Signs `movement` over `sections` with the source's install key and seals
/// the manifest to `target`'s key. Returns the sealed handoff and its signed
/// header, which a later move carries as its lineage.
pub(super) fn seal_handoff(
    movement: &HomeMove,
    key: &SigningKey,
    target: &HybridPublicKey,
    lineage: Option<SignedHeader>,
    sections: &[TableSection],
) -> Result<(SealedHandoff, SignedHeader)> {
    let sections = encode(sections)?;
    let header = HandoffHeader {
        movement: *movement,
        sections: *blake3::hash(&transcript(SECTIONS_DOMAIN, &sections)).as_bytes(),
    };
    let signed = SignedHeader::sign(&header, key)?;
    let id = signed.id();
    let plain = encode(&Manifest {
        signed: signed.clone(),
        lineage,
        sections,
    })?;
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::HomeHandoff,
        epoch: HANDOFF_EPOCH,
        key_id: &id,
        recipient: movement.target.machine.as_bytes(),
        vault_id: &movement.vault_id,
    };
    let sealed = seal(
        &params,
        SealKey::Hybrid {
            recipient: target,
            kem_suite: KEM,
        },
        &plain,
        &mut SysRng,
    )
    .map_err(|_| refused("sealing the handoff failed"))?
    .to_bytes();
    let handoff = SealedHandoff {
        id,
        digest: *blake3::hash(&sealed).as_bytes(),
        movement: *movement,
        sealed,
    };
    Ok((handoff, signed))
}

/// Opens `sealed`, the handoff `id` names, with this install's machine
/// secret, and verifies all of it before any transaction: the envelope's
/// binding to this vault, the id and this machine; the header's id and its
/// source's signature; the sections' digest; the predecessor's signed
/// header. A handoff that fails any of it is refused. Whether it adopts here
/// is [`super::adopt`]'s to judge.
pub(crate) fn open_handoff(vault: &Vault, id: HandoffId, sealed: &[u8]) -> Result<VerifiedHandoff> {
    let secret = vault.machine_secret_outside_txn()?;
    let fold = read_fold(vault)?;
    let vault_id = fold
        .vault_id
        .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
    let policy = OpenPolicy {
        purpose: Purpose::HomeHandoff,
        vault_id: &vault_id,
        recipient: secret.machine.as_bytes(),
        key_id: &id,
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: HANDOFF_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let plain = Envelope::parse(sealed)
        .and_then(|envelope| envelope.open(OpenKey::Hybrid(&secret.secret), &policy))
        .map_err(|_| refused("the handoff does not open for this machine"))?;
    let manifest: Manifest = decode(&plain)?;
    if manifest.signed.id() != id {
        return Err(refused("the handoff's header is not the one its id names"));
    }
    let header = manifest.signed.verify(&fold)?;
    if header.movement.vault_id != vault_id || header.movement.target.machine != secret.machine {
        return Err(refused("the handoff names another vault or target"));
    }
    if *blake3::hash(&transcript(SECTIONS_DOMAIN, &manifest.sections)).as_bytes() != header.sections
    {
        return Err(refused("the handoff's sections are not the ones it signed"));
    }
    let lineage = match &manifest.lineage {
        Some(prior) => Some((prior.id(), prior.verify(&fold)?)),
        None => None,
    };
    Ok(VerifiedHandoff {
        id,
        digest: *blake3::hash(sealed).as_bytes(),
        sections: decode(&manifest.sections)?,
        signed: manifest.signed,
        header,
        lineage,
    })
}

/// The target's ack of `handoff`, signed with its install key.
pub(super) fn sign_ack(handoff: &VerifiedHandoff, key: &SigningKey) -> HomeAck {
    let movement = &handoff.header.movement;
    let transcript = ack_transcript(
        &handoff.id,
        &handoff.digest,
        &movement.generation,
        &movement.target,
    );
    HomeAck {
        id: handoff.id,
        digest: handoff.digest,
        generation: movement.generation,
        target: movement.target,
        signature: key.sign(&transcript).to_bytes().to_vec(),
    }
}

/// The source half: `ack`, when its target is one of the owner's machines
/// here and that machine's key signed exactly it.
pub(crate) fn verify_ack(vault: &Vault, ack: HomeAck) -> Result<VerifiedHomeAck> {
    let fold = read_fold(vault)?;
    let transcript = ack_transcript(&ack.id, &ack.digest, &ack.generation, &ack.target);
    machine_key(&fold, ack.target.machine)?
        .verify_strict(&transcript, &signature(&ack.signature)?)
        .map_err(|_| refused("the handoff ack's signature does not verify"))?;
    Ok(VerifiedHomeAck(ack))
}

/// The encryption key of `machine`'s trusted identity here: what a handoff
/// to it is sealed to.
pub(super) fn target_key(fold: &AuthorityFold, machine: EntityId) -> Result<HybridPublicKey> {
    let trusted = fold
        .trusted_machine(machine)
        .ok_or_else(|| refused("the target is not one of the owner's machines here"))?;
    HybridPublicKey::from_bytes(&trusted.profile.encryption_key.key)
        .map_err(|_| refused("the target's encryption key does not import"))
}

fn read_fold(vault: &Vault) -> Result<AuthorityView> {
    let txn = vault.store.env.read_txn()?;
    vault.authority_view_readonly_in_txn(&txn)
}

/// The install key of `machine`'s trusted identity here.
fn machine_key(fold: &AuthorityFold, machine: EntityId) -> Result<VerifyingKey> {
    let trusted = fold
        .trusted_machine(machine)
        .ok_or_else(|| refused("the machine is not one of the owner's machines here"))?;
    VerifyingKey::from_bytes(&trusted.profile.machine_key)
        .map_err(|_| refused("the machine's key does not import"))
}

fn signature(bytes: &[u8]) -> Result<Signature> {
    <[u8; 64]>::try_from(bytes)
        .map(|bytes| Signature::from_bytes(&bytes))
        .map_err(|_| refused("a signature is malformed"))
}

fn ack_transcript(
    id: &HandoffId,
    digest: &[u8; 32],
    generation: &HomeGeneration,
    target: &HomeIdentity,
) -> Vec<u8> {
    let mut bytes = ACK_DOMAIN.to_vec();
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(digest);
    bytes.extend_from_slice(&generation.serial.to_be_bytes());
    match &generation.predecessor {
        Some(predecessor) => {
            bytes.push(1);
            bytes.extend_from_slice(predecessor);
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(target.machine.as_bytes());
    bytes.extend_from_slice(&target.node_id.to_be_bytes());
    bytes
}

fn transcript(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut out = domain.to_vec();
    out.extend_from_slice(bytes);
    out
}

fn encode<V: Serialize + ?Sized>(value: &V) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| refused("a handoff value does not encode"))
}

fn decode<V: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<V> {
    <Named as SideCodec<V>>::decode(bytes).map_err(|_| refused("a handoff value does not decode"))
}
