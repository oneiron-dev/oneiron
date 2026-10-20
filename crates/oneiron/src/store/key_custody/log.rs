//! The keyless custody log (KS-4, FIX 5685) and the local journal it is kept
//! in, beside the vault and outside its image like every custody entry.
//!
//! Every mint and every retirement of a bound custody is journaled as one
//! frame, synced before the act it records is acknowledged: a mint before a
//! row sealed under its key may commit, a retirement before its intent
//! clears. A frame binds the vault, the namespace, the writer epoch, its
//! sequence number and the hash of the frame before it; its body names the
//! id it mints or the subject it retires through a generation, with the
//! cause, or the released escrow recipient a cold managed restore retired
//! (its label and the BLAKE3 of its public key), sealed under the lineage's
//! log key. No frame, error or receipt holds a key, a key's fingerprint, a
//! value or a wrap; the frame hashes are public structure, never a
//! fingerprint of a secret.
//!
//! `<compartment>/.journal/` holds `control` (the lineage's control secret,
//! its writer epoch and the position its local log starts after), `tip` (a
//! cache of the newest frame's position) and one `f<seq hex16>` per frame.

use std::path::PathBuf;

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal,
};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

use super::files::{LocalCustody, open_dir, read_whole, replace_file, write_once};
use super::identity::{CustodyId, CustodyKind, CustodyNamespace, CustodySubject, CustodyVaultId};
use super::recipients::RecipientRetirement;
use super::retirement::RetireCause;

const JOURNAL: &str = ".journal";
const CONTROL: &str = "control";
const TIP: &str = "tip";
const CONTROL_VERSION: u8 = 1;
const CONTROL_LEN: usize = 1 + 32 + 8 + 8 + 32;
const FRAME_MAGIC: &[u8; 4] = b"OCLF";
const FRAME_VERSION: u8 = 1;
/// `magic | version | vault | namespace | epoch | seq | previous hash`.
const FRAME_HEADER_LEN: usize = 4 + 1 + 32 + 16 + 8 + 8 + 32;
pub(super) const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
/// The crypto epoch every custody envelope is sealed at.
pub(super) const CRYPTO_EPOCH: u64 = 1;
const LOG_KEY_CONTEXT: &str = "oneiron/custody-log/v1";
const ANCHOR_KEY_CONTEXT: &str = "oneiron/custody-anchor/v1";
const LOG_KEY_ID: &[u8] = b"oneiron/custody-log-frame/v1";
const OP_MINT: u8 = 1;
const OP_RETIRE: u8 = 2;
/// A released escrow recipient retired (LC FIX 5384/5385): an op of its
/// own, never a custody kind's tag.
const OP_RETIRE_RECIPIENT: u8 = 3;

pub(super) fn log_corrupt() -> Error {
    Error::CorruptedIndex("key custody log")
}

/// A lineage's writer epoch. A disaster recovery takes the lineage over at
/// the next one and advances the anchor to it, which fences every writer
/// still at an older one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CustodyEpoch(pub(super) u64);

impl CustodyEpoch {
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Where one lineage's log stands: its vault and namespace, the writer
/// epoch, the newest frame's sequence number and that frame's hash. An empty
/// log is sequence 0 under an all-zero tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyPosition {
    pub vault: CustodyVaultId,
    pub namespace: CustodyNamespace,
    pub epoch: CustodyEpoch,
    pub seq: u64,
    pub tip: [u8; 32],
}

/// `vault (32) | namespace (16) | epoch u64be | seq u64be | tip (32)`.
pub(super) const POSITION_LEN: usize = 32 + 16 + 8 + 8 + 32;

impl CustodyPosition {
    /// The 96-byte wire form an anchor record and a manifest carry.
    pub fn to_bytes(self) -> [u8; POSITION_LEN] {
        let mut out = [0u8; POSITION_LEN];
        out[..32].copy_from_slice(self.vault.as_bytes());
        out[32..48].copy_from_slice(self.namespace.as_bytes());
        out[48..56].copy_from_slice(&self.epoch.0.to_be_bytes());
        out[56..64].copy_from_slice(&self.seq.to_be_bytes());
        out[64..].copy_from_slice(&self.tip);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != POSITION_LEN {
            return None;
        }
        Some(Self {
            vault: CustodyVaultId::from_bytes(bytes[..32].try_into().ok()?),
            namespace: CustodyNamespace::from_bytes(bytes[32..48].try_into().ok()?),
            epoch: CustodyEpoch(u64::from_be_bytes(bytes[48..56].try_into().ok()?)),
            seq: u64::from_be_bytes(bytes[56..64].try_into().ok()?),
            tip: bytes[64..].try_into().ok()?,
        })
    }

    /// The same lineage, vault and namespace both.
    pub(super) fn same_lineage(&self, other: &Self) -> bool {
        self.vault == other.vault && self.namespace == other.namespace
    }
}

/// One lineage's control state: the secret its log key and anchor key come
/// from, its writer epoch here, and the position its local log starts after
/// (none for a lineage begun here; the admitted head's for one a disaster
/// recovery took over). Its secret is carried in every head's control
/// compartment, never in a frame.
pub(super) struct Control {
    secret: Zeroizing<[u8; 32]>,
    pub(super) epoch: CustodyEpoch,
    base_seq: u64,
    base_tip: [u8; 32],
}

impl Control {
    fn fresh() -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; 32]);
        crate::world_keys::os_fill(&mut secret[..])?;
        Ok(Self {
            secret,
            epoch: CustodyEpoch(0),
            base_seq: 0,
            base_tip: [0; 32],
        })
    }

    /// The control state of a lineage a disaster recovery takes over at
    /// `from`, the admitted position, in the next writer epoch.
    pub(super) fn taken_over(secret: Zeroizing<[u8; 32]>, from: &CustodyPosition) -> Result<Self> {
        Ok(Self {
            secret,
            epoch: CustodyEpoch(
                from.epoch
                    .0
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow("key custody writer epoch"))?,
            ),
            base_seq: from.seq,
            base_tip: from.tip,
        })
    }

    /// The control state a restore opens a lineage's frames and anchor
    /// records with: the secret its head carries. Its epoch and base are
    /// not the restore's to know.
    pub(super) fn for_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        Self {
            secret,
            epoch: CustodyEpoch(0),
            base_seq: 0,
            base_tip: [0; 32],
        }
    }

    pub(super) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// The position the local log starts after: none (0) for a lineage
    /// begun here, the admitted head's for one taken over.
    pub(super) fn base_seq(&self) -> u64 {
        self.base_seq
    }

    fn derive(&self, context: &str) -> Zeroizing<[u8; 32]> {
        crate::world_keys::derive_guarded(context, &[&self.secret[..]])
    }

    fn log_kek(&self) -> Kek {
        Kek::from_zeroizing(self.derive(LOG_KEY_CONTEXT))
    }

    /// The key the lineage's anchor records are authenticated under.
    pub(super) fn anchor_key(&self) -> Zeroizing<[u8; 32]> {
        self.derive(ANCHOR_KEY_CONTEXT)
    }

    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(CONTROL_LEN));
        out.push(CONTROL_VERSION);
        out.extend_from_slice(&self.secret[..]);
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&self.base_seq.to_be_bytes());
        out.extend_from_slice(&self.base_tip);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CONTROL_LEN || bytes[0] != CONTROL_VERSION {
            return Err(log_corrupt());
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&bytes[1..33]);
        let word = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
        Ok(Self {
            secret,
            epoch: CustodyEpoch(word(33)),
            base_seq: word(41),
            base_tip: bytes[49..81].try_into().map_err(|_| log_corrupt())?,
        })
    }
}

/// What one frame records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LogEntry {
    /// A new entry was published for this id.
    Mint(CustodyId),
    /// Every generation of the subject through `through` was destroyed here.
    Retire {
        subject: CustodySubject,
        through: u64,
        cause: RetireCause,
    },
    /// A released escrow recipient was retired here by a cold managed
    /// restore, at its takeover writer epoch: its label, public-key
    /// fingerprint and receipt id, never a key.
    RetireRecipient(RecipientRetirement),
}

impl LogEntry {
    fn encode(&self) -> Vec<u8> {
        let (op, subject, generation, cause) = match self {
            Self::RetireRecipient(fact) => {
                let mut out = vec![OP_RETIRE_RECIPIENT];
                out.extend_from_slice(&fact.encode());
                return out;
            }
            Self::Mint(id) => (OP_MINT, id.subject(), id.generation(), None),
            Self::Retire {
                subject,
                through,
                cause,
            } => (OP_RETIRE, subject, *through, Some(*cause)),
        };
        let mut out = vec![op, subject.kind().tag()];
        // An item is its kind's fixed width, well under 256 bytes.
        out.push(subject.item().len() as u8);
        out.extend_from_slice(subject.item());
        out.extend_from_slice(&generation.to_be_bytes());
        if let Some(cause) = cause {
            out.push(match cause {
                RetireCause::Retention => 0,
                RetireCause::Erase => 1,
            });
        }
        out
    }

    fn decode(vault: CustodyVaultId, bytes: &[u8]) -> Result<Self> {
        if let Some((&OP_RETIRE_RECIPIENT, fact)) = bytes.split_first() {
            return RecipientRetirement::decode(fact)
                .map(Self::RetireRecipient)
                .ok_or_else(log_corrupt);
        }
        let decoded = (|| {
            let (&op, rest) = bytes.split_first()?;
            let (&tag, rest) = rest.split_first()?;
            let (&len, rest) = rest.split_first()?;
            let item = rest.get(..usize::from(len))?;
            let rest = &rest[usize::from(len)..];
            let generation = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
            let rest = &rest[8..];
            let subject = CustodySubject::new(vault, CustodyKind::from_tag(tag)?, item).ok()?;
            match (op, rest) {
                (OP_MINT, []) => Some(Self::Mint(subject.at(generation))),
                (OP_RETIRE, [cause]) => Some(Self::Retire {
                    subject,
                    through: generation,
                    cause: match *cause {
                        0 => RetireCause::Retention,
                        1 => RetireCause::Erase,
                        _ => return None,
                    },
                }),
                _ => None,
            }
        })();
        decoded.ok_or_else(log_corrupt)
    }
}

/// A frame's clear header: what a shipper checks continuity by, keyless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FrameHeader {
    pub(super) vault: CustodyVaultId,
    pub(super) namespace: CustodyNamespace,
    pub(super) epoch: CustodyEpoch,
    pub(super) seq: u64,
    pub(super) prev: [u8; 32],
}

impl FrameHeader {
    fn to_bytes(self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[..4].copy_from_slice(FRAME_MAGIC);
        out[4] = FRAME_VERSION;
        out[5..37].copy_from_slice(self.vault.as_bytes());
        out[37..53].copy_from_slice(self.namespace.as_bytes());
        out[53..61].copy_from_slice(&self.epoch.0.to_be_bytes());
        out[61..69].copy_from_slice(&self.seq.to_be_bytes());
        out[69..].copy_from_slice(&self.prev);
        out
    }

    /// The header of `frame`, with its body's envelope bytes; refused when
    /// the frame does not parse.
    pub(super) fn parse(frame: &[u8]) -> Result<(Self, &[u8])> {
        let parsed = (|| {
            let head = frame.get(..FRAME_HEADER_LEN)?;
            if &head[..4] != FRAME_MAGIC || head[4] != FRAME_VERSION {
                return None;
            }
            let len = u32::from_be_bytes(
                frame
                    .get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + 4)?
                    .try_into()
                    .ok()?,
            );
            let body = frame.get(FRAME_HEADER_LEN + 4..)?;
            if body.len() != usize::try_from(len).ok()? {
                return None;
            }
            Some((
                Self {
                    vault: CustodyVaultId::from_bytes(head[5..37].try_into().ok()?),
                    namespace: CustodyNamespace::from_bytes(head[37..53].try_into().ok()?),
                    epoch: CustodyEpoch(u64::from_be_bytes(head[53..61].try_into().ok()?)),
                    seq: u64::from_be_bytes(head[61..69].try_into().ok()?),
                    prev: head[69..].try_into().ok()?,
                },
                body,
            ))
        })();
        parsed.ok_or_else(log_corrupt)
    }
}

/// A frame's hash: what the next frame and a position name it by.
pub(super) fn frame_hash(frame: &[u8]) -> [u8; 32] {
    *blake3::hash(frame).as_bytes()
}

/// Seals `plaintext` under `kek` as a custody envelope of `purpose`.
pub(super) fn seal_sym(
    purpose: Purpose,
    vault: CustodyVaultId,
    key_id: &[u8],
    recipient: &[u8],
    kek: &Kek,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let params = SealParams {
        suite: AEAD,
        purpose,
        epoch: CRYPTO_EPOCH,
        key_id,
        recipient,
        vault_id: vault.as_bytes(),
    };
    seal(&params, SealKey::SymmetricKek(kek), plaintext, &mut SysRng)
        .map(|envelope| envelope.to_bytes())
        .map_err(|_| crate::world_keys::refused("sealing key custody failed"))
}

/// Opens a custody envelope [`seal_sym`] sealed, refused unless every bound
/// field matches.
pub(super) fn open_sym(
    purpose: Purpose,
    vault: CustodyVaultId,
    key_id: &[u8],
    recipient: &[u8],
    kek: &Kek,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let policy = OpenPolicy {
        purpose,
        vault_id: vault.as_bytes(),
        recipient,
        key_id,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: CRYPTO_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    Envelope::parse(envelope)
        .map_err(|_| log_corrupt())?
        .open(OpenKey::SymmetricKek(kek), &policy)
        .map_err(|_| crate::world_keys::refused("key custody does not open with this key"))
}

/// Seals one frame at `header` recording `entry`.
fn seal_frame(control: &Control, header: FrameHeader, entry: &LogEntry) -> Result<Vec<u8>> {
    let clear = header.to_bytes();
    let body = seal_sym(
        Purpose::CustodyLogFrame,
        header.vault,
        LOG_KEY_ID,
        &clear,
        &control.log_kek(),
        &entry.encode(),
    )?;
    let mut frame = clear.to_vec();
    frame.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| log_corrupt())?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Opens one frame's body under the lineage's control secret.
pub(super) fn open_frame(control: &Control, frame: &[u8]) -> Result<(FrameHeader, LogEntry)> {
    let (header, body) = FrameHeader::parse(frame)?;
    let plain = open_sym(
        Purpose::CustodyLogFrame,
        header.vault,
        LOG_KEY_ID,
        &header.to_bytes(),
        &control.log_kek(),
        body,
    )?;
    Ok((header, LogEntry::decode(header.vault, &plain)?))
}

pub(super) fn frame_name(seq: u64) -> String {
    format!("f{seq:016x}")
}

/// One binding's journal: its control state and its local log.
pub(super) struct Journal {
    dir: PathBuf,
    vault: CustodyVaultId,
    namespace: CustodyNamespace,
}

impl LocalCustody<'_> {
    /// This binding's journal, in its compartment.
    pub(super) fn journal(&self) -> Result<Journal> {
        Ok(Journal {
            dir: self.compartment()?.join(JOURNAL),
            vault: self.binding().vault(),
            namespace: self.binding().namespace(),
        })
    }

    /// Journals `entry`, synced, before the act it records is acknowledged.
    pub(super) fn journal_entry(&self, entry: &LogEntry) -> Result<CustodyPosition> {
        self.open_compartment()?;
        self.journal()?.append(entry)
    }
}

impl Journal {
    /// The journal's directory in its compartment.
    pub(super) fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// The journal `batch` was sealed from.
    pub(super) fn of_batch(batch: &super::protocol::CustodyBatch) -> Self {
        Self {
            dir: batch.journal.clone(),
            vault: batch.position.vault,
            namespace: batch.position.namespace,
        }
    }

    fn open(&self, create: bool) -> Result<()> {
        open_dir(&self.dir, create, None).map(drop)
    }

    /// The lineage's control state here, when it has one.
    pub(super) fn control(&self) -> Result<Option<Control>> {
        read_whole(&self.dir.join(CONTROL))?
            .map(|bytes| Control::from_bytes(&Zeroizing::new(bytes)))
            .transpose()
    }

    /// The control state, made with a fresh secret at epoch 0 on the
    /// lineage's first journaled act. Two makers agree on whichever was
    /// published first.
    pub(super) fn control_or_create(&self) -> Result<Control> {
        if let Some(control) = self.control()? {
            return Ok(control);
        }
        self.open(true)?;
        let fresh = Control::fresh()?;
        if write_once(&self.dir, CONTROL, &fresh.to_bytes())? {
            return Ok(fresh);
        }
        self.control()?.ok_or_else(log_corrupt)
    }

    /// Installs `control` for a lineage a disaster recovery took over, in a
    /// journal that holds none yet.
    pub(super) fn install(&self, control: &Control) -> Result<()> {
        self.open(true)?;
        if !write_once(&self.dir, CONTROL, &control.to_bytes())? {
            return Err(log_corrupt());
        }
        Ok(())
    }

    /// The frame at `seq` in the local log, if it is here.
    pub(super) fn frame(&self, seq: u64) -> Result<Option<Vec<u8>>> {
        read_whole(&self.dir.join(frame_name(seq)))
    }

    /// Where the local log stands, walking on from the cached tip past any
    /// frame a crash linked before its cache was rewritten, each checked to
    /// extend the one before it. No control state is an empty log at epoch 0.
    pub(super) fn position(&self) -> Result<CustodyPosition> {
        match self.control()? {
            Some(control) => self.position_under(&control),
            None => Ok(CustodyPosition {
                vault: self.vault,
                namespace: self.namespace,
                epoch: CustodyEpoch(0),
                seq: 0,
                tip: [0; 32],
            }),
        }
    }

    fn position_under(&self, control: &Control) -> Result<CustodyPosition> {
        let (mut seq, mut tip) = (control.base_seq, control.base_tip);
        if let Some(cached) = read_whole(&self.dir.join(TIP))?
            && let Some((at, hash)) = parse_tip(&cached)
            && at > seq
            && self
                .frame(at)?
                .is_some_and(|frame| frame_hash(&frame) == hash)
        {
            (seq, tip) = (at, hash);
        }
        loop {
            let next = seq.checked_add(1).ok_or_else(log_corrupt)?;
            let Some(frame) = self.frame(next)? else {
                break;
            };
            let (header, _) = FrameHeader::parse(&frame)?;
            if header.seq != next
                || header.prev != tip
                || header.epoch > control.epoch
                || header.vault != self.vault
                || header.namespace != self.namespace
            {
                return Err(log_corrupt());
            }
            (seq, tip) = (next, frame_hash(&frame));
        }
        Ok(CustodyPosition {
            vault: self.vault,
            namespace: self.namespace,
            epoch: control.epoch,
            seq,
            tip,
        })
    }

    /// Appends one frame recording `entry` at the next sequence number,
    /// synced with its directory before this returns. A concurrent appender
    /// that took the number first is walked past.
    fn append(&self, entry: &LogEntry) -> Result<CustodyPosition> {
        self.open(true)?;
        let control = self.control_or_create()?;
        loop {
            let at = self.position_under(&control)?;
            let seq = at.seq.checked_add(1).ok_or_else(log_corrupt)?;
            let header = FrameHeader {
                vault: self.vault,
                namespace: self.namespace,
                epoch: control.epoch,
                seq,
                prev: at.tip,
            };
            let frame = seal_frame(&control, header, entry)?;
            if write_once(&self.dir, &frame_name(seq), &frame)? {
                let tip = frame_hash(&frame);
                // Only a cache: a reader walks on from an older one.
                let mut cached = seq.to_be_bytes().to_vec();
                cached.extend_from_slice(&tip);
                let _ = replace_file(&self.dir, TIP, &cached);
                return Ok(CustodyPosition { seq, tip, ..at });
            }
        }
    }
}

fn parse_tip(bytes: &[u8]) -> Option<(u64, [u8; 32])> {
    if bytes.len() != 40 {
        return None;
    }
    Some((
        u64::from_be_bytes(bytes[..8].try_into().ok()?),
        bytes[8..].try_into().ok()?,
    ))
}
