//! Core half of `store::key_custody::log`: its store-layer items live in `oneiron_store::key_custody::log` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::log::*;

use super::erase_evidence::CredentialFenceFact;
use super::files::{LocalCustody, open_dir, read_whole, replace_file, write_once};
use super::holders::{HolderDebt, decode_debt, encode_debt};
use super::identity::{CustodyId, CustodyKind, CustodyNamespace, CustodySubject, CustodyVaultId};
use super::recipients::RecipientRetirement;
use super::retirement::RetireCause;
use crate::error::{Error, Result};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal,
};
use std::path::PathBuf;
use zeroize::Zeroizing;

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
    /// Every head sealed from here on follows the publication policy whose
    /// digest this is: which worlds' pads each member's head leaves out
    /// (KS-5, FIX 7191). It names no key and retires none; it moves the log
    /// on, so every member's head is sealed and acknowledged again.
    PublicationPolicy([u8; 32]),
    /// The body history rows one writer is about to commit (FIX 6229): its
    /// obligations' ids, never a key. It moves the log on, so every
    /// member's head is sealed and acknowledged again.
    BodyHistory(Vec<(Vec<u8>, Vec<u8>)>),
    /// An erased credential's fact (FIX 10584 item 3): its id and where its
    /// erase stands, never a key or a value. It moves the log on, so every
    /// member's head is sealed again carrying it.
    EraseEvidence(CredentialFenceFact),
    /// A holder debt recorded, or cleared when not `standing` (FIX 11206):
    /// never a key. It moves the log on, so every member's head is sealed
    /// again carrying the debts that stand.
    HolderDebt { debt: HolderDebt, standing: bool },
}

impl LogEntry {
    fn encode(&self) -> Vec<u8> {
        let (op, subject, generation, cause) = match self {
            Self::RetireRecipient(fact) => {
                let mut out = vec![OP_RETIRE_RECIPIENT];
                out.extend_from_slice(&fact.encode());
                return out;
            }
            Self::PublicationPolicy(digest) => {
                let mut out = vec![OP_PUBLICATION_POLICY];
                out.extend_from_slice(digest);
                return out;
            }
            Self::EraseEvidence(fact) => {
                let mut out = vec![OP_ERASE_EVIDENCE];
                out.extend_from_slice(&fact.encode());
                return out;
            }
            Self::HolderDebt { debt, standing } => {
                let mut out = vec![OP_HOLDER_DEBT];
                out.extend_from_slice(&encode_debt(debt, *standing));
                return out;
            }
            Self::BodyHistory(rows) => {
                let mut out = vec![OP_BODY_HISTORY];
                out.extend_from_slice(&super::body_history::encode_rows(
                    rows.iter()
                        .map(|(key, value)| (key.as_slice(), value.as_slice())),
                ));
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
        if let Some((&OP_PUBLICATION_POLICY, digest)) = bytes.split_first() {
            return <[u8; 32]>::try_from(digest)
                .map(Self::PublicationPolicy)
                .map_err(|_| log_corrupt());
        }
        if let Some((&OP_ERASE_EVIDENCE, fact)) = bytes.split_first() {
            return CredentialFenceFact::decode(fact)
                .map(Self::EraseEvidence)
                .ok_or_else(log_corrupt);
        }
        if let Some((&OP_HOLDER_DEBT, debt)) = bytes.split_first() {
            return decode_debt(debt)
                .map(|(debt, standing)| Self::HolderDebt { debt, standing })
                .ok_or_else(log_corrupt);
        }
        if let Some((&OP_BODY_HISTORY, rows)) = bytes.split_first() {
            return super::body_history::decode_rows(rows)
                .map(Self::BodyHistory)
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

/// Seals one frame at `header` recording `entry`.
fn seal_frame(control: &Control, header: FrameHeader, entry: &LogEntry) -> Result<Vec<u8>> {
    let clear = header.to_bytes();
    let body = seal_sym(
        Purpose::CustodyLogFrame,
        header.vault,
        LOG_KEY_ID,
        &frame_recipient(&clear),
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
        &frame_recipient(&header.to_bytes()),
        &control.log_kek(),
        body,
    )?;
    Ok((header, LogEntry::decode(header.vault, &plain)?))
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

    /// The vault the journal's lineage is of.
    pub(super) fn vault(&self) -> CustodyVaultId {
        self.vault
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

    /// Whether the policy in force at `after` is still the one in force at
    /// `through` (FIX 11783): every `PublicationPolicy` frame between them
    /// records `digest`. Another lineage or writer epoch, a position past
    /// `through`, or a frame not here proves nothing.
    ///
    /// # Errors
    ///
    /// A frame that does not open.
    pub(super) fn policy_unchanged(
        &self,
        digest: &[u8; 32],
        after: &CustodyPosition,
        through: &CustodyPosition,
    ) -> Result<bool> {
        if !after.same_lineage(through) || after.epoch != through.epoch || after.seq > through.seq {
            return Ok(false);
        }
        if after.seq == through.seq {
            return Ok(after.tip == through.tip);
        }
        let Some(control) = self.control()? else {
            return Ok(false);
        };
        for seq in after.seq + 1..=through.seq {
            let Some(frame) = self.frame(seq)? else {
                return Ok(false);
            };
            if let (_, LogEntry::PublicationPolicy(recorded)) = open_frame(&control, &frame)?
                && recorded != *digest
            {
                return Ok(false);
            }
        }
        Ok(true)
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
