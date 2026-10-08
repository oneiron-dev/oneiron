//! Signature records: the canonical encoding, the strict parser and the roster rules.
//! Signing and verification live in `sign`.

mod sign;

pub use self::sign::{SigningKey, VerifyPolicy, VerifyingKey, sign};

use crate::MAX_ID_LEN;
use crate::codec::{Reader, check_len, put_lp8};
use crate::error::{Error, Result};
use crate::suite::{Suite, SuiteId, SuiteKind};

const MAGIC: &[u8; 4] = b"ONSG";
/// The canonical encoding version this build writes and reads.
const VERSION: u16 = 1;
const MAX_SIGNATURES: usize = 4;
const MAX_PROOF_LEN: usize = 64;
const BODY_SIGNATURES: u8 = 1;
const BODY_CHECKPOINT: u8 = 2;

/// What a signature record attests. Wire form: big-endian `u16`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SigPurpose {
    RootDelegation = 1,
    ReleaseManifest = 2,
    BatchCheckpoint = 3,
    Receipt = 4,
    RecoveryPolicy = 5,
    KeyHistory = 6,
}

impl SigPurpose {
    fn from_wire(value: u16) -> Result<Self> {
        Ok(match value {
            1 => Self::RootDelegation,
            2 => Self::ReleaseManifest,
            3 => Self::BatchCheckpoint,
            4 => Self::Receipt,
            5 => Self::RecoveryPolicy,
            6 => Self::KeyHistory,
            other => return Err(Error::UnknownSigPurpose(other)),
        })
    }
}

/// One component signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureEntry {
    pub suite: SuiteId,
    pub key_id: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A reference to a batch checkpoint that covers the subject (PQC-2 C hot receipts).
/// v1 parses and bounds it; it never counts as verified (see
/// [`Error::CheckpointRefUnverified`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointRef {
    pub checkpoint_epoch: u64,
    pub tree_size: u64,
    pub leaf_index: u64,
    pub root: [u8; 32],
    pub proof: Vec<[u8; 32]>,
}

/// A signature list or a checkpoint reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordBody {
    Signatures(Vec<SignatureEntry>),
    Checkpoint(CheckpointRef),
}

/// A signature record. Only [`SignatureRecord::parse`], [`fn@sign`] and
/// [`SignatureRecord::checkpoint_ref`] build one, so it has passed every
/// structural check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureRecord {
    suite: SuiteId,
    purpose: SigPurpose,
    epoch: u64,
    signer: Vec<u8>,
    body: RecordBody,
}

impl SignatureRecord {
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    pub fn purpose(&self) -> SigPurpose {
        self.purpose
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn signer(&self) -> &[u8] {
        &self.signer
    }

    pub fn body(&self) -> &RecordBody {
        &self.body
    }

    /// A record whose body is a checkpoint reference.
    pub fn checkpoint_ref(
        suite: SuiteId,
        purpose: SigPurpose,
        epoch: u64,
        signer: &[u8],
        checkpoint: CheckpointRef,
    ) -> Result<Self> {
        let record = Self {
            suite,
            purpose,
            epoch,
            signer: signer.to_vec(),
            body: RecordBody::Checkpoint(checkpoint),
        };
        record.validate()?;
        Ok(record)
    }

    /// Structural checks: suite table and epoch, id bounds, the roster, lengths.
    fn validate(&self) -> Result<()> {
        let suite = Suite::require(
            self.suite,
            &[SuiteKind::Signature, SuiteKind::DualSignature],
            self.epoch,
        )?;
        check_len("signer", self.signer.len(), 1, MAX_ID_LEN)?;
        match &self.body {
            RecordBody::Signatures(entries) => {
                check_len("signatures", entries.len(), 1, MAX_SIGNATURES)?;
                for entry in entries {
                    let component =
                        Suite::require(entry.suite, &[SuiteKind::Signature], self.epoch)?;
                    check_len("signature key_id", entry.key_id.len(), 1, MAX_ID_LEN)?;
                    check_len(
                        "signature",
                        entry.signature.len(),
                        component.signature_len,
                        component.signature_len,
                    )?;
                }
                check_roster(suite, entries)
            }
            RecordBody::Checkpoint(cref) => {
                check_len("inclusion proof", cref.proof.len(), 0, MAX_PROOF_LEN)?;
                if cref.leaf_index >= cref.tree_size {
                    return Err(Error::CheckpointIndexOutOfRange {
                        leaf_index: cref.leaf_index,
                        tree_size: cref.tree_size,
                    });
                }
                Ok(())
            }
        }
    }

    /// The signed-over part: header, body tag, and for a signature list the count and
    /// each entry's suite, key id and signature length. Only signature bytes are left
    /// out; a checkpoint body is encoded whole.
    fn transcript(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.suite.0.to_be_bytes());
        out.extend_from_slice(&(self.purpose as u16).to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        put_lp8(&mut out, &self.signer);
        match &self.body {
            RecordBody::Signatures(entries) => {
                out.push(BODY_SIGNATURES);
                out.push(u8::try_from(entries.len()).unwrap_or(u8::MAX));
                for entry in entries {
                    put_entry_descriptor(&mut out, entry);
                }
            }
            RecordBody::Checkpoint(cref) => {
                out.push(BODY_CHECKPOINT);
                out.extend_from_slice(&cref.checkpoint_epoch.to_be_bytes());
                out.extend_from_slice(&cref.tree_size.to_be_bytes());
                out.extend_from_slice(&cref.leaf_index.to_be_bytes());
                out.extend_from_slice(&cref.root);
                out.push(u8::try_from(cref.proof.len()).unwrap_or(u8::MAX));
                for node in &cref.proof {
                    out.extend_from_slice(node);
                }
            }
        }
        out
    }

    /// The canonical bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let RecordBody::Signatures(entries) = &self.body else {
            return self.transcript();
        };
        let mut out = Vec::with_capacity(
            128 + entries
                .iter()
                .map(|e| e.signature.len() + 72)
                .sum::<usize>(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.suite.0.to_be_bytes());
        out.extend_from_slice(&(self.purpose as u16).to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        put_lp8(&mut out, &self.signer);
        out.push(BODY_SIGNATURES);
        out.push(u8::try_from(entries.len()).unwrap_or(u8::MAX));
        for entry in entries {
            put_entry_descriptor(&mut out, entry);
            out.extend_from_slice(&entry.signature);
        }
        out
    }

    /// Strict parse: magic, version, suite table and epoch, every bound, the roster of
    /// the record's suite, exact signature lengths, exact consumption. Verifies nothing.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take(MAGIC.len(), "magic")? != MAGIC {
            return Err(Error::BadMagic {
                expected: "signature record",
            });
        }
        let version = r.u16("version")?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let suite = SuiteId(r.u16("suite")?);
        Suite::require(
            suite,
            &[SuiteKind::Signature, SuiteKind::DualSignature],
            u64::MAX,
        )?;
        let purpose = SigPurpose::from_wire(r.u16("purpose")?)?;
        let epoch = r.u64("epoch")?;
        let signer = r.lp8("signer", 1, MAX_ID_LEN)?.to_vec();
        let body = match r.u8("body")? {
            BODY_SIGNATURES => {
                let count = usize::from(r.u8("signature count")?);
                check_len("signatures", count, 1, MAX_SIGNATURES)?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let entry_suite = SuiteId(r.u16("signature suite")?);
                    let component = Suite::require(entry_suite, &[SuiteKind::Signature], epoch)?;
                    let key_id = r.lp8("signature key_id", 1, MAX_ID_LEN)?.to_vec();
                    let len = r.u32("signature length")? as usize;
                    check_len(
                        "signature",
                        len,
                        component.signature_len,
                        component.signature_len,
                    )?;
                    let signature = r.take(len, "signature")?.to_vec();
                    entries.push(SignatureEntry {
                        suite: entry_suite,
                        key_id,
                        signature,
                    });
                }
                RecordBody::Signatures(entries)
            }
            BODY_CHECKPOINT => {
                let checkpoint_epoch = r.u64("checkpoint epoch")?;
                let tree_size = r.u64("tree size")?;
                let leaf_index = r.u64("leaf index")?;
                let root = r.array::<32>("checkpoint root")?;
                let proof_len = usize::from(r.u8("inclusion proof length")?);
                check_len("inclusion proof", proof_len, 0, MAX_PROOF_LEN)?;
                let mut proof = Vec::with_capacity(proof_len);
                for _ in 0..proof_len {
                    proof.push(r.array::<32>("inclusion proof node")?);
                }
                RecordBody::Checkpoint(CheckpointRef {
                    checkpoint_epoch,
                    tree_size,
                    leaf_index,
                    root,
                    proof,
                })
            }
            other => return Err(Error::UnknownBody(other)),
        };
        r.finish()?;
        let record = Self {
            suite,
            purpose,
            epoch,
            signer,
            body,
        };
        record.validate()?;
        Ok(record)
    }
}

fn put_entry_descriptor(out: &mut Vec<u8>, entry: &SignatureEntry) {
    out.extend_from_slice(&entry.suite.0.to_be_bytes());
    put_lp8(out, &entry.key_id);
    out.extend_from_slice(
        &u32::try_from(entry.signature.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
}

/// The suites a record of `suite` must carry, in canonical (ascending) order.
pub(crate) fn roster(suite: &Suite) -> Vec<SuiteId> {
    if suite.kind == SuiteKind::DualSignature {
        suite.components.to_vec()
    } else {
        vec![suite.id]
    }
}

/// Entries must be exactly the roster, each once, in ascending suite order.
fn check_roster(suite: &Suite, entries: &[SignatureEntry]) -> Result<()> {
    let required = roster(suite);
    for pair in entries.windows(2) {
        if pair[0].suite == pair[1].suite {
            return Err(Error::SignatureDuplicate(crate::suite::name_of(
                pair[0].suite,
            )));
        }
        if pair[0].suite > pair[1].suite {
            return Err(Error::UnsortedSignatures);
        }
    }
    if let Some(extra) = entries.iter().find(|e| !required.contains(&e.suite)) {
        return Err(Error::SignatureUnexpected(crate::suite::name_of(
            extra.suite,
        )));
    }
    if let Some(missing) = required
        .iter()
        .find(|s| !entries.iter().any(|e| e.suite == **s))
    {
        return Err(Error::SignatureMissing(crate::suite::name_of(*missing)));
    }
    Ok(())
}
