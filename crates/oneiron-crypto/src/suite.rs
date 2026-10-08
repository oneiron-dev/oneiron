//! The suite table: every algorithm combination the format can name, its state and
//! its minimum epoch. Ids are never reused; a changed construction gets a new id.

use crate::error::{Error, Result};

/// A suite id. Wire form: big-endian `u16`. Any value can be constructed; only the
/// ids in [`suite_table`] with status [`SuiteStatus::Allowed`] are ever accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SuiteId(pub u16);

/// What a suite id may name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiteKind {
    /// Payload AEAD of an envelope.
    Aead,
    /// Key encapsulation of a hybrid capsule.
    Kem,
    /// One signature algorithm.
    Signature,
    /// A policy that requires every one of its component signatures.
    DualSignature,
}

/// Whether a suite is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiteStatus {
    /// Accepted for new writes and reads, from its minimum epoch on.
    Allowed,
    /// Never accepted. Named so a relabel to it is refused by name, not as unknown.
    Forbidden,
    /// Named for a pilot (PQC-4) and not implemented; refused.
    Reserved,
}

/// One row of the suite table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suite {
    pub id: SuiteId,
    pub name: &'static str,
    pub kind: SuiteKind,
    pub status: SuiteStatus,
    /// The lowest epoch at which this suite is accepted. Epoch 0 is never valid.
    pub min_epoch: u64,
    /// For [`SuiteKind::DualSignature`]: every signature suite the record must carry.
    pub components: &'static [SuiteId],
    /// For [`SuiteKind::Signature`]: the exact signature length in bytes.
    pub signature_len: usize,
}

impl SuiteId {
    pub const XCHACHA20POLY1305_V1: SuiteId = SuiteId(0x0001);
    pub const AES256GCM_V1: SuiteId = SuiteId(0x0002);
    pub const AES128GCM_V1: SuiteId = SuiteId(0x0003);
    pub const KEM_X25519_MLKEM1024_V1: SuiteId = SuiteId(0x0101);
    pub const KEM_X25519_MLKEM768_V1: SuiteId = SuiteId(0x0102);
    pub const KEM_X25519_V1: SuiteId = SuiteId(0x0103);
    pub const KEM_X25519_MLKEM1024_MCELIECE8192128_V1: SuiteId = SuiteId(0x01f0);
    pub const KEM_X25519_MLKEM1024_HQC256_V1: SuiteId = SuiteId(0x01f1);
    pub const SIG_ED25519_V1: SuiteId = SuiteId(0x0201);
    pub const SIG_SLHDSA_SHA2_256S_V1: SuiteId = SuiteId(0x0202);
    pub const SIG_DUAL_ED25519_SLHDSA_SHA2_256S_V1: SuiteId = SuiteId(0x0203);
}

const fn row(id: SuiteId, name: &'static str, kind: SuiteKind, status: SuiteStatus) -> Suite {
    Suite {
        id,
        name,
        kind,
        status,
        min_epoch: 1,
        components: &[],
        signature_len: 0,
    }
}

const ED25519_SIG_LEN: usize = 64;
const SLHDSA_SHA2_256S_SIG_LEN: usize = 29_792;

static SUITES: [Suite; 11] = {
    use SuiteKind::{Aead, DualSignature, Kem, Signature};
    use SuiteStatus::{Allowed, Forbidden, Reserved};
    [
        row(
            SuiteId::XCHACHA20POLY1305_V1,
            "xchacha20poly1305-v1",
            Aead,
            Allowed,
        ),
        row(SuiteId::AES256GCM_V1, "aes256gcm-v1", Aead, Allowed),
        // Below the 256-bit key floor.
        row(SuiteId::AES128GCM_V1, "aes128gcm-v1", Aead, Forbidden),
        row(
            SuiteId::KEM_X25519_MLKEM1024_V1,
            "kem-x25519-mlkem1024-v1",
            Kem,
            Allowed,
        ),
        // The X25519MLKEM768 TLS group is interim transport only (PQC-3 B); never a capsule.
        row(
            SuiteId::KEM_X25519_MLKEM768_V1,
            "kem-x25519-mlkem768-v1",
            Kem,
            Forbidden,
        ),
        // Classical-only capsules are never accepted (PQC-3 B).
        row(SuiteId::KEM_X25519_V1, "kem-x25519-v1", Kem, Forbidden),
        // PQC-4 B pilot: a third required component for rare long-term capsules.
        row(
            SuiteId::KEM_X25519_MLKEM1024_MCELIECE8192128_V1,
            "kem-x25519-mlkem1024-mceliece8192128-v1",
            Kem,
            Reserved,
        ),
        row(
            SuiteId::KEM_X25519_MLKEM1024_HQC256_V1,
            "kem-x25519-mlkem1024-hqc256-v1",
            Kem,
            Reserved,
        ),
        Suite {
            signature_len: ED25519_SIG_LEN,
            ..row(
                SuiteId::SIG_ED25519_V1,
                "sig-ed25519-v1",
                Signature,
                Allowed,
            )
        },
        Suite {
            signature_len: SLHDSA_SHA2_256S_SIG_LEN,
            ..row(
                SuiteId::SIG_SLHDSA_SHA2_256S_V1,
                "sig-slhdsa-sha2-256s-v1",
                Signature,
                Allowed,
            )
        },
        Suite {
            components: &[SuiteId::SIG_ED25519_V1, SuiteId::SIG_SLHDSA_SHA2_256S_V1],
            ..row(
                SuiteId::SIG_DUAL_ED25519_SLHDSA_SHA2_256S_V1,
                "sig-dual-ed25519-slhdsa-sha2-256s-v1",
                DualSignature,
                Allowed,
            )
        },
    ]
};

/// The full suite table, allowed, forbidden and reserved rows alike.
pub fn suite_table() -> &'static [Suite] {
    &SUITES
}

impl Suite {
    /// Looks a suite up and refuses unknown, forbidden and reserved ids.
    pub fn allowed(id: SuiteId) -> Result<&'static Suite> {
        let suite = SUITES
            .iter()
            .find(|s| s.id == id)
            .ok_or(Error::UnknownSuite(id.0))?;
        match suite.status {
            SuiteStatus::Allowed => Ok(suite),
            SuiteStatus::Forbidden => Err(Error::ForbiddenSuite(suite.name)),
            SuiteStatus::Reserved => Err(Error::ReservedSuite(suite.name)),
        }
    }

    /// [`Suite::allowed`], plus the slot's kind and the suite's minimum epoch.
    pub(crate) fn require(id: SuiteId, kinds: &[SuiteKind], epoch: u64) -> Result<&'static Suite> {
        let suite = Self::allowed(id)?;
        if !kinds.contains(&suite.kind) {
            return Err(Error::WrongSuiteKind {
                suite: suite.name,
                expected: kinds[0],
                actual: suite.kind,
            });
        }
        if epoch < suite.min_epoch {
            return Err(Error::EpochBelowSuiteMinimum {
                suite: suite.name,
                epoch,
                min: suite.min_epoch,
            });
        }
        Ok(suite)
    }

    /// The nonce length of an AEAD suite.
    pub(crate) fn nonce_len(&self) -> usize {
        if self.id == SuiteId::AES256GCM_V1 {
            12
        } else {
            24
        }
    }
}

/// The name of a suite id for messages; unknown ids read as `"unknown"`.
pub(crate) fn name_of(id: SuiteId) -> &'static str {
    SUITES
        .iter()
        .find(|s| s.id == id)
        .map_or("unknown", |s| s.name)
}
