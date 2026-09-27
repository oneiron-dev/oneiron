//! Shared RFC 3161 evidence evaluation and exhaustive report projection.
//!
//! The private result separates absent optional evidence, invalid crypto,
//! and valid crypto with trusted, unresolved or rejected TSA authority.

use super::super::verify_dss_core::EmbeddedCert;
use super::super::verify_revocation::gen_time_beyond_skew;
use super::{Checks, SigEntry, unpadded_cms};
use crate::api::{Sha256Digest, VerifyCheckKind, VerifyFindingCode};
use crate::native::{cms, pdf, tsp};

#[derive(Debug, Clone, Copy)]
pub(super) enum TimestampKind {
    Signature,
    Document,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum TsaTrust {
    Trusted,
    RootUnavailable,
    Rejected,
}

/// An applicable check always has one outcome. Optional absence is not an
/// outcome: it is represented by `TimestampSlots::Absent` instead.
enum CheckOutcome {
    Pass,
    Fail(VerifyFindingCode),
    NotRun(VerifyFindingCode),
}
impl CheckOutcome {
    fn emit(self, kind: VerifyCheckKind, checks: &mut Checks) {
        match self {
            Self::Pass => checks.record(kind, true, VerifyFindingCode::TimestampInvalid),
            Self::Fail(reason) => checks.record(kind, false, reason),
            Self::NotRun(reason) => checks.not_run(kind, reason),
        }
    }
}
enum TimestampSlots {
    Absent,
    Complete {
        crypto: CheckOutcome,
        trust: CheckOutcome,
    },
}

/// The complete outcome of evaluating either timestamp form. No caller may
/// independently emit just one check: `project` emits the pair together.
pub(super) enum TimestampEvidence {
    Absent,
    NotEvaluated,
    Malformed,
    CryptoRejected,
    Valid {
        gen_time: u64,
        tsa_chain_ders: Vec<Vec<u8>>,
        trust: TsaTrust,
    },
}

impl TimestampEvidence {
    pub(super) fn for_signature(
        clock_ms: u64,
        signer: &cms::ParsedSignerInfo,
        anchors: &[pkix_chain::TrustAnchor],
    ) -> Self {
        let mut token = None;
        for attr in &signer.unsigned_attrs {
            // Malformed attributes cannot be silently treated as absent,
            // even if an earlier timestamp attribute was well formed.
            let Ok((oid, value)) = cms::parse_attribute(attr) else {
                return Self::Malformed;
            };
            if oid == cms::OID_ATTR_TS_TOKEN.as_bytes() {
                if token.is_some() {
                    return Self::Malformed;
                }
                token = Some(value.full.to_vec());
            }
        }
        let Some(token) = token else {
            return Self::Absent;
        };
        Self::evaluate(&token, &cms::sha256(&signer.signature), anchors, clock_ms)
    }

    pub(super) fn for_document(
        bytes: &[u8],
        entry: &SigEntry,
        anchors: &[pkix_chain::TrustAnchor],
        clock_ms: u64,
        coverage_ok: bool,
    ) -> Self {
        if !coverage_ok {
            return Self::Malformed;
        }
        let Some(token) = unpadded_cms(&entry.contents) else {
            return Self::Malformed;
        };
        let Ok(imprint) = pdf::hash_byte_range(bytes, entry.byte_range) else {
            return Self::CryptoRejected;
        };
        Self::evaluate(token, &imprint, anchors, clock_ms)
    }

    fn evaluate(
        token: &[u8],
        imprint: &Sha256Digest,
        anchors: &[pkix_chain::TrustAnchor],
        clock_ms: u64,
    ) -> Self {
        let Ok((gen_time, tsa_chain_ders)) = tsp::validate_token_crypto_for_verify(token, imprint)
        else {
            return Self::CryptoRejected;
        };
        if gen_time_beyond_skew(gen_time, clock_ms) {
            return Self::CryptoRejected;
        }
        let trust = if tsp::validate_tsa_chain(&tsa_chain_ders, anchors, gen_time).is_ok() {
            TsaTrust::Trusted
        } else if anchors.is_empty() || tsp::tsa_root_unavailable(&tsa_chain_ders, gen_time) {
            TsaTrust::RootUnavailable
        } else {
            TsaTrust::Rejected
        };
        Self::Valid {
            gen_time,
            tsa_chain_ders,
            trust,
        }
    }

    /// Crypto-accepted but untrusted time is provisional. Only DocTimeStamp
    /// uses it as an untrusted ordering fact; signer validation does not use
    /// it in place of a verified signature timestamp.
    pub(super) fn provisional_time(&self) -> Option<u64> {
        match self {
            Self::Valid { gen_time, .. } => Some(*gen_time),
            Self::Absent | Self::NotEvaluated | Self::Malformed | Self::CryptoRejected => None,
        }
    }

    fn slots(&self, invalid: VerifyFindingCode) -> TimestampSlots {
        match self {
            Self::Absent => TimestampSlots::Absent,
            Self::NotEvaluated => TimestampSlots::Complete {
                crypto: CheckOutcome::NotRun(invalid),
                trust: CheckOutcome::NotRun(VerifyFindingCode::TrustCheckNotRun),
            },
            Self::Malformed | Self::CryptoRejected => TimestampSlots::Complete {
                crypto: CheckOutcome::Fail(invalid),
                trust: CheckOutcome::NotRun(VerifyFindingCode::TrustCheckNotRun),
            },
            Self::Valid { trust, .. } => TimestampSlots::Complete {
                crypto: CheckOutcome::Pass,
                trust: match trust {
                    TsaTrust::Trusted => CheckOutcome::Pass,
                    TsaTrust::RootUnavailable => {
                        CheckOutcome::NotRun(VerifyFindingCode::TrustRootUnavailable)
                    }
                    TsaTrust::Rejected => {
                        CheckOutcome::Fail(VerifyFindingCode::CertificatePathInvalid)
                    }
                },
            },
        }
    }

    /// The only check projection for both timestamp kinds. Both applicable
    /// slots are emitted together; no early return can forget TSA trust.
    pub(super) fn project(
        &self,
        kind: TimestampKind,
        checks: &mut Checks,
        covered: &mut Vec<EmbeddedCert>,
    ) -> Option<u64> {
        let (crypto_kind, trust_kind, invalid) = match kind {
            TimestampKind::Signature => (
                VerifyCheckKind::SignatureTimestamp,
                VerifyCheckKind::SignatureTimestampTrust,
                VerifyFindingCode::TimestampInvalid,
            ),
            TimestampKind::Document => (
                VerifyCheckKind::DocumentTimestamp,
                VerifyCheckKind::DocumentTimestampTrust,
                VerifyFindingCode::DocumentTimestampInvalid,
            ),
        };
        match self.slots(invalid) {
            TimestampSlots::Absent => {
                checks.absent(crypto_kind);
                checks.absent(trust_kind);
            }
            TimestampSlots::Complete { crypto, trust } => {
                crypto.emit(crypto_kind, checks);
                trust.emit(trust_kind, checks);
            }
        }
        if let Self::Valid {
            gen_time,
            tsa_chain_ders,
            trust,
        } = self
        {
            if !matches!(trust, TsaTrust::Rejected) {
                covered.extend(
                    tsa_chain_ders
                        .iter()
                        .filter_map(|d| EmbeddedCert::from_der(d)),
                );
            }
            return matches!(trust, TsaTrust::Trusted).then_some(*gen_time);
        }
        None
    }
}
