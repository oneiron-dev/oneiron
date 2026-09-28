//! Total private RFC 3161 outcomes; one projection emits crypto and TSA trust.
use super::verify_dss_core::EmbeddedCert;
use super::verify_evidence::ValidatedTimeToken;
use super::verify_revocation::gen_time_beyond_skew;
use super::verify_sig_pipeline::{Checks, SigEntry, unpadded_cms};
use crate::api::{Sha256Digest, VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode};
use crate::native::{cms, pdf, tsp};

#[derive(Clone, Copy)]
pub(super) enum TimestampKind {
    Signature,
    Document,
}
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
            Self::NotRun(reason) => checks.not_run_with_reason(kind, Some(reason)),
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

/// Parsed but untrusted time is never a signer-validation proof. It may only
/// explain why DSS verification could not complete without a trust root.
pub(super) struct TimestampResult {
    pub(super) trusted: Option<ValidatedTimeToken>,
    pub(super) untrusted_time: Option<u64>,
}
impl TimestampResult {
    pub(super) fn none() -> Self {
        Self {
            trusted: None,
            untrusted_time: None,
        }
    }
}

/// `Absent` only means no optional token was present. Every other variant
/// produces exactly one applicable crypto check AND one applicable TSA check.
pub(super) enum TimestampEvidence {
    Absent,
    NotEvaluated,
    Malformed,
    CryptoRejected,
    Valid(tsp::VerifiedToken),
}
impl TimestampEvidence {
    pub(super) fn for_signature(
        clock_ms: u64,
        signer: &cms::ParsedSignerInfo,
        anchors: &[pkix_chain::TrustAnchor],
    ) -> Self {
        let mut token = None;
        for attr in &signer.unsigned_attrs {
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
            return Self::CryptoRejected;
        }
        let Some(der) = unpadded_cms(&entry.contents) else {
            return Self::Malformed;
        };
        let Ok(imprint) = pdf::hash_byte_range(bytes, entry.byte_range) else {
            return Self::CryptoRejected;
        };
        Self::evaluate(der, &imprint, anchors, clock_ms)
    }
    fn evaluate(
        token: &[u8],
        imprint: &Sha256Digest,
        anchors: &[pkix_chain::TrustAnchor],
        clock_ms: u64,
    ) -> Self {
        let Ok(value) = tsp::validate_token_for_verify(token, imprint, anchors) else {
            return Self::CryptoRejected;
        };
        if gen_time_beyond_skew(value.gen_time_unix, clock_ms) {
            return Self::CryptoRejected;
        }
        Self::Valid(value)
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
            Self::Valid(token) => TimestampSlots::Complete {
                crypto: CheckOutcome::Pass,
                trust: match token.trust {
                    VerifyCheckStatus::Pass => CheckOutcome::Pass,
                    VerifyCheckStatus::Fail => {
                        CheckOutcome::Fail(VerifyFindingCode::CertificatePathInvalid)
                    }
                    VerifyCheckStatus::NotRun | VerifyCheckStatus::NotApplicable => {
                        CheckOutcome::NotRun(VerifyFindingCode::TrustRootUnavailable)
                    }
                },
            },
        }
    }
    /// Only trusted time may become signer or archival time evidence.
    pub(super) fn project(
        self,
        kind: TimestampKind,
        checks: &mut Checks,
        covered: &mut Vec<EmbeddedCert>,
    ) -> TimestampResult {
        let (crypto_kind, invalid) = match kind {
            TimestampKind::Signature => (
                VerifyCheckKind::SignatureTimestamp,
                VerifyFindingCode::TimestampInvalid,
            ),
            TimestampKind::Document => (
                VerifyCheckKind::DocumentTimestamp,
                VerifyFindingCode::DocumentTimestampInvalid,
            ),
        };
        let slots = self.slots(invalid);
        match slots {
            TimestampSlots::Absent => {
                checks.absent(crypto_kind);
                checks.absent(VerifyCheckKind::TimestampCertificatePath);
            }
            TimestampSlots::Complete { crypto, trust } => {
                crypto.emit(crypto_kind, checks);
                trust.emit(VerifyCheckKind::TimestampCertificatePath, checks);
            }
        }
        if let Self::Valid(token) = self {
            if matches!(
                token.trust,
                VerifyCheckStatus::Pass | VerifyCheckStatus::NotRun
            ) {
                covered.extend(
                    token
                        .tsa_chain_ders
                        .iter()
                        .filter_map(|d| EmbeddedCert::from_der(d)),
                );
            }
            return match token.trust {
                VerifyCheckStatus::Pass => TimestampResult {
                    trusted: Some(ValidatedTimeToken {
                        gen_time: token.gen_time_unix,
                        tsa_chain_ders: token.tsa_chain_ders,
                    }),
                    untrusted_time: None,
                },
                VerifyCheckStatus::NotRun => TimestampResult {
                    trusted: None,
                    untrusted_time: Some(token.gen_time_unix),
                },
                VerifyCheckStatus::Fail | VerifyCheckStatus::NotApplicable => {
                    TimestampResult::none()
                }
            };
        }
        TimestampResult::none()
    }
}
