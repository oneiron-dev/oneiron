//! Doors from the integration tests to crate-private items. Compiled only
//! under `--cfg oneiron_test_support`, which only the test command sets
//! (`RUSTFLAGS="--cfg oneiron_test_support" cargo test ... --test <stem>`,
//! with the `native` feature); never behind a cargo feature, so no
//! `--all-features` build reaches them. Hidden; never API.

use std::sync::Arc;

use crate::api::SealResourceLimits;
use crate::error::SealStage;
use crate::memory::{SealMemory, SealMemoryProvider, SealMemoryRefusal};
use crate::native::verify::{EmbeddedCert, EvidenceRejection, ocsp_entry_valid};

/// Why the door's OCSP entry was rejected: the test-visible mirror of the
/// validator's rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum OcspDoorRejection {
    /// Forged or unverifiable: discarded, never a failure.
    Unverifiable,
    /// Genuine but not usable here.
    Unusable,
    /// Genuine, and says a certificate is revoked.
    Revoked,
}

/// A memory service that grants every reservation: the door runs no PDF
/// decode, only the entry validator over caller bytes.
struct GrantAll;

impl SealMemory for GrantAll {
    fn reserve(&self, _bytes: u64) -> Result<Box<dyn Send>, SealMemoryRefusal> {
        Ok(Box::new(()))
    }
}

/// Runs the DSS OCSP entry validator over `ocsp_der`, with `embedded_ders`
/// as the DSS certificates and `anchor_ders` as the trust anchors at
/// `at_unix`, and returns the DER of every target it covers good, or why the
/// entry was rejected. Certificates that do not decode are skipped, as the
/// DSS pass skips them.
///
/// # Errors
/// The ledger's refusal (never under the granting service).
#[doc(hidden)]
pub fn ocsp_entry_good_targets(
    ocsp_der: &[u8],
    embedded_ders: &[Vec<u8>],
    anchor_ders: &[Vec<u8>],
    at_unix: u64,
) -> Result<Result<Vec<Vec<u8>>, OcspDoorRejection>, SealMemoryRefusal> {
    let limits = SealResourceLimits {
        memory: SealMemoryProvider::new(Arc::new(GrantAll)),
        ..SealResourceLimits::default()
    };
    let operation = limits
        .operation(SealStage::Verification)
        .map_err(|_| SealMemoryRefusal::Unavailable)?;
    let memory = operation.memory.ledger()?;
    let mut embedded = Vec::with_capacity(embedded_ders.len());
    for der_bytes in embedded_ders {
        if let Some(cert) = EmbeddedCert::admitted(der_bytes, &memory)? {
            embedded.push(cert);
        }
    }
    let mut anchors = Vec::with_capacity(anchor_ders.len());
    for der_bytes in anchor_ders {
        if let Some(cert) = EmbeddedCert::admitted(der_bytes, &memory)? {
            anchors.push(cert);
        }
    }
    let evidence = ocsp_entry_valid(ocsp_der, &embedded, &anchors, at_unix, &memory)?;
    Ok(evidence
        .map(|evidence| {
            evidence
                .good_targets
                .iter()
                .map(|target| target.to_vec())
                .collect()
        })
        .map_err(|rejection| match rejection {
            EvidenceRejection::Unverifiable => OcspDoorRejection::Unverifiable,
            EvidenceRejection::Unusable => OcspDoorRejection::Unusable,
            EvidenceRejection::Revoked => OcspDoorRejection::Revoked,
        }))
}
