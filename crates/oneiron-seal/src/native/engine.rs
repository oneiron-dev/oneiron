//! `NativeSealEngine`: composition of config, backend, fetcher, and clock.

use std::sync::Arc;

use async_trait::async_trait;

use crate::api::{
    PdfSealEngine, SealBackend, SealClock, SealConfig, SealFetcher, SealRequest, SealedPdf,
    VerifyReport,
};
use crate::error::{FatalCode, SealError, SealStage};

use super::{cms, pdf, profile, verify};

/// Native PAdES seal engine. See [`PdfSealEngine`] for the prepared-input
/// and retry contracts.
pub struct NativeSealEngine {
    config: SealConfig,
    backend: Arc<dyn SealBackend>,
    fetcher: Arc<dyn SealFetcher>,
    clock: Arc<dyn SealClock>,
}

impl NativeSealEngine {
    pub fn new(
        config: SealConfig,
        backend: Arc<dyn SealBackend>,
        fetcher: Arc<dyn SealFetcher>,
        clock: Arc<dyn SealClock>,
    ) -> Result<Self, SealError> {
        // Fail fast on unparsable trust-anchor material.
        for anchor in &config.trust_anchors_der {
            der::Decode::from_der(anchor)
                .map(|_: x509_cert::Certificate| ())
                .map_err(|_| SealError::Fatal {
                    stage: SealStage::InputValidation,
                    code: FatalCode::InvalidConfiguration,
                })?;
        }
        Ok(Self {
            config,
            backend,
            fetcher,
            clock,
        })
    }
}

#[async_trait]
impl PdfSealEngine for NativeSealEngine {
    async fn seal_pdf(
        &self,
        input_bytes: &[u8],
        seal_request: &SealRequest,
    ) -> Result<SealedPdf, SealError> {
        // operation_id is validated before any signing or fetch work (§4).
        seal_request.validate_operation_id()?;
        let prepared = pdf::validate_prepared(input_bytes, &self.config.resource_limits)?;
        let ctx = profile::SealContext {
            config: &self.config,
            backend: &self.backend,
            fetcher: &self.fetcher,
            clock_ms: self.clock.unix_time_ms(),
        };
        let outcome = profile::assemble(
            &ctx,
            &prepared,
            &seal_request.operation_id,
            seal_request.target_profile,
        )
        .await?;
        let report = self.verify_sealed_pdf(&outcome.bytes)?;
        if !report.passes_self_verify() {
            return Err(SealError::VerifyFailed {
                report: Box::new(report),
            });
        }
        Ok(SealedPdf {
            evidence_sha256: cms::sha256(&outcome.bytes),
            bytes: outcome.bytes,
            requested_profile: seal_request.target_profile,
            achieved_profile: outcome.achieved,
            warnings: outcome.warnings,
            self_verify_report: report,
        })
    }

    fn verify_sealed_pdf(&self, sealed_bytes: &[u8]) -> Result<VerifyReport, SealError> {
        let ctx = verify::VerifyCtx {
            config: &self.config,
            clock_ms: self.clock.unix_time_ms(),
        };
        verify::verify_document(sealed_bytes, &ctx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::api::PadesProfile;

    #[test]
    fn operation_id_contract_rejects_empty_and_oversized() {
        let req = |id: String| SealRequest {
            operation_id: id,
            target_profile: PadesProfile::BaselineB,
        };
        assert!(req("op-1".to_string()).validate_operation_id().is_ok());
        let boundary = req("x".repeat(crate::api::MAX_OPERATION_ID_BYTES));
        assert!(boundary.validate_operation_id().is_ok());
        for bad in [req(String::new()), req("x".repeat(257))] {
            let err = bad.validate_operation_id().unwrap_err();
            assert!(matches!(
                err,
                SealError::Fatal {
                    stage: SealStage::InputValidation,
                    code: FatalCode::InvalidConfiguration,
                }
            ));
        }
    }
}
