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
        if seal_request.operation_id.is_empty()
            || seal_request.operation_id.len() > 256
        {
            return Err(SealError::Fatal {
                stage: SealStage::InputValidation,
                code: FatalCode::InvalidConfiguration,
            });
        }
        let prepared = pdf::validate_prepared(input_bytes, &self.config.resource_limits)?;
        let ctx = profile::SealContext {
            config: &self.config,
            backend: &self.backend,
            fetcher: &self.fetcher,
            clock_ms: self.clock.unix_time_ms(),
        };
        let outcome =
            profile::assemble(&ctx, &prepared, &seal_request.operation_id, seal_request.target_profile)
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
