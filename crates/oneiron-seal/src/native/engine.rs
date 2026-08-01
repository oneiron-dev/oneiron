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
    /// Fail fast on unparsable trust-anchor material.
    fn validate_anchors(config: &SealConfig) -> Result<(), SealError> {
        for anchor in &config.trust_anchors_der {
            der::Decode::from_der(anchor)
                .map(|_: x509_cert::Certificate| ())
                .map_err(|_| SealError::Fatal {
                    stage: SealStage::InputValidation,
                    code: FatalCode::InvalidConfiguration,
                })?;
        }
        Ok(())
    }

    /// Engine over a caller-supplied fetcher. The fetch policy lives on the
    /// fetcher, not the engine, so this path cannot honor
    /// `config.fetch_policy`: a non-default policy is REJECTED instead of
    /// left as a silent dead knob. The wired alternative is
    /// `with_guarded_fetcher` (feature `network-fetch`), which builds the
    /// SSRF-guarded fetcher FROM `config.fetch_policy`.
    pub fn new(
        config: SealConfig,
        backend: Arc<dyn SealBackend>,
        fetcher: Arc<dyn SealFetcher>,
        clock: Arc<dyn SealClock>,
    ) -> Result<Self, SealError> {
        Self::validate_anchors(&config)?;
        if config.fetch_policy != crate::api::FetchPolicy::default() {
            return Err(SealError::Fatal {
                stage: SealStage::InputValidation,
                code: FatalCode::InvalidConfiguration,
            });
        }
        Ok(Self {
            config,
            backend,
            fetcher,
            clock,
        })
    }

    /// Engine whose fetcher is the SSRF-guarded HTTP client built from
    /// `config.fetch_policy` — the wired policy path (§5).
    #[cfg(feature = "network-fetch")]
    pub fn with_guarded_fetcher(
        config: SealConfig,
        backend: Arc<dyn SealBackend>,
        clock: Arc<dyn SealClock>,
    ) -> Result<Self, SealError> {
        Self::validate_anchors(&config)?;
        let fetcher: Arc<dyn SealFetcher> = Arc::new(super::fetch::SsrfGuardedHttpFetcher::new(
            config.fetch_policy.clone(),
        ));
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
    use crate::api::{FetchPolicy, PadesProfile, SealResourceLimits};

    struct NoopBackend;

    #[async_trait]
    impl SealBackend for NoopBackend {
        fn signing_identity(
            &self,
        ) -> Result<crate::api::SigningIdentity, crate::api::BackendError> {
            Err(crate::api::BackendError::Unavailable {
                retry_after_ms: None,
            })
        }

        async fn sign_digest(
            &self,
            _request: crate::api::SignDigestRequest,
        ) -> Result<crate::api::BackendSignature, crate::api::BackendError> {
            Err(crate::api::BackendError::Unavailable {
                retry_after_ms: None,
            })
        }
    }

    struct Clock;

    impl SealClock for Clock {
        fn unix_time_ms(&self) -> u64 {
            0
        }
    }

    fn test_config(fetch_policy: FetchPolicy) -> SealConfig {
        SealConfig {
            trust_anchors_der: Vec::new(),
            timestamp_authorities: Vec::new(),
            fetch_policy,
            resource_limits: SealResourceLimits::default(),
        }
    }

    #[test]
    fn injected_fetcher_path_rejects_a_non_default_fetch_policy() {
        // The injected-fetcher path cannot honor config.fetch_policy: a
        // configured policy must fail loud, never sit as a dead knob.
        let policy = FetchPolicy {
            allowed_origins: vec![url::Url::parse("https://ca.example.test").unwrap()],
            ..FetchPolicy::default()
        };
        let err = NativeSealEngine::new(
            test_config(policy),
            Arc::new(NoopBackend),
            Arc::new(crate::api::OfflineFetcher),
            Arc::new(Clock),
        )
        .err()
        .unwrap();
        assert!(matches!(
            err,
            SealError::Fatal {
                stage: SealStage::InputValidation,
                code: FatalCode::InvalidConfiguration,
            }
        ));
        // The default policy is accepted on this path.
        assert!(
            NativeSealEngine::new(
                test_config(FetchPolicy::default()),
                Arc::new(NoopBackend),
                Arc::new(crate::api::OfflineFetcher),
                Arc::new(Clock),
            )
            .is_ok()
        );
    }

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
