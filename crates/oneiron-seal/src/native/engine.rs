//! `NativeSealEngine`: composition of config, backend, fetcher, and clock.

use std::sync::Arc;

use async_trait::async_trait;

use crate::api::{
    PdfSealEngine, PreparedRevision, SealBackend, SealClock, SealConfig, SealFetcher, SealRequest,
    SealResourceLimits, SealedPdf, VerifyReport,
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
    /// A native engine reserves the memory its decodes take from a real
    /// service (`SealResourceLimits::memory`, FIX 7654): without one it does
    /// not start, and nothing is parsed.
    fn require_memory(config: &SealConfig) -> Result<(), SealError> {
        if config.resource_limits.memory.is_configured() {
            Ok(())
        } else {
            Err(SealError::Fatal {
                stage: SealStage::InputValidation,
                code: FatalCode::InvalidConfiguration,
            })
        }
    }

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
    /// SSRF-guarded fetcher FROM `config.fetch_policy`. A config whose
    /// `resource_limits.memory` names no service is refused first.
    pub fn new(
        config: SealConfig,
        backend: Arc<dyn SealBackend>,
        fetcher: Arc<dyn SealFetcher>,
        clock: Arc<dyn SealClock>,
    ) -> Result<Self, SealError> {
        Self::require_memory(&config)?;
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
    /// `config.fetch_policy` — the wired policy path (§5). The fetcher
    /// reserves its bodies and cache entries from
    /// `config.resource_limits.memory`, the service the decodes reserve
    /// from (FIX 7655). A config whose `resource_limits.memory` names no
    /// service is refused first.
    #[cfg(feature = "network-fetch")]
    pub fn with_guarded_fetcher(
        config: SealConfig,
        backend: Arc<dyn SealBackend>,
        clock: Arc<dyn SealClock>,
    ) -> Result<Self, SealError> {
        Self::require_memory(&config)?;
        Self::validate_anchors(&config)?;
        let fetcher: Arc<dyn SealFetcher> = Arc::new(super::fetch::SsrfGuardedHttpFetcher::new(
            config.fetch_policy.clone(),
            config.resource_limits.memory.clone(),
        )?);
        Ok(Self {
            config,
            backend,
            fetcher,
            clock,
        })
    }

    /// [`PdfSealEngine::seal_pdf`], signing in a signature revision the
    /// caller wrote rather than one written here: one per rung of the
    /// contents ladder, each `input_bytes` followed by its suffix. The
    /// engine builds the CMS for the one that fits, and any validation
    /// data or document timestamp after it.
    ///
    /// # Errors
    /// As [`PdfSealEngine::seal_pdf`]; a revision whose hole or ByteRange
    /// is not the ladder's is fatal.
    pub async fn seal_pdf_in_revisions(
        &self,
        input_bytes: &[u8],
        seal_request: &SealRequest,
        revisions: &[PreparedRevision<'_>],
    ) -> Result<SealedPdf, SealError> {
        if revisions.is_empty() {
            return Err(SealError::Fatal {
                stage: SealStage::InputValidation,
                code: FatalCode::InvalidConfiguration,
            });
        }
        self.seal(input_bytes, seal_request, revisions).await
    }

    async fn seal(
        &self,
        input_bytes: &[u8],
        seal_request: &SealRequest,
        revisions: &[PreparedRevision<'_>],
    ) -> Result<SealedPdf, SealError> {
        // operation_id is validated before any signing or fetch work (§4).
        seal_request.validate_operation_id()?;
        // One memory ledger for the whole seal: its parses, its profile's
        // re-parses and its self-verification (FIX 7654).
        let limits = self
            .config
            .resource_limits
            .operation(SealStage::InputValidation)?;
        let prepared = pdf::validate_prepared(input_bytes, &limits)?;
        // The same complete structural facts feed output classification;
        // unsigned originals may have fully framed anomalous revisions.
        let facts = match pdf::analyze_revision_facts(&prepared.bytes, &limits) {
            Ok(facts) => facts,
            Err(pdf::RevisionAnalysisError::Memory(refusal)) => {
                return Err(refusal.seal_error(SealStage::InputValidation));
            }
            Err(_) => {
                return Err(SealError::InputInvalid {
                    code: crate::error::InputInvalidCode::MalformedXref,
                });
            }
        };
        if facts.revisions.len() != 1 {
            return Err(SealError::InputInvalid {
                code: crate::error::InputInvalidCode::MalformedXref,
            });
        }
        let ctx = profile::SealContext {
            config: &self.config,
            limits: &limits,
            backend: &self.backend,
            fetcher: &self.fetcher,
            clock_ms: self.clock.unix_time_ms(),
        };
        let outcome = profile::assemble(
            &ctx,
            &prepared,
            revisions,
            &seal_request.operation_id,
            seal_request.target_profile,
        )
        .await?;
        let report = self.verify_under(&outcome.bytes, &limits)?;
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

    /// Verification under `limits`, an operation's: a seal's
    /// self-verification reserves under its seal's ledger.
    fn verify_under(
        &self,
        sealed_bytes: &[u8],
        limits: &SealResourceLimits,
    ) -> Result<VerifyReport, SealError> {
        let ctx = verify::VerifyCtx {
            config: &self.config,
            limits,
            clock_ms: self.clock.unix_time_ms(),
        };
        verify::verify_document(sealed_bytes, &ctx)
    }
}

#[async_trait]
impl PdfSealEngine for NativeSealEngine {
    async fn seal_pdf(
        &self,
        input_bytes: &[u8],
        seal_request: &SealRequest,
    ) -> Result<SealedPdf, SealError> {
        self.seal(input_bytes, seal_request, &[]).await
    }

    fn verify_sealed_pdf(&self, sealed_bytes: &[u8]) -> Result<VerifyReport, SealError> {
        // A memory ledger of its own, opened before anything is parsed.
        let limits = self
            .config
            .resource_limits
            .operation(SealStage::Verification)?;
        self.verify_under(sealed_bytes, &limits)
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

    #[tokio::test]
    async fn unsigned_unknown_incremental_revision_is_refused_before_backend() {
        let input = std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/classic_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let limits = SealResourceLimits::default();
        let state = pdf::reparse_revision(&input, &limits).unwrap();
        let id = state.max_obj + 1;
        let appended = pdf::append_revision(
            &input,
            &state,
            &pdf::RevisionKind::Dss {
                material_objects: vec![(id, b"<< /Type /DSS >>".to_vec())],
                dss_obj: id,
            },
            0,
        )
        .unwrap();
        let engine = NativeSealEngine::new(
            test_config(FetchPolicy::default()),
            Arc::new(NoopBackend),
            Arc::new(crate::api::OfflineFetcher),
            Arc::new(Clock),
        )
        .unwrap();
        let err = engine
            .seal_pdf(
                &appended.bytes,
                &SealRequest {
                    operation_id: "reject-extra-revision".into(),
                    target_profile: PadesProfile::BaselineB,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: crate::error::InputInvalidCode::MalformedXref
            }
        ));
        // /Pr#65v decodes to /Prev. A different spelling cannot erase the
        // unsigned revision from the shared structural analysis.
        let mut escaped = appended.bytes.clone();
        let marker = b"/Prev";
        let at = escaped
            .windows(marker.len())
            .rposition(|w| w == marker)
            .unwrap();
        escaped.splice(at..at + marker.len(), b"/Pr#65v".iter().copied());
        let err = engine
            .seal_pdf(
                &escaped,
                &SealRequest {
                    operation_id: "reject-escaped-prev".into(),
                    target_profile: PadesProfile::BaselineB,
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SealError::InputInvalid {
                    code: crate::error::InputInvalidCode::MalformedXref,
                }
            ),
            "escaped linkage must not bypass admission: {err:?}"
        );
        let report = engine.verify_sealed_pdf(&escaped).unwrap();
        assert_eq!(
            report.revisions.len(),
            2,
            "escaped /Prev must retain both revisions"
        );
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
}
