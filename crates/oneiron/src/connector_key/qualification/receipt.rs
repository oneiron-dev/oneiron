//! Durable evidence for the suite that actually ran, retained on activation.
use super::{ProbeReply, ProbeTool, QualificationFailure, QualificationPlan};
use crate::connector_key::record::{invalid_body, validate_protocol_revision};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CONNECTOR_QUALIFICATION_SUITE: &str = "oneiron.connector.qualification.v1";
/// A built-in connector pack's suite: the engine's own hash-verified adapter
/// rides its Verified setup connection instead of a probe suite. Only an
/// embedded built-in source may carry it.
pub const SETUP_CHECK_QUALIFICATION_SUITE: &str = "oneiron.connector.setup_check.v1";
/// The OpenAI proxy's own connector (ARCH-0028): the engine is the
/// connector, so no probe suite runs. Its admission is the owner's stamp on
/// the proxy's fixed slate. Only the proxy connector's key may carry it.
pub const PROXY_ADMISSION_QUALIFICATION_SUITE: &str = "oneiron.connector.proxy_admission.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorQualificationReceipt {
    pub suite: String,
    pub report_hash: String,
    pub protocol_revision: String,
    pub manifest_hash: [u8; 32],
    pub qualified_at: u64,
}

impl ConnectorQualificationReceipt {
    pub(crate) fn new(
        report_hash: String,
        protocol_revision: String,
        manifest_hash: [u8; 32],
        qualified_at: u64,
    ) -> Result<Self> {
        let receipt = Self {
            suite: CONNECTOR_QUALIFICATION_SUITE.to_owned(),
            report_hash,
            protocol_revision,
            manifest_hash,
            qualified_at,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// The receipt a built-in's checked setup connection earns. The
    /// revision is the engine's, which built-in adapters version with.
    pub(crate) fn setup_check(
        report_hash: String,
        engine_revision: String,
        source_hash: [u8; 32],
        qualified_at: u64,
    ) -> Result<Self> {
        let receipt = Self {
            suite: SETUP_CHECK_QUALIFICATION_SUITE.to_owned(),
            report_hash,
            protocol_revision: engine_revision,
            manifest_hash: source_hash,
            qualified_at,
        };
        receipt.validate_setup_check()?;
        Ok(receipt)
    }

    /// The receipt the proxy's own connector activates under. Its digest
    /// names the actor and the slate the owner stamped.
    pub(crate) fn proxy_admission(
        report_hash: String,
        protocol_revision: String,
        manifest_hash: [u8; 32],
        qualified_at: u64,
    ) -> Result<Self> {
        let receipt = Self {
            suite: PROXY_ADMISSION_QUALIFICATION_SUITE.to_owned(),
            report_hash,
            protocol_revision,
            manifest_hash,
            qualified_at,
        };
        receipt.validate_as(PROXY_ADMISSION_QUALIFICATION_SUITE)?;
        Ok(receipt)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_as(CONNECTOR_QUALIFICATION_SUITE)
    }

    /// A connector key's receipt: the probe suite's, or on the proxy's own
    /// connector the proxy admission's.
    pub(crate) fn validate_for_key(&self, connector: &str) -> Result<()> {
        if self.suite == PROXY_ADMISSION_QUALIFICATION_SUITE
            && connector == crate::connector_key::PROXY_CONNECTOR
        {
            return self.validate_as(PROXY_ADMISSION_QUALIFICATION_SUITE);
        }
        self.validate()
    }

    pub(crate) fn validate_setup_check(&self) -> Result<()> {
        self.validate_as(SETUP_CHECK_QUALIFICATION_SUITE)
    }

    fn validate_as(&self, suite: &str) -> Result<()> {
        validate_protocol_revision(&self.protocol_revision)?;
        if self.suite != suite
            || self.report_hash.len() != 64
            || !self
                .report_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid_body("invalid connector qualification receipt"));
        }
        Ok(())
    }
}

pub(super) struct QualificationEvidence {
    hasher: blake3::Hasher,
    pub(super) calls: usize,
    pub(super) result_types: BTreeSet<String>,
}

impl QualificationEvidence {
    pub(super) fn new(
        plan: &QualificationPlan,
        tools: &[ProbeTool],
    ) -> std::result::Result<Self, QualificationFailure> {
        let mut evidence = Self {
            hasher: blake3::Hasher::new(),
            calls: 0,
            result_types: BTreeSet::new(),
        };
        evidence
            .hasher
            .update(CONNECTOR_QUALIFICATION_SUITE.as_bytes());
        evidence.append(&(plan, tools))?;
        Ok(evidence)
    }

    fn append(&mut self, value: &impl Serialize) -> std::result::Result<(), QualificationFailure> {
        let bytes = serde_json::to_vec(value).map_err(|_| QualificationFailure::Trace)?;
        self.hasher.update(&(bytes.len() as u64).to_le_bytes());
        self.hasher.update(&bytes);
        Ok(())
    }

    pub(super) fn record(
        &mut self,
        reply: &ProbeReply,
    ) -> std::result::Result<(), QualificationFailure> {
        self.append(reply)?;
        self.calls += 1;
        self.result_types.insert(reply.result_type.clone());
        Ok(())
    }

    pub(super) fn state(&mut self, state: &[u8]) -> std::result::Result<(), QualificationFailure> {
        self.append(&state)
    }

    pub(super) fn finish(self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }
}
