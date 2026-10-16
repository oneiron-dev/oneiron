//! Durable evidence for the suite that actually ran, retained on activation.
use super::{ProbeReply, ProbeTool, QualificationFailure, QualificationPlan};
use crate::connector_key::record::{invalid_body, validate_protocol_revision};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CONNECTOR_QUALIFICATION_SUITE: &str = "oneiron.connector.qualification.v1";

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

    pub(crate) fn validate(&self) -> Result<()> {
        validate_protocol_revision(&self.protocol_revision)?;
        if self.suite != CONNECTOR_QUALIFICATION_SUITE
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
