//! Step 5's schema evidence (FIX 8590). ARCH-0077: schema validation is
//! necessary but not sufficient, so step 5 passes only on clean structural
//! checks and a schema report bound to the candidate's own bytes, charged
//! only with the diagnostics the deck it came from did not already have.
//! The validator is `scripts/office/deck_schema.py` (xmllint over the pinned
//! ECMA-376 transitional XML Schemas, after Markup Compatibility
//! processing); a run given no schema set, or one whose validator cannot
//! run, records the evidence as absent and step 5 stays inconclusive. The
//! candidate and its diagnostics are kept either way.

use super::record::{Res, sha256_hex, text};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What the schema validator found on one candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum SchemaEvidence {
    /// No validator report on these bytes, and why.
    Absent { why: String },
    /// The validator's report on exactly the bytes `sha256` names.
    Validated {
        sha256: String,
        validator: String,
        profile: String,
        /// The diagnostics the deck it came from did not already have:
        /// what step 5 charges.
        diagnostics: Vec<String>,
        /// How many of its diagnostics that deck already had.
        inherited: usize,
        /// The parts no schema of the set covers, by root element.
        unvalidated: Vec<String>,
    },
}

impl SchemaEvidence {
    pub(super) fn absent(why: impl Into<String>) -> Self {
        Self::Absent { why: why.into() }
    }
}

/// One validator report, as `deck_schema.py validate` prints it.
#[derive(Debug, Clone, Deserialize)]
struct Report {
    sha256: String,
    validator: String,
    profile: String,
    diagnostics: Vec<String>,
    unvalidated: Vec<String>,
}

/// The run's validator: the script, the schema set it reads, and every
/// report so far by the SHA-256 of the bytes it read, so a deck many
/// candidates come from is validated once.
pub(super) struct Validator {
    script: PathBuf,
    schemas: PathBuf,
    seen: BTreeMap<String, Result<Report, String>>,
}

impl Validator {
    pub(super) fn new(repo: &Path, schemas: &Path) -> Self {
        Self {
            script: repo.join("scripts/office/deck_schema.py"),
            schemas: schemas.to_path_buf(),
            seen: BTreeMap::new(),
        }
    }

    fn report(&mut self, bytes: &[u8]) -> Result<Report, String> {
        let sha256 = sha256_hex(bytes);
        if let Some(found) = self.seen.get(&sha256) {
            return found.clone();
        }
        let report = self.validate(bytes).and_then(|report| {
            if report.sha256 == sha256 {
                Ok(report)
            } else {
                Err(format!(
                    "the validator read other bytes ({}, not {sha256})",
                    report.sha256
                ))
            }
        });
        self.seen.insert(sha256, report.clone());
        report
    }

    fn validate(&self, bytes: &[u8]) -> Res<Report> {
        let mut child = Command::new("python3")
            .arg("-B")
            .arg(&self.script)
            .arg("validate")
            .arg(&self.schemas)
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("{}: {error}", self.script.display()))?;
        let written = child
            .stdin
            .take()
            .ok_or("the validator took no input")?
            .write_all(bytes)
            .map_err(text);
        let output = child.wait_with_output().map_err(text)?;
        written?;
        if !output.status.success() {
            let why = String::from_utf8_lossy(&output.stderr);
            return Err(format!("{}: {}", output.status, why.trim()));
        }
        serde_json::from_slice(&output.stdout).map_err(text)
    }

    /// The evidence for a candidate whose bytes hash to `sha256`, charged
    /// against `origin`, the deck it came from.
    pub(super) fn evidence(&mut self, bytes: &[u8], sha256: &str, origin: &[u8]) -> SchemaEvidence {
        let candidate = match self.report(bytes) {
            Ok(report) if report.sha256 == sha256 => report,
            Ok(report) => {
                return SchemaEvidence::absent(format!(
                    "the report is for other bytes ({})",
                    report.sha256
                ));
            }
            Err(why) => return SchemaEvidence::absent(format!("the validator did not run: {why}")),
        };
        let held = match self.report(origin) {
            Ok(report) => report.diagnostics,
            Err(why) => {
                return SchemaEvidence::absent(format!(
                    "the validator did not run on the deck it came from: {why}"
                ));
            }
        };
        let (inherited, diagnostics): (Vec<String>, Vec<String>) = candidate
            .diagnostics
            .into_iter()
            .partition(|diagnostic| held.contains(diagnostic));
        SchemaEvidence::Validated {
            sha256: candidate.sha256,
            validator: candidate.validator,
            profile: candidate.profile,
            diagnostics,
            inherited: inherited.len(),
            unvalidated: candidate.unvalidated,
        }
    }
}
