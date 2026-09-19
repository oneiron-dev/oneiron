// Copyright (c) 2026 Stemma. Licensed under Apache-2.0.
// Oneiron fork: selected stateless engine components; see ../PROVENANCE.md.
#[derive(Debug)]
pub struct ValidationFinding {
    pub rule_id: &'static str,
    pub severity: ValidationSeverity,
    pub message: String,
    /// Where the problem was found (e.g., "word/document.xml", "word/_rels/document.xml.rels")
    pub location: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    /// Word will reject the file or lose data.
    Error,
    /// File opens but behavior may be wrong.
    Warning,
}
