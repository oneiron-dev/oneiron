//! The document organ's namespace-aware reader, with this crate's errors.
use oneiron_docedit::retained_opc::Package;

pub(crate) use oneiron_docedit::ooxml::{
    DOCUMENT_RELATIONSHIPS as DOC_REL, PACKAGE_RELATIONSHIPS as REL, SPREADSHEET_MAIN as MAIN,
    XmlTree as Xml, escape_text as escaped,
};

use crate::{FormulaError, Result};

/// Parse one package part under the package's own XML limits.
pub(crate) fn parse_part(package: &Package, name: &str) -> Result<Xml> {
    let bytes = package
        .part(name)?
        .ok_or_else(|| invalid("missing workbook part"))?;
    Ok(Xml::parse(&bytes, package.limits().xml)?)
}

pub(crate) fn invalid(reason: &'static str) -> FormulaError {
    FormulaError::InvalidWorkbook(reason)
}
pub(crate) fn unsupported(reason: &'static str) -> FormulaError {
    FormulaError::UnsupportedWorkbook(reason)
}
