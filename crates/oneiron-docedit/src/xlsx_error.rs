//! Workbook read and projection errors.
//! Entry: `XlsxBodyError`.
//! The error is defined here; xlsx_body re-exports it and styles imports it directly.

use crate::ooxml::XmlError;
use crate::retained_opc;

#[derive(Debug, thiserror::Error)]
pub enum XlsxBodyError {
    #[error(transparent)]
    Package(#[from] retained_opc::Error),
    #[error(transparent)]
    Xml(#[from] XmlError),
    #[error("XLSX body refused: {0}")]
    Refused(&'static str),
}
