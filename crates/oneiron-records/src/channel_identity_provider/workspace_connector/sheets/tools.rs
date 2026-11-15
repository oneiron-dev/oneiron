//! Moved from `crates/oneiron/src/channel_identity_provider/workspace_connector/sheets/tools.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;

/// How a read renders cell values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueRenderOption {
    FormattedValue,
    UnformattedValue,
    Formula,
}

impl ValueRenderOption {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FormattedValue => "FORMATTED_VALUE",
            Self::UnformattedValue => "UNFORMATTED_VALUE",
            Self::Formula => "FORMULA",
        }
    }
}

/// How a write reads the values it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueInputOption {
    Raw,
    UserEntered,
}

impl ValueInputOption {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::UserEntered => "USER_ENTERED",
        }
    }
}

/// Whether the outer value lists are rows or columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MajorDimension {
    Rows,
    Columns,
}

impl MajorDimension {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rows => "ROWS",
            Self::Columns => "COLUMNS",
        }
    }
}
