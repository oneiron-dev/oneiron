//! The native runtime a local tagger runs on.

use std::str::FromStr;

use serde::Deserialize;

/// Native inference runtime. Endpoint providers keep their own runtime.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum OneironerRuntime {
    #[default]
    Candle,
}

impl OneironerRuntime {
    pub const fn as_str(self) -> &'static str {
        "candle"
    }
}

impl FromStr for OneironerRuntime {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "candle" => Ok(Self::Candle),
            _ => Err("oneironer runtime must be candle".to_owned()),
        }
    }
}
