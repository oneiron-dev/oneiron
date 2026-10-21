//! The runtime setting a local tagger's workers are chosen by (FIX 6755,
//! Engine call 4).

use std::str::FromStr;

use serde::Deserialize;

/// Which runtimes a local slot serves with. Endpoint providers keep their
/// own runtime.
///
/// `auto`, the default, serves the Candle baseline, and a platform runtime
/// this machine installs joins it only once its answers clear the bundle's
/// reference here. `candle` pins the slot to Candle, as a named device does.
/// Neither is what ran a call: each call's receipt names the runtime that
/// ran it, and `auto` is never one. The baseline load, its survey and
/// `oneironer qualify` run on Candle under either.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum OneironerRuntime {
    #[default]
    Auto,
    Candle,
}

impl OneironerRuntime {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Candle => "candle",
        }
    }
}

impl FromStr for OneironerRuntime {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "candle" => Ok(Self::Candle),
            _ => Err("oneironer runtime must be auto or candle".to_owned()),
        }
    }
}
