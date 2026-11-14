//! Moved from `crates/oneiron/src/runtime_hooks/source.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// Where a fact comes from. Each source has its own cursor.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FactSource {
    /// Claim writes, in commit order.
    ClaimChangelog,
    /// Settled proposals, in settlement order.
    Settlement,
    /// Due TASK ticks, in release order (FIX 4749).
    Schedule,
    /// Inbound connector surface events, in admission order (FIX 4749).
    SurfaceInbound,
}

impl FactSource {
    pub const ALL: [Self; 4] = [
        Self::ClaimChangelog,
        Self::Settlement,
        Self::Schedule,
        Self::SurfaceInbound,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimChangelog => "claim_changelog",
            Self::Settlement => "settlement",
            Self::Schedule => "schedule",
            Self::SurfaceInbound => "surface_inbound",
        }
    }

    pub const fn tag(self) -> u8 {
        match self {
            Self::ClaimChangelog => 0,
            Self::Settlement => 1,
            Self::Schedule => 2,
            Self::SurfaceInbound => 3,
        }
    }
}

/// A claim changelog position: the audit record id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimChangelogPosition(pub [u8; 16]);

/// A settlement position: the feed's committed sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettlementPosition(pub u64);

/// A tick feed position: the sequence its release committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulePosition(pub u64);

/// An inbound feed position: the sequence its admission committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SurfaceInboundPosition(pub u64);

/// A position in one source. Two positions compare only within one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactPosition {
    ClaimChangelog(ClaimChangelogPosition),
    Settlement(SettlementPosition),
    Schedule(SchedulePosition),
    SurfaceInbound(SurfaceInboundPosition),
}

impl FactPosition {
    #[must_use]
    pub const fn source(self) -> FactSource {
        match self {
            Self::ClaimChangelog(_) => FactSource::ClaimChangelog,
            Self::Settlement(_) => FactSource::Settlement,
            Self::Schedule(_) => FactSource::Schedule,
            Self::SurfaceInbound(_) => FactSource::SurfaceInbound,
        }
    }

    /// The position's own bytes: the record id, or the sequence big-endian.
    #[must_use]
    pub fn bytes(self) -> Vec<u8> {
        match self {
            Self::ClaimChangelog(position) => position.0.to_vec(),
            Self::Settlement(position) => position.0.to_be_bytes().to_vec(),
            Self::Schedule(position) => position.0.to_be_bytes().to_vec(),
            Self::SurfaceInbound(position) => position.0.to_be_bytes().to_vec(),
        }
    }

    /// Lowercase hex of [`Self::bytes`], as a hook's input carries it.
    #[must_use]
    pub fn hex(self) -> String {
        oneiron_store::receipt_row::hex_lower(&self.bytes())
    }

    /// The source-tagged form replay takes.
    #[must_use]
    pub fn to_hex(self) -> FactPositionHex {
        FactPositionHex(format!("{}:{}", self.source().as_str(), self.hex()))
    }
}

/// A position as text: `claim_changelog:<hex32>`, or `settlement:<hex16>`,
/// `schedule:<hex16>` or `surface_inbound:<hex16>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct FactPositionHex(pub String);

impl FactPositionHex {
    /// The typed position this text names.
    pub fn parse(&self) -> Result<FactPosition> {
        let (source, hex) = self
            .0
            .split_once(':')
            .ok_or_else(|| invalid("a fact position is <source>:<hex>"))?;
        match source {
            "claim_changelog" => Ok(FactPosition::ClaimChangelog(ClaimChangelogPosition(
                decode_hex(hex)?,
            ))),
            "settlement" => Ok(FactPosition::Settlement(SettlementPosition(
                u64::from_be_bytes(decode_hex(hex)?),
            ))),
            "schedule" => Ok(FactPosition::Schedule(SchedulePosition(
                u64::from_be_bytes(decode_hex(hex)?),
            ))),
            "surface_inbound" => Ok(FactPosition::SurfaceInbound(SurfaceInboundPosition(
                u64::from_be_bytes(decode_hex(hex)?),
            ))),
            _ => Err(invalid("unknown fact source")),
        }
    }
}

/// The kinds of fact the runner follows: slice 1's, and the two watcher
/// sources (FIX 4749).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub enum FactKind {
    #[serde(rename = "claim.landed")]
    ClaimLanded,
    #[serde(rename = "claim.superseded")]
    ClaimSuperseded,
    #[serde(rename = "proposal.settled")]
    ProposalSettled,
    /// A TASK's due time passed (ARCH-0080 §4 Watchers).
    #[serde(rename = "schedule.tick")]
    ScheduleTick,
    /// A connector SurfaceEvent was admitted (OF-247).
    #[serde(rename = "surface.inbound")]
    SurfaceInbound,
}

impl FactKind {
    pub const ALL: [Self; 5] = [
        Self::ClaimLanded,
        Self::ClaimSuperseded,
        Self::ProposalSettled,
        Self::ScheduleTick,
        Self::SurfaceInbound,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimLanded => "claim.landed",
            Self::ClaimSuperseded => "claim.superseded",
            Self::ProposalSettled => "proposal.settled",
            Self::ScheduleTick => "schedule.tick",
            Self::SurfaceInbound => "surface.inbound",
        }
    }

    /// The kind `token` names, as a selector entry spells it.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == token)
    }

    /// Whether the kind is a watcher source: no write made it, so it
    /// carries no claim and no verb hook sees it (FIX 4749).
    #[must_use]
    pub const fn is_watcher_source(self) -> bool {
        matches!(self, Self::ScheduleTick | Self::SurfaceInbound)
    }
}

pub fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return Err(invalid("fact position has the wrong length"));
    }
    let mut out = [0_u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

pub fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid("fact position is not lowercase hex")),
    }
}

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
