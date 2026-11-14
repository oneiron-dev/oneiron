//! The `erase_request_reply` policy row (ARCH-0043 #leaving-a-company: "The
//! reply to an erase request is each owner's setting"; Engine ruling
//! L7-09-REPLY-SETTING = A): one versioned row in the vault's policy
//! manifest that says how this vault answers a filed courtesy ask. Its only
//! writer today is the Owner's manifest install, as for the `inquiry` row.
//!
//! Wire shape, version 1:
//!
//! ```text
//! erase_request_reply: { version: 1, reply: "ask" | "honour" | "decline" }
//! ```
//!
//! No row means `ask`: every filed ask waits for the owner's pick, as
//! before this row existed. A row with an unknown version, an unknown or
//! missing field or an unknown reply makes the whole manifest unreadable,
//! as every other manifest key does; an unreadable policy also reads `ask`,
//! the setting that acts on nothing by itself. Filing stays pure under
//! every setting: receiving an ask deletes nothing.

use rmpv::Value;

use crate::Vault;
use crate::error::Result;

/// The policy-manifest key of the erase-request reply row.
pub(crate) const ERASE_REQUEST_REPLY_ROW_KEY: &str = "erase_request_reply";

/// The only version of the row this build reads.
pub const ERASE_REQUEST_REPLY_ROW_VERSION: u16 = 1;

/// How this vault answers a filed courtesy ask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EraseRequestReply {
    /// The ask waits for the owner's pick.
    Ask,
    /// The ask is answered `acknowledged`: what it names is erased, except
    /// a record a retention rule or a hold covers.
    Honour,
    /// The ask is answered `declined`; nothing is erased.
    Decline,
}

impl EraseRequestReply {
    /// The row's token for this reply.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Honour => "honour",
            Self::Decline => "decline",
        }
    }

    /// The reply a row token names; `None` for any other token.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "ask" => Some(Self::Ask),
            "honour" => Some(Self::Honour),
            "decline" => Some(Self::Decline),
            _ => None,
        }
    }
}

/// The decoded `erase_request_reply` row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EraseRequestReplyPolicy {
    reply: EraseRequestReply,
}

impl EraseRequestReplyPolicy {
    /// How the row says this vault answers a filed ask.
    #[must_use]
    pub const fn reply(self) -> EraseRequestReply {
        self.reply
    }

    /// Decodes the manifest row. `None` for anything but a well-formed
    /// version 1 row (module doc).
    pub(crate) fn decode_row(value: &Value) -> Option<Self> {
        let fields = value.as_map()?;
        if fields.len() != 2 {
            return None;
        }
        let version = u16::try_from(map_field(fields, "version")?.as_u64()?).ok()?;
        if version != ERASE_REQUEST_REPLY_ROW_VERSION {
            return None;
        }
        let reply = EraseRequestReply::from_token(map_field(fields, "reply")?.as_str()?)?;
        Some(Self { reply })
    }
}

/// What the vault's resolved policy says about the erase-request reply row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EraseRequestReplyRead {
    /// No trusted manifest names the row.
    NoRow,
    Row(EraseRequestReplyPolicy),
    /// The resolved policy failed closed.
    Unreadable,
}

/// Where the vault's erase-request reply came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EraseRequestReplySource {
    /// No row: `ask`, the behaviour before the row existed.
    Default,
    /// The `erase_request_reply` row of the vault's policy.
    Row,
    /// The policy failed closed: `ask`, the setting that acts on nothing by
    /// itself.
    Unreadable,
}

/// The vault's erase-request reply and its source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EraseRequestReplySetting {
    pub reply: EraseRequestReply,
    pub source: EraseRequestReplySource,
}

impl Vault {
    /// The owner's setting `erase_request_reply`, as this vault's policy
    /// resolves it now.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn erase_request_reply(&self) -> Result<EraseRequestReplySetting> {
        let txn = self.store.env.read_txn()?;
        let read =
            crate::gate::resolve_policy_manifest(&self.store, &txn)?.erase_request_reply_policy();
        Ok(match read {
            EraseRequestReplyRead::NoRow => EraseRequestReplySetting {
                reply: EraseRequestReply::Ask,
                source: EraseRequestReplySource::Default,
            },
            EraseRequestReplyRead::Row(policy) => EraseRequestReplySetting {
                reply: policy.reply(),
                source: EraseRequestReplySource::Row,
            },
            EraseRequestReplyRead::Unreadable => EraseRequestReplySetting {
                reply: EraseRequestReply::Ask,
                source: EraseRequestReplySource::Unreadable,
            },
        })
    }
}

/// The value of the one `name` field of a manifest map; `None` when it is
/// absent or repeated.
fn map_field<'a>(fields: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut found = fields.iter().filter(|(key, _)| key.as_str() == Some(name));
    let (_, value) = found.next()?;
    found.next().is_none().then_some(value)
}
