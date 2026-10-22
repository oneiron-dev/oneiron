//! The typed segment manifest of one model call (DESIGN-V2 §3.1, R2): which
//! bytes of which [`LlmRequest`](super::LlmRequest) message came from where,
//! on which clock, behind which trust fence, and whether they belong to the
//! canonical path (the stable prefix and the selected log) or to the turn's
//! ephemeral tail (the context board and the newest user message).
//!
//! The host builds a manifest beside the messages as it assembles them and
//! sets it on the request after admission
//! ([`LlmRequest::host_segments`](super::LlmRequest::host_segments)); it is
//! never read from a wire, never part of a request's canonical bytes, and
//! every adapter but the native EXL3 transport ignores it. Provenance no
//! producer knows stays unknown (`None`), never guessed. A manifest is bound
//! to the exact messages it describes ([`SegmentManifest::describes`]): one
//! that no longer matches them describes nothing, and a call it does not
//! describe runs as it always did.
//!
//! Reuse never removes a fence: a guest segment stays data, never
//! instructions, and the board is never canonical.
use serde::Serialize;

use super::session::ConversationAnchor;
use super::{ContentPart, LlmMessage, LlmMessageRole};
use oneiron_contracts::EntityId;

/// Fixed-width bytes that travel as lowercase hex.
macro_rules! hex_bytes {
    ($(#[$doc:meta])* $name:ident, $len:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// The bytes from their lowercase hex form.
            #[must_use]
            pub fn from_hex(hex: &str) -> Option<Self> {
                $crate::llm::segments::parse_hex(hex).map(Self)
            }

            #[must_use]
            pub fn to_hex(&self) -> String {
                ::oneiron_contracts::entity_id::bytes_to_hex_lower(&self.0)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let hex = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                Self::from_hex(&hex).ok_or_else(|| {
                    ::serde::de::Error::custom(concat!(stringify!($name), " is not lowercase hex"))
                })
            }
        }
    };
}
pub(super) use hex_bytes;

/// `hex` as `N` bytes: exactly `2 * N` lowercase hex digits.
pub(super) fn parse_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let digits = hex.as_bytes();
    if digits.len() != 2 * N {
        return None;
    }
    let nibble = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut bytes = [0_u8; N];
    for (byte, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(bytes)
}

hex_bytes!(
    /// BLAKE3 of a manifest's segments, anchor and message stamps.
    ManifestDigest,
    32
);
hex_bytes!(
    /// BLAKE3 of one message as a manifest binds it: its role, whether it
    /// is plain text, and its text ([`message_digest`]).
    MessageDigest,
    32
);
hex_bytes!(
    /// A vault revision a segment's bytes were read at: the revision ref's
    /// own bytes, opaque here.
    SourceRevision,
    16
);

/// What a segment is, in the order a renderer places it. Closed: a new
/// piece of prompt is a new variant, never a free string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    /// The soul, an agent's instructions, or a system prompt.
    System,
    /// A host-owned section of the system text, or a host block (an
    /// agent's resident craft).
    HostSection,
    /// One activated memory in the system text.
    ActivatedMemory,
    /// The tool definitions the template renders.
    Tools,
    /// One retained message of the selected log.
    LogMessage,
    /// A landed summary standing in the log for the turns it covers.
    LogSummary,
    /// One section of the rendered context board, by its rendered name.
    BoardSection(String),
    /// The turn's newest user message.
    NewestUser,
}

/// The clock a segment changes on (ARCH-0067 canon): the stable epoch
/// prefix, the append-only log, or the live turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentClock {
    Epoch,
    Log,
    Live,
}

/// Where a segment's bytes came from; `None` when no producer knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SegmentLocator {
    None,
    /// A retained MESSAGE.
    Message {
        id: EntityId,
    },
    /// A landed summary and the fold epoch it landed in.
    Summary {
        id: EntityId,
        epoch: u64,
    },
    /// A memory row, at the revision its body was served at when the read
    /// pinned one.
    Memory {
        id: EntityId,
        revision: Option<SourceRevision>,
    },
    /// A skill, at the version its lifecycle chain served.
    Skill {
        id: EntityId,
        version: Option<String>,
    },
    /// A tool call's result, by its call id.
    ToolCall {
        call_id: String,
    },
    /// A context-board section, by its rendered name.
    BoardSection {
        name: String,
    },
}

impl SegmentLocator {
    #[must_use]
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Whether a segment renders as the host's own text or as guest evidence:
/// data, never instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustFence {
    Authoritative,
    Guest,
}

/// A segment's disclosure band, where its producer knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureLabel {
    Public,
    Private,
    Sensitive,
    Restricted,
}

/// Whether a segment belongs to the canonical path a session may keep, or
/// to the turn's ephemeral tail, which is rendered and admitted fresh every
/// turn and never kept: the board and the newest user message always are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentClass {
    Canonical,
    Ephemeral,
}

impl SegmentClass {
    /// The class `kind` always has: the board and the newest user message
    /// are ephemeral; every other kind is canonical.
    #[must_use]
    pub fn of(kind: &SegmentKind) -> Self {
        match kind {
            SegmentKind::BoardSection(_) | SegmentKind::NewestUser => Self::Ephemeral,
            _ => Self::Canonical,
        }
    }
}

/// A byte range inside one message's text, when the message holds more
/// than one segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

/// One segment of a call's messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Segment {
    pub kind: SegmentKind,
    pub clock: SegmentClock,
    pub locator: SegmentLocator,
    /// The revision the bytes were read at, where the read pinned one.
    pub source_revision: Option<SourceRevision>,
    /// What else the bytes were read from: a board section's memory rows
    /// and skills.
    pub dependencies: Vec<SegmentLocator>,
    pub fence: TrustFence,
    pub disclosure: Option<DisclosureLabel>,
    pub class: SegmentClass,
    /// The index of the request message it lies in.
    pub message: usize,
    /// Where in that message's text, when the message holds several.
    pub bytes: Option<ByteSpan>,
}

impl Segment {
    /// A segment of `kind` that is all of message `message`, authoritative,
    /// with its kind's class and nothing else known.
    #[must_use]
    pub fn whole(kind: SegmentKind, clock: SegmentClock, message: usize) -> Self {
        Self {
            class: SegmentClass::of(&kind),
            kind,
            clock,
            locator: SegmentLocator::None,
            source_revision: None,
            dependencies: Vec::new(),
            fence: TrustFence::Authoritative,
            disclosure: None,
            message,
            bytes: None,
        }
    }

    #[must_use]
    pub fn at(mut self, locator: SegmentLocator) -> Self {
        self.locator = locator;
        self
    }

    #[must_use]
    pub fn within(mut self, bytes: ByteSpan) -> Self {
        self.bytes = Some(bytes);
        self
    }
}

/// One message as a manifest binds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MessageStamp {
    pub digest: MessageDigest,
    /// The message is text alone: no image, audio, reasoning or tool part.
    pub plain: bool,
}

/// The ordered segments of one call's messages, bound to those messages,
/// with the conversation they were read from when a producer names one.
#[derive(Clone)]
pub struct SegmentManifest {
    segments: Vec<Segment>,
    anchor: Option<ConversationAnchor>,
    messages: Vec<MessageStamp>,
    digest: ManifestDigest,
}

impl SegmentManifest {
    /// The manifest of `segments` over `messages`, read from `anchor`'s
    /// conversation when it names one.
    #[must_use]
    pub fn new(
        segments: Vec<Segment>,
        anchor: Option<ConversationAnchor>,
        messages: &[LlmMessage],
    ) -> Self {
        let messages: Vec<MessageStamp> = messages.iter().map(message_stamp).collect();
        let digest = manifest_digest(&segments, anchor.as_ref(), &messages);
        Self {
            segments,
            anchor,
            messages,
            digest,
        }
    }

    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    #[must_use]
    pub fn anchor(&self) -> Option<&ConversationAnchor> {
        self.anchor.as_ref()
    }

    #[must_use]
    pub fn digest(&self) -> &ManifestDigest {
        &self.digest
    }

    #[must_use]
    pub fn messages(&self) -> &[MessageStamp] {
        &self.messages
    }

    /// Whether the manifest describes exactly `messages`, in order.
    #[must_use]
    pub fn describes(&self, messages: &[LlmMessage]) -> bool {
        messages.len() == self.messages.len()
            && messages
                .iter()
                .zip(&self.messages)
                .all(|(message, stamp)| message_stamp(message) == *stamp)
    }

    /// How many leading messages form the canonical path: each holds at
    /// least one segment, every segment of it is canonical, its log
    /// segments name where they were read, and it is plain text (the
    /// conservative cut before any image, audio, reasoning or tool part).
    /// The first message that is not ends it.
    #[must_use]
    pub fn canonical_prefix(&self) -> usize {
        (0..self.messages.len())
            .take_while(|&index| {
                let mut segments = self
                    .segments
                    .iter()
                    .filter(|segment| segment.message == index)
                    .peekable();
                segments.peek().is_some()
                    && self.messages[index].plain
                    && segments.all(|segment| {
                        segment.class == SegmentClass::Canonical
                            && (!matches!(
                                segment.kind,
                                SegmentKind::LogMessage | SegmentKind::LogSummary
                            ) || segment.locator.is_known())
                    })
            })
            .count()
    }
}

impl std::fmt::Debug for SegmentManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentManifest")
            .field("digest", &self.digest)
            .field("segments", &self.segments.len())
            .finish_non_exhaustive()
    }
}

/// Two manifests are equal when their digests are.
impl PartialEq for SegmentManifest {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

/// One message's digest as a manifest binds it: `role`, whether it is plain
/// text, and `text`, its text parts joined. Both sides of a call compute it
/// this way, from the request's messages or from their wire form.
#[must_use]
pub fn message_digest(role: &str, plain: bool, text: &str) -> MessageDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.llm.segments.message.v1\0");
    hasher.update(role.as_bytes());
    hasher.update(&[0, u8::from(plain)]);
    hasher.update(text.as_bytes());
    MessageDigest(*hasher.finalize().as_bytes())
}

/// The wire name of a message's role.
#[must_use]
pub fn role_name(role: LlmMessageRole) -> &'static str {
    match role {
        LlmMessageRole::System => "system",
        LlmMessageRole::User => "user",
        LlmMessageRole::Assistant => "assistant",
        LlmMessageRole::Tool => "tool",
    }
}

fn message_stamp(message: &LlmMessage) -> MessageStamp {
    let mut text = String::new();
    let mut plain = message.role != LlmMessageRole::Tool;
    for part in &message.content {
        match part {
            ContentPart::Text { text: piece } => text.push_str(piece),
            _ => plain = false,
        }
    }
    MessageStamp {
        digest: message_digest(role_name(message.role), plain, &text),
        plain,
    }
}

fn manifest_digest(
    segments: &[Segment],
    anchor: Option<&ConversationAnchor>,
    messages: &[MessageStamp],
) -> ManifestDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.llm.segments.manifest.v1\0");
    let bytes = super::canonical_json_bytes(&(segments, anchor, messages)).unwrap_or_default();
    hasher.update(&bytes);
    ManifestDigest(*hasher.finalize().as_bytes())
}
