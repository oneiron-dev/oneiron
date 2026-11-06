//! Document frame tags shared by persisted document consumers and transport.

/// Entity text-plane frame: `[tag][entity:16][kind:1][payload]`.
pub const TAG_DOCUMENT: u8 = 11;
/// Document batch: `[tag][len:4BE][document frame]...`. Nesting is forbidden.
pub const TAG_BATCH: u8 = 12;

/// Document payload kinds. A state copy replaces the receiver's document.
pub mod document_sub_tags {
    pub const UPDATE: u8 = 0;
    pub const STATE: u8 = 1;
    /// Payload is a selector request envelope, with the peer's document VV.
    pub const REQUEST: u8 = 2;
    /// Receiver VV after a durable import.
    pub const ACK: u8 = 3;
    /// Authenticated semantic NOTE command. Actor is bound out of band.
    pub const NOTE_OPS: u8 = 4;
    /// Idempotent NOTE command result, sent only to the requesting connection.
    pub const NOTE_RECEIPT: u8 = 5;
    /// An own device's pinned artifact pointer change, with the rows that
    /// serve it. Owner lane only; the entity names the channel and artifact.
    pub const ARTIFACT_PUBLICATION: u8 = 6;
    /// The sync server's answer to one publication: its digest and outcome.
    pub const ARTIFACT_RECEIPT: u8 = 7;
    /// Direct, nonterminal answer: one REQUEST or UPDATE waited out its open.
    pub const WAITED_OUT: u8 = 8;
    /// One ordered piece of a logical document, verified whole before admission.
    pub const PART: u8 = 13;
}
