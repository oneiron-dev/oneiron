//! Staging an ASSET body from a reader before the transaction that puts it
//! (FIX 3677): the body streams into the body directory, measured as it
//! passes, and is published as a file only when it is long and opaque, or
//! long MessagePack the whole-body classification files, a record its
//! stored-row readers read nothing from among them (FIX 12150). On a
//! sealed vault it spills sealed as it streams and is published as an
//! envelope, whose key row the put commits (FIX 5348). While the file plane
//! is on, the values custody holds are found in the stream too, and marked
//! when the put binds the file (FIX 5395, `secret_scan::stream_known`).

use std::io::{self, Read};
use std::sync::Arc;

use heed::RwTxn;

use crate::asset_body::ASSET_FILE_PLANE;
use crate::asset_body::ASSET_INLINE_BODY_BYTES;
use crate::asset_body::AssetBodyFacts;
use crate::asset_body::AssetFileKind;
use crate::asset_body::AssetFileManifest;
use crate::result_body_pins::ResultBodyPin;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_ASSET;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;

/// The bytes of a body's head its stream classification reads: enough for
/// every owning adapter's tag and every container's magic.
pub const HEAD_BYTES: usize = 64;

/// What a streamed body's head shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamShape {
    /// None of the bodies a reader interprets: a body file as it streams.
    Opaque,
    /// A MessagePack map or array leads it (a record, or a pack source's
    /// envelope): judged whole before it is a body file (FIX 12150).
    MessagePack,
    /// A body a reader interprets: it stays in its row.
    Row,
}

/// What a body's `head` shows it: an owning adapter's tag (each names
/// itself `oneiron.` at the head, one byte in at most) or a ZIP, gzip or
/// PDF container stays in its row; a MessagePack map or array is judged
/// whole; any other head is opaque.
pub fn stream_shape(head: &[u8]) -> StreamShape {
    let Some(&lead) = head.first() else {
        return StreamShape::Row;
    };
    let tagged = |bytes: &[u8]| bytes.starts_with(b"oneiron.");
    if tagged(head)
        || head.get(1..).is_some_and(tagged)
        || crate::batch::secret_scan::container::is_container(head)
    {
        StreamShape::Row
    } else if matches!(lead, 0x80..=0x9f | 0xdc..=0xdf) {
        StreamShape::MessagePack
    } else {
        StreamShape::Opaque
    }
}

/// What the file plane makes of a staged body MessagePack leads (FIX 12150).
pub enum Judged {
    /// A body file of this kind.
    File(AssetFileKind),
    /// It stays in its row: its bytes, when the judgement read them whole.
    Row(Option<Vec<u8>>),
}

/// UTF-8 checked across frames, a character split between two carried.
#[derive(Default)]
pub struct Utf8Stream {
    pub broken: bool,
    pub carry: [u8; 4],
    pub carry_len: usize,
}

impl Utf8Stream {
    pub fn feed(&mut self, mut bytes: &[u8]) {
        while self.carry_len > 0 && !self.broken {
            let Some((first, after)) = bytes.split_first() else {
                return;
            };
            self.carry[self.carry_len] = *first;
            self.carry_len += 1;
            bytes = after;
            match std::str::from_utf8(&self.carry[..self.carry_len]) {
                Ok(_) => self.carry_len = 0,
                Err(error) if error.error_len().is_some() || self.carry_len == 4 => {
                    self.broken = true;
                }
                Err(_) => {}
            }
        }
        if self.broken {
            return;
        }
        if let Err(error) = std::str::from_utf8(bytes) {
            if error.error_len().is_some() {
                self.broken = true;
            } else {
                let tail = &bytes[error.valid_up_to()..];
                self.carry[..tail.len()].copy_from_slice(tail);
                self.carry_len = tail.len();
            }
        }
    }

    /// Whether every byte fed was UTF-8, the last character whole.
    pub const fn text(&self) -> bool {
        !self.broken && self.carry_len == 0
    }
}
