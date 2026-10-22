//! An answer's bytes, in the organ's own memory (FIX 8454). Bytes that ride
//! inline came with the answer's frame. A region the engine sealed is
//! mapped, its bytes reserved by a `memory.grow` of their own, then copied
//! out and unmapped as the answer arrives: the engine's pages are never
//! held past the ask, and the copy is on the machine's memory floor before
//! it is made. An owner that keeps the bytes takes them whole
//! ([`AskBytes::into_parts`]), so nothing copies them again.

use std::ops::Deref;
use std::os::fd::OwnedFd;

use super::AskLine;
use crate::memory::{ASK_MEMORY_GROW, MemoryAnswer, MemoryAsk};
use crate::region::MappedRegion;
use crate::wire::{AskCode, AskData, AskRefusal, Hash32, Payload};

/// An answer's bytes, in the organ's own memory.
#[derive(Debug)]
pub struct AskBytes {
    pub content_hash: Hash32,
    bytes: Vec<u8>,
    memory: AnswerMemory,
}

/// What holds an answer's bytes in the machine's memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnswerMemory {
    /// Copied out of the engine's region once `memory.grow` reserved
    /// `bytes`: the engine's host holds them in the call's room until the
    /// call ends.
    Reserved { bytes: u64 },
    /// Inline in the answer's frame, as the frame decoded them.
    Inline,
    /// Copied out unreserved: no host reserves this organ's memory (its
    /// grant names no `memory.grow`, or the session speaks 1.0).
    Unreserved,
}

impl AskBytes {
    /// What holds these bytes in the machine's memory.
    #[must_use]
    pub fn memory(&self) -> AnswerMemory {
        self.memory
    }

    /// The bytes themselves and what holds them, for an owner that keeps
    /// them on: it adopts this allocation, and no second copy is made.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, AnswerMemory) {
        (self.bytes, self.memory)
    }
}

impl Deref for AskBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AskLine {
    /// An answer's bytes in this process's memory: inline as they came, or
    /// copied out of the engine's region once they are reserved.
    pub(super) fn answer_bytes(
        &self,
        data: AskData,
        fds: Vec<OwnedFd>,
    ) -> Result<AskBytes, AskRefusal> {
        let broken = |what: &str| AskRefusal::new(AskCode::Failed, format!("answer data: {what}"));
        let (bytes, memory) = match data.data {
            Payload::Inline(bytes) if bytes.len() as u64 == data.len => {
                (bytes.into_vec(), AnswerMemory::Inline)
            }
            Payload::Inline(_) => return Err(broken("inline length")),
            Payload::Slot(slot) => {
                let fd = fds
                    .into_iter()
                    .nth(usize::from(slot))
                    .ok_or_else(|| broken("slot"))?;
                // The engine's pages, mapped: nothing of this process's yet.
                let region =
                    MappedRegion::map(fd, data.len).map_err(|err| broken(&err.to_string()))?;
                let memory = self.reserve(data.len)?;
                // Copied, then unmapped here; the descriptor closes too.
                (region.to_vec(), memory)
            }
        };
        Ok(AskBytes {
            content_hash: data.content_hash,
            bytes,
            memory,
        })
    }

    /// Reserves `bytes` this process is about to copy, by a `memory.grow`
    /// ask: the engine's host leases them from the machine's floor. A host
    /// that reserves nothing for this organ leaves the copy as it was; the
    /// floor and the deadline are refusals, retryable.
    fn reserve(&self, bytes: u64) -> Result<AnswerMemory, AskRefusal> {
        let failed = |detail: String| AskRefusal::new(AskCode::Failed, detail).retryable();
        if bytes == 0 {
            return Ok(AnswerMemory::Reserved { bytes });
        }
        let value = to_value(&MemoryAsk { bytes })
            .ok_or_else(|| failed("the memory ask did not encode".to_owned()))?;
        let (value, _) = match self.exchange(ASK_MEMORY_GROW, value) {
            Ok(answered) => answered,
            Err(refusal) if matches!(refusal.code, AskCode::NotGranted | AskCode::Unsupported) => {
                return Ok(AnswerMemory::Unreserved);
            }
            Err(refusal) => return Err(refusal),
        };
        match from_value::<MemoryAnswer>(&value) {
            Some(MemoryAnswer::Granted) => Ok(AnswerMemory::Reserved { bytes }),
            Some(MemoryAnswer::Floor { needed, available }) => Err(failed(format!(
                "the machine cannot hold the answer's {bytes} bytes: {needed} needed, \
                 {available} available"
            ))),
            Some(MemoryAnswer::Deadline) => Err(failed(
                "the answer's bytes were not reserved before the call's deadline".to_owned(),
            )),
            None => Err(failed("the memory answer did not read".to_owned())),
        }
    }
}

/// A wire value with named fields.
fn to_value<T: serde::Serialize>(value: &T) -> Option<rmpv::Value> {
    let bytes = rmp_serde::to_vec_named(value).ok()?;
    rmpv::decode::read_value(&mut bytes.as_slice()).ok()
}

/// A wire value read as `T`, by its field names.
fn from_value<T: serde::de::DeserializeOwned>(value: &rmpv::Value) -> Option<T> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}
