//! A callable skill's answer, spooled to disk as it streams and checked
//! against its return contract as it is read, with no value tree built.

use std::io::{Read, Seek, Write};

use serde_json::Value as JsonValue;

use super::json_tokens::{AnswerMemory, check_answer};

/// A callable skill's answer: a temporary file from its first byte, so no
/// part of it sits in memory outside the caller's result share (FIX 10149),
/// gone when this drops. Nothing refuses it for size.
pub struct CallableSkillAnswer {
    body: tempfile::SpooledTempFile,
    len: u64,
}

impl CallableSkillAnswer {
    pub(super) fn spool() -> Self {
        Self {
            body: tempfile::SpooledTempFile::new(0),
            len: 0,
        }
    }

    /// Starts the answer over: a later `finish` replaces an earlier one.
    pub(super) fn restart(&mut self) -> crate::Result<()> {
        self.body.set_len(0)?;
        self.body.rewind()?;
        self.len = 0;
        Ok(())
    }

    pub(super) fn write(&mut self, frame: &[u8]) -> crate::Result<()> {
        self.body.write_all(frame)?;
        self.len = self.len.saturating_add(frame.len() as u64);
        Ok(())
    }

    /// The answer's length in bytes.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.len
    }

    /// The answer, read from its first byte.
    pub fn reader(&mut self) -> crate::Result<&mut impl Read> {
        self.body.rewind()?;
        Ok(&mut self.body)
    }

    /// Reads the answer once, judging it against `shape` as the contract
    /// judges a parsed value: its SHA-256 when it is JSON within the
    /// contract, `None` when it is JSON outside it. Bytes that are no JSON
    /// are an error. The check's buffers are held on `memory`, the caller's
    /// result share, when it lent one.
    pub(super) fn check(
        &mut self,
        shape: &JsonValue,
        memory: Option<AnswerMemory<'_>>,
    ) -> crate::Result<Option<[u8; 32]>> {
        self.body.rewind()?;
        check_answer(&mut self.body, shape, memory)
    }
}
