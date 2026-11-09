//! Lifted half of `oneiron::code_sandbox::proposal::body::text` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::proposal::body::text::*;
#[allow(unused_imports)]
use crate::ext::*;
use super::SandboxProposalBody;
use crate::Error;
use crate::Result;
use memmap2::MmapOptions;
use std::sync::Arc;

/// Methods of [`SandboxProposalText`] that moved out of `oneiron` with `code_sandbox::proposal::body::text` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxProposalBodyTextSandboxProposalTextExt {
    fn from_body(
        body: &SandboxProposalBody,
        offset: u64,
        len: u64,
        invalid_utf8: &'static str,
        mut checkpoint: impl FnMut() -> Result<()>,
    ) -> Result<Self>;
    /// The exact text. No changed span is recollected into a `String`.
    #[must_use]
    fn as_str(&self) -> &str;
}

impl CodeSandboxProposalBodyTextSandboxProposalTextExt for SandboxProposalText {
    fn from_body(
            body: &SandboxProposalBody,
            offset: u64,
            len: u64,
            invalid_utf8: &'static str,
            mut checkpoint: impl FnMut() -> Result<()>,
        ) -> Result<Self> {
            checkpoint()?;
            if offset.checked_add(len).is_none_or(|end| end > body.len) {
                return Err(Error::InvalidClaimBody("proposal body range out of bounds"));
            }
            if len == 0 {
                return Ok(Self::default());
            }
            let len = usize::try_from(len)
                .map_err(|_| Error::InvalidClaimBody("code edit span exceeds host memory"))?;
            let file = body
                .spooled
                .file
                .lock()
                .map_err(|_| Error::InvalidClaimBody("proposal body poisoned"))?;
            // SAFETY: finish consumes the only writer. The settled body's file is
            // private; all subsequent access only seeks or reads it, never writes or
            // truncates it. Its anonymous file is not exposed by path or descriptor.
            // The checked span lies within that immutable file, retained below.
            let map = unsafe {
                MmapOptions::new()
                    .offset(body.offset + offset)
                    .len(len)
                    .map(&*file)?
            };
            drop(file);
            let mut at = 0;
            while at < map.len() {
                checkpoint()?;
                let end = at.saturating_add(super::super::LOWER_FRAME).min(map.len());
                match std::str::from_utf8(&map[at..end]) {
                    Ok(_) => at = end,
                    Err(error) if error.error_len().is_none() && end < map.len() => {
                        // Revisit only the incomplete scalar in the next frame.
                        at += error.valid_up_to();
                    }
                    Err(_) => return Err(Error::InvalidClaimBody(invalid_utf8)),
                }
            }
            checkpoint()?;
            Ok(Self(Text::Mapped(Arc::new(MappedText {
                map,
                _body: body.clone(),
            }))))
        }

    /// The exact text. No changed span is recollected into a `String`.
    #[must_use]
    fn as_str(&self) -> &str {
            match &self.0 {
                Text::Empty => "",
                Text::Inline(text) => text.as_str(),
                // SAFETY: from_body validated the entire span as UTF-8 before
                // publishing it. The backing file cannot change, and MappedText
                // retains both the mapping and its body for this borrow's lifetime.
                Text::Mapped(text) => unsafe { std::str::from_utf8_unchecked(&text.map) },
            }
        }
}
