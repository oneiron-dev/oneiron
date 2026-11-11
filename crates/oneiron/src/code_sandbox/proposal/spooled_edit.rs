//! Whole-file proposals compared with a spooled boot snapshot.

use super::{
    LOWER_FRAME, SandboxFileEdit, SandboxFileEditProposal, SandboxFileWriteProposal,
    SandboxProposalBody, SandboxProposalText, zeroed,
};
use crate::{Error, Result, engine_executor::StepCancellation};
use std::{io::Read, time::Instant};

pub(super) fn lower(
    write: &SandboxFileWriteProposal,
    base: &SandboxProposalBody,
    cancel: &StepCancellation,
    deadline: Instant,
) -> Result<Option<SandboxFileEditProposal>> {
    checkpoint(cancel, deadline)?;
    let body = &write.body;
    if body == base {
        return Ok(None);
    }
    let shared = base.len().min(body.len());
    let mut before = zeroed(LOWER_FRAME)?;
    let mut after = zeroed(LOWER_FRAME)?;
    let mut old_reader = base.reader();
    let mut new_reader = body.reader();
    let mut prefix = 0;
    while prefix < shared {
        checkpoint(cancel, deadline)?;
        let want = (LOWER_FRAME as u64).min(shared - prefix) as usize;
        old_reader.read_exact(&mut before[..want])?;
        new_reader.read_exact(&mut after[..want])?;
        let same = before[..want]
            .iter()
            .zip(&after[..want])
            .take_while(|(a, b)| a == b)
            .count();
        prefix += same as u64;
        if same < want {
            break;
        }
    }
    // A valid UTF-8 sequence has at most three continuation bytes. Do not
    // byte-seek through an arbitrarily long invalid binary prefix or suffix.
    let mut retreated = 0;
    while prefix > 0 && !boundary(base, prefix)? {
        if retreated == 3 {
            return Err(Error::InvalidClaimBody("code edit base is not UTF-8"));
        }
        prefix -= 1;
        retreated += 1;
    }
    let mut suffix = 0;
    while suffix < shared - prefix {
        checkpoint(cancel, deadline)?;
        let want = (LOWER_FRAME as u64).min(shared - prefix - suffix) as usize;
        let old_tail = base.read_range(base.len() - suffix - want as u64, want)?;
        let new_tail = body.read_range(body.len() - suffix - want as u64, want)?;
        let same = old_tail
            .iter()
            .rev()
            .zip(new_tail.iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        suffix += same as u64;
        if same < want {
            break;
        }
    }
    let mut retreated = 0;
    while suffix > 0 && !boundary(base, base.len() - suffix)? {
        if retreated == 3 {
            return Err(Error::InvalidClaimBody("code edit base is not UTF-8"));
        }
        suffix -= 1;
        retreated += 1;
    }
    let old_end = base.len() - suffix;
    // Validate the entire base, including unchanged bytes, just as the slice
    // lowering does. UTF-8 sequences may cross any comparison frame boundary.
    let (start, end) = char_offsets(base, prefix, old_end, cancel, deadline)?;
    let expected = SandboxProposalText::from_body(
        base,
        prefix,
        old_end - prefix,
        "code edit base is not UTF-8",
        || checkpoint(cancel, deadline),
    )?;
    let replacement = SandboxProposalText::from_body(
        body,
        prefix,
        body.len() - prefix - suffix,
        "code edit output is not UTF-8",
        || checkpoint(cancel, deadline),
    )?;
    Ok(Some(SandboxFileEditProposal {
        path: write.path.clone(),
        base_content_hash: base.digest(),
        edit: SandboxFileEdit {
            path: write.path.relative_path().to_owned(),
            start,
            end,
            expected,
            replacement,
            new_path: None,
        },
    }))
}

fn boundary(base: &SandboxProposalBody, at: u64) -> Result<bool> {
    Ok(at == base.len() || base.read_range(at, 1)?[0] & 0xc0 != 0x80)
}

/// Counts character offsets while validating the full stream. At most one
/// incomplete UTF-8 sequence stays between reads, never an entire source file.
fn char_offsets(
    base: &SandboxProposalBody,
    start: u64,
    end: u64,
    cancel: &StepCancellation,
    deadline: Instant,
) -> Result<(usize, usize)> {
    let invalid = || Error::InvalidClaimBody("code edit base is not UTF-8");
    let mut frame = zeroed(LOWER_FRAME)?;
    let mut reader = base.reader();
    let mut carry = 0;
    let mut offset = 0;
    let mut start_chars = 0usize;
    let mut end_chars = 0usize;
    loop {
        checkpoint(cancel, deadline)?;
        let read = reader.read(&mut frame[carry..])?;
        if read == 0 {
            if carry != 0 {
                return Err(invalid());
            }
            return Ok((start_chars, end_chars));
        }
        let total = carry + read;
        let valid = match std::str::from_utf8(&frame[..total]) {
            Ok(_) => total,
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Err(invalid()),
        };
        let text = std::str::from_utf8(&frame[..valid]).map_err(|_| invalid())?;
        for (at, _) in text.char_indices() {
            let at = offset + at as u64;
            start_chars += usize::from(at < start);
            end_chars += usize::from(at < end);
        }
        offset += valid as u64;
        carry = total - valid;
        frame.copy_within(valid..total, 0);
    }
}

pub(super) fn checkpoint(cancel: &StepCancellation, deadline: Instant) -> Result<()> {
    cancel.check()?;
    if Instant::now() >= deadline {
        return Err(Error::InvalidClaimBody("code edit deadline exceeded"));
    }
    Ok(())
}
