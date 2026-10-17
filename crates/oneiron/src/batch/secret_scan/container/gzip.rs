//! A gzip file's payload: every member it chains, decoded in order as one
//! payload, each member's CRC-32 and length checked and nothing left after
//! the last. The rebuilt copy is one gzip member holding the masked payload,
//! without the original's name, comment or time.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;

use super::{Budget, Walked, encode_failed, over_budget, unreadable};
use crate::secret_custody::MemberStep;

fn payload(bytes: &[u8], budget: &mut Budget) -> Walked<Vec<u8>> {
    budget.member()?;
    let limit = budget.limit();
    let mut payload = Vec::new();
    // One byte past the limit is enough to tell a payload past it.
    MultiGzDecoder::new(bytes)
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut payload)
        .map_err(|_| unreadable())?;
    if payload.len() > limit {
        return Err(over_budget());
    }
    budget.spend(payload.len())?;
    Ok(payload)
}

pub(super) fn members(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    let payload = payload(bytes, budget)?;
    each(MemberStep::Gzip, &payload, budget)
}

pub(super) fn rebuilt(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<Option<Vec<u8>>>,
) -> Walked<Vec<u8>> {
    let payload = payload(bytes, budget)?;
    let payload = each(MemberStep::Gzip, &payload, budget)?.unwrap_or(payload);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&payload).map_err(|_| encode_failed())?;
    encoder.finish().map_err(|_| encode_failed())
}
