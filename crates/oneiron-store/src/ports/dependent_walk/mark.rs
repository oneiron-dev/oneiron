//! A walk row and the marks it holds: what each mark of a source covers,
//! and the worlds a row is withdrawn for.

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// Earlier marks one walk keeps apart. Past it the two oldest merge into one
/// that withdraws the rows of both for the worlds of both, settled rows as
/// the newer one passes them: a narrowing, never a widening, and only for a
/// source whose worlds changed this often within one walk.
pub const EARLIER_MARKS: usize = 16;

pub fn corrupt_walk() -> Error {
    Error::CorruptedIndex("dependent walk")
}

/// The next `n` bytes of `raw`, which moves past them.
pub fn take<'a>(raw: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    let (head, rest) = raw.split_at_checked(n).ok_or_else(corrupt_walk)?;
    *raw = rest;
    Ok(head)
}
