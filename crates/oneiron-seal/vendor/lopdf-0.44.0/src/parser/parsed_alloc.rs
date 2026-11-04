//! Admission before parsed containers allocate or grow.

use super::{NomError, NomResult, ParserInput};
use crate::decode_admission::{self, DecodeAdmissionError, ParsedAdmission};
use crate::{Dictionary, Object};
use nom::Parser;
use nom::error::{ErrorKind, ParseError};
use std::mem::size_of;

fn refused(input: ParserInput, error: DecodeAdmissionError) -> nom::Err<NomError> {
    decode_admission::note_parsed_refusal(error);
    nom::Err::Failure(NomError::from_error_kind(input, ErrorKind::Fail))
}

pub(super) fn grow_parsed<'a, T>(out: &mut Vec<T>, additional: usize, input: ParserInput<'a>) -> NomResult<'a, ()> {
    decode_admission::reserve(&ParsedAdmission, out, additional).map_err(|error| refused(input, error))?;
    Ok((input, ()))
}

pub(super) fn push_parsed<'a, T>(out: &mut Vec<T>, value: T, input: ParserInput<'a>) -> NomResult<'a, ()> {
    grow_parsed(out, 1, input)?;
    out.push(value);
    Ok((input, ()))
}

pub(super) fn extend_parsed<'a>(out: &mut Vec<u8>, bytes: &[u8], input: ParserInput<'a>) -> NomResult<'a, ()> {
    decode_admission::extend(&ParsedAdmission, out, bytes).map_err(|error| refused(input, error))?;
    Ok((input, ()))
}

/// nom's many0 fold, but the fold can refuse before it grows its output.
pub(super) fn fold_parsed<'a, O, A, P, I, F>(
    mut input: ParserInput<'a>, mut parser: P, mut init: I, mut fold: F,
) -> NomResult<'a, A>
where
    P: Parser<ParserInput<'a>, Output = O, Error = NomError<'a>>,
    I: FnMut() -> A,
    F: FnMut(&mut A, O, ParserInput<'a>) -> NomResult<'a, ()>,
{
    let mut out = init();
    loop {
        match parser.parse(input) {
            Ok((rest, value)) => {
                if rest.len() == input.len() {
                    return Err(nom::Err::Error(NomError::from_error_kind(input, ErrorKind::Many0)));
                }
                fold(&mut out, value, rest)?;
                input = rest;
            }
            Err(nom::Err::Error(_)) => return Ok((input, out)),
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn many_parsed<'a, O, P>(input: ParserInput<'a>, parser: P) -> NomResult<'a, Vec<O>>
where
    P: Parser<ParserInput<'a>, Output = O, Error = NomError<'a>>,
{
    fold_parsed(input, parser, Vec::new, push_parsed)
}

// The same map-layout estimate the parser used after parsing: ordered
// entries plus two index slots and their control bytes per capacity unit.
const DICT_ENTRY_BYTES: usize =
    size_of::<usize>() + size_of::<Vec<u8>>() + size_of::<Object>() + 2 * (size_of::<usize>() + 1);

pub(super) fn reserve_dict_parsed<'a>(dict: &mut Dictionary, key: &[u8], input: ParserInput<'a>) -> NomResult<'a, ()> {
    let map = dict.as_hashmap();
    if map.contains_key(key) || map.len() < map.capacity() {
        return Ok((input, ()));
    }
    let before = map.capacity().saturating_mul(DICT_ENTRY_BYTES);
    // Hashbrown doubles buckets (3 -> 7 -> 14 usable entries). Adding one
    // before doubling also covers the small-table floor. Admit the whole
    // new map while the old map is still alive, not only its net growth.
    let next = map.capacity().saturating_add(1).saturating_mul(2).max(4);
    let estimate = next.saturating_mul(DICT_ENTRY_BYTES);
    decode_admission::charge_parsed(estimate).map_err(|error| refused(input, error))?;
    dict.as_hashmap_mut().try_reserve(1).map_err(|_| {
        refused(
            input,
            DecodeAdmissionError::MemoryFloor {
                needed: u64::try_from(estimate).unwrap_or(u64::MAX),
                available: 0,
            },
        )
    })?;
    let after = dict.as_hashmap().capacity().saturating_mul(DICT_ENTRY_BYTES);
    decode_admission::release_parsed(estimate.saturating_sub(after.saturating_sub(before)));
    Ok((input, ()))
}
