use std::cell::Cell;

use nom::Parser;
use nom::branch::alt;
use nom::bytes::complete::{tag, take, take_while1};
use nom::combinator::{map, map_opt};
use nom::error::{ErrorKind, ParseError};
use nom::sequence::{preceded, terminated};

use super::{
    NomError, NomResult, ParserInput, boolean, eol, escape_sequence, hex_char, hex_digit, integer,
    is_direct_literal_string, is_regular, null, real, reference, space, white_space,
};
use crate::admitted::parser_ctx;
use crate::decode_admission::{self, DecodeAdmission, DecodeAdmissionError};
use crate::{Dictionary, Object, StringFormat};

fn failure<'a>(
    input: ParserInput<'a>, refused: &Cell<Option<DecodeAdmissionError>>, err: DecodeAdmissionError,
) -> nom::Err<NomError<'a>> {
    refused.set(Some(err));
    nom::Err::Failure(NomError::from_error_kind(input, ErrorKind::Fail))
}

fn reserve<'a, T>(
    admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>, input: ParserInput<'a>,
    output: &mut Vec<T>, additional: usize,
) -> Result<(), nom::Err<NomError<'a>>> {
    if let Some(admission) = admission {
        decode_admission::reserve(admission, output, additional).map_err(|err| failure(input, refused, err))?;
    }
    Ok(())
}

fn extend<'a>(
    admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>, input: ParserInput<'a>,
    output: &mut Vec<u8>, bytes: &[u8],
) -> Result<(), nom::Err<NomError<'a>>> {
    if let Some(admission) = admission {
        decode_admission::extend(admission, output, bytes).map_err(|err| failure(input, refused, err))?;
    } else {
        output.extend_from_slice(bytes);
    }
    Ok(())
}

fn push<'a, T>(
    admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>, input: ParserInput<'a>,
    output: &mut Vec<T>, value: T,
) -> Result<(), nom::Err<NomError<'a>>> {
    reserve(admission, refused, input, output, 1)?;
    output.push(value);
    Ok(())
}

fn name<'a>(
    input: ParserInput<'a>, admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>,
) -> NomResult<'a, Vec<u8>> {
    let (mut rest, _) = tag(&b"/"[..]).parse(input)?;
    let mut output = Vec::new();
    loop {
        let parsed = alt((
            preceded(tag(&b"#"[..]), hex_char),
            map_opt(take(1usize), |c: ParserInput| {
                if c[0] != b'#' && is_regular(c[0]) {
                    Some(c[0])
                } else {
                    None
                }
            }),
        ))
        .parse(rest);
        match parsed {
            Ok((next, byte)) => {
                push(admission, refused, rest, &mut output, byte)?;
                rest = next;
            }
            Err(nom::Err::Error(_)) => break,
            Err(err) => return Err(err),
        }
    }
    Ok((rest, output))
}

pub(super) fn literal_string<'a>(
    input: ParserInput<'a>, admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>,
) -> NomResult<'a, Vec<u8>> {
    let (mut rest, _) = tag(&b"("[..]).parse(input)?;
    let mut depth = 1usize;
    let mut output = Vec::new();
    loop {
        if rest.is_empty() {
            return Err(nom::Err::Error(NomError::from_error_kind(rest, ErrorKind::Eof)));
        }
        match rest[0] {
            b'(' => {
                depth += 1;
                push(admission, refused, rest, &mut output, b'(')?;
                rest = &rest[1..];
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&rest[1..], output));
                }
                push(admission, refused, rest, &mut output, b')')?;
                rest = &rest[1..];
            }
            b'\\' => {
                let (next, escaped) = escape_sequence(rest)?;
                if let Some(byte) = escaped {
                    push(admission, refused, rest, &mut output, byte)?;
                }
                rest = next;
            }
            b'\r' | b'\n' => {
                let (next, ending) = eol(rest)?;
                extend(admission, refused, rest, &mut output, ending)?;
                rest = next;
            }
            _ => {
                let (next, direct) = take_while1(is_direct_literal_string).parse(rest)?;
                extend(admission, refused, rest, &mut output, direct)?;
                rest = next;
            }
        }
    }
}

pub(super) fn hexadecimal_string<'a>(
    input: ParserInput<'a>, admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>,
) -> NomResult<'a, Object> {
    let (mut rest, _) = tag(&b"<"[..]).parse(input)?;
    let mut output = Vec::new();
    let mut low_nibble = false;
    loop {
        match preceded(white_space, hex_digit).parse(rest) {
            Ok((next, digit)) => {
                if low_nibble {
                    *output.last_mut().expect("a high nibble was pushed") |= digit;
                } else {
                    push(admission, refused, rest, &mut output, digit << 4)?;
                }
                low_nibble = !low_nibble;
                rest = next;
            }
            Err(nom::Err::Error(_)) => break,
            Err(err) => return Err(err),
        }
    }
    let (rest, _) = preceded(white_space, tag(&b">"[..])).parse(rest)?;
    Ok((rest, Object::String(output, StringFormat::Hexadecimal)))
}

fn scalar<'a>(
    input: ParserInput<'a>, admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>,
) -> NomResult<'a, Object> {
    alt((
        null,
        boolean,
        reference,
        map(real, Object::Real),
        map(integer, Object::Integer),
        map(|input| name(input, admission, refused), Object::Name),
        map(
            |input| literal_string(input, admission, refused),
            Object::string_literal,
        ),
        |input| hexadecimal_string(input, admission, refused),
    ))
    .parse(input)
}

enum Frame {
    Array(Vec<Object>),
    Dictionary(Dictionary, Option<Vec<u8>>),
}

enum Step {
    CloseArray,
    CloseDictionary,
    DictionaryKey,
    Value,
}

pub(super) fn object<'a>(
    input: ParserInput<'a>, admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>,
) -> NomResult<'a, Object> {
    let mut rest = input;
    let mut frames = Vec::new();
    let mut completed = None;
    loop {
        if let Some(object) = completed.take() {
            rest = space(rest)?.0;
            match frames.last_mut() {
                None => return Ok((rest, object)),
                Some(Frame::Array(objects)) => {
                    push(admission, refused, rest, objects, object)?;
                }
                Some(Frame::Dictionary(dict, key)) => {
                    let key = key.take().expect("a dictionary value follows its key");
                    parser_ctx::insert(admission, dict, key, object).map_err(|err| failure(rest, refused, err))?;
                }
            }
            continue;
        }

        let step = match frames.last() {
            Some(Frame::Array(_)) if rest.first() == Some(&b']') => Step::CloseArray,
            Some(Frame::Array(_)) => Step::Value,
            Some(Frame::Dictionary(_, key)) if key.is_none() && rest.starts_with(b">>") => Step::CloseDictionary,
            Some(Frame::Dictionary(_, key)) if key.is_none() => Step::DictionaryKey,
            Some(Frame::Dictionary(_, _)) => Step::Value,
            None => Step::Value,
        };
        match step {
            Step::CloseArray => {
                rest = &rest[1..];
                let Some(Frame::Array(objects)) = frames.pop() else {
                    unreachable!()
                };
                completed = Some(Object::Array(objects));
            }
            Step::CloseDictionary => {
                rest = &rest[2..];
                let Some(Frame::Dictionary(dict, _)) = frames.pop() else {
                    unreachable!()
                };
                completed = Some(Object::Dictionary(dict));
            }
            Step::DictionaryKey => {
                let (next, key) = name(rest, admission, refused)?;
                rest = space(next)?.0;
                let Some(Frame::Dictionary(_, slot)) = frames.last_mut() else {
                    unreachable!()
                };
                *slot = Some(key);
            }
            Step::Value if rest.first() == Some(&b'[') => {
                rest = space(&rest[1..])?.0;
                push(admission, refused, rest, &mut frames, Frame::Array(Vec::new()))?;
            }
            Step::Value if rest.starts_with(b"<<") => {
                rest = space(&rest[2..])?.0;
                push(
                    admission,
                    refused,
                    rest,
                    &mut frames,
                    Frame::Dictionary(Dictionary::new(), None),
                )?;
            }
            Step::Value => {
                let (next, object) = scalar(rest, admission, refused)?;
                rest = next;
                completed = Some(object);
            }
        }
    }
}

pub(super) fn array<'a>(
    input: ParserInput<'a>, admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>,
) -> NomResult<'a, Vec<Object>> {
    if input.first() != Some(&b'[') {
        return Err(nom::Err::Error(NomError::from_error_kind(input, ErrorKind::Tag)));
    }
    let (rest, mut object) = object(input, admission, refused)?;
    match &mut object {
        Object::Array(objects) => Ok((rest, std::mem::take(objects))),
        _ => Err(nom::Err::Error(NomError::from_error_kind(input, ErrorKind::MapRes))),
    }
}

pub(super) fn inner_dictionary<'a>(
    input: ParserInput<'a>, admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>,
) -> NomResult<'a, Dictionary> {
    let mut rest = input;
    let mut dict = Dictionary::new();
    loop {
        let parsed = (terminated(|input| name(input, admission, refused), space), |input| {
            direct_object(input, admission, refused)
        })
            .parse(rest);
        match parsed {
            Ok((next, (key, value))) => {
                parser_ctx::insert(admission, &mut dict, key, value).map_err(|err| failure(rest, refused, err))?;
                rest = next;
            }
            Err(nom::Err::Error(_)) => return Ok((rest, dict)),
            Err(err) => return Err(err),
        }
    }
}

pub(super) fn direct_object<'a>(
    input: ParserInput<'a>, admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>,
) -> NomResult<'a, Object> {
    terminated(|input| object(input, admission, refused), space).parse(input)
}

pub(super) fn dictionary<'a>(
    input: ParserInput<'a>, admission: Option<&dyn DecodeAdmission>, refused: &Cell<Option<DecodeAdmissionError>>,
) -> NomResult<'a, Dictionary> {
    if !input.starts_with(b"<<") {
        return Err(nom::Err::Error(NomError::from_error_kind(input, ErrorKind::Tag)));
    }
    let (rest, mut object) = object(input, admission, refused)?;
    match &mut object {
        Object::Dictionary(dict) => Ok((rest, std::mem::take(dict))),
        _ => Err(nom::Err::Error(NomError::from_error_kind(input, ErrorKind::MapRes))),
    }
}
