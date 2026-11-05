use super::work::{WorkError, WorkLimits};

use crate::api::Counter;
use crate::error::InputInvalidCode;
use lopdf::{Object, Stream};

/// A stream's bytes as preparation reads them: an unfiltered stream whole,
/// a filtered one exactly decoded, every buffer admitted first by `limits`.
/// Growth is admitted, never refused past a per-stream codec bound.
pub(super) fn decoded(stream: &Stream, limits: &WorkLimits) -> Result<Vec<u8>, WorkError> {
    decoded_admitted(stream, limits)
}

/// [`decoded`], each buffer it allocates admitted first by `limits`.
pub(super) fn decoded_admitted(stream: &Stream, limits: &WorkLimits) -> Result<Vec<u8>, WorkError> {
    if stream.dict.has(b"Filter") {
        // organ: admitted, not refused (FIX 7980)
        decode_admitted(stream, limits)
    } else {
        limits
            .ledger
            .admit_len::<u8>(stream.content.len())
            .map_err(WorkError::Memory)?;
        Ok(stream.content.clone())
    }
}

// lopdf's Flate helper deliberately accepts truncated data/checksum errors.
// Preparation must not turn recovered partial content into a signed original.
// Reuse the existing native flate2 decoder and require an actual stream end.
pub(crate) fn decode_stream(stream: &Stream, limits: &WorkLimits) -> Result<Vec<u8>, WorkError> {
    decode_admitted(stream, limits)
}

/// [`decode_stream`], its output admitted by `limits` before each growth:
/// the whole new allocation, doubling unclamped, while the old one lives.
fn decode_admitted(stream: &Stream, limits: &WorkLimits) -> Result<Vec<u8>, WorkError> {
    if !stream.dict.has(b"Filter") {
        // organ: admitted, not refused (FIX 7980)
        limits
            .ledger
            .admit_len::<u8>(stream.content.len())
            .map_err(WorkError::Memory)?;
        return Ok(stream.content.clone());
    }
    if stream
        .filters()
        .map_err(|err| lopdf_error(limits, err))?
        .as_slice()
        != [b"FlateDecode".as_slice()]
    {
        return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
    }
    if let Ok(params) = stream.dict.get(b"DecodeParms") {
        let params = match params {
            Object::Array(v) if v.len() == 1 => &v[0],
            other => other,
        };
        let params = if matches!(params, Object::Null) {
            None
        } else {
            Some(params.as_dict().map_err(|err| lopdf_error(limits, err))?)
        };
        if params
            .and_then(|p| p.get(b"Predictor").ok())
            .is_some_and(|v| !matches!(v.as_i64(), Ok(1 | 10..=15)))
        {
            return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
        }
    }
    let mut decoder = flate2::Decompress::new(true);
    let mut output = Vec::new();
    loop {
        let (before_in, before_out) = (decoder.total_in(), decoder.total_out());
        let mut buffer = [0; 8192];
        let status = decoder
            .decompress(
                &stream.content[before_in as usize..],
                &mut buffer,
                flate2::FlushDecompress::None,
            )
            .map_err(|_| WorkError::Invalid(InputInvalidCode::MalformedPdf))?;
        let count = (decoder.total_out() - before_out) as usize;
        // organ: admitted, not refused (FIX 7980)
        let needed = output.len() + count;
        if needed > output.capacity() {
            // organ: admitted, not refused (FIX 7980)
            let grown = output.capacity().saturating_mul(2).max(needed);
            limits
                .ledger
                .admit_len::<u8>(grown)
                .map_err(WorkError::Memory)?;
            output.reserve_exact(grown - output.len());
        }
        output.extend_from_slice(&buffer[..count]);
        if status == flate2::Status::StreamEnd {
            if decoder.total_in() as usize != stream.content.len() {
                return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
            }
            limits
                .observed
                .note(Counter::StreamDecodeBytes, output.len());
            return predictor(stream, output, limits);
        }
        if decoder.total_in() == before_in && count == 0 {
            return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
        }
    }
}

// PNG predictors are common in xref streams. Decode rows exactly, without
// accepting a partial final row; buffers are admitted, never refused on size.
fn predictor(stream: &Stream, data: Vec<u8>, limits: &WorkLimits) -> Result<Vec<u8>, WorkError> {
    let Some(params) = stream.dict.get(b"DecodeParms").ok() else {
        return Ok(data);
    };
    let params = match params {
        Object::Array(v) if v.len() == 1 => &v[0],
        v => v,
    };
    if matches!(params, Object::Null) {
        return Ok(data);
    }
    let params = params.as_dict().map_err(|err| lopdf_error(limits, err))?;
    let number = |name: &[u8], default| -> Result<usize, WorkError> {
        params
            .get(name)
            .map_or(Ok(default), Object::as_i64)
            .map_err(|err| lopdf_error(limits, err))?
            .try_into()
            .map_err(|_| WorkError::Invalid(InputInvalidCode::MalformedPdf))
    };
    let predictor = number(b"Predictor", 1)?;
    if predictor == 1 {
        return Ok(data);
    }
    let (columns, colors, bits) = (
        number(b"Columns", 1)?,
        number(b"Colors", 1)?,
        number(b"BitsPerComponent", 8)?,
    );
    if !(10..=15).contains(&predictor) || bits != 8 || colors == 0 || colors > 32 || columns == 0 {
        return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
    }
    // organ: admitted, not refused (FIX 7980)
    let width = columns
        .checked_mul(colors)
        .ok_or(WorkError::Invalid(InputInvalidCode::TooLarge))?;
    if !data.len().is_multiple_of(width + 1) {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    // The output, the previous row and the row being decoded.
    limits
        .ledger
        .admit_len::<u8>(data.len().saturating_add(width.saturating_mul(2)))
        .map_err(WorkError::Memory)?;
    let mut output = Vec::with_capacity(data.len());
    let mut previous = vec![0u8; width];
    for row in data.chunks_exact(width + 1) {
        let mut current = row[1..].to_vec();
        for x in 0..width {
            let a = if x >= colors { current[x - colors] } else { 0 };
            let b = previous[x];
            let c = if x >= colors { previous[x - colors] } else { 0 };
            let predicted = match row[0] {
                0 => 0,
                1 => a,
                2 => b,
                3 => ((u16::from(a) + u16::from(b)) / 2) as u8,
                4 => {
                    let p = i32::from(a) + i32::from(b) - i32::from(c);
                    let (pa, pb, pc) = (
                        (p - i32::from(a)).abs(),
                        (p - i32::from(b)).abs(),
                        (p - i32::from(c)).abs(),
                    );
                    if pa <= pb && pa <= pc {
                        a
                    } else if pb <= pc {
                        b
                    } else {
                        c
                    }
                }
                _ => return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf)),
            };
            current[x] = current[x].wrapping_add(predicted);
        }
        output.extend_from_slice(&current);
        previous = current;
    }
    Ok(output)
}

/// A lopdf read failure as the organ reads it: a kept memory refusal as
/// itself, anything else as a malformed PDF, never the reverse.
fn lopdf_error(limits: &WorkLimits, err: lopdf::Error) -> WorkError {
    limits.ledger.refusal_of(&err).map_or(
        WorkError::Invalid(InputInvalidCode::MalformedPdf),
        WorkError::Memory,
    )
}
