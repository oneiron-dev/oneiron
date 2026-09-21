//! Exact, budgeted decoding for PDF content and structural streams.
use super::*;

// lopdf's Flate helper deliberately accepts truncated data/checksum errors.
// Preparation must not turn recovered partial content into a signed original.
// Reuse the existing native flate2 decoder and require an actual stream end.
pub(super) fn decode_stream(stream: &Stream, limit: usize) -> Result<Vec<u8>> {
    if !stream.dict.has(b"Filter") {
        if stream.content.len() > limit {
            return Err(PdfPreparationError::Limit);
        }
        return Ok(stream.content.clone());
    }
    if stream.filters()?.as_slice() != [b"FlateDecode".as_slice()] {
        return Err(PdfPreparationError::UnsupportedPdf);
    }
    if let Ok(params) = stream.dict.get(b"DecodeParms") {
        let params = match params {
            Object::Array(v) if v.len() == 1 => &v[0],
            other => other,
        };
        let params = if matches!(params, Object::Null) {
            None
        } else {
            Some(params.as_dict()?)
        };
        if params
            .and_then(|p| p.get(b"Predictor").ok())
            .is_some_and(|v| !matches!(v.as_i64(), Ok(1 | 10..=15)))
        {
            return Err(PdfPreparationError::UnsupportedPdf);
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
            .map_err(|_| PdfPreparationError::MalformedPdf)?;
        let count = (decoder.total_out() - before_out) as usize;
        if count > limit.saturating_sub(output.len()) {
            return Err(PdfPreparationError::Limit);
        }
        output.extend_from_slice(&buffer[..count]);
        if status == flate2::Status::StreamEnd {
            if decoder.total_in() as usize != stream.content.len() {
                return Err(PdfPreparationError::MalformedPdf);
            }
            return predictor(stream, output, limit);
        }
        if decoder.total_in() == before_in && count == 0 {
            return Err(PdfPreparationError::MalformedPdf);
        }
    }
}

// PNG predictors are common in xref streams. Decode rows exactly, without
// accepting a partial final row or expanding beyond the structural budget.
fn predictor(stream: &Stream, data: Vec<u8>, limit: usize) -> Result<Vec<u8>> {
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
    let params = params.as_dict()?;
    let number = |name: &[u8], default| -> Result<usize> {
        params
            .get(name)
            .map_or(Ok(default), Object::as_i64)?
            .try_into()
            .map_err(|_| PdfPreparationError::MalformedPdf)
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
        return Err(PdfPreparationError::UnsupportedPdf);
    }
    let width = columns
        .checked_mul(colors)
        .filter(|v| *v <= limit)
        .ok_or(PdfPreparationError::Limit)?;
    if !data.len().is_multiple_of(width + 1) {
        return Err(PdfPreparationError::MalformedPdf);
    }
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
                _ => return Err(PdfPreparationError::MalformedPdf),
            };
            current[x] = current[x].wrapping_add(predicted);
        }
        output.extend_from_slice(&current);
        previous = current;
    }
    Ok(output)
}
