//! Scans a completed sink using its existing inline bytes or finished spill.
//!
//! The sink's meter keeps only streaming scan state. The whole-payload scan
//! runs when that state found no hit. File bytes are read through the native
//! reader, including authenticated decryption for sealed bodies.

use super::{BodyFacts, BodyMeter, BodySink, SunkBody, body_file_name};
use crate::store::BodyFile;
use crate::{Error, Result};
use zeroize::Zeroizing;

/// The facts of `meter`, measured as its bytes streamed past, with `secret`,
/// the scan's first hit: the one construction both the standalone and the
/// sink finishes use, bit for bit.
pub(super) fn body_facts(
    meter: BodyMeter,
    secret: Option<&'static str>,
    preview_chars: usize,
) -> BodyFacts {
    let BodyMeter {
        hasher,
        len,
        newlines,
        last,
        text,
        carry_len,
        head,
        line_index,
        ..
    } = meter;
    let (preview, cut) = crate::serialize::compressed_code_run_output_preview(&head, preview_chars);
    BodyFacts {
        digest: *hasher.finalize().as_bytes(),
        len,
        text: text && carry_len == 0,
        lines: newlines + u64::from(last.is_some_and(|byte| byte != b'\n')),
        preview,
        preview_truncated: cut || len > head.len() as u64,
        secret,
        line_index,
    }
}

/// The facts of a sink's externally-backed `meter`: its streamed rules,
/// then `whole_scan`, the lazy whole reading of its external body, only
/// when they have no hit. The closure runs at most once and never after a
/// streamed hit, so the first hit's reason stands.
pub(super) fn finish_sink_scanned(
    mut meter: BodyMeter,
    preview_chars: usize,
    whole_scan: impl FnOnce() -> Result<Option<&'static str>>,
) -> Result<BodyFacts> {
    let mut secret = meter.secrets.finish_streamed();
    if secret.is_none() {
        secret = whole_scan()?;
    }
    Ok(body_facts(meter, secret, preview_chars))
}

/// The whole reading of the finished body `file` holds, `len` bytes long:
/// its bytes from the start through the native reader, checked against
/// `digest`, the meter's own, before the scan. A mismatch or a length past
/// this machine's memory fails closed; nothing is declared clean on error.
pub(super) fn scanned_file_hit(
    file: &BodyFile,
    digest: &[u8; 32],
    len: u64,
) -> Result<Option<&'static str>> {
    let len_usize =
        usize::try_from(len).map_err(|_| Error::ArithmeticOverflow("result body spill length"))?;
    let raw = Zeroizing::new(file.read_range(0, len_usize)?);
    if blake3::hash(&raw).as_bytes() != digest {
        return Err(Error::CorruptedIndex("result body spill readback digest"));
    }
    Ok(crate::batch::secret_scan::write_payload_hit(&raw))
}

impl BodySink {
    /// Finishes the body: a spilled one is published under its digest.
    pub(crate) fn finish(mut self, preview_chars: usize) -> Result<(BodyFacts, SunkBody)> {
        self.finalize_sweep()?;
        let meter = self
            .meter
            .take()
            .ok_or(Error::InvariantViolation("result body sink finished twice"))?;
        let Some(spill) = self.spill.take() else {
            let facts = finish_sink_scanned(meter, preview_chars, || {
                Ok(crate::batch::secret_scan::write_payload_hit(&self.inline))
            })?;
            return Ok((facts, SunkBody::Inline(std::mem::take(&mut self.inline))));
        };
        let temp = spill.temp().to_owned();
        let digest = *meter.hasher.finalize().as_bytes();
        let len = meter.len;
        let finished = spill.finish(&digest, len).and_then(|spilled| {
            let facts = finish_sink_scanned(meter, preview_chars, || {
                let file = spilled.reader()?;
                scanned_file_hit(&file, &digest, len)
            })?;
            Ok((facts, spilled))
        });
        let (facts, spilled) = match finished {
            Ok(finished) => finished,
            Err(error) => {
                self.dir.discard(&temp);
                return Err(error);
            }
        };
        let key = spilled.publish(&self.dir)?;
        match &key {
            Some(key) => key.write_line_index(&self.dir, &facts.line_index),
            None => self
                .dir
                .write_line_index(&body_file_name(&facts.digest), &facts.line_index),
        }
        let free_bytes = self.dir.free_bytes().ok();
        Ok((facts, SunkBody::File { free_bytes, key }))
    }
}
