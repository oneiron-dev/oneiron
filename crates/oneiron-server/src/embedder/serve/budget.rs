//! How many bytes an answer may hold, and the buffer it is encoded into.
//! Request bodies and answers wait for their bytes on byte lines
//! ([`crate::byte_line`]).

/// What an answer of `inputs` rows of `dimensions` floats may hold until it
/// is delivered: the rows as the model returns them (4 bytes a float) or as
/// base64 (under 6), and at the same time their encoding
/// ([`encoding_bytes`]).
pub(super) fn answer_bytes(inputs: usize, dimensions: usize) -> usize {
    inputs
        .saturating_mul(dimensions.saturating_mul(6))
        .saturating_add(encoding_bytes(inputs, dimensions))
}

/// The most an answer's encoding takes: 18 bytes a float as JSON (an f32's
/// shortest form, as ryu writes it, is at most 17: a sign, `0.`, five zeros
/// and nine digits; and its comma), with room for each row's own fields and
/// the answer's. The answer is encoded into a buffer of exactly this many
/// bytes, which is never grown, so what it holds is what was counted.
pub(super) fn encoding_bytes(inputs: usize, dimensions: usize) -> usize {
    inputs
        .saturating_mul(dimensions.saturating_mul(18).saturating_add(ROW_FIELDS))
        .saturating_add(ANSWER_FIELDS)
}

/// A buffer that is never grown: a write past its capacity fails, so an
/// answer holds no more than the room it took.
pub(super) struct Fixed(pub(super) Vec<u8>);

impl std::io::Write for Fixed {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0.capacity() - self.0.len() {
            return Err(std::io::Error::other("the answer is past its room"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One answer row's fields past its floats, counted generously.
const ROW_FIELDS: usize = 256;

/// An answer's fields past its rows (the model, its transform, profile and
/// provenance), counted generously.
const ANSWER_FIELDS: usize = 16 * 1024;
