use crate::decode_admission::{self, DecodeAdmission, DecodeAdmissionError};
use crate::error::ParseError;
use crate::xref::{Xref, XrefEntry};

/// Admit the root allocation of a textual cross-reference table.
pub(crate) fn admit_table(admission: &dyn DecodeAdmission) -> Result<(), DecodeAdmissionError> {
    decode_admission::admit_btree::<u32, XrefEntry>(admission, 0)
}

/// Admit one entry before a textual cross-reference table inserts it.
pub(crate) fn admit_entry(admission: &dyn DecodeAdmission, first: bool) -> Result<(), DecodeAdmissionError> {
    if first {
        admit_table(admission)?;
    }
    admission.admit(decode_admission::btree_entry_bytes::<u32, XrefEntry>())
}

/// Admit every entry a `/Prev` or hybrid merge adds, before any of them allocates.
pub(crate) fn merge_admitted(
    target: &mut Xref, incoming: Xref, admission: Option<&dyn DecodeAdmission>,
) -> Result<(), DecodeAdmissionError> {
    if let Some(admission) = admission {
        let growth = incoming
            .entries
            .keys()
            .filter(|id| !target.entries.contains_key(id))
            .count();
        if growth != 0 {
            decode_admission::admit_btree::<u32, XrefEntry>(admission, growth)?;
        }
    }
    target.merge(incoming);
    Ok(())
}

/// A checked object id from a hostile xref-stream `/Index` pair.
pub(crate) fn object_id(start: i64, index: i64) -> Result<u32, ParseError> {
    start
        .checked_add(index)
        .and_then(|id| u32::try_from(id).ok())
        .ok_or(ParseError::InvalidXref)
}
