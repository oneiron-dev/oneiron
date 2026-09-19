//! Native carrier serialization from the forked Stemma typed revision model.
use super::writer::{RevisionMark, escape_attr};
use crate::{Error, Result};
use oneiron_stemma::domain::{RevisionInfo, TrackingStatus};

fn revision(mark: &RevisionMark, id: i64) -> Result<RevisionInfo> {
    RevisionMark::new(mark.author.clone(), mark.date.clone())?;
    let id = u32::try_from(id)
        .ok()
        .filter(|id| *id > 0 && *id <= i32::MAX as u32)
        .ok_or(Error::InvalidManifest(
            "docx revision id must be a positive signed 32-bit integer",
        ))?;
    Ok(RevisionInfo {
        revision_id: id,
        author: Some(mark.author.clone()),
        date: Some(mark.date.clone()),
        apply_op_id: None,
        identity: id,
    })
}

pub(super) fn tracked_xml(
    mark: &RevisionMark,
    id: i64,
    inserted: bool,
    runs: &str,
) -> Result<String> {
    let revision = revision(mark, id)?;
    let status = if inserted {
        TrackingStatus::Inserted(revision)
    } else {
        TrackingStatus::Deleted(revision)
    };
    let (tag, rev) = match &status {
        TrackingStatus::Inserted(rev) => ("ins", rev),
        TrackingStatus::Deleted(rev) => ("del", rev),
        TrackingStatus::Normal | TrackingStatus::InsertedThenDeleted(_) => {
            return Err(Error::InvalidManifest("unsupported native revision state"));
        }
    };
    let attrs = attributes(rev);
    Ok(format!("<w:{tag} {attrs}>{runs}</w:{tag}>"))
}

pub(super) fn paragraph_deletion(mark: &RevisionMark, id: i64) -> Result<String> {
    let status = TrackingStatus::Deleted(revision(mark, id)?);
    let TrackingStatus::Deleted(rev) = status else {
        unreachable!("constructed deleted revision")
    };
    Ok(format!("<w:del {}/>", attributes(&rev)))
}

fn attributes(rev: &RevisionInfo) -> String {
    let author = escape_attr(rev.author.as_deref().unwrap_or_default());
    let date = escape_attr(rev.date.as_deref().unwrap_or_default());
    let id = rev.revision_id;
    format!("w:author=\"{author}\" w:date=\"{date}\" w:id=\"{id}\"")
}

/// The native writer accepts the deterministic UTC second-precision subset.
pub(super) fn valid_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    let fields = [(0, 4), (5, 7), (8, 10), (11, 13), (14, 16), (17, 19)];
    let mut values = [0u32; 6];
    for (index, (start, end)) in fields.into_iter().enumerate() {
        if !bytes[start..end].iter().all(u8::is_ascii_digit) {
            return false;
        }
        for byte in &bytes[start..end] {
            values[index] = values[index] * 10 + u32::from(byte - b'0');
        }
    }
    let [year, month, day, hour, minute, second] = values;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year > 0 && day > 0 && day <= max_day && hour < 24 && minute < 60 && second < 60
}
