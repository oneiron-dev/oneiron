//! Imported receipt source artifacts and their physical, non-authoritative custody.
mod access;
mod codec;
mod custody;
pub(crate) use access::archived_receipt_sources_in_txn;
pub(crate) use codec::is_receipt_archive_source;
pub(crate) use custody::{
    receipt_archive_custody_exists, receipt_archives_for_holder, remove_receipt_archive_custody,
    retire_receipt_archives_for_erased_id, stage_receipt_archive_put, validate_receipt_archive_put,
};

#[cfg(feature = "sync")]
pub(crate) use codec::{receipt_archive_holder, receipt_archive_matches_id};

#[cfg(test)]
mod tests;
