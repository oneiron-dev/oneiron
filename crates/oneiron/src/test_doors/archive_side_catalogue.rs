//! Doors for `tests/archive_side_catalogue_coverage.rs`: the whole-vault
//! archive's coverage of the canonical side-table catalogue (SIDE-1); and for
//! `tests/archive_import_retained_side_rows.rs`: the export's credential
//! judgement of one retained row; and for
//! `tests/archive_import_owner_installs_side_receipts.rs`: a rotation receipt
//! body as an earlier writer stored it.

use crate::batch::export::archive_retained_side_rows::{
    retained_side_row_key, retained_side_row_withholds_credential,
};
use crate::batch::export::archive_side_dispositions::ArchiveSideDisposition;
use crate::batch::export::archive_side_dispositions::{
    OTHER_ARCHIVE_SECTION_TABLES, SIDE_TABLE_DISPOSITIONS,
};
use crate::batch::export::{ArchiveRetainedSideRow, ArchiveSideFamily, SideRowBytes};
use crate::error::{Error, Result};
use crate::side_table::{self, HexId, Named, Raw, SideCodec, SideTable, StorageTier};
use crate::{EntityId, Vault};

/// Stores `body` as the secret-rotation receipt `receipt_id`, as the
/// rotation writers store it (raw bytes under the id in hex). A test writes
/// the body an earlier writer wrote, which today's writers no longer write.
///
/// # Errors
///
/// Storage errors.
pub fn put_secret_rotation_receipt_body(
    vault: &Vault,
    receipt_id: EntityId,
    body: &[u8],
) -> Result<()> {
    const RECEIPTS: SideTable<HexId, Vec<u8>, Raw> =
        SideTable::new(&side_table::SECRET_ROTATION_RECEIPT);
    vault.with_write_txn(|txn| RECEIPTS.put(&vault.store, txn, &HexId(receipt_id), &body.to_vec()))
}

/// Whether the export holds out of every archive, as a credential, the
/// retained row of `source_table` whose stored key suffix is `source_key`
/// and whose stored value is `source_value`: the judgement the export and
/// the owner's restore make of each retained envelope.
///
/// # Errors
///
/// The envelope does not encode.
pub fn retained_row_withholds_credential(
    source_table: &str,
    source_key: &[u8],
    source_value: &[u8],
) -> Result<bool> {
    let row = ArchiveRetainedSideRow {
        source_table: source_table.to_owned(),
        source_key: source_key.to_vec(),
        source_value: source_value.to_vec(),
        source_live: true,
    };
    let value = <Named as SideCodec<ArchiveRetainedSideRow>>::encode(&row)
        .map_err(|_| Error::InvalidConfig("retained envelope does not encode".to_owned()))?;
    Ok(retained_side_row_withholds_credential(&SideRowBytes {
        family: ArchiveSideFamily::RetainedSideRow,
        key: retained_side_row_key(&row).to_vec(),
        value,
        owner: None,
        carriers: Vec::new(),
    }))
}

/// Every canonical side-table declaration with the archive classes covering
/// it: `family` (an `ArchiveSideFamily` carries it), `other_section`
/// (another archive section carries it), `retained` (the archive carries
/// its rows as inert copies) or `omitted` (the manifest declares it
/// omitted). In catalogue order. Production code never calls this; the
/// catalogue guard test does.
#[must_use]
pub fn canonical_archive_side_coverage() -> Vec<(&'static str, Vec<&'static str>)> {
    let families: Vec<&'static str> =
        crate::batch::export::archive_side_family_table_names().collect();
    let mut seen = std::collections::BTreeSet::new();
    for name in &families {
        assert!(
            seen.insert(*name),
            "no archive family table repeats: {name}"
        );
        assert!(
            crate::side_table::declared()
                .any(|decl| decl.name == *name && decl.tier == StorageTier::Canonical),
            "an archive family names an existing canonical table: {name}"
        );
    }
    crate::side_table::declared()
        .filter(|decl| decl.tier == StorageTier::Canonical)
        .map(|decl| {
            let mut classes = Vec::new();
            if families.contains(&decl.name) {
                classes.push("family");
            }
            if OTHER_ARCHIVE_SECTION_TABLES
                .iter()
                .any(|(name, _)| *name == decl.name)
            {
                classes.push("other_section");
            }
            if let Some(class) = disposition_class(decl.name) {
                classes.push(class);
            }
            (decl.name, classes)
        })
        .collect()
}

/// The archive class of the disposition `SIDE_TABLE_DISPOSITIONS` gives
/// `name`: `retained` or `omitted`. `None` when no disposition names it.
fn disposition_class(name: &str) -> Option<&'static str> {
    SIDE_TABLE_DISPOSITIONS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, disposition)| match disposition {
            ArchiveSideDisposition::Retained => "retained",
            ArchiveSideDisposition::Omitted(_) => "omitted",
        })
}

/// Every name the disposition consts decide, with its class: each
/// `SIDE_TABLE_DISPOSITIONS` name as `retained` or `omitted`, then each
/// `OTHER_ARCHIVE_SECTION_TABLES` name as `other_section`. The catalogue
/// guard test checks each names a canonical declaration.
#[must_use]
pub fn archive_side_disposition_names() -> Vec<(&'static str, &'static str)> {
    let mut names: Vec<(&'static str, &'static str)> = SIDE_TABLE_DISPOSITIONS
        .iter()
        .map(|(name, disposition)| {
            (
                *name,
                match disposition {
                    ArchiveSideDisposition::Retained => "retained",
                    ArchiveSideDisposition::Omitted(_) => "omitted",
                },
            )
        })
        .collect();
    names.extend(
        OTHER_ARCHIVE_SECTION_TABLES
            .iter()
            .map(|(name, _)| (*name, "other_section")),
    );
    names
}
