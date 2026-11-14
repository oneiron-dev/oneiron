//! [`safe_read_asset_text`] as a diagnostic record: the strict read's text with
//! the `_validity` flag bag, one flag per reason the strict read gives no
//! text, for a UI badge or a monitor (ARCH-0005a, Read patterns; census
//! L9-43). This test fails to compile on main, where the record does not
//! exist.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test safe_read_asset_validity`.
use oneiron::deletion::DeleteEntityOptions;
use oneiron::registry::{ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_PERSON};
use oneiron::store::ports::{
    AssetTextRead, AssetTextValidity, safe_read_asset_text, safe_read_asset_text_diagnostic,
};
use oneiron::{EdgeKind, EntityId, TimeRange, Vault, VaultConfig};

const SOURCE: [u8; 32] = [7; 32];
const OTHER: [u8; 32] = [8; 32];

fn put(vault: &Vault, id: &EntityId, kind: u8, body: &[u8]) {
    vault
        .put_entity(id, kind, TimeRange { start: 1, end: 1 }, 1, body)
        .expect("put writes the row");
}

fn read(
    vault: &Vault,
    id: &EntityId,
    derived: &[u8; 32],
    source: &[u8; 32],
) -> (AssetTextRead, Option<Vec<u8>>) {
    vault
        .with_read_snapshot(|txn| -> Result<_, oneiron::Error> {
            let record = safe_read_asset_text_diagnostic(vault, txn, id, derived, source)?;
            let strict = safe_read_asset_text(vault, txn, id, derived, source)?;
            Ok((record, strict))
        })
        .expect("read")
}

#[test]
fn asset_text_read_reports_validity_flags() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");

    // Live text, matching hashes.
    let live = EntityId::now();
    put(&vault, &live, ENTITY_TYPE_ASSET_TEXT, b"page text");
    let (record, strict) = read(&vault, &live, &SOURCE, &SOURCE);
    assert_eq!(
        record,
        AssetTextRead {
            body: Some(b"page text".to_vec()),
            validity: AssetTextValidity::default(),
        },
        "live text serves its body with no flags"
    );
    assert!(record.validity.is_valid(), "live text is valid");
    assert_eq!(record.body, strict, "live text matches the strict read");

    // The same row, mismatched hashes.
    let (record, strict) = read(&vault, &live, &OTHER, &SOURCE);
    assert_eq!(record.body, None, "mismatched hashes serve no body");
    assert_eq!(
        record.validity,
        AssetTextValidity {
            hash_mismatch: true,
            ..Default::default()
        },
        "mismatched hashes set only hash_mismatch"
    );
    assert_eq!(strict, None, "mismatched hashes: strict reads nothing");

    // A deleted row.
    let withdrawn = EntityId::now();
    put(
        &vault,
        &withdrawn,
        ENTITY_TYPE_ASSET_TEXT,
        b"withdrawn text",
    );
    vault.delete_entity(&withdrawn).expect("delete the row");
    let (record, strict) = read(&vault, &withdrawn, &SOURCE, &SOURCE);
    assert_eq!(record.body, None, "deleted row serves no body");
    assert!(record.validity.deleted, "deleted row sets deleted");
    assert!(record.validity.absent, "deleted row sets absent");
    assert!(
        !record.validity.hash_mismatch,
        "deleted row keeps matching hashes"
    );
    assert_eq!(strict, None, "deleted row: strict reads nothing");

    // Text whose source is deleted.
    let source = EntityId::now();
    let derived = EntityId::now();
    put(&vault, &source, ENTITY_TYPE_PERSON, b"human");
    put(&vault, &derived, ENTITY_TYPE_ASSET_TEXT, b"derived text");
    vault
        .put_edge(&derived, EdgeKind::DerivedFrom, &source, 1.0)
        .expect("link derived text to its source");
    let (record, strict) = read(&vault, &derived, &SOURCE, &SOURCE);
    assert!(record.validity.is_valid(), "derived text starts valid");
    assert_eq!(
        record.body, strict,
        "derived text starts matching the strict read"
    );
    vault
        .delete_entity_with_options(&source, DeleteEntityOptions { purge: true })
        .expect("purge the source");
    let (record, strict) = read(&vault, &derived, &SOURCE, &SOURCE);
    assert_eq!(record.body, None, "withdrawn source serves no body");
    assert!(record.validity.stale, "withdrawn source sets stale");
    assert!(
        !record.validity.deleted,
        "withdrawn source is not itself deleted"
    );
    assert!(record.validity.absent, "withdrawn source sets absent");
    assert_eq!(strict, None, "withdrawn source: strict reads nothing");

    // An unknown id.
    let unknown = EntityId::now();
    let (record, strict) = read(&vault, &unknown, &SOURCE, &SOURCE);
    assert_eq!(record.body, None, "unknown id serves no body");
    assert_eq!(
        record.validity,
        AssetTextValidity {
            absent: true,
            ..Default::default()
        },
        "unknown id sets only absent"
    );
    assert_eq!(strict, None, "unknown id: strict reads nothing");
}
