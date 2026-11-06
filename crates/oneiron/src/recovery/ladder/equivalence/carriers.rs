//! Native carrier payload equality over the shared byte and row cursors.

use crate::error::Result;
use crate::recovery::canonical::{CanonicalContainerManifest, CanonicalSchemaManifest};

use super::{PayloadPart, compare_bytes, compare_value};

pub(super) fn compare_payload_rows<T, F: PartialEq>(
    actual: &[T],
    wanted: &[T],
    next: &mut usize,
    byte: &mut usize,
    fields: impl Fn(&T) -> (F, &[u8]),
) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    let Some(row) = actual.get(*next) else {
        return Ok(true);
    };
    let (prefix, bytes) = fields(row);
    let (expected_prefix, expected_bytes) = fields(&wanted[*next]);
    if *byte == 0 {
        compare_value(&prefix, &expected_prefix)?;
    }
    if compare_bytes(bytes, expected_bytes, byte)? {
        *next += 1;
        *byte = 0;
    }
    Ok(false)
}

pub(super) fn compare_named_rows<T>(
    actual: &[T],
    wanted: &[T],
    next: &mut usize,
    byte: &mut usize,
    payload: &mut PayloadPart,
    fields: impl Fn(&T) -> (&str, &[u8]),
) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    let Some(row) = actual.get(*next) else {
        return Ok(true);
    };
    let (key, bytes) = fields(row);
    let (expected_key, expected_bytes) = fields(&wanted[*next]);
    if *payload == PayloadPart::First {
        if compare_bytes(key.as_bytes(), expected_key.as_bytes(), byte)? {
            *payload = PayloadPart::Second;
            *byte = 0;
        }
        return Ok(false);
    }
    if compare_bytes(bytes, expected_bytes, byte)? {
        *next += 1;
        *byte = 0;
        *payload = PayloadPart::First;
    }
    Ok(false)
}

pub(super) fn compare_container_manifests(
    actual: &[CanonicalContainerManifest],
    wanted: &[CanonicalContainerManifest],
    next: &mut usize,
    byte: &mut usize,
    payload: &mut PayloadPart,
) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    let Some(CanonicalContainerManifest {
        container_id,
        container_kind,
        schema_version,
        source_entity_id,
    }) = actual.get(*next)
    else {
        return Ok(true);
    };
    let expected = &wanted[*next];
    if *payload == PayloadPart::First {
        if compare_bytes(
            container_id.as_bytes(),
            expected.container_id.as_bytes(),
            byte,
        )? {
            *payload = PayloadPart::Second;
            *byte = 0;
        }
        return Ok(false);
    }
    if compare_bytes(
        container_kind.as_bytes(),
        expected.container_kind.as_bytes(),
        byte,
    )? {
        compare_value(schema_version, &expected.schema_version)?;
        compare_value(source_entity_id, &expected.source_entity_id)?;
        *next += 1;
        *byte = 0;
        *payload = PayloadPart::First;
    }
    Ok(false)
}

pub(super) fn compare_schema_manifest(
    actual: &CanonicalSchemaManifest,
    wanted: &CanonicalSchemaManifest,
    byte: &mut usize,
) -> Result<bool> {
    let CanonicalSchemaManifest {
        oneiron_schema_version,
        loro_version,
        container_schema_version,
        analyzer_manifest_blake3,
    } = actual;
    if *byte == 0 {
        compare_value(oneiron_schema_version, &wanted.oneiron_schema_version)?;
    }
    if compare_bytes(
        loro_version.as_bytes(),
        wanted.loro_version.as_bytes(),
        byte,
    )? {
        compare_value(container_schema_version, &wanted.container_schema_version)?;
        compare_value(analyzer_manifest_blake3, &wanted.analyzer_manifest_blake3)?;
        return Ok(true);
    }
    Ok(false)
}
