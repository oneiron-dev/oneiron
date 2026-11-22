//! Census L7-43 (ARCH-0023b, the stream-class row "Cloud-produced f16 embeddings" and the
//! derived-bytes rule under it): an image or audio vector a home holds replicates into the
//! matching declared space without a recompute. By default images and raw audio share one
//! media space. The home serves the vector bound to its ASSET's row, whose body names the
//! bytes by hash, so the row's digest pins the exact bytes the vector was made from. The
//! receiver installs it only where its own ASSET row has that digest, the kind matches, and
//! its space fills that kind at its own width.
//!
//! Red on main: a declared space's replica door serves only claim, summary and turn text, so
//! an image or audio ASSET serves no replica, and the install refuses an ASSET. Green on the
//! head.
//!
//! A record past the inline limit lives in the file plane, and its stored row keeps a
//! manifest. A residence door serves that row whole (`sync::asset_body::served_row`) and
//! hashes it so, so a replica names the digest of the whole row, never of the manifest.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test media_vector_replica`
#![cfg(all(feature = "sync", oneiron_test_support))]

use std::collections::BTreeSet;

use base64::Engine as _;
use oneiron::embed::{EmbeddingSpace, InputKind, MediaVectorReplica};
use oneiron::memory::AssetIngestRequest;
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::test_doors::media_vector_replica::{install_media_vector_replica, stored_row};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The one media space images and raw audio share, as a cloud model fills it.
const SPACE: &str = "media-embed@1@cloud";
const WIDTH: usize = 4;
const OCCURRED_AT: u64 = 1_790_000_000;

/// A device vault whose image and audio slots bind one declared 4-wide media space.
fn media_vault(dir: &std::path::Path) -> TestResult<Vault> {
    let vault = Vault::open(dir, VaultConfig::device())?;
    vault.seed_embedding_space(EmbeddingSpace {
        id: SPACE.to_owned(),
        dimensions: WIDTH,
        accepts: BTreeSet::from([InputKind::Image, InputKind::Audio]),
        query_towers: BTreeSet::new(),
        evidence: None,
    })?;
    vault.seed_kind_slot(InputKind::Image, SPACE)?;
    vault.seed_kind_slot(InputKind::Audio, SPACE)?;
    Ok(vault)
}

/// Ingests one ASSET of `kind` holding `bytes` as the owner, and stores `vector` as its vector
/// in the media space.
fn asset_with_vector(
    vault: &Vault,
    kind: InputKind,
    mime_type: &str,
    bytes: &[u8],
    vector: &[f32],
) -> TestResult<EntityId> {
    let owner = vault.ensure_embedded_owner_actor()?;
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .ingest_asset(&AssetIngestRequest {
            asset_ref: None,
            embedding_kind: kind,
            mime_type: mime_type.to_owned(),
            bytes_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
            text: None,
            occurred_at: OCCURRED_AT,
        })?;
    let asset = EntityId::from_hex(&receipt.asset_ref)?;
    vault.put_media_vector(SPACE, &asset, kind, vector)?;
    Ok(asset)
}

/// The digest of the ASSET row as the vault holds it: the source carrier a replica binds.
fn row_digest(vault: &Vault, asset: &EntityId) -> TestResult<[u8; 32]> {
    let raw = vault.get_raw(asset)?.ok_or("the ASSET row is stored")?;
    Ok(*blake3::hash(&raw).as_bytes())
}

/// The one replica the home serves for `asset`, checked to be of `kind` and bound to the
/// ASSET's own row alone.
fn served_replica(vault: &Vault, asset: &EntityId, kind: &str) -> TestResult<MediaVectorReplica> {
    let served = vault.media_vector_replicas(asset, SPACE)?;
    assert_eq!(
        served.len(),
        1,
        "the home serves one replica of the {kind} ASSET's vector"
    );
    let replica = served.into_iter().next().ok_or("one replica")?;
    let wire = serde_json::to_value(&replica)?;
    assert_eq!(wire["kind"], kind, "the replica names its input kind");
    assert_eq!(replica.space_id(), SPACE);
    assert_eq!(
        replica.sources(),
        [(*asset, row_digest(vault, asset)?)].as_slice(),
        "an image or audio replica is bound to its ASSET row, which names the bytes"
    );
    Ok(replica)
}

/// `record`, an ingested ASSET's body, with one binary field past the 8 MiB inline limit: a
/// body the file plane holds, as a long ASSET record is held.
fn long_record(record: &[u8]) -> TestResult<Vec<u8>> {
    let rmpv::Value::Map(mut fields) = rmpv::decode::read_value(&mut &record[..])? else {
        return Err("an ASSET record is a map".into());
    };
    fields.push((
        rmpv::Value::from("padding"),
        rmpv::Value::Binary(vec![0; 8 * 1024 * 1024 + 1]),
    ));
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &rmpv::Value::Map(fields))?;
    Ok(body)
}

/// `replica` as it arrives on the wire after `edit` changed it.
fn edited(
    replica: &MediaVectorReplica,
    edit: impl FnOnce(&mut Value),
) -> TestResult<MediaVectorReplica> {
    let mut wire = serde_json::to_value(replica)?;
    edit(&mut wire);
    Ok(serde_json::from_value(wire)?)
}

#[test]
fn an_image_vector_serves_as_a_replica_bound_to_its_asset_row() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = media_vault(dir.path())?;
    let asset = asset_with_vector(
        &vault,
        InputKind::Image,
        "image/png",
        b"\x89PNG\r\n\x1a\n image bytes",
        &[0.25, 0.5, -0.25, 1.0],
    )?;
    served_replica(&vault, &asset, "image")?;
    Ok(())
}

#[test]
fn an_audio_vector_serves_from_the_shared_media_space() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = media_vault(dir.path())?;
    let asset = asset_with_vector(
        &vault,
        InputKind::Audio,
        "audio/wav",
        b"RIFF audio bytes",
        &[1.0, 0.0, 0.5, -0.5],
    )?;
    served_replica(&vault, &asset, "audio")?;
    Ok(())
}

#[test]
fn an_image_replica_installs_only_where_the_asset_row_matches() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = media_vault(dir.path())?;
    let asset = asset_with_vector(
        &vault,
        InputKind::Image,
        "image/png",
        b"\x89PNG\r\n\x1a\n receiver image",
        &[0.25, 0.5, -0.25, 1.0],
    )?;
    let replica = served_replica(&vault, &asset, "image")?;

    // A replica whose source digest names another row's bytes lands nothing.
    let other_digest = edited(&replica, |wire| {
        wire["sources"][0][1][0] =
            Value::from((wire["sources"][0][1][0].as_u64().unwrap_or_default() + 1) % 256);
    })?;
    assert!(
        !install_media_vector_replica(&vault, &asset, &other_digest)?,
        "a source digest that is not the ASSET row's is refused"
    );
    // A replica that names another kind lands nothing.
    let other_kind = edited(&replica, |wire| wire["kind"] = Value::from("audio"))?;
    assert!(
        !install_media_vector_replica(&vault, &asset, &other_kind)?,
        "an image ASSET takes no audio vector"
    );
    // A 3-wide row does not decode at the space's own width.
    let narrow = edited(&replica, |wire| {
        if let Some(row) = wire["row"].as_array_mut() {
            row.truncate(row.len() - 2);
        }
    })?;
    assert!(
        !install_media_vector_replica(&vault, &asset, &narrow)?,
        "a row of another width is refused"
    );
    assert_eq!(
        vault.media_vector_replicas(&asset, SPACE)?,
        vec![replica.clone()],
        "a refused replica leaves the local vector as it was"
    );

    // The receiver's own vector differs; the served replica replaces it with the home's.
    vault.put_media_vector(SPACE, &asset, InputKind::Image, &[-1.0, 0.0, 0.0, 0.5])?;
    assert_ne!(
        vault.media_vector_replicas(&asset, SPACE)?,
        vec![replica.clone()]
    );
    assert!(
        install_media_vector_replica(&vault, &asset, &replica)?,
        "a replica bound to this ASSET row, of its kind and width, installs"
    );
    assert_eq!(
        vault.media_vector_replicas(&asset, SPACE)?,
        vec![replica],
        "the installed vector is the home's"
    );
    Ok(())
}

#[test]
fn a_file_held_image_replica_names_the_row_a_residence_door_serves() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = media_vault(dir.path())?;
    let vector = [0.25, 0.5, -0.25, 1.0];
    let ingested = asset_with_vector(
        &vault,
        InputKind::Image,
        "image/png",
        b"\x89PNG\r\n\x1a\n filed image",
        &vector,
    )?;
    let body = long_record(&vault.get(&ingested)?.ok_or("the ingested ASSET record")?)?;
    let occurred = TimeRange {
        start: OCCURRED_AT,
        end: OCCURRED_AT,
    };
    // The first long body a vault stores stays in its row while the body-instance pool fills
    // (FIX 22091); the next one is filed.
    vault.put_entity(
        &EntityId::now(),
        ENTITY_TYPE_ASSET,
        occurred,
        OCCURRED_AT,
        &body,
    )?;
    let asset = EntityId::now();
    vault.put_entity(&asset, ENTITY_TYPE_ASSET, occurred, OCCURRED_AT, &body)?;
    // The row as stored; the public raw read hands the whole record in place of its manifest.
    let stored = stored_row(&vault, &asset)?.ok_or("the filed ASSET row")?;
    assert!(
        stored.len() < body.len(),
        "the file plane holds the long record; its stored row keeps a manifest ({} stored \
         bytes, a {}-byte record)",
        stored.len(),
        body.len()
    );
    vault.put_media_vector(SPACE, &asset, InputKind::Image, &vector)?;

    // A residence door serves the filed row whole: its header, then the whole record.
    let mut served = stored[..ENTITY_METADATA_HEADER_LEN].to_vec();
    served.extend_from_slice(&body);
    assert_eq!(
        vault.get_raw(&asset)?.map(|row| blake3::hash(&row)),
        Some(blake3::hash(&served)),
        "the public raw read hands the row a residence door serves"
    );
    let replicas = vault.media_vector_replicas(&asset, SPACE)?;
    assert_eq!(
        replicas.len(),
        1,
        "the home serves one replica of the filed image's vector"
    );
    assert_eq!(
        replicas[0].sources(),
        [(asset, *blake3::hash(&served).as_bytes())].as_slice(),
        "the replica names the digest of the row a residence door serves, not of its manifest"
    );
    assert!(
        install_media_vector_replica(&vault, &asset, &replicas[0])?,
        "the replica installs where the same filed row is held"
    );
    Ok(())
}
