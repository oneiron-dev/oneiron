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
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test media_vector_replica`
#![cfg(all(feature = "sync", oneiron_test_support))]

use std::collections::BTreeSet;

use base64::Engine as _;
use oneiron::embed::{EmbeddingSpace, InputKind, MediaVectorReplica};
use oneiron::memory::AssetIngestRequest;
use oneiron::test_doors::media_vector_replica::install_media_vector_replica;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
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
    let served = vault.text_media_vector_replicas(asset, SPACE)?;
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
        vault.text_media_vector_replicas(&asset, SPACE)?,
        vec![replica.clone()],
        "a refused replica leaves the local vector as it was"
    );

    // The receiver's own vector differs; the served replica replaces it with the home's.
    vault.put_media_vector(SPACE, &asset, InputKind::Image, &[-1.0, 0.0, 0.0, 0.5])?;
    assert_ne!(
        vault.text_media_vector_replicas(&asset, SPACE)?,
        vec![replica.clone()]
    );
    assert!(
        install_media_vector_replica(&vault, &asset, &replica)?,
        "a replica bound to this ASSET row, of its kind and width, installs"
    );
    assert_eq!(
        vault.text_media_vector_replicas(&asset, SPACE)?,
        vec![replica],
        "the installed vector is the home's"
    );
    Ok(())
}
