//! A masked reader is served an asset's image and audio forms, and a graph-fs
//! file, only as every other masked serve door serves it (FIX
//! RAWBODY-CENSUS-UNTRACED-SERVE-PATHS). With the write door's scan off, an
//! uploaded clip or image whose bytes hold a token carries no mark, and a row
//! whose body holds one carries no lifted key; serve still redacts
//! (`SecretScanMode::Off`). So `vault.assets.resolve` serves no such clip,
//! `vault.images.view` no such image, and `graph_fs.cat` serves such a body as
//! an entity view does, with the token redacted. A graph-fs listing of an entity
//! whose asset is withheld answers rather than failing. The clean twin of each
//! is served its stored bytes unchanged, so each withhold is the scan, not the
//! lane. Only public doors are used, so the file builds on main.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test masked_forms_and_graph_fs_release_scan`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine as _;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::embed::InputKind;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::graph_fs::GraphFsReference;
use oneiron::memory::graph_fs_doors::{
    GraphFsEncoding, GraphFsLsRequest, GraphFsMountRequest, GraphFsOutput, GraphFsPathRequest,
};
use oneiron::memory::{
    AssetIngestRequest, AssetResolveRequest, ImageViewRequest, Memory, MemoryError,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig,
};

const FORMS_TEST_NOW: u64 = 1_700_000_000;

const FORMS_TEST_TIME: TimeRange = TimeRange {
    start: FORMS_TEST_NOW,
    end: FORMS_TEST_NOW,
};

/// An enabled, active agent definition the owner creates as `name`.
fn forms_definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "masked forms fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

struct FormsFixture {
    vault: Vault,
    owner: EntityId,
    holder: EntityId,
    _dir: tempfile::TempDir,
}

/// A fresh vault whose owner turned the write door's scan off, with one agent
/// the owner granted the base world to read, rooted and enrolled first as a
/// serving start does. The agent's key reads masked: it is not the owner's.
fn forms_fixture() -> FormsFixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let holder = EntityId::now();
    vault
        .create_agent_definition_as(
            &owner_proof,
            &holder,
            &forms_definition("yuki"),
            FORMS_TEST_TIME,
            FORMS_TEST_NOW,
        )
        .expect("owner creates the agent");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: holder,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner grants the agent the base world");
    assert!(minted.grant.confers, "the grant confers");
    vault
        .set_secret_scan_mode(&owner_proof, SecretScanMode::Off, FORMS_TEST_NOW)
        .expect("owner turns the write door's scan off");
    FormsFixture {
        vault,
        owner,
        holder,
        _dir: dir,
    }
}

/// A GitHub token shape the release scan reads, joined at run time so no token
/// literal sits in the source.
fn forms_token() -> String {
    ["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat()
}

fn forms_holds(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// The owner uploads `bytes` as an asset of `kind` and `mime_type`, with a
/// text form; with the scan off they land with no mark.
fn forms_ingest(
    owner: &Memory<'_>,
    kind: InputKind,
    mime_type: &str,
    bytes: &[u8],
    text: &str,
) -> String {
    owner
        .ingest_asset(&AssetIngestRequest {
            asset_ref: None,
            embedding_kind: kind,
            mime_type: mime_type.to_owned(),
            bytes_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
            text: Some(text.to_owned()),
            occurred_at: FORMS_TEST_NOW,
        })
        .expect("owner uploads the asset with the scan off")
        .asset_ref
}

/// `asset_ref` as `memory`'s reader resolves it for a consumer that reads
/// audio (`audio`) or images.
fn forms_resolve(
    memory: &Memory<'_>,
    asset_ref: &str,
    audio: bool,
) -> Result<oneiron::memory::AssetResolved, MemoryError> {
    memory
        .resolve_asset_form(&AssetResolveRequest {
            asset_ref: asset_ref.to_owned(),
            image_input: !audio,
            audio_input: audio,
            room_bytes: None,
        })
        .map(|resolved| resolved.value)
}

fn forms_decoded(b64: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("standard base64")
}

/// The CRC-32 a PNG chunk carries over its type and data.
fn forms_crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A valid one-pixel PNG of `rgba`, with a `tEXt` comment chunk holding
/// `comment` after its header chunk when one is given.
fn forms_png(rgba: [u8; 4], comment: Option<&str>) -> Vec<u8> {
    let mut png = Vec::new();
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(1, 1, image::Rgba(rgba)))
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .expect("one-pixel PNG");
    let Some(comment) = comment else {
        return png;
    };
    // The signature (8 bytes) and the IHDR chunk (4 + 4 + 13 + 4 bytes).
    let after_header = 8 + 25;
    let mut data = b"Comment\0".to_vec();
    data.extend_from_slice(comment.as_bytes());
    let mut typed = b"tEXt".to_vec();
    typed.extend_from_slice(&data);
    let mut chunk = u32::try_from(data.len())
        .expect("short comment")
        .to_be_bytes()
        .to_vec();
    chunk.extend_from_slice(&typed);
    chunk.extend_from_slice(&forms_crc32(&typed).to_be_bytes());
    let tail = png.split_off(after_header);
    png.extend_from_slice(&chunk);
    png.extend_from_slice(&tail);
    png
}

/// The live-head graph-fs mount.
fn forms_mount() -> GraphFsMountRequest {
    GraphFsMountRequest {
        reference: GraphFsReference::LiveHead,
        page_byte_cap: None,
        max_entries: None,
    }
}

/// `id`'s body as `memory`'s reader cats it from the live-head graph fs.
fn forms_cat(memory: &Memory<'_>, id: &EntityId) -> Vec<u8> {
    let output = memory
        .graph_fs_cat(GraphFsPathRequest {
            mount: forms_mount(),
            path: format!("/entities/{}/body", id.to_hex()),
            cursor: None,
        })
        .expect("the body cats");
    forms_output_bytes(&output)
}

fn forms_output_bytes(output: &GraphFsOutput) -> Vec<u8> {
    match output.encoding {
        GraphFsEncoding::Utf8 => output.output.clone().into_bytes(),
        GraphFsEncoding::Base64 => forms_decoded(&output.output),
    }
}

/// `body` stored as `entity_type` under a fresh id; with the scan off it is
/// stored raw, with no mark and no lifted key.
fn forms_put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, entity_type, FORMS_TEST_TIME, FORMS_TEST_NOW, body)
        .expect("owner stores the row with the scan off");
    id
}

/// A clip whose bytes hold a token, uploaded with the scan off, carries no
/// mark: the audio form served a masked reader holds no token (on main it is
/// the stored clip), while the clean twin's clip is served as stored.
#[test]
fn asset_resolve_withholds_a_scan_off_clip_whose_bytes_hold_a_key() {
    let fixture = forms_fixture();
    let token = forms_token();
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let mut keyed_clip = b"ID3\x04\x00\x00\x00\x00\x00\x30COMM deploy token ".to_vec();
    keyed_clip.extend_from_slice(token.as_bytes());
    keyed_clip.extend_from_slice(b"\n\xff\xfb\x90\x00");
    let clean_clip = b"ID3\x04\x00\x00\x00\x00\x00\x30COMM deploy notes\n\xff\xfb\x90\x00".to_vec();
    let keyed = forms_ingest(
        &owner,
        InputKind::Audio,
        "audio/mpeg",
        &keyed_clip,
        "a clip",
    );
    let clean = forms_ingest(
        &owner,
        InputKind::Audio,
        "audio/mpeg",
        &clean_clip,
        "a clip",
    );
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let clean_served = forms_resolve(&memory, &clean, true).expect("the clean clip resolves");
    assert_eq!(
        clean_served.bytes_b64.as_deref().map(forms_decoded),
        Some(clean_clip),
        "a clean clip is served to the masked reader as stored",
    );
    let keyed_served = forms_resolve(&memory, &keyed, true);
    if let Ok(served) = &keyed_served {
        assert!(
            !served
                .bytes_b64
                .as_deref()
                .map(forms_decoded)
                .is_some_and(|bytes| forms_holds(&bytes, token.as_bytes())),
            "a masked reader is served no clip whose bytes hold a token",
        );
    }
    let owner_served = forms_resolve(&owner, &keyed, true).expect("the owner resolves the clip");
    assert_eq!(
        owner_served.bytes_b64.as_deref().map(forms_decoded),
        Some(keyed_clip),
        "the owner reads the clip as stored",
    );
}

/// An image whose metadata holds a token, uploaded with the scan off,
/// carries no mark, so no raster runs: neither `vault.images.view` nor
/// `vault.assets.resolve` serves a masked reader its bytes (on main both serve
/// the stored image), while the clean twin's view is its stored bytes.
#[test]
fn image_view_withholds_a_scan_off_image_whose_metadata_holds_a_key() {
    let fixture = forms_fixture();
    let token = forms_token();
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let keyed_png = forms_png([200, 10, 10, 255], Some(&format!("deploy token {token}\n")));
    let clean_png = forms_png([10, 200, 10, 255], None);
    let keyed = forms_ingest(&owner, InputKind::Image, "image/png", &keyed_png, "a chart");
    let clean = forms_ingest(&owner, InputKind::Image, "image/png", &clean_png, "a chart");
    let handle = |asset_ref: &str| {
        forms_resolve(&owner, asset_ref, false)
            .expect("the owner resolves the image")
            .handle
            .expect("the owner's image form has a handle")
    };
    let (keyed_handle, clean_handle) = (handle(&keyed), handle(&clean));
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let view = |handle: &str| {
        memory.view_image(&ImageViewRequest {
            handle: handle.to_owned(),
            region: None,
            edge: None,
        })
    };
    let clean_view = view(&clean_handle).expect("the clean image views");
    assert_eq!(
        forms_decoded(&clean_view.bytes),
        clean_png,
        "a clean image is served to the masked reader as stored",
    );
    if let Ok(keyed_view) = view(&keyed_handle) {
        assert!(
            !forms_holds(&forms_decoded(&keyed_view.bytes), token.as_bytes()),
            "a masked reader views no image whose bytes hold a token",
        );
    }
    if let Ok(resolved) = forms_resolve(&memory, &keyed, false) {
        assert!(
            !resolved
                .bytes_b64
                .as_deref()
                .map(forms_decoded)
                .is_some_and(|bytes| forms_holds(&bytes, token.as_bytes())),
            "a masked reader resolves no image whose bytes hold a token",
        );
    }
}

/// A row whose body holds a token, stored with the scan off, has no lifted
/// key: `graph_fs.cat` serves a masked reader that body with the token
/// redacted, as an entity view reads it, in a text body and in a MessagePack
/// body alike (on main it serves the stored body), while a clean body is
/// served as stored.
#[test]
fn graph_fs_cat_redacts_a_scan_off_body_that_holds_a_key() {
    let fixture = forms_fixture();
    let token = forms_token();
    let keyed_text = format!("deploy token {token}\n");
    let clean_text = b"deploy notes with no key\n".to_vec();
    let mut keyed_map = Vec::new();
    rmpv::encode::write_value(
        &mut keyed_map,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("note"),
            rmpv::Value::from(format!("deploy token {token}")),
        )]),
    )
    .expect("keyed MessagePack body");
    let mut clean_map = Vec::new();
    rmpv::encode::write_value(
        &mut clean_map,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("note"),
            rmpv::Value::from("deploy notes"),
        )]),
    )
    .expect("clean MessagePack body");
    let keyed_text_row = forms_put(&fixture.vault, ENTITY_TYPE_PERSON, keyed_text.as_bytes());
    let clean_text_row = forms_put(&fixture.vault, ENTITY_TYPE_PERSON, &clean_text);
    let keyed_map_row = forms_put(&fixture.vault, ENTITY_TYPE_PERSON, &keyed_map);
    let clean_map_row = forms_put(&fixture.vault, ENTITY_TYPE_PERSON, &clean_map);
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    assert_eq!(
        forms_cat(&memory, &clean_text_row),
        clean_text,
        "a clean text body is served as stored",
    );
    assert_eq!(
        forms_cat(&memory, &clean_map_row),
        clean_map,
        "a clean MessagePack body is served as stored",
    );
    let text_served = forms_cat(&memory, &keyed_text_row);
    assert!(
        !forms_holds(&text_served, token.as_bytes()),
        "a masked reader cats no text body that holds a token",
    );
    let map_served = forms_cat(&memory, &keyed_map_row);
    assert!(
        !forms_holds(&map_served, token.as_bytes()),
        "a masked reader cats no MessagePack body that holds a token",
    );
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    assert_eq!(
        forms_cat(&owner, &keyed_text_row),
        keyed_text.into_bytes(),
        "the owner cats the body as stored",
    );
}

/// An ASSET whose plain bytes hold a token, stored with the scan off, is
/// withheld from a masked reader. A graph-fs listing of its entity answers
/// (on main the withhold is an error that fails the listing), and its body
/// serves no token.
#[test]
fn graph_fs_ls_lists_an_entity_whose_asset_is_withheld() {
    let fixture = forms_fixture();
    let token = forms_token();
    let keyed = forms_put(
        &fixture.vault,
        ENTITY_TYPE_ASSET,
        format!("deploy token {token}\n").as_bytes(),
    );
    let clean_body = b"deploy notes with no key\n".to_vec();
    let clean = forms_put(&fixture.vault, ENTITY_TYPE_ASSET, &clean_body);
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let ls = |id: &EntityId| {
        memory.graph_fs_ls(GraphFsLsRequest {
            mount: forms_mount(),
            path: format!("/entities/{}", id.to_hex()),
            cursor: None,
            by_time: false,
        })
    };
    ls(&clean).expect("the clean asset's entity lists");
    assert_eq!(
        forms_cat(&memory, &clean),
        clean_body,
        "a clean asset's body is served as stored",
    );
    let listed = ls(&keyed);
    assert!(
        listed.is_ok(),
        "a withheld asset's entity lists for a masked reader: {:?}",
        listed.err(),
    );
    if let Ok(output) = memory.graph_fs_cat(GraphFsPathRequest {
        mount: forms_mount(),
        path: format!("/entities/{}/body", keyed.to_hex()),
        cursor: None,
    }) {
        assert!(
            !forms_holds(&forms_output_bytes(&output), token.as_bytes()),
            "a masked reader cats no asset body that holds a token",
        );
    }
}
