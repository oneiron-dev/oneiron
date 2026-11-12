//! `NativeRawRead::entity_body`, the native raw read a credential-read callback
//! hands its reader, serves a masked reader an ASSET as `vault.assets.masked_read`
//! serves it (FIX NATIVE-RAW-ENTITY-BODY-SHIPS-SCAN-OFF-CREDENTIALS). An ASSET
//! under an id its bytes do not derive, stored with the write door's scan off and
//! holding a token, answers none, while its clean twin is served its stored bytes
//! unchanged. An unmarked container whose member holds a token answers none too,
//! as a withheld row does. The seam every masked serve door reads through, the
//! public `Vault::sighted_asset_bytes`, withholds unmarked plain bytes that hold a
//! token from a masked reader, as it withholds a container's live key, while the
//! owner reads them as stored. Only public doors are used, so the file builds on
//! main.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test native_raw_entity_body_release_scan`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::io::Write as _;
use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{Memory, MemoryError};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::secret_custody::SecretSight;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, ErrorKind,
    TimeRange, Vault, VaultConfig,
};

const RAW_BODY_TEST_NOW: u64 = 1_700_000_000;

const RAW_BODY_TEST_TIME: TimeRange = TimeRange {
    start: RAW_BODY_TEST_NOW,
    end: RAW_BODY_TEST_NOW,
};

/// An enabled, active agent definition the owner creates as `name`.
fn raw_body_definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "native raw body fixture",
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

struct RawBodyFixture {
    vault: Vault,
    holder: EntityId,
    _dir: tempfile::TempDir,
}

/// A fresh vault whose owner turned the write door's scan off, with one agent
/// the owner granted the base world to read, rooted and enrolled first as a
/// serving start does. The agent's key reads masked: it is not the owner's.
fn raw_body_fixture() -> RawBodyFixture {
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
            &raw_body_definition("yuki"),
            RAW_BODY_TEST_TIME,
            RAW_BODY_TEST_NOW,
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
        },
    )
    .expect("owner grants the agent the base world");
    assert!(minted.grant.confers, "the grant confers");
    vault
        .set_secret_scan_mode(&owner_proof, SecretScanMode::Off, RAW_BODY_TEST_NOW)
        .expect("owner turns the write door's scan off");
    RawBodyFixture {
        vault,
        holder,
        _dir: dir,
    }
}

/// Stores `body` as an ASSET under a fresh id its bytes do not derive, so no
/// repo projection reaches it; with the scan off it is stored raw, no mark.
fn raw_body_put_asset(vault: &Vault, body: &[u8]) -> EntityId {
    let asset = EntityId::now();
    vault
        .put_entity(
            &asset,
            ENTITY_TYPE_ASSET,
            RAW_BODY_TEST_TIME,
            RAW_BODY_TEST_NOW,
            body,
        )
        .expect("owner stores the asset with the scan off");
    asset
}

/// `id`'s body as `memory`'s actor reads it through the public native raw door.
fn raw_body_read(memory: &Memory<'_>, id: &EntityId) -> Result<Option<Vec<u8>>, MemoryError> {
    memory.with_credential_raw_read(|read| read.entity_body(id))
}

/// A GitHub token shape the release scan reads, joined at run time so no token
/// literal sits in the source.
fn raw_body_token() -> String {
    ["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat()
}

fn raw_body_holds(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// A ZIP archive with one stored (uncompressed) member `name` holding `member`.
fn raw_body_zip(name: &str, member: &[u8]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            name,
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .expect("zip member");
    writer.write_all(member).expect("zip member bytes");
    writer.finish().expect("zip archive").into_inner()
}

/// A plain-text ASSET stored with the scan off carries no mark, so the masks
/// leave it as it is; the release scan still reads the token in it, and the
/// masked reader is served none. Its clean twin is served its stored bytes
/// unchanged, so the none is the withhold, not the lane.
#[test]
fn native_raw_entity_body_withholds_a_scan_off_asset_whose_bytes_hold_a_key() {
    let fixture = raw_body_fixture();
    let token = raw_body_token();
    let keyed_body = format!("deploy token {token}\n");
    let clean_body = b"deploy notes with no key\n";
    let keyed = raw_body_put_asset(&fixture.vault, keyed_body.as_bytes());
    let clean = raw_body_put_asset(&fixture.vault, clean_body);
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    assert_eq!(
        raw_body_read(&memory, &clean).expect("the clean asset answers"),
        Some(clean_body.to_vec()),
        "a clean non-repo asset is served its stored bytes unchanged",
    );
    let served = raw_body_read(&memory, &keyed).expect("the keyed asset answers");
    assert!(
        !served
            .as_deref()
            .is_some_and(|bytes| raw_body_holds(bytes, token.as_bytes())),
        "FAILBEFORE NATIVE-RAW-ENTITY-BODY-SHIPS-SCAN-OFF-CREDENTIALS: the masked reader is served no bytes that hold the token",
    );
    assert_eq!(
        served.map(|bytes| bytes.len()),
        None,
        "a non-repo asset whose bytes hold a token answers none",
    );
}

/// A container stored with the scan off carries no mark either; the walk reads
/// the token in its member, and the masked reader is served none, as a withheld
/// row answers, not an error.
#[test]
fn native_raw_entity_body_withholds_an_unmarked_container_whose_member_holds_a_key() {
    let fixture = raw_body_fixture();
    let token = raw_body_token();
    let archive = raw_body_zip("config.txt", format!("deploy token {token}\n").as_bytes());
    let asset = raw_body_put_asset(&fixture.vault, &archive);
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let served = raw_body_read(&memory, &asset);
    let shown = served
        .as_ref()
        .map(|body| body.as_ref().map(Vec::len))
        .map_err(|error| format!("{}: {}", error.code, error.message));
    assert!(
        matches!(served, Ok(None)),
        "an unmarked container whose member holds a token answers none, as a withheld row does; got {shown:?} (Ok(Some(n)) is the served length)",
    );
}

/// The seam itself, through the public `Vault::sighted_asset_bytes` that the
/// hosted serve, the artifact exports and reads, the organ lend and graph-fs
/// all read through: plain bytes that hold a token and carry no mark are
/// withheld from a masked reader as `MaskedCopyWithheld`, as a container's live
/// key is. The owner reads them as stored, and clean plain bytes pass unchanged.
#[test]
fn sighted_asset_bytes_withholds_unmarked_plain_bytes_that_hold_a_key() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let token = raw_body_token();
    let keyed = format!("deploy token {token}\n").into_bytes();
    let clean = b"deploy notes with no key\n".to_vec();
    assert_eq!(
        vault
            .sighted_asset_bytes(keyed.clone(), SecretSight::Owner)
            .expect("the owner reads"),
        keyed,
        "the owner reads the stored bytes",
    );
    assert_eq!(
        vault
            .sighted_asset_bytes(clean.clone(), SecretSight::Masked)
            .expect("clean bytes read"),
        clean,
        "clean plain bytes pass unchanged",
    );
    let masked = vault.sighted_asset_bytes(keyed, SecretSight::Masked);
    assert!(
        !masked
            .as_ref()
            .is_ok_and(|bytes| raw_body_holds(bytes, token.as_bytes())),
        "FAILBEFORE NATIVE-RAW-ENTITY-BODY-SHIPS-SCAN-OFF-CREDENTIALS: a masked reader is served no unmarked plain bytes that hold the token",
    );
    let shown = masked.as_ref().map(Vec::len).map_err(|error| error.kind());
    assert!(
        matches!(shown, Err(ErrorKind::MaskedCopyWithheld)),
        "unmarked plain bytes that hold a token are withheld as MaskedCopyWithheld; got {shown:?} (Ok(n) is the served length)",
    );
}
