//! The owner's listing and excerpt bounds, served (restriction wave 21, C85-C89).
//!
//! Commit `c17fe39fc9b6` moves five hard-coded bounds onto the Setting
//! primitive as owner keys, each defaulting to today's bound, so nothing
//! changes until the owner moves it:
//!
//! - `verbs.support_grant.list_max` (PageMax, 500): the most grants one
//!   `vault.support_grants.list` answers; an ask with no limit is served 500.
//! - `verbs.hooks_replay.page_max` (PageMax, 256): the most entries one
//!   `vault.hooks.replay` page holds.
//! - `lens.list.max_page` (PageMax, 200): the most rows one
//!   `vault.lenses.list` page holds; an ask with no limit is served 200.
//! - `lens.refs.snippet_chars` (280): the most characters of a record's
//!   admitted text a `vault.refs.resolve` snippet carries.
//! - `lens.dossier.lines_shown` (32): the most non-blank body lines one
//!   `vault.lenses.default` dossier section shows.
//!
//! Each key refuses 0: the PageMax keys with "a page maximum is at least one
//! row", the excerpt keys with "a lens excerpt shows at least one unit".
//!
//! What each test chose: the two list maxima are TIGHTEN tests (a raise
//! would need 500 support grants and 200 lens proposals); the snippet and
//! the dossier are RAISE tests (400 characters, 40 lines). The hooks replay
//! page is NOT pinned here: its owner call needs a hook body runtime, and no
//! integration test under `crates/oneiron` reaches one without the server
//! (see NOTES.md); its key is covered by the zero table only.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test restriction_wave_21_list_keys`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use oneiron::authority::{HostSlipIssuer, SupportGrantRequest, SupportHolderClass};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use oneiron::lens::{
    GeneratedLens, LensAtom, LensAtomId, LensDefaultRequest, LensDossierSource, LensListRequest,
    LensNode, LensProposeRequest, LensSlot, LensText, LensTextSpan,
    RECORD_REF_SNIPPET_MAX_CHARS, ResolveRecordRefRequest, TextBlockAtom,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{SupportGrantListRequest, list_support_grants_embedded};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A vault this process owns: `open_owned` holds the writer lease the
/// owner's doors ask for, as `rooms_lens_skills_list_limits.rs` opens one.
fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

/// The owner's proof, as `restriction_page_keys.rs` mints it.
fn owner_proof(
    vault: &Vault,
    owner: EntityId,
) -> Result<AuthenticatedOwner, Box<dyn std::error::Error>> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// The owner's set of `value` on the vault row of `key`, applied.
/// At the parent this fails: the key is unknown there.
fn set_applied(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    key: &str,
    value: serde_json::Value,
) -> TestResult {
    let outcome = vault.set_setting(
        SettingCaller::Owner(proof),
        SetSetting::vault_value(key, value),
    )?;
    if !matches!(outcome, SetSettingOutcome::Applied { .. }) {
        return Err(format!("the owner's set of {key} applies").into());
    }
    Ok(())
}

/// How many active grants the owner's list serves with no limit.
fn grant_count(vault: &Vault, owner: EntityId) -> Result<usize, Box<dyn std::error::Error>> {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let page = list_support_grants_embedded(
        &memory,
        SupportGrantListRequest {
            include_inactive: false,
            limit: None,
        },
    )?;
    Ok(page.grants.len())
}

/// `list_support_grants_as` (`crates/oneiron/src/verbs/support_grant.rs`)
/// serves the owner's tightened `verbs.support_grant.list_max`: with no row
/// an ask with no limit serves both grants; after the owner sets the key to
/// 1 the same ask serves one.
#[test]
fn support_grant_list_serves_only_the_owners_tightened_maximum() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(&vault, owner)?;
    let issuer = HostSlipIssuer::from_secret(b"restriction-wave-21-support-secret")?;
    vault.ensure_host_root_slip(&issuer)?;
    let holder = EntityId::now();
    let at = vault.now_recorded_at();
    vault.put_entity(
        &holder,
        ENTITY_TYPE_PERSON,
        TimeRange { start: at, end: at },
        at,
        b"support holder",
    )?;
    let world = EntityId::now();
    let scope = || Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(world)])),
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
        audience: ScopeAxis::All,
        verbs: ScopeAxis::Bottom,
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Public),
    };
    for seed in [0x11u8, 0x22u8] {
        let holder_key = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        vault.mint_support_grant(
            &proof,
            &issuer,
            SupportGrantRequest {
                holder,
                holder_class: SupportHolderClass::Human,
                holder_key,
                scope: scope(),
                records: BTreeSet::new(),
                ttl_secs: None,
                purpose: "Fix the sync drive".to_owned(),
                ticket_ref: None,
                comm: None,
                repairs: BTreeSet::new(),
            },
        )?;
    }
    assert_eq!(
        grant_count(&vault, owner)?,
        2,
        "guard: with no row, an ask with no limit serves both grants"
    );
    set_applied(&vault, &proof, "verbs.support_grant.list_max", json!(1))?;
    assert_eq!(
        grant_count(&vault, owner)?,
        1,
        "tightened: the same ask serves one grant"
    );
    Ok(())
}

/// The pack the owner puts for the lens list bound: one skill, no hooks.
const LENS_PACK: &str = "example.lensbound";
const LENS_PACK_MD: &str = "---
name: example.lensbound
description: One skill for the lens list bound test.
version: 1.0.0
kind: capability
---
A pack whose one skill carries two lens proposals.
";
const LENS_SKILL_MD: &str = "---
name: example.lensbound.note
description: A note skill for the lens list bound test.
version: 1.0.0
---
# Note skill
";

/// A vault opened as `pack_hook_owner_floor.rs` opens one, with its owner's
/// proof: the install behind a lens proposal needs this install's signing.
struct LensFixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl LensFixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let vault = Vault::open(directory.path(), VaultConfig::device())?;
        vault.install_device_keystore(std::sync::Arc::new(
            oneiron_keystore::MemoryKeystore::new(),
        ));
        vault.prepare_install_signing()?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let proof = owner_proof(&vault, owner)?;
        Ok(Self {
            vault,
            owner,
            proof,
            _directory: directory,
        })
    }

    /// The owner's put of the pack; answers its skill and content hash.
    fn put_pack(&self) -> Result<(String, String), Box<dyn std::error::Error>> {
        let files = vec![
            HubFile::new("PACK.md", LENS_PACK_MD),
            HubFile::new("skills/note/SKILL.md", LENS_SKILL_MD),
        ];
        let receipt = match self.vault.put_pack(&self.proof, files)? {
            PackInstallDisposition::Installed(receipt) => receipt,
            other => return Err(format!("the owner's put installs the pack: {other:?}").into()),
        };
        let skill = receipt
            .skills
            .first()
            .ok_or("the install carries its skill")?
            .clone();
        Ok((skill, receipt.content_hash))
    }

    /// The owner's proposal of one card for the pack's skill.
    fn propose(&self, skill: &str, content_hash: &str, card: &str, prompt: &str) -> TestResult {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let root = LensNode::new(
            LensAtomId::new("lens-bound-card")?,
            LensAtom::TextBlock(TextBlockAtom {
                spans: vec![LensTextSpan::Literal(LensText::new(card)?)],
            }),
        );
        memory.lenses_propose(LensProposeRequest {
            slot: LensSlot {
                pack_name: LENS_PACK.to_owned(),
                skill_id: skill.to_owned(),
            },
            pack_content_hash: content_hash.to_owned(),
            compiled: GeneratedLens::new(root)?,
            intent_prompt: prompt.to_owned(),
            trigger: None,
            scope: None,
        })?;
        Ok(())
    }
}

/// `Memory::lenses_list` (`crates/oneiron/src/lens/proposal.rs`) serves the
/// owner's tightened `lens.list.max_page`: with no row an ask with no limit
/// serves both proposals; after the owner sets the key to 1 the same ask
/// serves one row with a cursor to the rest.
#[test]
fn lens_list_serves_only_the_owners_tightened_maximum() -> TestResult {
    let fixture = LensFixture::open()?;
    let (skill, content_hash) = fixture.put_pack()?;
    fixture.propose(
        &skill,
        &content_hash,
        "First sharpening of the note card.",
        "first sharpening of the note card",
    )?;
    fixture.propose(
        &skill,
        &content_hash,
        "Second sharpening of the note card.",
        "second sharpening of the note card",
    )?;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let page = memory.lenses_list(LensListRequest {
        limit: None,
        ..Default::default()
    })?;
    assert_eq!(
        page.rows.len(),
        2,
        "guard: with no row, an ask with no limit serves both proposals"
    );
    set_applied(
        &fixture.vault,
        &fixture.proof,
        "lens.list.max_page",
        json!(1),
    )?;
    let page = memory.lenses_list(LensListRequest {
        limit: None,
        ..Default::default()
    })?;
    assert_eq!(
        page.rows.len(),
        1,
        "tightened: the same ask serves one row"
    );
    assert_eq!(
        page.next_after,
        Some(page.rows[0].lens_ref.clone()),
        "tightened: a cursor continues to the rest"
    );
    Ok(())
}

/// The snippet `vault.refs.resolve` serves for `id`.
fn snippet_of(
    vault: &Vault,
    owner: EntityId,
    id: &EntityId,
) -> Result<String, Box<dyn std::error::Error>> {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let preview = memory.resolve_record_ref(&ResolveRecordRefRequest {
        reference: id.to_hex(),
        filter: None,
    })?;
    preview
        .value
        .snippet
        .ok_or("the record's text is excerpted")
        .map_err(Into::into)
}

/// `Memory::resolve_record_ref` (`crates/oneiron/src/lens/record_ref.rs`)
/// serves the owner's raised `lens.refs.snippet_chars`: a record whose
/// admitted text is 400 characters is excerpted to 280 while the key is
/// unset, and carried whole after the owner raises the key to 400.
#[test]
fn record_ref_snippet_serves_the_owners_raised_length() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let text = "s".repeat(400);
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "content": text.clone() }))?;
    let at = vault.now_recorded_at();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: at, end: at },
        at,
        &body,
    )?;
    let snippet = snippet_of(&vault, owner, &id)?;
    assert_eq!(
        snippet.chars().count(),
        RECORD_REF_SNIPPET_MAX_CHARS,
        "guard: with no row, the snippet is cut to 280 characters"
    );
    assert!(
        snippet.ends_with('\u{2026}'),
        "guard: the cut snippet closes with an ellipsis"
    );
    let proof = owner_proof(&vault, owner)?;
    set_applied(&vault, &proof, "lens.refs.snippet_chars", json!(400))?;
    assert_eq!(
        snippet_of(&vault, owner, &id)?,
        text,
        "raised: the same ask carries the whole 400 characters"
    );
    Ok(())
}

/// The dossier section's lines over `id`, in order.
fn dossier_lines(
    vault: &Vault,
    owner: EntityId,
    id: &EntityId,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let hosted = memory.lenses_default_framed(LensDefaultRequest {
        title: "Bound dossier".to_owned(),
        ledger: Vec::new(),
        dossiers: vec![LensDossierSource {
            entity_ref: id.to_hex(),
            title: "Forty lines".to_owned(),
        }],
        threads: Vec::new(),
        as_of: None,
        surface: None,
    })?
    .value;
    let section = hosted
        .card
        .tree
        .root()
        .children
        .iter()
        .find_map(|node| match &node.atom {
            LensAtom::DossierSection(section) => Some(section),
            _ => None,
        })
        .ok_or("the dossier section is rendered")?;
    Ok(section
        .lines
        .iter()
        .map(|line| line.as_str().to_owned())
        .collect())
}

/// `Memory::lenses_default_framed` (`crates/oneiron/src/lens/sdk.rs`) serves the
/// owner's raised `lens.dossier.lines_shown`: a source body of 40 non-blank
/// lines shows 32 while the key is unset, and all 40 after the owner raises
/// the key to 64.
#[test]
fn dossier_section_serves_the_owners_raised_line_count() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let body = (1..=40)
        .map(|line| format!("line {line:02}"))
        .collect::<Vec<_>>()
        .join("\n");
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: at, end: at },
        at,
        body.as_bytes(),
    )?;
    let lines = dossier_lines(&vault, owner, &id)?;
    assert_eq!(
        lines.len(),
        32,
        "guard: with no row, the section shows 32 lines"
    );
    assert_eq!(lines[31], "line 32", "guard: the section ends at line 32");
    let proof = owner_proof(&vault, owner)?;
    set_applied(&vault, &proof, "lens.dossier.lines_shown", json!(64))?;
    let lines = dossier_lines(&vault, owner, &id)?;
    assert_eq!(
        lines.len(),
        40,
        "raised: the same ask shows all 40 lines"
    );
    assert_eq!(lines[39], "line 40", "raised: the section ends at line 40");
    Ok(())
}

/// The owner's set of 0 on `key` answers `InvalidConfig` with its refusal,
/// as `restriction_page_keys.rs` asserts it.
fn assert_zero_refused(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    key: &str,
    refusal: &str,
) -> TestResult {
    match vault.set_setting(
        SettingCaller::Owner(proof),
        SetSetting::vault_value(key, json!(0)),
    ) {
        Err(oneiron::Error::InvalidConfig(text)) => {
            assert_eq!(text, refusal, "{key} refuses zero");
            Ok(())
        }
        Err(other) => Err(format!("{key}: zero is refused as invalid config, not {other:?}").into()),
        Ok(_) => Err(format!("{key}: a zero bound is refused").into()),
    }
}

/// A zero bound is refused on all five keys: the three PageMax keys with
/// the page maximum's refusal, the two excerpt keys with the excerpt's.
#[test]
fn a_zero_bound_is_refused_on_all_five_keys() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(&vault, owner)?;
    for key in [
        "verbs.support_grant.list_max",
        "verbs.hooks_replay.page_max",
        "lens.list.max_page",
    ] {
        assert_zero_refused(&vault, &proof, key, "a page maximum is at least one row")?;
    }
    for key in ["lens.refs.snippet_chars", "lens.dossier.lines_shown"] {
        assert_zero_refused(&vault, &proof, key, "a lens excerpt shows at least one unit")?;
    }
    Ok(())
}
