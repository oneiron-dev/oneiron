//! A framed lens names each row it binds by the row's engine short id
//! (FIX WEAVE-LENS-BACKING-REF-FULL-HEX).
//!
//! The owner's live weave lens and the default vault lens mint one backing
//! ref per bound row, and the frame reads each ref back as a short
//! reference before it admits the render. Both callers passed the row's
//! full hex id as its short id. The short-id table resolves only engine
//! short ids, so every framed lens with a bound row refused "lens backing
//! short ref is not readable by the acting principal". These tests open
//! each lens as the owner and check that every backing ref resolves back to
//! its row, and that the card's row is bound to it.
//!
//! The fixture is the run repo fixture's owned vault (`tests/repo_run`),
//! with one Approved, Active claim the owner stated about the owner.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test lens_backing_refs_use_engine_short_ids`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use fixture::{RepoFixture, TestResult};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, WeaveLensPlan,
    WeaveLensPlanLine, WeaveLensPlanSection, WeaveReportRequest, WeaveSectionInput,
    WeaveSectionKind,
};
use oneiron::lens::{
    GeneratedUiSurfaceCapabilities, LensBackingTargetKind, LensDefaultRequest, LensHandleRef,
    LensHandleRole, LensRenderFrame,
};
use oneiron::{EntityId, TimeRange};

/// A predicate the shipped policy manifest names normal (its `profile.`
/// rule), so the owner's Approved claim lands without pending.
const NOTE_PREDICATE: &str = "profile.note";

/// One Approved, Active claim the owner stated about the owner.
fn put_note(repo: &RepoFixture) -> TestResult<EntityId> {
    let at = repo.vault.now_recorded_at();
    let mut body = ClaimBody::new(
        NOTE_PREDICATE,
        ClaimSubject::Entity(repo.owner),
        rmpv::Value::from("yuki"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    let id = EntityId::now();
    repo.vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)?;
    Ok(id)
}

/// The frame's one backing ref under `handle`: it names `row` by a short
/// id that is not the row's hex id, and that short reference resolves back
/// to `row`.
fn assert_backing_ref(
    repo: &RepoFixture,
    frame: &LensRenderFrame,
    handle: &str,
    row: EntityId,
    role: LensHandleRole,
    kind: LensBackingTargetKind,
) -> TestResult {
    let mut named = frame
        .backing_refs()
        .iter()
        .filter(|backing| backing.handle().as_str() == handle);
    let backing = named
        .next()
        .ok_or_else(|| format!("the frame mints no backing ref {handle}"))?;
    assert!(named.next().is_none(), "two backing refs named {handle}");
    assert_eq!(backing.role(), role);
    let target = backing.target();
    assert_eq!(target.kind(), kind);
    assert_eq!(*target.entity_id(), row);
    assert_ne!(target.short_id(), row.to_hex());
    let hydrated = repo
        .vault
        .hydrate_short_id(target.short_id(), target.content_hash())?
        .ok_or_else(|| format!("the short ref {} resolves to no row", target.short_ref()))?;
    assert_eq!(hydrated.id, row);
    Ok(())
}

/// The bindings of the card node `id`.
fn node_bindings(
    nodes: &[oneiron::lens::GeneratedUiNode],
    id: &str,
) -> TestResult<Vec<LensHandleRef>> {
    let node = nodes
        .iter()
        .find(|node| node.id.as_str() == id)
        .ok_or_else(|| format!("the card has no node {id}"))?;
    Ok(node.bindings.clone())
}

#[test]
fn the_owners_weave_lens_binds_its_claim_by_the_claims_short_id() -> TestResult {
    let repo = RepoFixture::new()?;
    let note = put_note(&repo)?;
    let request = WeaveReportRequest {
        sections: vec![WeaveSectionInput {
            kind: WeaveSectionKind::Conflicts,
            predicates: vec![NOTE_PREDICATE.to_owned()],
            edge_kinds: Vec::new(),
        }],
    };
    let memory = repo.owner_memory();
    let live = memory
        .weave_lens_prepare(Some(&repo.owner_proof), &request)?
        .ok_or("the weave-report skill loads")?;
    let input: serde_json::Value = serde_json::from_str(&live.input)?;
    let mut keys = Vec::new();
    for section in input["sections"].as_array().ok_or("input sections")? {
        for item in section["items"].as_array().ok_or("section items")? {
            keys.push(item["key"].as_str().ok_or("item key")?.to_owned());
        }
    }
    assert_eq!(keys.len(), 1, "the one note: {}", live.input);

    // The model's answer, as the server's weave lens step hands it on.
    let answer = serde_json::to_string(&WeaveLensPlan {
        title: "Owen's notes".to_owned(),
        wrong_label: "Not right".to_owned(),
        sections: vec![WeaveLensPlanSection {
            heading: "Notes".to_owned(),
            summary: Vec::new(),
            items: keys
                .into_iter()
                .map(|key| WeaveLensPlanLine {
                    key,
                    line: "yuki noted one thing".to_owned(),
                })
                .collect(),
        }],
    })?;
    assert_eq!(live.plan_refusal(&answer), None);
    let lens = memory
        .weave_lens_finish_framed(
            Some(&repo.owner_proof),
            &request,
            live,
            &answer,
            "lens-backing-model",
        )?
        .ok_or("the report moved between the two reads")?;
    let (frame, card) = lens.lower(&GeneratedUiSurfaceCapabilities::all_atom_kit())?;
    assert_backing_ref(
        &repo,
        &frame,
        "weave-0",
        note,
        LensHandleRole::ClaimSet,
        LensBackingTargetKind::Claim,
    )?;
    let bindings = node_bindings(&card.render.nodes, "weave-lens-0-0")?;
    assert_eq!(bindings.len(), 1, "{bindings:?}");
    assert_eq!(bindings[0].name.as_str(), "weave-0");
    assert_eq!(bindings[0].role, LensHandleRole::ClaimSet);
    Ok(())
}

#[test]
fn the_default_lens_binds_a_ledger_claim_by_the_claims_short_id() -> TestResult {
    let repo = RepoFixture::new()?;
    let note = put_note(&repo)?;
    let hosted = repo
        .owner_memory()
        .lenses_default_framed(LensDefaultRequest {
            title: "Ledger".to_owned(),
            ledger: vec![note.to_hex()],
            dossiers: Vec::new(),
            threads: Vec::new(),
            as_of: None,
            surface: None,
        })?
        .value;
    let (frame, card) = hosted.lower(&GeneratedUiSurfaceCapabilities::all_atom_kit())?;
    assert_backing_ref(
        &repo,
        &frame,
        "ledger-0",
        note,
        LensHandleRole::ClaimSet,
        LensBackingTargetKind::Claim,
    )?;
    let bindings = node_bindings(&card.render.nodes, "default-vault-ledger-0")?;
    assert_eq!(bindings.len(), 1, "{bindings:?}");
    assert_eq!(bindings[0].name.as_str(), "ledger-0");
    Ok(())
}

#[test]
fn the_default_lens_binds_a_ledger_entity_by_the_entitys_short_id() -> TestResult {
    let repo = RepoFixture::new()?;
    let hosted = repo
        .owner_memory()
        .lenses_default_framed(LensDefaultRequest {
            title: "Ledger".to_owned(),
            ledger: vec![repo.repo.to_hex()],
            dossiers: Vec::new(),
            threads: Vec::new(),
            as_of: None,
            surface: None,
        })?
        .value;
    let (frame, card) = hosted.lower(&GeneratedUiSurfaceCapabilities::all_atom_kit())?;
    assert_backing_ref(
        &repo,
        &frame,
        "ledger-0",
        repo.repo,
        LensHandleRole::EntitySet,
        LensBackingTargetKind::Entity,
    )?;
    let bindings = node_bindings(&card.render.nodes, "default-vault-ledger-0")?;
    assert_eq!(bindings.len(), 1, "{bindings:?}");
    assert_eq!(bindings[0].name.as_str(), "ledger-0");
    Ok(())
}
