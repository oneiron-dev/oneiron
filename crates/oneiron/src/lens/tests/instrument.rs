//! End-to-end Instrument safety and WorldSet read confinement.
use super::*;
use crate::test_util::entity as test_entity_id;
use proptest::prelude::*;

fn frame(viewer: &str) -> LensRenderFrame {
    let key = actor_key(viewer);
    LensRenderFrame::new(
        render_id("instrument"),
        LensPrincipalBinding::human_view(viewer, key.clone(), vec![key]).unwrap(),
    )
}

#[test]
fn shared_renderer_resolves_now_and_escapes_closed_atoms() -> crate::Result<()> {
    let (_dir, vault) = test_vault();
    let target = test_entity_id(61);
    put_person(&vault, &target)?;
    let read = vault.scoped_read(actor_key("viewer"));
    let mut frame = frame("viewer");
    frame.mint_backing_ref(
        &read,
        handle("current"),
        LensHandleRole::EntitySet,
        backing_target_for(&vault, &target, LensBackingTargetKind::Entity)?,
    )?;
    let atoms = InstrumentAtoms::new(vec![LensAtom::TextBlock(TextBlockAtom {
        spans: vec![
            LensTextSpan::Literal(text("<script>")),
            LensTextSpan::Interpolation {
                key: handle("current"),
                fallback: text("hidden"),
            },
        ],
    })])?;
    assert_eq!(
        render_instrument(&atoms, &frame, &read)?.html,
        "<article data-instrument=\"1\"><section data-atom=\"text_block\">&lt;script&gt;person</section></article>"
    );
    vault.put_entity(
        &target,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 2, end: 2 },
        2,
        b"<updated>",
    )?;
    // Old content-hash tokens fail closed. A fresh view proves a new backing ref
    // rather than leaking a previously materialized value after a revision.
    assert!(render_instrument(&atoms, &frame, &read).is_err());
    let mut fresh = self::frame("viewer");
    fresh.mint_backing_ref(
        &read,
        handle("current"),
        LensHandleRole::EntitySet,
        backing_target_for(&vault, &target, LensBackingTargetKind::Entity)?,
    )?;
    assert!(
        render_instrument(&atoms, &fresh, &read)?
            .html
            .contains("&lt;updated&gt;")
    );
    assert!(InstrumentAtoms::decode(br#"[{"kind":"raw_html","html":"<script>"}]"#).is_err());
    let runtime = LensExecutionRuntime::link(vec![
        LensHostImport::ScopedRead,
        LensHostImport::ResolveBackingRef,
        LensHostImport::EmitAtom,
    ])?;
    assert!(runtime.run(b"[]", &frame, &read).is_err()); // an unscoped frame is not a lens frame
    assert!(
        LensExecutionRuntime::link(vec![LensHostImport::ScopedRead, LensHostImport::VaultWrite])
            .is_err()
    );
    Ok(())
}

#[test]
fn arbitrary_utf8_and_golden_closed_atoms_never_inject_markup() -> crate::Result<()> {
    let (_dir, vault) = test_vault();
    let frame = frame("viewer");
    let read = vault.scoped_read(actor_key("viewer"));
    let golden = InstrumentAtoms::decode(include_bytes!("fixtures/instrument.json"))?;
    assert_eq!(
        render_instrument(&golden, &frame, &read)?.html,
        include_str!("fixtures/instrument.html").trim_end()
    );
    // Corpus covers every closed atom variant, not only the text leaf.
    let corpus = serde_json::to_vec(&sample_atoms()).unwrap();
    let atoms = InstrumentAtoms::decode(&corpus)?;
    let html = render_instrument(&atoms, &frame, &read)?.html;
    assert_eq!(
        html.matches("<section data-atom=").count(),
        GENERATED_LENS_ATOM_KINDS.len()
    );
    let mut runner = proptest::test_runner::TestRunner::default();
    runner
        .run(&proptest::collection::vec(any::<u8>(), 0..4096), |bytes| {
            if let Ok(atoms) = InstrumentAtoms::decode(&bytes) {
                let _ = render_instrument(&atoms, &frame, &read);
            }
            Ok(())
        })
        .unwrap();
    runner
        .run(&".{1,256}", |value| {
            if let Ok(value) = LensText::new(&value) {
                let atoms = InstrumentAtoms::new(vec![LensAtom::TextBlock(TextBlockAtom {
                    spans: vec![LensTextSpan::Literal(value)],
                })])
                .unwrap();
                let html = render_instrument(&atoms, &frame, &read).unwrap().html;
                prop_assert_eq!(html.matches('<').count(), 4);
            }
            Ok(())
        })
        .unwrap();
    Ok(())
}

#[test]
fn lenses_read_only_their_own_codebase_set() -> crate::Result<()> {
    use crate::codebase::{CodebaseSnapshot, RepoRef};
    let (_dir, vault) = test_vault();
    let a = test_entity_id(81);
    let b = test_entity_id(82);
    let mut scope_keys = Vec::new();
    for (id, project) in [(a, "first"), (b, "second")] {
        let repo = RepoRef::parse(&format!(
            "github:example/{project}#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ))?;
        let artifact =
            crate::code_artifact::CodeArtifactBody::new("code", [0xA5; 32], repo.canonical());
        vault.put_code_artifact(&id, &artifact, crate::TimeRange { start: 1, end: 1 }, 1)?;
        let snapshot = CodebaseSnapshot::new(
            project,
            repo,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            vec![],
        )?;
        vault.put_codebase_snapshot(&id, &snapshot, &|_| None)?;
        scope_keys.push(snapshot.scope_key);
    }
    let read = vault.scoped_read(actor_key("viewer"));
    let fa = frame("viewer").with_codebase_scope(scope_keys[0]);
    let fb = frame("viewer").with_codebase_scope(scope_keys[1]);
    assert!(fa.scoped_body(&read, &a)?.is_some());
    assert!(fa.scoped_body(&read, &b)?.is_none());
    assert!(fb.scoped_body(&read, &a)?.is_none());
    assert!(fb.scoped_body(&read, &b)?.is_some());
    let runtime = LensExecutionRuntime::link(vec![
        LensHostImport::ScopedRead,
        LensHostImport::ResolveBackingRef,
        LensHostImport::EmitAtom,
    ])?;
    assert!(
        runtime
            .run(include_bytes!("fixtures/instrument.json"), &fa, &read)?
            .html
            .contains("&lt;script&gt;")
    );
    Ok(())
}

#[test]
fn ordinary_world_sets_constrain_lens_reads_backing_refs_and_pipeline() -> crate::Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::pipeline::{WorldAuthoritySet, WorldScope};
    let (_dir, vault) = test_vault();
    let subject = test_entity_id(90);
    let world_a = test_entity_id(91);
    let world_b = test_entity_id(92);
    let a = test_entity_id(93);
    let b = test_entity_id(94);
    let base = test_entity_id(95);
    put_person(&vault, &subject)?;
    for (id, world) in [(a, Some(world_a)), (b, Some(world_b)), (base, None)] {
        let mut body = ClaimBody::new(
            "profile.likes",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("tea"),
            0.75,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.world = world;
        vault.put_claim(&id, &body, crate::TimeRange { start: 1, end: 1 }, 2)?;
    }
    let set_a = WorldAuthoritySet::new(false, [world_a])?;
    let set_b = WorldAuthoritySet::new(true, [world_b])?;
    let read = vault.scoped_read(actor_key("viewer"));
    let mut fa = frame("viewer").with_world_set(set_a.clone());
    let fb = frame("viewer").with_world_set(set_b.clone());
    for (id, in_a, in_b) in [
        (a, true, false),
        (b, false, true),
        (base, false, true),
        (subject, false, true),
    ] {
        assert_eq!(fa.scoped_body(&read, &id)?.is_some(), in_a);
        assert_eq!(fb.scoped_body(&read, &id)?.is_some(), in_b);
    }
    assert!(
        fa.mint_backing_ref(
            &read,
            handle("other-world"),
            LensHandleRole::ClaimSet,
            backing_target_for(&vault, &b, LensBackingTargetKind::Claim)?,
        )
        .is_err()
    );
    let token = fa.mint_backing_ref(
        &read,
        handle("own-world"),
        LensHandleRole::ClaimSet,
        backing_target_for(&vault, &a, LensBackingTargetKind::Claim)?,
    )?;
    assert_eq!(
        fa.resolve_backing_ref_token(&read, &token)?
            .target()
            .entity_id(),
        &a
    );
    let runtime = LensExecutionRuntime::link(vec![
        LensHostImport::ScopedRead,
        LensHostImport::ResolveBackingRef,
        LensHostImport::EmitAtom,
    ])?;
    assert!(
        runtime
            .run(b"[]", &fa, &read)?
            .html
            .contains("data-instrument")
    );
    let empty = frame("viewer").with_world_set(WorldAuthoritySet::default());
    for id in [a, b, base, subject] {
        assert!(empty.scoped_body(&read, &id)?.is_none());
    }
    // The ordinary retrieval door uses the same world-id membership, not codebase keys.
    for (worlds, expected) in [(set_a, vec![a]), (set_b, vec![b, base])] {
        let results = vault
            .query()
            .search_temporal(0, 10, 10)
            .filter_types(&[crate::registry::ENTITY_TYPE_CLAIM])
            .world(WorldScope::WorldSet(worlds))
            .limit(10)
            .run()?;
        let mut ids: Vec<_> = results.into_iter().map(|r| r.id).collect();
        ids.sort();
        assert_eq!(ids, expected);
    }
    Ok(())
}
