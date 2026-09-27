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

// A Component Model guest, not a JSON atom-stream decoder. The guest can
// request a scoped read, resolve a host ref, then emit only closed atoms.
fn lens_component(imports: bool) -> Vec<u8> {
    lens_component_with_atom(
        imports,
        r#"{"kind":"text_block","props":{"spans":[{"type":"literal","value":"<script>"}]}}"#,
    )
}

fn lens_component_with_atom(imports: bool, atom: &str) -> Vec<u8> {
    let data = atom
        .as_bytes()
        .iter()
        .map(|b| format!("\\{b:02x}"))
        .collect::<String>();
    let code = if imports {
        format!(
            r#"(import "scoped-read" (func $read (param "handle" string) (result string)))
            (import "resolve-backing-ref" (func $resolve (param "handle" string) (result string)))
            (import "emit-atom" (func $emit (param "atom" string)))
            (core func $lower-read (canon lower (func $read) (memory (core memory $mem "memory")) (realloc (core func $mem "realloc"))))
            (core func $lower-resolve (canon lower (func $resolve) (memory (core memory $mem "memory")) (realloc (core func $mem "realloc"))))
            (core func $lower-emit (canon lower (func $emit) (memory (core memory $mem "memory")) (realloc (core func $mem "realloc"))))
            (core module $main
                (import "mem" "memory" (memory 1))
                (import "host" "read" (func $read (param i32 i32 i32)))
                (import "host" "resolve" (func $resolve (param i32 i32 i32)))
                (import "host" "emit" (func $emit (param i32 i32)))
                (func (export "run")
                    i32.const 64 i32.const 7 i32.const 0 call $read
                    i32.const 64 i32.const 7 i32.const 16 call $resolve
                    i32.const 128 i32.const {length} call $emit))
            (core instance $host (export "read" (func $lower-read)) (export "resolve" (func $lower-resolve)) (export "emit" (func $lower-emit)))
            (core instance $main (instantiate $main (with "mem" (instance $mem)) (with "host" (instance $host))))
            (func (export "run") (canon lift (core func $main "run")))"#,
            length = atom.len()
        )
    } else {
        format!(
            r#"(import "emit-atom" (func $emit (param "atom" string)))
            (core func $lower-emit (canon lower (func $emit) (memory (core memory $mem "memory")) (realloc (core func $mem "realloc"))))
            (core module $main
                (import "mem" "memory" (memory 1))
                (import "host" "emit" (func $emit (param i32 i32)))
                (func (export "run") i32.const 128 i32.const {length} call $emit))
            (core instance $host (export "emit" (func $lower-emit)))
            (core instance $main (instantiate $main (with "mem" (instance $mem)) (with "host" (instance $host))))
            (func (export "run") (canon lift (core func $main "run")))"#,
            length = atom.len()
        )
    };
    format!(
        r#"(component
        (core module $mem
            (memory (export "memory") 1)
            (global $next (mut i32) (i32.const 4096))
            (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                (local $ptr i32) global.get $next local.tee $ptr local.get 3 i32.add
                i32.const 7 i32.add i32.const -8 i32.and global.set $next local.get $ptr)
            (data (i32.const 64) "current")
            (data (i32.const 128) "{data}"))
        (core instance $mem (instantiate $mem))
        {code})"#
    )
    .into_bytes()
}

#[test]
fn guest_component_rejects_write_and_unknown_imports_at_construction() {
    for import in [
        "vault-write",
        "batch-write",
        "evaluate-gate",
        "wasi:filesystem/preopens@0.2.0",
    ] {
        let component = format!(r#"(component (import "{import}" (func $write)))"#);
        assert!(
            LensExecutionRuntime::from_component(component.as_bytes()).is_err(),
            "{import}"
        );
    }
    // An atom stream is data, never a component or executable lens program.
    assert!(
        LensExecutionRuntime::from_component(include_bytes!("fixtures/instrument.json")).is_err()
    );
}

#[test]
fn guest_executes_imports_under_principal_scoped_read_and_host_backing() -> crate::Result<()> {
    use crate::pipeline::WorldAuthoritySet;
    let (_dir, vault) = test_vault();
    let target = test_entity_id(67);
    put_person(&vault, &target)?;
    install_viewer_base_grant(&vault)?;
    let read = vault.scoped_read(actor_key("viewer"));
    let mut bound = frame("viewer");
    bound.mint_backing_ref(
        &read,
        handle("current"),
        LensHandleRole::EntitySet,
        backing_target_for(&vault, &target, LensBackingTargetKind::Entity)?,
    )?;
    let bound = bound.with_world_set(WorldAuthoritySet::new(true, [])?);
    let guest = LensExecutionRuntime::from_component(&lens_component_with_atom(
        true,
        r#"{"kind":"text_block","props":{"spans":[{"type":"literal","value":"<script>"},{"type":"interpolation","value":{"key":"current","fallback":"hidden"}}]}}"#,
    ))?;
    assert_eq!(
        guest.imports(),
        &[
            LensHostImport::ScopedRead,
            LensHostImport::ResolveBackingRef,
            LensHostImport::EmitAtom
        ]
    );
    assert!(
        guest
            .run(&bound, &read)?
            .html
            .contains("&lt;script&gt;person")
    );
    assert!(
        guest
            .run(&bound, &vault.scoped_read(actor_key("other")))
            .is_err()
    );
    // The same host row cannot cross into a narrower WorldSet.
    let denied = bound.with_world_set(WorldAuthoritySet::new(false, [])?);
    assert!(guest.run(&denied, &read).is_err());
    // An unbound handle cannot be supplied by the component itself.
    let empty = frame("viewer").with_world_set(WorldAuthoritySet::new(true, [])?);
    assert!(guest.run(&empty, &read).is_err());
    Ok(())
}

#[test]
fn guest_invalid_atom_and_fuel_exhaustion_fail_closed() -> crate::Result<()> {
    use crate::pipeline::WorldAuthoritySet;
    let (_dir, vault) = test_vault();
    let read = vault.scoped_read(actor_key("viewer"));
    let scoped = frame("viewer").with_world_set(WorldAuthoritySet::new(true, [])?);
    let invalid = LensExecutionRuntime::from_component(&lens_component_with_atom(
        false,
        r#"{"kind":"raw_html","html":"<script>"}"#,
    ))?;
    assert!(invalid.run(&scoped, &read).is_err());
    let spin = LensExecutionRuntime::from_component(
        br#"(component
      (core module $m (func (export "run") (loop br 0)))
      (core instance $i (instantiate $m))
      (func (export "run") (canon lift (core func $i "run"))))"#,
    )?;
    assert!(spin.run(&scoped, &read).is_err());
    Ok(())
}

#[test]
fn repeated_scoped_interpolation_cannot_expand_render_without_bound() -> crate::Result<()> {
    use crate::pipeline::WorldAuthoritySet;
    let (_dir, vault) = test_vault();
    let target = test_entity_id(68);
    vault.put_entity(
        &target,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        &vec![b'a'; 2048],
    )?;
    install_viewer_base_grant(&vault)?;
    let read = vault.scoped_read(actor_key("viewer"));
    let mut frame = frame("viewer");
    frame.mint_backing_ref(
        &read,
        handle("current"),
        LensHandleRole::EntitySet,
        backing_target_for(&vault, &target, LensBackingTargetKind::Entity)?,
    )?;
    let frame = frame.with_world_set(WorldAuthoritySet::new(true, [])?);
    let atoms = InstrumentAtoms::new(
        (0..600)
            .map(|_| {
                LensAtom::TextBlock(TextBlockAtom {
                    spans: vec![LensTextSpan::Interpolation {
                        key: handle("current"),
                        fallback: text("hidden"),
                    }],
                })
            })
            .collect(),
    )?;
    assert!(render_instrument(&atoms, &frame, &read).is_err());
    Ok(())
}

#[test]
fn shared_renderer_resolves_now_and_escapes_closed_atoms() -> crate::Result<()> {
    let (_dir, vault) = test_vault();
    let target = test_entity_id(61);
    put_person(&vault, &target)?;
    install_viewer_base_grant(&vault)?;
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
    let runtime = LensExecutionRuntime::from_component(&lens_component(false))?;
    assert!(runtime.run(&frame, &read).is_err()); // an unscoped frame is not a lens frame
    assert!(
        LensExecutionBoundary::read_only(vec![
            LensHostImport::ScopedRead,
            LensHostImport::VaultWrite
        ])
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
    install_viewer_base_grant(&vault)?;
    let read = vault.scoped_read(actor_key("viewer"));
    let fa = frame("viewer").with_codebase_scope(scope_keys[0]);
    let fb = frame("viewer").with_codebase_scope(scope_keys[1]);
    assert!(fa.scoped_body(&read, &a)?.is_some());
    assert!(fa.scoped_body(&read, &b)?.is_none());
    assert!(fb.scoped_body(&read, &a)?.is_none());
    assert!(fb.scoped_body(&read, &b)?.is_some());
    let runtime = LensExecutionRuntime::from_component(&lens_component(false))?;
    assert!(runtime.run(&fa, &read)?.html.contains("&lt;script&gt;"));
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
    // Vault::open seeds the bootstrap skills' base-world claims at time 0, so
    // the fixture claims live in their own window of the retrieval door.
    let at: u64 = 10_000_000;
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
        vault.put_claim(&id, &body, crate::TimeRange { start: at, end: at }, at + 1)?;
    }
    let set_a = WorldAuthoritySet::new(false, [world_a])?;
    let set_b = WorldAuthoritySet::new(true, [world_b])?;
    install_read_grants(
        &vault,
        vec![
            base_read_grant("viewer"),
            world_read_grant("viewer", rmpv::Value::from(world_a.to_hex())),
            world_read_grant("viewer", rmpv::Value::from(world_b.to_hex())),
        ],
    )?;
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
    let runtime = LensExecutionRuntime::from_component(&lens_component(false))?;
    assert!(runtime.run(&fa, &read)?.html.contains("data-instrument"));
    let empty = frame("viewer").with_world_set(WorldAuthoritySet::default());
    for id in [a, b, base, subject] {
        assert!(empty.scoped_body(&read, &id)?.is_none());
    }
    // The ordinary retrieval door uses the same world-id membership, not codebase keys.
    for (worlds, expected) in [(set_a, vec![a]), (set_b, vec![b, base])] {
        let results = vault
            .query()
            .search_temporal(at, at + 10, 10)
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
