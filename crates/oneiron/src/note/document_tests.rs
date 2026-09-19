//! NOTE caller-observable storage, cursor, fork and bridge laws.
use super::*;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::registry::{ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{Vault, VaultConfig};

fn fixture() -> (tempfile::TempDir, Vault, WriteActor) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    (dir, vault, WriteActor::new(actor, EdgeActorClass::Human))
}
fn current(vault: &Vault, id: EntityId) -> String {
    vault.note_document(id).unwrap().unwrap().text()
}

#[test]
fn six_descriptors_and_namespaced_kind_round_trip() {
    let (_dir, vault, actor) = fixture();
    for kind in [
        "scratchpad",
        "observation",
        "handoff",
        "research",
        "reflection",
        "diary",
    ] {
        let id = vault.create_note(kind, "birth", actor).unwrap();
        let body = vault.read_note(&id).unwrap().unwrap();
        assert_eq!(body.kind.as_str(), kind);
        assert!(body.markdown.is_empty());
        assert_eq!(
            body.document_head,
            Some(vault.note_document(id).unwrap().unwrap().head())
        );
        assert_eq!(current(&vault, id), "birth");
    }
    assert!(vault.create_note("unknown", "birth", actor).is_err());
    let descriptor = NoteKindDescriptor {
        pack: "example.notes".into(),
        kind: "example.notes/runbook".into(),
        extraction: ExtractionDefault::AfterSeal,
        context: ContextDefault::OwnerOnly,
        retention: RetentionDefault::Durable,
        archive_after_days: None,
    };
    vault.register_note_kind(&descriptor).unwrap();
    let id = vault
        .create_note(&descriptor.kind, "custom", actor)
        .unwrap();
    assert_eq!(
        vault.read_note(&id).unwrap().unwrap().kind.as_str(),
        descriptor.kind
    );
    assert!(
        vault
            .register_note_kind(&NoteKindDescriptor {
                pack: "other".into(),
                ..descriptor
            })
            .is_err()
    );
}

#[test]
fn old_cursor_survives_concurrent_insert_and_rewrite_never_touches_live_head() {
    let (_dir, vault, actor) = fixture();
    let id = vault.create_note("research", "alpha beta", actor).unwrap();
    let read = vault.note_document(id).unwrap().unwrap();
    let start = read.anchor(6).unwrap();
    let end = read.anchor(10).unwrap();
    vault
        .edit_note(
            id,
            &NoteEdit::InsertAfter {
                anchor: read.anchor(0).unwrap(),
                text: "prefix ".into(),
            },
            actor,
        )
        .unwrap();
    vault
        .edit_note(
            id,
            &NoteEdit::ReplaceSpan {
                start,
                end,
                text: "gamma".into(),
            },
            actor,
        )
        .unwrap();
    assert_eq!(current(&vault, id), "prefix alpha gamma");
    let before = vault.get_raw(&id).unwrap();
    let NoteEditOutcome::RewriteFork { fork } = vault
        .edit_note(
            id,
            &NoteEdit::Rewrite {
                text: "rewrite".into(),
            },
            actor,
        )
        .unwrap()
    else {
        panic!("rewrite fork");
    };
    assert_eq!(current(&vault, id), "prefix alpha gamma");
    assert_eq!(vault.get_raw(&id).unwrap(), before);
    let bundle = vault
        .open_note_proposal(&[fork], "Replace the document", actor)
        .unwrap();
    assert_eq!(bundle.waiting.len(), 1);
    vault
        .review_note_proposal(bundle.id, NoteVerdict::Switch, actor)
        .unwrap();
    assert_eq!(current(&vault, id), "rewrite");
}

#[test]
fn source_bridge_is_lazy_and_source_is_unchanged() {
    let (_dir, vault, actor) = fixture();
    let source = EntityId::now();
    vault
        .put_entity(
            &source,
            ENTITY_TYPE_ASSET_TEXT,
            TimeRange { start: 42, end: 42 },
            42,
            b"source words",
        )
        .unwrap();
    let before = vault.get_raw(&source).unwrap();
    let id = vault.create_from_entity(source, "research", actor).unwrap();
    assert!(vault.note_document(id).unwrap().is_none());
    assert_eq!(
        vault.read_note(&id).unwrap().unwrap().markdown,
        "source words"
    );
    assert_eq!(
        vault.targets(&id, EdgeKind::DerivedFrom, None).unwrap(),
        vec![source]
    );
    vault
        .edit_note(
            id,
            &NoteEdit::WholeText {
                text: "new words".into(),
                timeout_ms: 100,
                base: None,
            },
            actor,
        )
        .unwrap();
    assert_eq!(current(&vault, id), "new words");
    assert!(vault.read_note(&id).unwrap().unwrap().markdown.is_empty());
    assert_eq!(vault.get_raw(&source).unwrap(), before);
}

#[test]
fn five_forks_route_two_to_land_and_three_to_one_bundle_merge_keeps_concurrent_edits() {
    let (_dir, vault, owner) = fixture();
    let agent_id = EntityId::now();
    vault
        .put_entity(
            &agent_id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .unwrap();
    let agent = WriteActor::new(agent_id, EdgeActorClass::Agent);
    let notes: Vec<_> = (0..5)
        .map(|_| vault.create_note("observation", "base", owner).unwrap())
        .collect();
    let mut forks = Vec::new();
    for note in &notes {
        let anchor = vault
            .note_document(*note)
            .unwrap()
            .unwrap()
            .anchor(4)
            .unwrap();
        forks.push(
            vault
                .fork_note(
                    *note,
                    &NoteEdit::InsertAfter {
                        anchor,
                        text: " proposed".into(),
                    },
                    agent,
                )
                .unwrap(),
        );
    }
    let mut manifest = crate::gate::default_policy_manifest();
    let rmpv::Value::Map(ref mut entries) =
        rmpv::decode::read_value(&mut manifest.as_slice()).unwrap()
    else {
        panic!("manifest map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
    entries.push((
        rmpv::Value::from("scoped_grants"),
        rmpv::Value::Array(vec![rmpv::Value::Map(vec![
            (
                rmpv::Value::from("actor_ref"),
                rmpv::Value::from(agent_id.to_hex()),
            ),
            (
                rmpv::Value::from("effector"),
                rmpv::Value::from("note.edit"),
            ),
            (
                rmpv::Value::from("scope"),
                rmpv::Value::Map(vec![(
                    rmpv::Value::from("entity_refs"),
                    rmpv::Value::Array(
                        notes[..2]
                            .iter()
                            .map(|id| rmpv::Value::from(id.to_hex()))
                            .collect(),
                    ),
                )]),
            ),
        ])]),
    ));
    manifest.clear();
    rmpv::encode::write_value(&mut manifest, &rmpv::Value::Map(entries.clone())).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &manifest,
    )
    .unwrap();
    let bundle = vault
        .open_note_proposal(&forks, "Five edits", agent)
        .unwrap();
    assert_eq!(bundle.landed.len(), 2);
    assert_eq!(bundle.waiting.len(), 3);
    let anchor = vault
        .note_document(notes[2])
        .unwrap()
        .unwrap()
        .anchor(0)
        .unwrap();
    vault
        .edit_note(
            notes[2],
            &NoteEdit::InsertAfter {
                anchor,
                text: "concurrent ".into(),
            },
            owner,
        )
        .unwrap();
    let accepted = vault
        .review_note_proposal(bundle.id, NoteVerdict::Merge, owner)
        .unwrap();
    assert!(accepted.waiting.is_empty());
    assert_eq!(current(&vault, notes[2]), "concurrent base proposed");
    for id in [notes[0], notes[1], notes[3], notes[4]] {
        assert_eq!(current(&vault, id), "base proposed");
    }
    assert!(
        vault
            .open_note_proposal(&forks, "Cannot assign twice", agent)
            .is_err()
    );
}

#[test]
fn stale_whole_text_diff_preserves_concurrent_prefix() {
    let (_dir, vault, actor) = fixture();
    let id = vault.create_note("research", "alpha beta", actor).unwrap();
    let read = vault.note_document(id).unwrap().unwrap();
    let base = read.version();
    vault
        .edit_note(
            id,
            &NoteEdit::InsertAfter {
                anchor: read.anchor(0).unwrap(),
                text: "concurrent ".into(),
            },
            actor,
        )
        .unwrap();
    vault
        .edit_note(
            id,
            &NoteEdit::WholeText {
                text: "alpha gamma".into(),
                timeout_ms: 100,
                base: Some(base),
            },
            actor,
        )
        .unwrap();
    assert_eq!(current(&vault, id), "concurrent alpha gamma");
}

#[test]
fn asset_bridge_selects_latest_text_and_links_asset_atomically() {
    let (_dir, vault, actor) = fixture();
    let asset = EntityId::now();
    vault
        .put_entity(
            &asset,
            crate::registry::ENTITY_TYPE_ASSET,
            TimeRange { start: 1, end: 1 },
            1,
            b"asset",
        )
        .unwrap();
    let before = vault.get_raw(&asset).unwrap();
    for (at, text) in [(2, "old text"), (3, "current text")] {
        let id = EntityId::now();
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_ASSET_TEXT,
                TimeRange { start: at, end: at },
                at,
                text.as_bytes(),
            )
            .edge(&id, EdgeKind::DerivedFrom, &asset, 1.0)
            .commit()
            .unwrap();
    }
    let note = vault
        .create_note_from_asset(asset, "research", actor)
        .unwrap();
    assert_eq!(
        vault.read_note(&note).unwrap().unwrap().markdown,
        "current text"
    );
    assert_eq!(
        vault.targets(&note, EdgeKind::DerivedFrom, None).unwrap(),
        vec![asset]
    );
    assert!(vault.note_document(note).unwrap().is_none());
    assert_eq!(vault.get_raw(&asset).unwrap(), before);
}

#[test]
fn wrong_document_anchor_leaves_live_bytes_unchanged() {
    let (_dir, vault, actor) = fixture();
    let one = vault.create_note("research", "one", actor).unwrap();
    let two = vault.create_note("research", "two", actor).unwrap();
    let anchor = vault
        .note_document(one)
        .unwrap()
        .unwrap()
        .anchor(0)
        .unwrap();
    let before = vault.get_raw(&two).unwrap();
    assert!(
        vault
            .edit_note(
                two,
                &NoteEdit::InsertAfter {
                    anchor,
                    text: "bad".into()
                },
                actor
            )
            .is_err()
    );
    assert_eq!(vault.get_raw(&two).unwrap(), before);
    assert_eq!(current(&vault, two), "two");
}

#[test]
fn agent_facade_and_pack_project_live_document_text() {
    let (_dir, vault, actor) = fixture();
    let memory = vault.memory(actor.entity_ref(), actor.actor_class());
    for kind in [
        "scratchpad",
        "observation",
        "handoff",
        "research",
        "reflection",
        "diary",
    ] {
        let receipt = memory.create_note(kind, "olivine birth").unwrap();
        let id = EntityId::from_hex(&receipt.id_hex).unwrap();
        let doc = vault.note_document(id).unwrap().unwrap();
        memory
            .edit_note(
                &receipt.id_hex,
                &NoteEdit::InsertAfter {
                    anchor: doc.anchor(doc.text().chars().count()).unwrap(),
                    text: " copper".into(),
                },
            )
            .unwrap();
        assert_eq!(
            memory
                .get_entity(&receipt.id_hex)
                .unwrap()
                .unwrap()
                .body
                .unwrap()["markdown"],
            "olivine birth copper"
        );
        assert!(
            vault
                .search_text("copper", 20)
                .unwrap()
                .iter()
                .any(|row| row.id == id)
        );
        let result = vault
            .context_pack()
            .search_text("copper", 20)
            .run()
            .unwrap();
        assert!(
            result
                .results
                .iter()
                .chain(result.neighbors.iter())
                .any(|row| row.id == id
                    && row.fields.as_ref().unwrap()["markdown"] == "olivine birth copper")
        );
    }
}

#[test]
fn unknown_plugin_kind_is_refused_at_raw_local_and_replay_doors() {
    let (_dir, vault, actor) = fixture();
    let body = encode_note_body(&NoteBody {
        kind: NoteKind::wire("example.notes/uninstalled").unwrap(),
        author_ref: actor.entity_ref(),
        markdown: "birth".into(),
        document_head: None,
    })
    .unwrap();
    let id = EntityId::now();
    let time = TimeRange { start: 1, end: 1 };
    assert!(matches!(
        vault.put_entity(&id, crate::registry::ENTITY_TYPE_NOTE, time, 1, &body),
        Err(Error::Record(crate::error::RecordError::InvalidNoteBody(_)))
    ));
    assert!(vault.get(&id).unwrap().is_none());
    assert!(matches!(
        vault
            .batch()
            .put_replicated(&id, crate::registry::ENTITY_TYPE_NOTE, time, 1, &body)
            .commit(),
        Err(Error::Record(crate::error::RecordError::InvalidNoteBody(_)))
    ));
    assert!(vault.get(&id).unwrap().is_none());
}

#[test]
fn source_bridge_refuses_retained_stale_asset_text() {
    let (_dir, vault, actor) = fixture();
    let asset = EntityId::now();
    let text = EntityId::now();
    let occurred = TimeRange { start: 42, end: 42 };
    vault
        .put_entity(
            &asset,
            crate::registry::ENTITY_TYPE_ASSET,
            occurred,
            42,
            b"bytes",
        )
        .unwrap();
    vault
        .put_entity(
            &text,
            ENTITY_TYPE_ASSET_TEXT,
            occurred,
            42,
            b"derived words",
        )
        .unwrap();
    vault
        .put_edge(&text, EdgeKind::DerivedFrom, &asset, 1.0)
        .unwrap();
    vault.delete_entity(&asset).unwrap();
    assert!(vault.get_raw(&text).unwrap().is_some());
    assert!(vault.create_from_entity(text, "research", actor).is_err());
    assert!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_NOTE)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn append_to_section_uses_its_unicode_anchor_after_another_edit() {
    let (_dir, vault, actor) = fixture();
    let id = vault
        .create_note("research", "# α\nfirst\n# β\nsecond", actor)
        .unwrap();
    let read = vault.note_document(id).unwrap().unwrap();
    let end = read.anchor("# α\nfirst\n".chars().count()).unwrap();
    vault
        .edit_note(
            id,
            &NoteEdit::InsertAfter {
                anchor: read.anchor(0).unwrap(),
                text: "preface 🦀\n".into(),
            },
            actor,
        )
        .unwrap();
    vault
        .edit_note(
            id,
            &NoteEdit::AppendToSection {
                end,
                text: "appended\n".into(),
            },
            actor,
        )
        .unwrap();
    assert_eq!(
        current(&vault, id),
        "preface 🦀\n# α\nfirst\nappended\n# β\nsecond"
    );
    assert_eq!(
        vault.note_document(id).unwrap().unwrap().head(),
        read.head()
    );
}

#[test]
fn recovered_merge_refuses_ambiguous_overlap_without_losing_bundle_members() {
    let (_dir, vault, owner) = fixture();
    let first = vault.create_note("research", "alpha beta", owner).unwrap();
    let second = vault.create_note("research", "gamma delta", owner).unwrap();
    let agent_id = EntityId::now();
    vault
        .put_entity(
            &agent_id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .unwrap();
    let agent = WriteActor::new(agent_id, EdgeActorClass::Agent);
    let mut forks = Vec::new();
    for note in [first, second] {
        let read = vault.note_document(note).unwrap().unwrap();
        let fork = vault
            .fork_note(
                note,
                &NoteEdit::InsertAfter {
                    anchor: read.anchor(0).unwrap(),
                    text: "proposed ".into(),
                },
                agent,
            )
            .unwrap();
        forks.push(fork);
    }
    let bundle = vault
        .open_note_proposal(&forks, "both pending", agent)
        .unwrap();
    // Seed only the value-based metadata used by a canonical recovery. This
    // storage fixture keeps the atomic review law covered without sync enabled.
    vault
        .with_write_txn(|txn| {
            let mut bundle = bundle.clone();
            for fork in &mut bundle.waiting {
                let base = vault.note_text_in_txn(txn, fork.note)?;
                fork.rewrite = false;
                fork.frontier.clear();
                fork.recovery_merge = Some((base.clone(), format!("proposed {base}")));
                let key = [b"note_fork:v1:".as_slice(), fork.fork.as_bytes()].concat();
                vault
                    .store
                    .vault_meta
                    .put(txn, &key, &rmp_serde::to_vec_named(fork).unwrap())?;
            }
            let key = [b"note_proposal:v1:".as_slice(), bundle.id.as_bytes()].concat();
            vault
                .store
                .vault_meta
                .put(txn, &key, &rmp_serde::to_vec_named(&bundle).unwrap())
        })
        .unwrap();
    let read = vault.note_document(second).unwrap().unwrap();
    vault
        .edit_note(
            second,
            &NoteEdit::InsertAfter {
                anchor: read.anchor(0).unwrap(),
                text: "conflict ".into(),
            },
            owner,
        )
        .unwrap();
    assert!(
        vault
            .review_note_proposal(bundle.id, NoteVerdict::Merge, owner)
            .is_err()
    );
    assert_eq!(vault.note_text(first).unwrap(), "alpha beta");
    assert_eq!(vault.note_text(second).unwrap(), "conflict gamma delta");
    assert_eq!(vault.note_proposal(bundle.id).unwrap().waiting.len(), 2);
    assert!(vault.note_proposal(bundle.id).unwrap().landed.is_empty());
}
