//! Returned bytes and typed refusals; no assertions of PowerPoint visibility.
pub(crate) mod support;
use super::package::*;
use super::xml::Xml;
use super::*;
use crate::anchored_annotation::{Locator, ReanchorOutcome};
use crate::entity_id::EntityId;
use std::collections::BTreeSet;
use support::*;

#[test]
fn modern_shape_comment_writes_exact_allowlist_and_preserves_unknown_bytes() {
    let original = parts(false);
    let input = bytes(&original);
    let patch = patch(true);
    let output = comment_patch(&input, std::slice::from_ref(&patch)).unwrap();
    let after = unpack(&output.new_bytes);
    let comment = after
        .keys()
        .find(|s| s.starts_with("ppt/comments/"))
        .unwrap();
    let expected: BTreeSet<_> = [
        "ppt/authors.xml",
        "ppt/slides/slide9.xml",
        "ppt/slides/_rels/slide9.xml.rels",
        "ppt/_rels/presentation.xml.rels",
        "[Content_Types].xml",
        comment,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(output.touched_parts, expected);
    assert!(output.minted_slide_creation_ids.is_empty());
    assert_eq!(
        output.anchors,
        vec![(
            patch.thread_id,
            PptxAnchorOutcome::Shape {
                slide: 1,
                sld_id: 256,
                creation_id: 41,
                shape_creation_id: SHAPE.into(),
                x: 123,
                y: 456
            }
        )]
    );
    for (name, data) in &original {
        if !expected.contains(name) {
            assert_eq!(&after[name], data, "{name}");
        }
    }
    let slide = String::from_utf8(after["ppt/slides/slide9.xml"].clone()).unwrap();
    let before_slide = String::from_utf8(original["ppt/slides/slide9.xml"].clone()).unwrap();
    let original_xml = Xml::parse(&before_slide).unwrap();
    let new_xml = Xml::parse(&slide).unwrap();
    let old_tree = original_xml
        .nodes
        .iter()
        .find(|n| n.is(P, "spTree"))
        .unwrap();
    let new_tree = new_xml.nodes.iter().find(|n| n.is(P, "spTree")).unwrap();
    assert_eq!(
        &before_slide[old_tree.start..old_tree.end],
        &slide[new_tree.start..new_tree.end]
    );
    assert!(slide.contains("v:keep=\"a &amp; b\""));
    let xml = Xml::parse(std::str::from_utf8(&after[comment]).unwrap()).unwrap();
    let root = xml.root(P188, "cmLst").unwrap();
    let cm = xml.children(root, P188, "cm")[0];
    assert_eq!(xml.nodes[cm].attr("authorId"), Some(AUTHOR));
    assert_eq!(
        xml.nodes[cm].attr("created"),
        Some("2023-11-14T22:13:20.123Z")
    );
    let pos = xml.child(cm, P188, "pos").unwrap().unwrap();
    assert_eq!(xml.nodes[pos].attr("x"), Some("123"));
    assert_eq!(xml.nodes[pos].attr("y"), Some("456"));
    let monikers = xml
        .child(
            cm,
            "http://schemas.microsoft.com/office/powerpoint/2013/main/command",
            "sldMkLst",
        )
        .unwrap()
        .unwrap();
    assert!(
        xml.child(
            monikers,
            "http://schemas.microsoft.com/office/powerpoint/2013/main/command",
            "docMk"
        )
        .unwrap()
        .is_some()
    );
    let author_xml = Xml::parse(std::str::from_utf8(&after[AUTHORS]).unwrap()).unwrap();
    let author = author_xml.children(0, P188, "author")[0];
    assert_eq!(
        author_xml.nodes[author].attr("name"),
        Some("Selected Author")
    );
    assert_eq!(author_xml.nodes[author].attr("userId"), Some(AUTHOR));
    assert_eq!(author_xml.nodes[author].attr("providerId"), Some(""));
    assert!(
        std::str::from_utf8(&after[comment])
            .unwrap()
            .contains("A &amp; B &lt;sources&gt;")
    );
}

#[test]
fn inspection_is_read_only_and_mint_is_declared_and_replayable() {
    let input = bytes(&parts(true));
    let inspection = inspect_pptx(&input).unwrap();
    assert_eq!(inspection.slides[0].creation_id, None);
    let empty = comment_patch(&input, &[]).unwrap();
    assert_eq!(input, empty.new_bytes);
    assert!(empty.touched_parts.is_empty());
    let mut patch = patch(false);
    if let PptxCommentAction::Add { target, .. } = &mut patch.action {
        target.slide_creation_id = None;
    }
    let proposal = run_comment_roundtrip(&input, &[patch], "mint-run").unwrap();
    let mints: Vec<_> = proposal
        .manifest
        .ops
        .iter()
        .filter_map(|op| match op {
            crate::edit_roundtrip::EditOp::MintPptxSlideCreationId { slide, creation_id } => {
                Some((*slide, *creation_id))
            }
            _ => None,
        })
        .collect();
    assert_eq!(mints.len(), 1);
    assert_eq!(mints[0].0, 1);
    assert_eq!(
        inspect_pptx(&proposal.new_bytes).unwrap().slides[0].creation_id,
        Some(mints[0].1)
    );
    verify_comment_proposal(&input, &proposal).unwrap();
}

#[test]
fn replies_precede_text_and_only_original_author_resolves() {
    let original = bytes(&parts(false));
    let add = patch(false);
    let first = comment_patch(&original, std::slice::from_ref(&add)).unwrap();
    let mut reply = add.clone();
    reply.comment_id = EntityId::now();
    reply.action = PptxCommentAction::Reply {
        text: "Reply & evidence".into(),
    };
    reply.author = PptxAuthor {
        guid: "{11111111-2222-4333-8444-555555555555}".into(),
        name: "Another Author".into(),
    };
    let second = comment_patch(&first.new_bytes, &[reply.clone()]).unwrap();
    let after = unpack(&second.new_bytes);
    let name = after
        .keys()
        .find(|s| s.starts_with("ppt/comments/"))
        .unwrap();
    assert_eq!(
        second.touched_parts,
        [AUTHORS.to_owned(), name.clone()].into_iter().collect()
    );
    let xml = Xml::parse(std::str::from_utf8(&after[name]).unwrap()).unwrap();
    let cm = xml.children(0, P188, "cm")[0];
    let list = xml.child(cm, P188, "replyLst").unwrap().unwrap();
    let tx = xml.child(cm, P188, "txBody").unwrap().unwrap();
    assert!(xml.nodes[list].end <= xml.nodes[tx].start);
    assert_eq!(xml.children(list, P188, "reply").len(), 1);
    let mut resolve = add.clone();
    resolve.action = PptxCommentAction::Resolve { resolved: true };
    resolve.author = reply.author;
    assert_eq!(
        comment_patch(&second.new_bytes, &[resolve.clone()]).unwrap_err(),
        PptxError::NotAuthor
    );
    resolve.author = PptxAuthor {
        guid: add.author.guid.clone(),
        name: "Different Author".into(),
    };
    assert_eq!(
        comment_patch(&second.new_bytes, std::slice::from_ref(&resolve)).unwrap_err(),
        PptxError::AuthorConflict
    );
    resolve.author.name.clear();
    assert_eq!(
        comment_patch(&second.new_bytes, std::slice::from_ref(&resolve)).unwrap_err(),
        PptxError::InvalidPatch
    );
    resolve.author = add.author;
    let third = comment_patch(&second.new_bytes, &[resolve.clone()]).unwrap();
    let resolved = unpack(&third.new_bytes);
    assert_eq!(third.touched_parts, [name.clone()].into_iter().collect());
    let xml = Xml::parse(std::str::from_utf8(&resolved[name]).unwrap()).unwrap();
    assert_eq!(
        xml.nodes[xml.children(0, P188, "cm")[0]].attr("status"),
        Some("resolved")
    );
    let noop = comment_patch(&third.new_bytes, &[resolve]).unwrap();
    assert_eq!(noop.new_bytes, third.new_bytes);
    assert!(noop.touched_parts.is_empty());
}

#[test]
fn missing_ambiguous_and_changed_shape_emit_typed_unknown_not_nearby_anchor() {
    for reason in [
        PptxDriftReason::MissingShape,
        PptxDriftReason::AmbiguousShape,
        PptxDriftReason::TargetChanged,
    ] {
        let mut original = parts(false);
        let mut request = patch(true);
        match reason {
            PptxDriftReason::MissingShape => with_text(
                &mut original,
                "ppt/slides/slide9.xml",
                SHAPE,
                "{00000001-2222-4333-8444-555555555555}",
            ),
            PptxDriftReason::AmbiguousShape => {
                let slide = String::from_utf8(original["ppt/slides/slide9.xml"].clone()).unwrap();
                let xml = Xml::parse(&slide).unwrap();
                let shape = xml.nodes.iter().find(|n| n.is(P, "sp")).unwrap();
                let duplicate = slide[shape.start..shape.end].replace("id=\"2\"", "id=\"3\"");
                with_text(
                    &mut original,
                    "ppt/slides/slide9.xml",
                    "</p:spTree>",
                    &format!("{duplicate}</p:spTree>"),
                );
            }
            PptxDriftReason::TargetChanged => {
                if let PptxCommentAction::Add { target, .. } = &mut request.action {
                    target.shape_fingerprint = Some([1; 32]);
                }
            }
            _ => unreachable!(),
        }
        let output = comment_patch(&bytes(&original), std::slice::from_ref(&request)).unwrap();
        assert_eq!(
            output.anchors,
            vec![(
                request.thread_id,
                PptxAnchorOutcome::UnknownAnchor { reason }
            )]
        );
        let output_parts = unpack(&output.new_bytes);
        let comment = output_parts
            .iter()
            .find(|(n, _)| n.starts_with("ppt/comments/"))
            .unwrap()
            .1;
        let xml = Xml::parse(std::str::from_utf8(comment).unwrap()).unwrap();
        let cm = xml.children(0, P188, "cm")[0];
        assert!(xml.child(cm, P188, "unknownAnchor").unwrap().is_some());
        assert!(xml.child(cm, P188, "pos").unwrap().is_none());
        assert!(
            unknown_anchor_threads(&output.new_bytes)
                .unwrap()
                .contains(&request.thread_id)
        );
    }
}

#[test]
fn unverified_geometry_refuses_shape_but_allows_explicit_slide_choice() {
    let mut original = parts(false);
    with_text(
        &mut original,
        "ppt/slides/slide9.xml",
        "<a:xfrm>",
        "<a:xfrm rot=\"5400000\">",
    );
    let input = bytes(&original);
    assert_eq!(
        comment_patch(&input, &[patch(true)]).unwrap_err(),
        PptxError::UnverifiedGeometry
    );
    assert!(comment_patch(&input, &[patch(false)]).is_ok());
}

#[test]
fn signed_noop_is_exact_and_signed_mutation_refuses() {
    let mut original = parts(false);
    original.insert("_xmlsignatures/sig1.xml".into(), b"<Signature/>".to_vec());
    let input = bytes(&original);
    assert_eq!(
        inspect_pptx(&input).unwrap().signature_parts,
        vec!["_xmlsignatures/sig1.xml"]
    );
    assert_eq!(comment_patch(&input, &[]).unwrap().new_bytes, input);
    assert_eq!(
        comment_patch(&input, &[patch(false)]).unwrap_err(),
        PptxError::SignedPackage
    );
}

#[test]
fn candidate_validation_rejects_outside_and_inside_allowed_part_tampering() {
    let input = bytes(&parts(false));
    let proposal = run_comment_roundtrip(&input, &[patch(true)], "checked-run").unwrap();
    verify_comment_proposal(&input, &proposal).unwrap();
    for name in ["ppt/theme/theme1.xml", "ppt/slides/slide9.xml"] {
        let mut altered = proposal.clone();
        let mut parts = unpack(&altered.new_bytes);
        parts
            .get_mut(name)
            .unwrap()
            .extend_from_slice(b"<!-- forged -->");
        altered.new_bytes = bytes(&parts);
        altered.manifest.touched_parts.insert(name.into());
        assert_eq!(
            verify_comment_proposal(&input, &altered).unwrap_err(),
            PptxError::PartDiffOutsideTransaction
        );
    }
    let mut other = parts(false);
    other.insert("ppt/media/extra.bin".into(), vec![1]);
    assert_eq!(
        super::archive::enforce_allowlist(&parts(false), &other, &BTreeSet::new()).unwrap_err(),
        PptxError::PartDiffOutsideTransaction
    );
}

#[test]
fn pure_rebind_follows_creation_identity_and_drifts_deleted_or_changed_shape() {
    let original = parts(false);
    let before = inspect_pptx(&bytes(&original)).unwrap();
    let locator = Locator::pptx(1, "2").unwrap();
    assert_eq!(
        rebind_locator(&locator, &before, &before),
        ReanchorOutcome::Mapped(Locator::pptx(1, SHAPE).unwrap())
    );
    for (from, to) in [
        (SHAPE, "{00000001-2222-4333-8444-555555555555}"),
        ("Original text", "Changed text"),
    ] {
        let mut new = original.clone();
        with_text(&mut new, "ppt/slides/slide9.xml", from, to);
        let after = inspect_pptx(&bytes(&new)).unwrap();
        assert_eq!(
            rebind_locator(&locator, &before, &after),
            ReanchorOutcome::Drifted
        );
    }
}

#[test]
fn xml_prefix_aliases_and_retained_unknowns_are_not_reserialized() {
    let mut original = parts(false);
    for name in ["ppt/presentation.xml", "ppt/slides/slide9.xml"] {
        let value = String::from_utf8(original[name].clone())
            .unwrap()
            .replace("xmlns:p=", "xmlns:z=")
            .replace("<p:", "<z:")
            .replace("</p:", "</z:");
        original.insert(name.into(), value.into_bytes());
    }
    let input = bytes(&original);
    let result = comment_patch(&input, &[patch(true)]).unwrap();
    assert_eq!(
        inspect_pptx(&result.new_bytes).unwrap().slides[0].creation_id,
        Some(41)
    );
    let after = unpack(&result.new_bytes);
    assert!(
        std::str::from_utf8(&after["ppt/slides/slide9.xml"])
            .unwrap()
            .contains("<z:sp>")
    );
}

#[test]
fn malformed_xml_and_missing_slide_fail_with_typed_refusals() {
    let mut original = parts(false);
    with_text(
        &mut original,
        "ppt/slides/slide9.xml",
        "<p:spTree>",
        "<!DOCTYPE foo [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><p:spTree>",
    );
    assert_eq!(
        comment_patch(&bytes(&original), &[patch(false)]).unwrap_err(),
        PptxError::InvalidXml
    );
    let mut unsupported = parts(false);
    with_text(
        &mut unsupported,
        "ppt/slides/slide9.xml",
        "encoding=\"UTF-8\"",
        "encoding=\"UTF-16\"",
    );
    assert_eq!(
        comment_patch(&bytes(&unsupported), &[patch(false)]).unwrap_err(),
        PptxError::InvalidXml
    );
    let mut missing = patch(false);
    if let PptxCommentAction::Add { target, .. } = &mut missing.action {
        target.slide_creation_id = Some(999);
    }
    assert_eq!(
        comment_patch(&bytes(&parts(false)), &[missing]).unwrap_err(),
        PptxError::SlideNotFound
    );
}

#[test]
fn duplicate_comment_and_author_identity_conflicts_are_refused() {
    let input = bytes(&parts(false));
    let request = patch(false);
    let result = comment_patch(&input, std::slice::from_ref(&request)).unwrap();
    assert_eq!(
        comment_patch(&result.new_bytes, std::slice::from_ref(&request)).unwrap_err(),
        PptxError::DuplicateComment
    );
    let mut another = patch(false);
    another.author.name = "Not the imported identity".into();
    assert_eq!(
        comment_patch(&result.new_bytes, &[another]).unwrap_err(),
        PptxError::AuthorConflict
    );
}

#[test]
fn compressed_local_records_and_archive_comment_survive_comment_patch() {
    use std::io::Write;
    let parts = parts(false);
    let mut input = Vec::new();
    let mut directory = Vec::new();
    for (name, data) in &parts {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        let packed = encoder.finish().unwrap();
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let offset = input.len() as u32;
        let mut local = Vec::new();
        local.extend_from_slice(&0x04034b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&8u16.to_le_bytes());
        local.extend_from_slice(&123u16.to_le_bytes());
        local.extend_from_slice(&456u16.to_le_bytes());
        local.extend_from_slice(&crc.sum().to_le_bytes());
        local.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        input.extend_from_slice(&local);
        input.extend_from_slice(name.as_bytes());
        input.extend_from_slice(&packed);
        directory.extend_from_slice(&0x02014b50u32.to_le_bytes());
        directory.extend_from_slice(&20u16.to_le_bytes());
        directory.extend_from_slice(&local[4..28]);
        directory.extend_from_slice(&[0; 12]);
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let local_end = input.len();
    input.extend_from_slice(&directory);
    input.extend_from_slice(&0x06054b50u32.to_le_bytes());
    input.extend_from_slice(&[0; 4]);
    input.extend_from_slice(&(parts.len() as u16).to_le_bytes());
    input.extend_from_slice(&(parts.len() as u16).to_le_bytes());
    input.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    input.extend_from_slice(&(local_end as u32).to_le_bytes());
    input.extend_from_slice(&7u16.to_le_bytes());
    input.extend_from_slice(b"archive");
    assert_eq!(comment_patch(&input, &[]).unwrap().new_bytes, input);
    let output = comment_patch(&input, &[patch(false)]).unwrap();
    // No orphaned local ZIP records may remain after a part replacement.
    let entries = output
        .new_bytes
        .windows(4)
        .filter(|record| *record == b"PK\x03\x04")
        .count();
    assert_eq!(entries, unpack(&output.new_bytes).len());
    assert!(output.new_bytes.ends_with(b"archive"));
    let after = unpack(&output.new_bytes);
    assert_eq!(
        after["customXml/unreachable.xml"],
        parts["customXml/unreachable.xml"]
    );
}

#[test]
fn imported_comment_part_keeps_unknown_nodes_attributes_and_namespace_context() {
    let input = bytes(&parts(false));
    let add = patch(false);
    let first = comment_patch(&input, std::slice::from_ref(&add)).unwrap();
    let mut imported = unpack(&first.new_bytes);
    let part = imported
        .keys()
        .find(|p| p.starts_with("ppt/comments/"))
        .unwrap()
        .clone();
    with_text(
        &mut imported,
        &part,
        "<p188:cm xmlns:p188=",
        "<p188:cm xmlns:vendor=\"urn:vendor\" vendor:keep=\"opaque\" xmlns:p188=",
    );
    with_text(
        &mut imported,
        &part,
        "</p188:cm>",
        "<p188:extLst><p:ext xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" uri=\"opaque\"><vendor:unknown><![CDATA[keep <all>]]></vendor:unknown></p:ext></p188:extLst></p188:cm>",
    );
    let mut reply = add.clone();
    reply.comment_id = EntityId::now();
    reply.action = PptxCommentAction::Reply {
        text: "Follow-up".into(),
    };
    let reply_result = comment_patch(&bytes(&imported), &[reply]).unwrap();
    let mut resolve = add;
    resolve.action = PptxCommentAction::Resolve { resolved: true };
    let result = comment_patch(&reply_result.new_bytes, &[resolve]).unwrap();
    let output = unpack(&result.new_bytes);
    let comment = std::str::from_utf8(&output[&part]).unwrap();
    assert!(comment.contains("vendor:keep=\"opaque\""));
    assert!(comment.contains("<vendor:unknown><![CDATA[keep <all>]]></vendor:unknown>"));
    assert_eq!(result.touched_parts, [part].into_iter().collect());
}

#[test]
fn relationship_target_cannot_widen_comment_write_set() {
    let original = bytes(&parts(false));
    let add = patch(false);
    let first = comment_patch(&original, std::slice::from_ref(&add)).unwrap();
    let mut imported = unpack(&first.new_bytes);
    let comment = imported
        .keys()
        .find(|p| p.starts_with("ppt/comments/"))
        .unwrap()
        .clone();
    with_text(
        &mut imported,
        "ppt/slides/_rels/slide9.xml.rels",
        &comment.replace("ppt/", "../"),
        "../theme/theme1.xml",
    );
    let mut reply = add;
    reply.comment_id = EntityId::now();
    reply.action = PptxCommentAction::Reply {
        text: "Attempt".into(),
    };
    assert_eq!(
        comment_patch(&bytes(&imported), &[reply]).unwrap_err(),
        PptxError::InvalidReference
    );
}

#[test]
fn manifest_roundtrip_keeps_comment_and_declared_identity_effects() {
    let input = bytes(&parts(true));
    let mut request = patch(false);
    if let PptxCommentAction::Add { target, .. } = &mut request.action {
        target.slide_creation_id = None;
    }
    let proposal = run_comment_roundtrip(&input, &[request], "manifest").unwrap();
    let manifest =
        crate::edit_roundtrip::EditManifest::from_msgpack(&proposal.manifest.to_msgpack().unwrap())
            .unwrap();
    assert_eq!(manifest, proposal.manifest);
    let legacy = rmpv::Value::Map(vec![
        ("schema_version".into(), 1u64.into()),
        ("format".into(), "xlsx".into()),
        ("ops".into(), rmpv::Value::Array(vec![])),
        ("touched_parts".into(), rmpv::Value::Array(vec![])),
        ("mutation_mode".into(), "full".into()),
        ("warnings".into(), rmpv::Value::Array(vec![])),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &legacy).unwrap();
    let decoded = crate::edit_roundtrip::EditManifest::from_msgpack(&bytes).unwrap();
    assert_eq!(decoded.format, crate::edit_roundtrip::OfficeFormat::Xlsx);
    assert!(decoded.ops.is_empty());
}

#[test]
fn clean_office_fixture_comment_declares_only_review_parts() {
    let input = include_bytes!("../../../../../scripts/office/fixtures/clean.pptx");
    let mut patch = support::patch(false);
    if let PptxCommentAction::Add { target, .. } = &mut patch.action {
        target.slide_creation_id = None;
    }
    let proposal = run_comment_roundtrip(input, &[patch], "clean-oracle").unwrap();
    verify_comment_proposal(input, &proposal).unwrap();
    let before = unpack(input);
    let after = unpack(&proposal.new_bytes);
    assert_eq!(
        proposal.manifest.touched_parts,
        before
            .keys()
            .chain(after.keys())
            .filter(|name| before.get(*name) != after.get(*name))
            .cloned()
            .collect()
    );
    assert!(
        proposal
            .manifest
            .touched_parts
            .contains("ppt/slides/slide1.xml")
    );
    assert!(proposal.manifest.touched_parts.contains("ppt/authors.xml"));
    for (name, contents) in &before {
        if !proposal.manifest.touched_parts.contains(name) {
            assert_eq!(after.get(name), Some(contents), "{name}");
        }
    }
}

#[test]
fn policy_xml_budgets_are_enforced_instead_of_parser_literals() {
    let xml = "<root xmlns:p=\"urn:p\" one=\"1\" two=\"2\"><p:child/></root>";
    let defaults = PptxOperationalLimits::default();
    assert!(Xml::parse_with_limits(xml, &defaults).is_ok());
    for limits in [
        PptxOperationalLimits {
            max_xml_bytes: xml.len() - 1,
            ..defaults
        },
        PptxOperationalLimits {
            max_xml_attributes: 2,
            ..defaults
        },
        PptxOperationalLimits {
            max_xml_namespaces: 1,
            ..defaults
        },
        PptxOperationalLimits {
            max_xml_depth: 1,
            ..defaults
        },
        PptxOperationalLimits {
            max_xml_nodes: 1,
            ..defaults
        },
    ] {
        assert!(Xml::parse_with_limits(xml, &limits).is_err(), "{limits:?}");
    }
    let bytes = bytes(&parts(false));
    let request = patch(false);
    let bounded = PptxOperationalLimits {
        max_xml_bytes: 64,
        ..defaults
    };
    assert!(
        super::proposal::run_comment_roundtrip_with_limits(
            &bytes,
            &[request],
            "xml-limited",
            bounded,
            None
        )
        .is_err()
    );
}
