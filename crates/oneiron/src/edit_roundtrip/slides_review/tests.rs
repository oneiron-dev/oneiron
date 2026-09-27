use super::*;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::pptx::PptxCommentAction;
use crate::edit_roundtrip::pptx::tests::support;
use crate::edit_settle::{SettleConsent, SettleOutcomeKind};
use crate::llm::decision::{AnswerContract, DecisionClass};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::{embedding_test_config, open_test_vault_with};
use crate::{TimeRange, WriteActor};
use std::cell::RefCell;

fn deck(count: usize) -> Vec<u8> {
    let mut parts = support::parts(false);
    let slide = parts.remove("ppt/slides/slide9.xml").unwrap();
    let p = super::super::pptx::tests::support::parts(false);
    let mut presentation = String::from_utf8(p["ppt/presentation.xml"].clone()).unwrap();
    let mut relationships =
        String::from_utf8(p["ppt/_rels/presentation.xml.rels"].clone()).unwrap();
    let first = "<p:sldId id=\"256\" r:id=\"theSlide\"/>";
    let mut entries = String::new();
    let mut links = String::new();
    let rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    for i in 1..=count {
        entries.push_str(&format!("<p:sldId id=\"{}\" r:id=\"s{i}\"/>", 255 + i));
        links.push_str(&format!(
            "<Relationship Id=\"s{i}\" Type=\"{rel}/slide\" Target=\"slides/slide{i}.xml\"/>"
        ));
        // The relationship kind is the canonical Office relationship namespace.
        parts.insert(
            format!("ppt/slides/slide{i}.xml"),
            String::from_utf8(slide.clone())
                .unwrap()
                .replace("val=\"41\"", &format!("val=\"{}\"", 40 + i))
                .into_bytes(),
        );
    }
    presentation = presentation.replace(first, &entries);
    relationships = relationships.replace(
        &format!(
            "<Relationship Id=\"theSlide\" Type=\"{}/slide\" Target=\"slides/slide9.xml\"/>",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        ),
        &links,
    );
    let mut content_types = String::from_utf8(parts["[Content_Types].xml"].clone()).unwrap();
    let slide_override = "<Override PartName=\"/ppt/slides/slide9.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/>";
    let overrides = (1..=count)
        .map(|i| slide_override.replace("slide9.xml", &format!("slide{i}.xml")))
        .collect::<String>();
    content_types = content_types.replace(slide_override, &overrides);
    parts.insert("[Content_Types].xml".into(), content_types.into_bytes());
    parts.insert("ppt/presentation.xml".into(), presentation.into_bytes());
    parts.insert(
        "ppt/_rels/presentation.xml.rels".into(),
        relationships.into_bytes(),
    );
    support::bytes(&parts)
}

fn units(count: usize) -> Vec<SlideReviewUnit> {
    (1..=count)
        .map(|i| SlideReviewUnit {
            target: PptxCommentTarget {
                slide: i as u64,
                slide_creation_id: Some(40 + i as u32),
                shape_creation_id: None,
                shape_fingerprint: None,
            },
            text: format!("Slide {i} claim and evidence"),
            review_image: vec![i as u8, 5],
            renderer: "fixture-renderer@1".into(),
        })
        .collect()
}
fn question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 2,
        text: "Does this claim overstate its cited evidence?".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}
fn labels() -> SlideReviewLabels {
    SlideReviewLabels {
        yes: "Overstated".into(),
        no: "Supported".into(),
        low: "Low".into(),
        middle: "Medium".into(),
        high: "High".into(),
    }
}
fn dial() -> DecisionDial {
    DecisionDial {
        first: DecisionRung::Local,
        ceiling: DecisionRung::SystemOne,
        band: DecisionBand::default(),
    }
}
struct Provider {
    rung: DecisionRung,
    calls: RefCell<Vec<Vec<u64>>>,
    malformed: bool,
}
impl Provider {
    fn new(rung: DecisionRung) -> Self {
        Self {
            rung,
            calls: RefCell::new(Vec::new()),
            malformed: false,
        }
    }
}
impl SlideReviewProvider for Provider {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: self.rung,
            model: "fixture".into(),
            version: "2".into(),
        }
    }
    fn decide_batch(
        &self,
        _question: &DecisionQuestion,
        rows: &[SlideReviewUnit],
    ) -> Result<Vec<ProviderDecision>> {
        self.calls
            .borrow_mut()
            .push(rows.iter().map(|u| u.target.slide).collect());
        let mut answers: Vec<_> = rows
            .iter()
            .map(|row| {
                let slide = row.target.slide;
                if slide == 11 && self.rung == DecisionRung::SystemOne {
                    ProviderDecision {
                        answer: DecisionAnswer::Abstain,
                        probability: None,
                    }
                } else if self.rung == DecisionRung::Local && matches!(slide, 5 | 11 | 20) {
                    ProviderDecision {
                        answer: DecisionAnswer::Noul(true),
                        probability: Some(0.5),
                    }
                } else {
                    ProviderDecision {
                        answer: DecisionAnswer::Noul(slide % 2 == 0),
                        probability: Some(0.9),
                    }
                }
            })
            .collect();
        if self.malformed {
            answers[0].probability = Some(f64::NAN);
        }
        Ok(answers)
    }
}
fn review(input: &[u8], count: usize, run_ref: &str) -> SlideReviewRun {
    let local = Provider::new(DecisionRung::Local);
    let jev = Provider::new(DecisionRung::SystemOne);
    review_slides(
        input,
        Some(1),
        &SlideReviewRequest {
            units: &units(count),
            question: &question(),
            principal: EntityId::now(),
            answered_by: EntityId::now(),
            author: &PptxAuthor {
                guid: support::AUTHOR.into(),
                name: "Editor".into(),
            },
            dial: dial(),
            labels: &labels(),
            providers: &[&local, &jev],
            run_ref,
            at: 1_700_000_000_123,
        },
    )
    .unwrap()
}

#[test]
fn twenty_slides_batch_fallback_abstention_and_comment_receipt_agree() {
    let input = deck(20);
    let local = Provider::new(DecisionRung::Local);
    let jev = Provider::new(DecisionRung::SystemOne);
    let asker = EntityId::now();
    let answerer = EntityId::now();
    let q = question();
    let result = review_slides(
        &input,
        Some(1),
        &SlideReviewRequest {
            units: &units(20),
            question: &q,
            principal: asker,
            answered_by: answerer,
            author: &PptxAuthor {
                guid: support::AUTHOR.into(),
                name: "Editor".into(),
            },
            dial: dial(),
            labels: &labels(),
            providers: &[&local, &jev],
            run_ref: "20-slides",
            at: 1_700_000_000_123,
        },
    )
    .unwrap();
    assert_eq!(
        local
            .calls
            .borrow()
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [8, 8, 4]
    );
    assert_eq!(*jev.calls.borrow(), vec![vec![5], vec![11], vec![20]]);
    assert_eq!(result.abstained.len(), 1);
    assert_eq!(result.abstained[0].slide, 11);
    let proposal = result.proposal.unwrap();
    assert_eq!(proposal.manifest.slide_judgments.len(), 19);
    verify_judgments(&proposal).unwrap();
    super::super::pptx::verify_comment_proposal(&input, &proposal).unwrap();
    let parts = support::unpack(&proposal.new_bytes);
    for row in &proposal.manifest.slide_judgments {
        assert_eq!(row.decision.receipt.question, q.id);
        assert_eq!(row.decision.receipt.question_version, 2);
        assert_eq!(row.decision.receipt.principal, asker);
        assert_eq!(row.judged_version, Some(1));
        assert_eq!(row.frontier, *blake3::hash(&input).as_bytes());
        assert_eq!(row.renderer, "fixture-renderer@1");
        let op = proposal
            .manifest
            .ops
            .iter()
            .find_map(|op| match op {
                super::super::EditOp::PptxComment { patch } if patch.thread_id == row.thread_id => {
                    Some(patch)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(op.asked_by, asker);
        assert_eq!(op.answered_by, answerer);
        let PptxCommentAction::Add { text, .. } = &op.action else {
            panic!("not add")
        };
        assert_eq!(text, &row.comment);
        assert!(
            parts
                .values()
                .any(|bytes| std::str::from_utf8(bytes).is_ok_and(|xml| xml.contains(text)))
        );
        let expected = if matches!(row.target.slide, 5 | 20) {
            2
        } else {
            1
        };
        assert_eq!(row.decision.receipt.providers.len(), expected);
    }
}

#[test]
fn malformed_response_or_missing_evidence_never_yields_a_proposal() {
    let input = deck(2);
    let local = Provider {
        rung: DecisionRung::Local,
        calls: RefCell::new(Vec::new()),
        malformed: true,
    };
    let jev = Provider::new(DecisionRung::SystemOne);
    let call = |units: Vec<_>| {
        review_slides(
            &input,
            Some(1),
            &SlideReviewRequest {
                units: &units,
                question: &question(),
                principal: EntityId::now(),
                answered_by: EntityId::now(),
                author: &PptxAuthor {
                    guid: support::AUTHOR.into(),
                    name: "Editor".into(),
                },
                dial: dial(),
                labels: &labels(),
                providers: &[&local, &jev],
                run_ref: "malformed",
                at: 1_700_000_000_123,
            },
        )
    };
    assert!(call(units(2)).is_err());
    let mut bad = units(2);
    bad[0].review_image.clear();
    assert!(call(bad).is_err());
    let mut duplicate = units(2);
    duplicate[1] = duplicate[0].clone();
    assert!(call(duplicate).is_err());
}

fn vault_with_deck(input: &[u8]) -> (tempfile::TempDir, Vault, EntityId, WriteActor) {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"reviewer",
        )
        .unwrap();
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(
                "deck.pptx",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ),
            TimeRange { start: 2, end: 2 },
            2,
        )
        .unwrap();
    vault
        .append_blob_artifact_version(
            &artifact,
            input,
            &BlobVersionProvenance::UserUpload,
            actor,
            TimeRange { start: 3, end: 3 },
            3,
        )
        .unwrap();
    (dir, vault, artifact, actor)
}

#[test]
fn keep_receipt_survives_reopen_and_stale_preview_cannot_overwrite() {
    let input = deck(2);
    let (dir, vault, artifact, actor) = vault_with_deck(&input);
    let first = review(&input, 2, "review:kept").proposal.unwrap();
    let stale = review(&input, 2, "review:stale").proposal.unwrap();
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    let selected = vault
        .settle_select_edit_proposal(
            &artifact,
            &first,
            &consent,
            actor,
            TimeRange { start: 4, end: 4 },
            4,
        )
        .unwrap();
    assert_eq!(selected.version.version, 2);
    assert_eq!(selected.receipt.outcome, "selected");
    assert!(selected.receipt.fields["slide_judgments"].contains("fixture-renderer@1"));
    assert_eq!(
        vault
            .blob_artifact_settlement(&artifact, "review:kept")
            .unwrap()
            .unwrap()
            .pptx_judgments,
        first.manifest.slide_judgments
    );
    let old = vault
        .settle_select_edit_proposal(
            &artifact,
            &stale,
            &consent,
            actor,
            TimeRange { start: 5, end: 5 },
            5,
        )
        .unwrap();
    assert!(old.stranded_proposal.is_some());
    assert_eq!(old.receipt.outcome, "proposed");
    assert_eq!(old.version.version, 2);
    assert_eq!(
        vault
            .blob_artifact_settlement(&artifact, "review:stale")
            .unwrap()
            .unwrap()
            .outcome,
        SettleOutcomeKind::Proposed
    );
    assert_eq!(
        vault
            .blob_artifact_settlement(&artifact, "review:stale")
            .unwrap()
            .unwrap()
            .pptx_judgments,
        stale.manifest.slide_judgments
    );
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &stale,
                &consent,
                actor,
                TimeRange { start: 6, end: 6 },
                6
            )
            .is_err()
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config()).unwrap();
    assert_eq!(
        reopened
            .blob_artifact_settlement(&artifact, "review:kept")
            .unwrap()
            .unwrap()
            .pptx_judgments,
        first.manifest.slide_judgments
    );
}

#[test]
fn forged_receipt_or_comment_is_refused_at_settle() {
    let input = deck(1);
    let (_dir, vault, artifact, actor) = vault_with_deck(&input);
    let mut forged = review(&input, 1, "review:forged").proposal.unwrap();
    forged.manifest.slide_judgments[0].decision.probability = Some(2.0);
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &forged,
                &consent,
                actor,
                TimeRange { start: 4, end: 4 },
                4
            )
            .is_err()
    );
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "review:forged")
            .unwrap()
            .is_none()
    );
    let mut forged = review(&input, 1, "review:forged-2").proposal.unwrap();
    if let super::super::EditOp::PptxComment { patch } = &mut forged.manifest.ops[0]
        && let PptxCommentAction::Add { text, .. } = &mut patch.action
    {
        text.push_str(" changed");
    }
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &forged,
                &consent,
                actor,
                TimeRange { start: 4, end: 4 },
                4
            )
            .is_err()
    );
}

#[test]
fn discard_keeps_the_review_receipt_but_never_writes_comments() {
    let input = deck(1);
    let (_dir, vault, artifact, actor) = vault_with_deck(&input);
    let proposal = review(&input, 1, "review:discard").proposal.unwrap();
    let result = vault
        .settle_discard_edit_proposal(
            &artifact,
            &proposal,
            &SettleConsent::OwnerConsent { brief_ref: None },
            actor,
            "not selected",
            4,
        )
        .unwrap();
    assert_eq!(result.receipt.outcome, "discarded");
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    let row = vault
        .blob_artifact_settlement(&artifact, "review:discard")
        .unwrap()
        .unwrap();
    assert_eq!(row.pptx_judgments, proposal.manifest.slide_judgments);
    assert_eq!(row.outcome, SettleOutcomeKind::Discarded);
    assert!(result.receipt.fields["slide_judgments"].contains("fixture-renderer@1"));
}

struct ShortProvider;
impl SlideReviewProvider for ShortProvider {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "short".into(),
            version: "1".into(),
        }
    }
    fn decide_batch(
        &self,
        _: &DecisionQuestion,
        _: &[SlideReviewUnit],
    ) -> Result<Vec<ProviderDecision>> {
        Ok(Vec::new())
    }
}

#[test]
fn wrong_batch_cardinality_fails_closed() {
    let input = deck(2);
    let jev = Provider::new(DecisionRung::SystemOne);
    assert!(
        review_slides(
            &input,
            Some(1),
            &SlideReviewRequest {
                units: &units(2),
                question: &question(),
                principal: EntityId::now(),
                answered_by: EntityId::now(),
                author: &PptxAuthor {
                    guid: support::AUTHOR.into(),
                    name: "Editor".into()
                },
                dial: dial(),
                labels: &labels(),
                providers: &[&ShortProvider, &jev],
                run_ref: "short-output",
                at: 1_700_000_000_123,
            }
        )
        .is_err()
    );
}
