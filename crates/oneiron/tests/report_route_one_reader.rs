//! Regression coverage for report routing with LMDB's one reader slot per thread.
//! Public owner and report doors only; no test-support cfg is needed.

use oneiron::feedback::{
    FeedbackProposal, IssueCategory, ReportDisclosure, ReportKind, ReportRequest, ReportRoute,
};
use oneiron::memory::WitnessAssertions;
use oneiron::{
    EdgeActorClass, EntityId, Vault, VaultConfig, WitnessAuthor, WitnessMessage, WitnessTurn,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    request: ReportRequest,
    // Close the vault before removing its directory.
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let message = EntityId::now();
    let witnessed = vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: "The skill returned the wrong wording.".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: WitnessAssertions::default(),
        })?;
    // A fresh owner-authored TURN has no import or installed pack behind it.
    // Mirror the E2E proposal's TURN subject and MESSAGE evidence, not its publisher route.
    let request = ReportRequest {
        subject_ref: witnessed.turn_id.to_hex(),
        category: IssueCategory::SkillDefect,
        kind: ReportKind::Proposal,
        note: Some("This proposal quotes vault text: the wrong wording.".to_owned()),
        evidence_refs: vec![message.to_hex()],
        why: Some("The quoted wording in the witnessed turn is the defect to fix.".to_owned()),
        proposal: Some(FeedbackProposal::new(
            "The witnessed turn records the wrong wording.",
            "Correct the wording returned by the skill.",
        )),
    };
    request.validate()?;
    Ok(Fixture {
        vault,
        owner,
        request,
        _dir: dir,
    })
}

#[test]
fn a_report_about_a_subject_with_no_installed_source_lands_and_reads_back() -> TestResult {
    let fixture = open()?;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let receipt = memory
        .report(fixture.request.clone())
        .expect("a local report must land without a nested reader transaction");
    assert!(!receipt.already_submitted);
    assert_eq!(receipt.route, ReportRoute::OwnerInbox);
    assert_eq!(receipt.disclosure, ReportDisclosure::Local);

    let id = EntityId::from_hex(&receipt.issue_ref)?;
    let issue = fixture
        .vault
        .report_issue(&id)?
        .expect("the accepted report must read back through the issue door");
    assert_eq!(issue.issue_ref, receipt.issue_ref);
    assert_eq!(issue.actor_ref, fixture.owner.to_hex());
    assert_eq!(issue.request.subject_ref, fixture.request.subject_ref);
    assert_eq!(issue.request.category, IssueCategory::SkillDefect);
    assert_eq!(issue.request, fixture.request);
    assert_eq!(issue.route, ReportRoute::OwnerInbox);
    assert_eq!(issue.disclosure, ReportDisclosure::Local);
    Ok(())
}

#[test]
fn the_same_report_filed_twice_counts_once() -> TestResult {
    let fixture = open()?;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let first = memory
        .report(fixture.request.clone())
        .expect("the first local report must land without a nested reader transaction");
    let repeated = memory
        .report(fixture.request.clone())
        .expect("an exact retry must pass through report routing again");
    assert!(!first.already_submitted);
    assert!(repeated.already_submitted);
    assert_eq!(repeated.issue_ref, first.issue_ref);
    assert_eq!(repeated.route, ReportRoute::OwnerInbox);
    assert_eq!(repeated.disclosure, ReportDisclosure::Local);

    // Ask for two rows so a second arrival cannot hide behind a one-row page.
    let issues = fixture.vault.report_inbox(None, 2)?;
    assert_eq!(issues.len(), 1, "an exact retry creates no second issue");
    assert_eq!(issues[0].issue_ref, first.issue_ref);
    assert_eq!(issues[0].actor_ref, fixture.owner.to_hex());
    assert_eq!(issues[0].request.subject_ref, fixture.request.subject_ref);
    assert_eq!(issues[0].request.category, IssueCategory::SkillDefect);
    assert_eq!(issues[0].request, fixture.request);
    assert_eq!(issues[0].route, ReportRoute::OwnerInbox);
    assert_eq!(issues[0].disclosure, ReportDisclosure::Local);
    Ok(())
}
