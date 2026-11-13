//! The owner's whole-vault restore brings each archived ISSUE back with its review (D11).
//!
//! On the owner's door only (`import_whole_vault_archive_from_as_owner`), each
//! filed report comes back under its ISSUE id with the source's actor,
//! request, filing time and review, marked `OwnerArchiveRestore`. The route
//! and disclosure are computed on this vault; no publisher signature is sent
//! or queued for a restored report. The manifest still lists each ISSUE as
//! `LocalHistoryNotRestored`, and the actor-taking door keeps every ISSUE
//! omitted.
//!
//! * `owner_restore_brings_each_report_back_with_its_review`: two reports on
//!   two PERSON subjects (one `Proposal` with note, why, proposal and three
//!   unsorted evidence refs; one `Problem`), reviewed `NeedsMoreEvidence`
//!   with 0.8 and `Duplicate` of the first with 0.3. The owner's restore
//!   brings both back with actor, request, filing time and review intact,
//!   in source arrival order, counted as inserted and no longer omitted.
//! * `owner_restore_recomputes_the_route_and_sends_no_signature`: a report
//!   with text filed on an owner-inbox subject becomes a Publisher report on
//!   a vault whose owner set that route before the import (disclosure
//!   `NeedsApproval`); a counting transport answers no send and the delivery
//!   status shows no lane.
//! * `owner_restore_keeps_a_denial_on_the_same_route`: a denial on a
//!   Publisher route survives the restore when the destination set the same
//!   route, with the same deny round.
//! * `the_actor_import_keeps_issue_rows_omitted`: the control. The same
//!   two-report archive through `import_whole_vault_archive_from_with_actor`
//!   with a valid local actor restores the PERSONs and keeps both ISSUE rows
//!   omitted.
//!
//! Public doors only; neutral fixtures (`owen`, `yuki`, `owen@example.com`);
//! vaults in tempdirs. Each destination opens at least one wall-clock second
//! after its source (sleep 1100 ms), as in
//! `archive_import_maintenance_kinds.rs`. Reasons are compared in their
//! `Debug` form.
//! `cargo test --locked -p oneiron --all-features --test archive_restore_owner_issues`.

use std::io::Cursor;

use oneiron::consent::AuthenticatedOwner;
use oneiron::feedback::{
    FeedbackProposal, IssueCategory, ReportDeliveryStatusRequest, ReportDisclosure,
    ReportDisclosureChoice, ReportIssueOrigin, ReportKind, ReportPublisherEndpoint, ReportRequest,
    ReportReview, ReportRoute, ReportSignatureTransport, ReportSignatureTransportRequest,
    ReportStatus,
};
use oneiron::outbound::OutboundExecutionOutcome;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A source vault opened as the report door's own test opens it
/// (`report_route_one_reader.rs`).
fn open_source_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("open source vault");
    (dir, vault)
}

/// A fresh destination whose engine-seed seconds differ from the source's:
/// any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_vault()
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn put_person(vault: &Vault, id: &EntityId, name: &str) {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode map body");
    vault
        .put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("ordinary row");
}

fn export_whole(vault: &Vault) -> Vec<u8> {
    vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec()
}

/// The manifest's import omissions of `archive`, as (entity id, reason in
/// its `Debug` form).
fn import_omissions(reader: &Vault, archive: &[u8]) -> Vec<(String, String)> {
    reader
        .read_whole_vault_archive(archive)
        .expect("read the archive")
        .manifest
        .import_omissions
        .iter()
        .map(|omission| (omission.entity_id.clone(), format!("{:?}", omission.reason)))
        .collect()
}

/// A source vault holding the PERSONs `owen` and `yuki` and two filed,
/// reviewed reports: a `Proposal` about `owen` and a `Problem` about `yuki`.
/// `archive` is its whole archive; `baseline_archive` is the same vault
/// exported after the two PERSON rows and before either report was filed.
struct TwoReportSource {
    vault: Vault,
    owen: EntityId,
    yuki: EntityId,
    proposal: EntityId,
    problem: EntityId,
    archive: Vec<u8>,
    baseline_archive: Vec<u8>,
    // Close the vault before removing its directory.
    _dir: tempfile::TempDir,
}

fn source_with_two_reports() -> TwoReportSource {
    let (dir, vault) = open_source_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = owner_proof(&vault);
    let owen = EntityId::now();
    let yuki = EntityId::now();
    put_person(&vault, &owen, "owen");
    put_person(&vault, &yuki, "yuki");
    let baseline_archive = export_whole(&vault);
    // Three evidence refs in unsorted order: entity ids mint in time order,
    // so the rotation below never reads sorted.
    let first = EntityId::now();
    let second = EntityId::now();
    let third = EntityId::now();
    let evidence = vec![third.to_hex(), first.to_hex(), second.to_hex()];
    let mut sorted = evidence.clone();
    sorted.sort();
    assert_ne!(
        evidence, sorted,
        "the proposal fixture must carry unsorted evidence refs"
    );
    let proposal_request = ReportRequest {
        subject_ref: owen.to_hex(),
        category: IssueCategory::SkillDefect,
        kind: ReportKind::Proposal,
        note: Some("The summary of owen names the wrong city.".to_owned()),
        evidence_refs: evidence,
        why: Some("The city matters for owen's record.".to_owned()),
        proposal: Some(FeedbackProposal::new(
            "The summary names the wrong city.",
            "Name the city owen's record holds.",
        )),
    };
    let proposal_receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .report(proposal_request)
        .expect("the proposal report lands");
    let proposal = EntityId::from_hex(&proposal_receipt.issue_ref).expect("proposal issue id");
    let problem_request = ReportRequest {
        subject_ref: yuki.to_hex(),
        category: IssueCategory::SkillDefect,
        kind: ReportKind::Problem,
        note: Some("The summary of yuki names the wrong city.".to_owned()),
        evidence_refs: vec![owen.to_hex()],
        why: Some("The city matters for yuki's record.".to_owned()),
        proposal: None,
    };
    let problem_receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .report(problem_request)
        .expect("the problem report lands");
    let problem = EntityId::from_hex(&problem_receipt.issue_ref).expect("problem issue id");
    vault
        .review_report(
            &proof,
            &proposal,
            ReportReview {
                status: ReportStatus::NeedsMoreEvidence,
                quality_score: Some(0.8),
                duplicate_of: None,
            },
        )
        .expect("the owner reviews the proposal");
    vault
        .review_report(
            &proof,
            &problem,
            ReportReview {
                status: ReportStatus::Duplicate,
                quality_score: Some(0.3),
                duplicate_of: Some(proposal.to_hex()),
            },
        )
        .expect("the owner marks the problem a duplicate of the proposal");
    let archive = export_whole(&vault);
    TwoReportSource {
        vault,
        owen,
        yuki,
        proposal,
        problem,
        archive,
        baseline_archive,
        _dir: dir,
    }
}

/// A host carrier that counts every signature send instead of delivering.
struct CountingTransport {
    sends: usize,
}

impl ReportSignatureTransport for CountingTransport {
    fn destination(&self) -> Option<ReportPublisherEndpoint> {
        None
    }

    fn send_issue_signature(
        &mut self,
        _request: &ReportSignatureTransportRequest<'_>,
    ) -> OutboundExecutionOutcome {
        self.sends += 1;
        OutboundExecutionOutcome::failed("the counting transport never sends")
    }
}

#[test]
fn owner_restore_brings_each_report_back_with_its_review() {
    let source = source_with_two_reports();
    let source_proposal = source
        .vault
        .report_issue(&source.proposal)
        .expect("read the source proposal")
        .expect("the source holds the proposal ISSUE row");
    assert_eq!(
        source_proposal.review.status,
        ReportStatus::NeedsMoreEvidence,
        "the proposal fixture carries its NeedsMoreEvidence review"
    );
    assert_eq!(
        source_proposal.review.quality_score,
        Some(0.8),
        "the proposal fixture carries its 0.8 score"
    );
    let source_problem = source
        .vault
        .report_issue(&source.problem)
        .expect("read the source problem")
        .expect("the source holds the problem ISSUE row");
    assert_eq!(
        source_problem.review.status,
        ReportStatus::Duplicate,
        "the problem fixture carries its Duplicate review"
    );
    assert_eq!(
        source_problem.review.quality_score,
        Some(0.3),
        "the problem fixture carries its 0.3 score"
    );
    assert_eq!(
        source_problem.review.duplicate_of,
        Some(source.proposal.to_hex()),
        "the problem fixture names the proposal as its duplicate target"
    );
    let source_inbox = source
        .vault
        .report_inbox(None, 10)
        .expect("read the source inbox");
    assert_eq!(
        source_inbox.len(),
        2,
        "the source inbox holds both filed reports"
    );
    let source_order: Vec<String> = source_inbox
        .iter()
        .map(|issue| issue.issue_ref.clone())
        .collect();

    let (_baseline_dir, baseline_dest) = open_later_vault();
    let baseline_owner = owner_proof(&baseline_dest);
    let baseline_receipt = match baseline_dest.import_whole_vault_archive_from_as_owner(
        Cursor::new(&source.baseline_archive),
        &baseline_owner,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            panic!("the owner's baseline archive holding no ISSUE row must restore: {error:?}")
        }
    };

    let (_dest_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let receipt =
        match dest.import_whole_vault_archive_from_as_owner(Cursor::new(&source.archive), &owner) {
            Ok(receipt) => receipt,
            Err(error) => {
                panic!("the owner's whole archive holding two ISSUE rows must restore: {error:?}")
            }
        };

    for (id, expected) in [
        (&source.proposal, &source_proposal),
        (&source.problem, &source_problem),
    ] {
        let restored = dest
            .report_issue(id)
            .expect("read the restored issue")
            .unwrap_or_else(|| {
                panic!("the owner's restore must bring report {} back", id.to_hex())
            });
        assert_eq!(
            restored.actor_ref,
            expected.actor_ref,
            "the restored report {} keeps the source actor",
            id.to_hex()
        );
        assert_eq!(
            restored.request,
            expected.request,
            "the restored report {} keeps the full source request",
            id.to_hex()
        );
        assert_eq!(
            restored.received_at,
            expected.received_at,
            "the restored report {} keeps the source filing time",
            id.to_hex()
        );
        assert_eq!(
            restored.review,
            expected.review,
            "the restored report {} keeps the source review",
            id.to_hex()
        );
        assert_eq!(
            restored.origin,
            ReportIssueOrigin::OwnerArchiveRestore,
            "the restored report {} is marked as an owner-archive restore",
            id.to_hex()
        );
    }
    assert_eq!(
        dest.report_issue(&source.proposal)
            .expect("read the restored proposal")
            .expect("the owner's restore must bring the proposal back")
            .review
            .duplicate_of,
        None,
        "the restored proposal keeps no duplicate target"
    );
    assert_eq!(
        dest.report_issue(&source.problem)
            .expect("read the restored problem")
            .expect("the owner's restore must bring the problem back")
            .review
            .duplicate_of,
        Some(source.proposal.to_hex()),
        "the restored duplicate still names the restored proposal"
    );

    let inbox = dest
        .report_inbox(None, 10)
        .expect("read the restored inbox");
    assert_eq!(
        inbox.len(),
        2,
        "the restored inbox holds both recovered reports"
    );
    let order: Vec<String> = inbox.iter().map(|issue| issue.issue_ref.clone()).collect();
    assert_eq!(
        order, source_order,
        "the restored inbox lists both reports in source arrival order"
    );

    assert_eq!(
        receipt.inserted_entities,
        baseline_receipt.inserted_entities + 2,
        "the two restored ISSUE rows count as inserted over the baseline: {receipt:?} vs {baseline_receipt:?}"
    );
    assert_eq!(
        receipt.omitted_entities, baseline_receipt.omitted_entities,
        "the restored ISSUE rows add no omission over the baseline: {receipt:?} vs {baseline_receipt:?}"
    );
    let omissions = import_omissions(&source.vault, &source.archive);
    for id in [&source.proposal, &source.problem] {
        assert!(
            omissions
                .iter()
                .any(|(listed, reason)| listed == &id.to_hex()
                    && reason == "LocalHistoryNotRestored"),
            "the manifest names the ISSUE row {} as LocalHistoryNotRestored: {omissions:?}",
            id.to_hex()
        );
    }
    assert_eq!(
        dest.get_entity_type(&source.owen).expect("read owen"),
        Some(ENTITY_TYPE_PERSON),
        "the restore brings owen back"
    );
    assert_eq!(
        dest.get_entity_type(&source.yuki).expect("read yuki"),
        Some(ENTITY_TYPE_PERSON),
        "the restore brings yuki back"
    );
}

#[test]
fn owner_restore_recomputes_the_route_and_sends_no_signature() {
    let (_source_dir, source) = open_source_vault();
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let owen = EntityId::now();
    put_person(&source, &owen, "owen");
    let receipt = source
        .memory(owner, EdgeActorClass::Human)
        .report(ReportRequest {
            subject_ref: owen.to_hex(),
            category: IssueCategory::SkillDefect,
            kind: ReportKind::Problem,
            note: Some("The summary of owen names the wrong city.".to_owned()),
            evidence_refs: Vec::new(),
            why: Some("The city matters for owen's record.".to_owned()),
            proposal: None,
        })
        .expect("the report with text lands");
    let issue = EntityId::from_hex(&receipt.issue_ref).expect("issue id");
    let filed = source
        .report_issue(&issue)
        .expect("read the filed report")
        .expect("the source holds the ISSUE row");
    assert_eq!(
        filed.route,
        ReportRoute::OwnerInbox,
        "a report with no route override lands in the owner inbox"
    );
    assert_eq!(
        filed.disclosure,
        ReportDisclosure::Local,
        "an owner-inbox report with text reads Local"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let publisher = "owen@example.com".to_owned();
    dest.set_report_route(
        &dest_owner,
        &owen.to_hex(),
        ReportRoute::Publisher {
            publisher_ref: publisher.clone(),
        },
    )
    .expect("the destination owner sets the publisher route before the import");
    if let Err(error) =
        dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
    {
        panic!("the owner's whole archive holding one ISSUE row must restore: {error:?}");
    }

    let restored = dest
        .report_issue(&issue)
        .expect("read the restored report")
        .expect("the owner's restore must bring the report back for route recomputation");
    assert_eq!(
        restored.route,
        ReportRoute::Publisher {
            publisher_ref: publisher.clone(),
        },
        "the route is recomputed from destination policy, not the archived route"
    );
    assert_eq!(
        restored.disclosure,
        ReportDisclosure::NeedsApproval,
        "a publisher report with text and no local approval waits on the owner"
    );
    assert_eq!(
        restored.origin,
        ReportIssueOrigin::OwnerArchiveRestore,
        "the recomputed report is marked as an owner-archive restore"
    );

    let mut transport = CountingTransport { sends: 0 };
    let now = dest.now_recorded_at();
    match dest.send_report_signature(&issue.to_hex(), &mut transport, now) {
        Ok(None) => {}
        Ok(Some(record)) => {
            panic!("a restored report must offer no signature lane, got {record:?}")
        }
        Err(error) => panic!("the send probe on a restored report must answer None: {error:?}"),
    }
    assert_eq!(
        transport.sends, 0,
        "no publisher send leaves for a restored report"
    );

    let status = dest
        .report_delivery_status(
            &dest_owner,
            &ReportDeliveryStatusRequest {
                issue_ref: issue.to_hex(),
            },
        )
        .expect("read the delivery status")
        .expect("a restored report answers its delivery status");
    assert_eq!(
        status.issue_ref,
        issue.to_hex(),
        "the delivery status names the restored report"
    );
    assert!(
        status.routed,
        "a publisher report with text still routes: {status:?}"
    );
    assert!(
        status.delivery.is_none(),
        "a restored report holds no delivery lane: {status:?}"
    );
}

#[test]
fn owner_restore_keeps_a_denial_on_the_same_route() {
    let (_source_dir, source) = open_source_vault();
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let proof = owner_proof(&source);
    let owen = EntityId::now();
    put_person(&source, &owen, "owen");
    let route = ReportRoute::Publisher {
        publisher_ref: "owen@example.com".to_owned(),
    };
    source
        .set_report_route(&proof, &owen.to_hex(), route.clone())
        .expect("the source owner sets the publisher route");
    let receipt = source
        .memory(owner, EdgeActorClass::Human)
        .report(ReportRequest {
            subject_ref: owen.to_hex(),
            category: IssueCategory::SkillDefect,
            kind: ReportKind::Problem,
            note: Some("The summary of owen names the wrong city.".to_owned()),
            evidence_refs: Vec::new(),
            why: Some("The city matters for owen's record.".to_owned()),
            proposal: None,
        })
        .expect("the report with text lands");
    let issue = EntityId::from_hex(&receipt.issue_ref).expect("issue id");
    let filed = source
        .report_issue(&issue)
        .expect("read the filed report")
        .expect("the source holds the ISSUE row");
    assert_eq!(
        filed.route, route,
        "the filed report follows the source publisher route"
    );
    assert_eq!(
        filed.disclosure,
        ReportDisclosure::NeedsApproval,
        "a publisher report with text waits on the owner before its denial"
    );
    let denied = source
        .decide_report_disclosure(&proof, &issue, ReportDisclosureChoice::Deny)
        .expect("the source owner denies the disclosure");
    assert_eq!(
        denied.disclosure,
        ReportDisclosure::Denied,
        "the source denial lands"
    );
    let source_round = denied.disclosure_round;
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    dest.set_report_route(&dest_owner, &owen.to_hex(), route.clone())
        .expect("the destination owner sets the same publisher route before the import");
    if let Err(error) =
        dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
    {
        panic!("the owner's whole archive holding a denied ISSUE row must restore: {error:?}");
    }

    let restored = dest
        .report_issue(&issue)
        .expect("read the restored report")
        .expect("the owner's restore must bring the denied report back");
    assert_eq!(
        restored.route, route,
        "the same publisher route is recomputed on the destination"
    );
    assert_eq!(
        restored.disclosure,
        ReportDisclosure::Denied,
        "a denial on the same route survives the restore"
    );
    assert_eq!(
        restored.disclosure_round, source_round,
        "the restored denial keeps the source deny round"
    );
    assert_eq!(
        restored.origin,
        ReportIssueOrigin::OwnerArchiveRestore,
        "the denied report is marked as an owner-archive restore"
    );
}

#[test]
fn the_actor_import_keeps_issue_rows_omitted() {
    let source = source_with_two_reports();
    let (_dest_dir, dest) = open_later_vault();
    let actor = dest.ensure_embedded_owner_actor().expect("embedded owner");
    let receipt = match dest.import_whole_vault_archive_from_with_actor(
        Cursor::new(&source.archive),
        &WriteActor::new(actor, EdgeActorClass::Human),
    ) {
        Ok(receipt) => receipt,
        Err(error) => panic!(
            "the actor import of a two-report archive must succeed with ISSUE rows omitted: {error:?}"
        ),
    };

    assert!(
        dest.report_issue(&source.proposal)
            .expect("read the proposal")
            .is_none(),
        "the actor door keeps the proposal ISSUE row omitted"
    );
    assert!(
        dest.report_issue(&source.problem)
            .expect("read the problem")
            .is_none(),
        "the actor door keeps the problem ISSUE row omitted"
    );
    assert!(
        receipt.omitted_entities >= 2,
        "the receipt counts both omitted ISSUE rows: {receipt:?}"
    );
    let omissions = import_omissions(&source.vault, &source.archive);
    for id in [&source.proposal, &source.problem] {
        assert!(
            omissions
                .iter()
                .any(|(listed, reason)| listed == &id.to_hex()
                    && reason == "LocalHistoryNotRestored"),
            "the manifest names the ISSUE row {} as LocalHistoryNotRestored: {omissions:?}",
            id.to_hex()
        );
    }
    assert_eq!(
        dest.get_entity_type(&source.owen).expect("read owen"),
        Some(ENTITY_TYPE_PERSON),
        "the actor import still restores owen"
    );
    assert_eq!(
        dest.get_entity_type(&source.yuki).expect("read yuki"),
        Some(ENTITY_TYPE_PERSON),
        "the actor import still restores yuki"
    );
}
