//! The checkpoint-pins door's body seeds: code documents, code revisions,
//! office bodies and blob artifacts.

use super::*;

/// A head with a named and a nameless receipt, a frontier, a named and a
/// nameless ingress receipt, a path row, and a head whose ids disagree.
pub(super) fn seed_code_document(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let document = [0xd0; 32];
    let frontier = CodeDocumentFrontier {
        document_id: document,
        repo: "pins-repo".to_owned(),
        path: "pins/main.rs".to_owned(),
        version: vec![(7, 3)],
        op_fold: [0xf0; 32],
        text_hash: [0xb1; 32],
        file_presence: None,
    };
    let actor = id(0x71)?;
    let operation = id(0x72)?;
    let session = id(0x74)?;
    let receipt =
        |operation: EntityId, actor: Option<EntityId>, sequence: u64| PinsCodeDocumentReceipt {
            operation: operation.to_hex(),
            session: session.to_hex(),
            actor,
            actor_class: EdgeActorClass::Human as u8,
            provenance: CodeOpProvenance::default(),
            sequence,
            peer_id: 7,
            counter_start: 0,
            counter_end: 3,
            edit: CodeFileEdit::between("pins/main.rs", "a", "b"),
            metadata_edit: None,
            before: frontier.clone(),
            after: frontier.clone(),
        };
    put_pins_code_document_head_in_txn(
        &vault.store,
        txn,
        &document,
        &[0xbb; 32],
        &frontier,
        b"pins-snap",
        &[
            receipt(operation, Some(actor), 1),
            receipt(id(0x73)?, None, 2),
        ],
    )?;
    put_pins_code_document_frontier_in_txn(
        &vault.store,
        txn,
        &(document, [0xf0; 32]),
        &frontier,
        b"pins-snap",
    )?;
    put_pins_code_document_ingress_in_txn(
        &vault.store,
        txn,
        &operation,
        &receipt(operation, Some(actor), 1),
    )?;
    put_pins_code_document_ingress_in_txn(
        &vault.store,
        txn,
        &id(0x75)?,
        &receipt(id(0x75)?, None, 3),
    )?;
    put_pins_code_document_path_in_txn(&vault.store, txn, "pins-repo", "pins/main.rs", &document)?;
    put_pins_code_document_head_in_txn(
        &vault.store,
        txn,
        &[0xd1; 32],
        &[0xbb; 32],
        &frontier,
        b"pins-snap",
        &[],
    )?;
    Ok(())
}

/// A named and a nameless record, a record filed under another key, an
/// integrity, frontier, fork, session and parent row, a fork-parent row, a
/// stranded proposal, and a promotion.
pub(super) fn seed_code_revision(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_009;
    let session = id(0x81)?;
    let root = id(0x82)?;
    let child = id(0x83)?;
    let fork_session = id(0x84)?;
    let stray = id(0x85)?;
    let wrong = id(0x86)?;
    let author = id(0x8a)?;
    REV_RECORDS.put(
        vault,
        txn,
        &root,
        &CodeRevision::commit(root, session, at)
            .with_commit_metadata(CodeCommitMetadata::new(author, "pins root")),
    )?;
    REV_RECORDS.put(
        vault,
        txn,
        &child,
        &CodeRevision::commit_child(child, session, root, at),
    )?;
    REV_RECORDS.put(
        vault,
        txn,
        &wrong,
        &CodeRevision::commit(child, session, at),
    )?;
    put_pins_code_revision_integrity_in_txn(
        &vault.store,
        txn,
        &root,
        &root,
        &session,
        &[0x61; 32],
        &[0x62; 32],
        at,
    )?;
    put_pins_code_revision_frontier_in_txn(
        &vault.store,
        txn,
        &session,
        &session,
        &child,
        &[0x63; 32],
        at,
    )?;
    REV_FORKS.put(
        vault,
        txn,
        &fork_session,
        &CodeRevisionFork::new(fork_session, session, child, at),
    )?;
    REV_SESSION_INDEX.put(vault, txn, &(session, root), &())?;
    REV_SESSION_INDEX.put(vault, txn, &(session, child), &())?;
    REV_PARENT_INDEX.put(vault, txn, &(root, child), &())?;
    REV_PARENT_INDEX.put(vault, txn, &(root, stray), &())?;
    REV_FORK_PARENT_INDEX.put(vault, txn, &(session, fork_session), &())?;
    let proposal_session = id(0x88)?;
    let proposal = id(0x87)?;
    REV_PROPOSALS.put(
        vault,
        txn,
        &proposal,
        &CodeRevisionProposal {
            revision: CodeRevision::commit(proposal, proposal_session, at)
                .with_commit_metadata(CodeCommitMetadata::new(author, "pins stranded")),
            head_revision_id: child,
            head_fold: [0x64; 32],
            proposed_fold: [0x65; 32],
            artifact_body: b"pins-body".to_vec(),
        },
    )?;
    REV_PROMOTIONS.put(vault, txn, &root, &vec![id(0x89)?.to_hex()])?;
    Ok(())
}

/// A source, an open and a merged fork, an export with its author tokens, a
/// waiting and a settled proposal with their memberships, and the oracle
/// and live-edit rows no owner holds.
pub(super) fn seed_office_body(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_010;
    let artifact = id(0xb1)?;
    let opener = id(0xb4)?;
    put_pins_office_source_in_txn(
        &vault.store,
        txn,
        &artifact,
        OfficeBodyKind::Docx,
        7,
        &[0xb0; 32],
    )?;
    let fork = id(0xb2)?;
    OFF_FORKS.put(
        vault,
        txn,
        &(artifact, fork),
        &OfficeBodyFork {
            id: fork,
            artifact,
            opener: BodyActor::Actor(opener),
            base: b"pins-base".to_vec(),
            commits: 2,
            opened_at: at,
            state: ForkState::Open,
            run_root: None,
            origin: None,
        },
    )?;
    let landed = id(0xb3)?;
    let settler = id(0xb5)?;
    OFF_FORKS.put(
        vault,
        txn,
        &(artifact, landed),
        &OfficeBodyFork {
            id: landed,
            artifact,
            opener: BodyActor::Actor(opener),
            base: b"pins-base".to_vec(),
            commits: 2,
            opened_at: at,
            state: ForkState::Merged {
                by: BodyActor::Actor(settler),
                at,
                head: b"pins-head".to_vec(),
            },
            run_root: None,
            origin: None,
        },
    )?;
    let export_actor = id(0xb6)?;
    let export_key = pins_version_key(&artifact, 3);
    OFF_EXPORTS.put(
        vault,
        txn,
        &export_key,
        &OfficeBodyExportRecord {
            artifact,
            version: 3,
            frontier: b"pins-frontier".to_vec(),
            rebind_frontier: None,
            held_ids: None,
            source_version: 7,
            actor: BodyActor::Actor(export_actor),
            author: "pins author".to_owned(),
            token: Some("pins-token-1".to_owned()),
            at,
            changes: 1,
            recalc: None,
            recalc_failure: None,
            recalc_zone: None,
            effects: Vec::new(),
        },
    )?;
    let author_key = (artifact, 3, 0);
    OFF_EXPORT_AUTHORS.put(
        vault,
        txn,
        &author_key,
        &OfficeBodyExportAuthor {
            actor: Some(export_actor),
            token: "pins-token-1".to_owned(),
        },
    )?;
    let spare_key = (artifact, 3, 1);
    OFF_EXPORT_AUTHORS.put(
        vault,
        txn,
        &spare_key,
        &OfficeBodyExportAuthor {
            actor: None,
            token: "pins-token-2".to_owned(),
        },
    )?;
    put_pins_export_token_ref_in_txn(&vault.store, txn, &export_key, "pins-token-1")?;
    put_pins_author_token_ref_in_txn(&vault.store, txn, &author_key, "pins-token-1")?;
    put_pins_author_token_ref_in_txn(&vault.store, txn, &spare_key, "pins-token-2")?;
    let waiting = id(0xb7)?;
    let member_fork = id(0xb8)?;
    OFF_PROPOSALS.put(
        vault,
        txn,
        &waiting,
        &OfficeBodyProposal {
            header: ProposalHeader {
                proposal: waiting,
                artifact,
                opener: BodyActor::Actor(opener),
                run_root: None,
                opened_at: at,
            },
            members: vec![ProposalMember {
                artifact,
                fork: member_fork,
                opener: BodyActor::Actor(opener),
                run_root: None,
                origin: None,
                verdict: MemberVerdict::Waiting,
                answer: None,
            }],
            settlement: None,
            asks: Vec::new(),
            ask_refused: Vec::new(),
        },
    )?;
    OFF_MEMBERSHIP.put(vault, txn, &(artifact, member_fork), &waiting)?;
    let settled = id(0xb9)?;
    let member = id(0xba)?;
    let member_opener = id(0xbb)?;
    let person = id(0xbc)?;
    let caller = id(0xbd)?;
    let other = id(0xbe)?;
    let answer = |head: &[u8], fork_head: &[u8], landed: Option<&[u8]>| MemberAnswer {
        by: AnsweringAuthority::Word {
            person: BodyActor::Actor(person),
        },
        caller: BodyActor::Actor(caller),
        head: head.to_vec(),
        fork_head: fork_head.to_vec(),
        landed: landed.map(|bytes| bytes.to_vec()),
        at,
    };
    OFF_PROPOSALS.put(
        vault,
        txn,
        &settled,
        &OfficeBodyProposal {
            header: ProposalHeader {
                proposal: settled,
                artifact,
                opener: BodyActor::Actor(opener),
                run_root: None,
                opened_at: at,
            },
            members: vec![
                ProposalMember {
                    artifact,
                    fork: member,
                    opener: BodyActor::Actor(member_opener),
                    run_root: None,
                    origin: None,
                    verdict: MemberVerdict::Landed,
                    answer: Some(answer(b"h1", b"f1", Some(b"l1"))),
                },
                ProposalMember {
                    artifact,
                    fork: other,
                    opener: BodyActor::Actor(member_opener),
                    run_root: None,
                    origin: None,
                    verdict: MemberVerdict::Rejected,
                    answer: Some(answer(b"h2", b"f2", None)),
                },
            ],
            settlement: Some(ProposalSettlement {
                verdict: BundleVerdict::Mixed,
                at,
                reason: None,
            }),
            asks: Vec::new(),
            ask_refused: Vec::new(),
        },
    )?;
    OFF_MEMBERSHIP.put(vault, txn, &(artifact, member), &settled)?;
    OFF_MEMBERSHIP.put(vault, txn, &(artifact, other), &settled)?;
    put_pins_oracle_in_txn(
        &vault.store,
        txn,
        "pins-profile",
        &OracleReceipt {
            profile: "pins-profile".to_owned(),
            powerpoint_version: "pins-pp".to_owned(),
            macos_version: "pins-macos".to_owned(),
            font_versions: vec!["pins-font".to_owned()],
            steps: vec![StepOutcome::Passed; 8],
            clean: true,
            projector: "pins-projector".to_owned(),
            source_sha: "pins-source".to_owned(),
            case_manifest_sha256: "pins-case".to_owned(),
        },
        &BodyActor::Actor(export_actor),
        at,
    )?;
    put_pins_live_edit_route_in_txn(
        &vault.store,
        txn,
        &id(0xbf)?,
        &artifact,
        &id(0xaf)?,
        &[id(0xae)?, id(0xad)?],
        11,
    )?;
    Ok(())
}

/// A head and two versions of one artifact, an erased artifact's head and
/// version, a matching and a stray pointer and admission, a code pointer,
/// and a serving descriptor.
pub(super) fn seed_blob_artifact(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_011;
    let artifact = id(0x91)?;
    let producer = id(0x92)?;
    let version =
        |number: u64, claim: EntityId, actor: EntityId, parent: Option<u64>| BlobArtifactVersion {
            version: number,
            content_hash: [0xc0; 32],
            provenance: BlobVersionProvenance::UserUpload,
            calc_engine: None,
            claim_id: claim,
            created_at: at,
            export_name: "pins.bin".to_owned(),
            export_media_type: "application/octet-stream".to_owned(),
            parent_version: parent,
            fork_of_version: None,
            made_by: MadeBy {
                inputs: Vec::new(),
                process: MadeByProcess {
                    actor,
                    class: MadeByClass::Stated,
                    identity: "user_upload".to_owned(),
                    version: "1".to_owned(),
                    params_hash: sha256_hex(b"pins-blob"),
                },
                at,
                trigger: None,
            },
        };
    let head = version(2, id(0x95)?, producer, Some(1));
    BLOB_HEAD.put(vault, txn, &artifact, &head)?;
    BLOB_VERSIONS.put(
        vault,
        txn,
        &(artifact, 1),
        &version(1, id(0x94)?, producer, None),
    )?;
    BLOB_VERSIONS.put(vault, txn, &(artifact, 2), &head)?;
    let erased = id(0x98)?;
    let erased_producer = pins_erased_producer()?;
    let erased_head = version(1, id(0x96)?, erased_producer, None);
    BLOB_HEAD.put(vault, txn, &erased, &erased_head)?;
    BLOB_VERSIONS.put(vault, txn, &(erased, 1), &erased_head)?;
    let other = id(0x97)?;
    put_pins_artifact_pointer_in_txn(
        &vault.store,
        txn,
        ArtifactPointerChannel::Published,
        &artifact.to_hex(),
        ArtifactExportRef::BlobVersion {
            artifact_id: artifact,
            version: 2,
        },
        false,
        ArtifactServeTier::Private,
    )?;
    put_pins_artifact_pointer_in_txn(
        &vault.store,
        txn,
        ArtifactPointerChannel::Preview,
        &artifact.to_hex(),
        ArtifactExportRef::BlobVersion {
            artifact_id: other,
            version: 1,
        },
        false,
        ArtifactServeTier::Private,
    )?;
    put_pins_artifact_pointer_in_txn(
        &vault.store,
        txn,
        ArtifactPointerChannel::Published,
        "pins-code",
        ArtifactExportRef::ForkHash([0xf0; 32]),
        false,
        ArtifactServeTier::Private,
    )?;
    let gate = GateDecisionId::from_bytes([0x9a; 16]);
    let publish = WriteActor::new(producer, EdgeActorClass::Human);
    put_pins_artifact_admission_in_txn(
        &vault.store,
        txn,
        &id(0x99)?,
        &artifact.to_hex(),
        ArtifactPointerChannel::Published,
        ArtifactExportRef::BlobVersion {
            artifact_id: artifact,
            version: 2,
        },
        &artifact,
        &publish,
        &gate,
        at,
        false,
        ArtifactServeTier::Private,
    )?;
    put_pins_artifact_admission_in_txn(
        &vault.store,
        txn,
        &id(0x9b)?,
        &artifact.to_hex(),
        ArtifactPointerChannel::Preview,
        ArtifactExportRef::BlobVersion {
            artifact_id: artifact,
            version: 2,
        },
        &other,
        &publish,
        &gate,
        at,
        false,
        ArtifactServeTier::Private,
    )?;
    put_pins_serving_blob_in_txn(
        &vault.store,
        txn,
        &(artifact, 2),
        &[0xc2; 32],
        "pins.bin",
        "application/octet-stream",
    )?;
    Ok(())
}
