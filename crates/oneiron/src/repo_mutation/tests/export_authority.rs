use super::*;
use crate::code_artifact::CodeArtifactBody;
use crate::code_document::CodeDocumentFrontier;
use crate::code_revision::{CodeCommitMetadata, CodeRevision, CodeRevisionWriteOutcome};
use crate::critic::CritiqueVerdict;
use crate::git_wire::{GitRefName, GitWire};
use crate::origin::export::EngineCommitExport;
use crate::repo_mutation::proposal::RepoProposal;

fn apply_review(vault: &Vault, proposal: &RepoProposal) -> CodeDocumentFrontier {
    vote_proposal(vault, proposal, CritiqueVerdict::Accept, true);
    vote_proposal(vault, proposal, CritiqueVerdict::Accept, true);
    vault.apply_repo_proposal(proposal.id).unwrap();
    vault
        .code_file_edit_receipt(proposal.id)
        .unwrap()
        .unwrap()
        .after
}

fn next_file(vault: &Vault, repo: &TempDir, previous: &RepoProposal) -> RepoProposal {
    vault
        .propose_repo_mutation(
            RepoMutationRequest::new(
                repo_ref(repo),
                RepoMutationOperation::CommitFile {
                    path: "next.txt".into(),
                    content: b"next reviewed file\n".to_vec(),
                    message: "Review next file".into(),
                },
            )
            .with_actor_id(previous.actor)
            .with_session_id(previous.session)
            .with_provenance_claim_id(previous.provenance_claim),
            previous.catalog.clone(),
        )
        .unwrap()
}

fn revision(
    vault: &Vault,
    proposal: &RepoProposal,
    parent: Option<EntityId>,
    files: &[CodeDocumentFrontier],
    modes: &[([u8; 32], u32)],
) -> EntityId {
    let id = EntityId::now();
    let now = parent.map_or(30, |id| {
        vault.get_code_revision(&id).unwrap().unwrap().finalized_at + 1
    });
    vault
        .put_code_artifact(
            &id,
            &CodeArtifactBody::new("fixture", [1; 32], proposal.repo.clone()),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .unwrap();
    let mut metadata = CodeCommitMetadata::new(proposal.actor, "Reviewed engine commit");
    for (document, mode) in modes {
        metadata = metadata.with_file_mode(*document, *mode);
    }
    let mut revision = match parent {
        Some(parent) => CodeRevision::commit_child(id, proposal.session, parent, now),
        None => CodeRevision::commit(id, proposal.session, now),
    }
    .with_provenance_claim_id(proposal.provenance_claim)
    .with_commit_metadata(metadata);
    for file in files {
        revision = revision.with_file_frontier(file.clone());
    }
    assert_eq!(
        vault.commit_code_revision(&revision).unwrap(),
        CodeRevisionWriteOutcome::Finalized
    );
    id
}

fn request(revision_id: EntityId) -> EngineCommitExport {
    EngineCommitExport {
        revision_id,
        ref_name: GitRefName::parse_full("refs/heads/export").unwrap(),
        expected_old_oid: None,
    }
}

fn objects(repo: &TempDir) -> Vec<u8> {
    stock_git(
        repo.path(),
        &["cat-file", "--batch-all-objects", "--batch-check"],
    )
}

#[test]
fn promotion_refuses_unreviewed_modes_on_new_and_unchanged_frontiers() {
    for mode in [0o100755, 0o120000] {
        for with_parent in [false, true] {
            let (_dir, vault) = open_test_vault();
            let repo = init_repo();
            let proposal = reviewed_proposal_fixture(&vault, &repo);
            let file = apply_review(&vault, &proposal);
            let document = file.document_id;
            let (parent, files, review_id) = if with_parent {
                let id = revision(&vault, &proposal, None, std::slice::from_ref(&file), &[]);
                vault.promote_code_revision(id, proposal.id).unwrap();
                let next = next_file(&vault, &repo, &proposal);
                let next_file = apply_review(&vault, &next);
                // A review of another changed file cannot authorize changing
                // this unchanged file's mode.
                (Some(id), vec![file, next_file], next.id)
            } else {
                (None, vec![file], proposal.id)
            };
            let id = revision(&vault, &proposal, parent, &files, &[(document, mode)]);
            assert!(matches!(
                vault.promote_code_revision(id, review_id),
                Err(Error::InvalidClaimBody(_))
            ));
            assert!(vault.code_revision_promotions(id).unwrap().is_empty());
            let git = GitWire::new(&vault).unwrap();
            let handle = git.open_repo(repo_ref(&repo), repo.path()).unwrap();
            let before = objects(&repo);
            let request = request(id);
            assert!(matches!(
                vault.export_engine_commit(&git, &handle, &request, None),
                Err(Error::InvalidClaimBody(_))
            ));
            assert_eq!(objects(&repo), before);
            assert!(git.read_ref(&handle, &request.ref_name).unwrap().is_none());
            assert!(vault.exported_engine_commit(&handle, id).unwrap().is_none());
        }
    }
}

#[test]
fn promotion_cannot_inherit_modes_from_an_unpromoted_parent() {
    let (_dir, vault) = open_test_vault();
    let repo = init_repo();
    let first = reviewed_proposal_fixture(&vault, &repo);
    let first_file = apply_review(&vault, &first);
    let modes = [(first_file.document_id, 0o100755)];
    let parent = revision(
        &vault,
        &first,
        None,
        std::slice::from_ref(&first_file),
        &modes,
    );
    let next = next_file(&vault, &repo, &first);
    let next_file = apply_review(&vault, &next);
    let child = revision(
        &vault,
        &next,
        Some(parent),
        &[first_file, next_file],
        &modes,
    );
    assert!(matches!(
        vault.promote_code_revision(child, next.id),
        Err(Error::InvalidClaimBody(_))
    ));
    assert!(vault.code_revision_promotions(child).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn promotion_preserves_reviewed_executable_modes_and_inherits_only_promoted_modes() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, vault) = open_test_vault();
    let repo = init_repo();
    fs::set_permissions(
        repo.path().join("README.md"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    stock_git(repo.path(), &["add", "README.md"]);
    stock_git(
        repo.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "Executable base",
        ],
    );
    let first = reviewed_proposal_fixture(&vault, &repo);
    let first_file = apply_review(&vault, &first);
    // The live checkout is no longer executable. Authority remains the fork
    // the critics reviewed, not a permission read at promotion or export time.
    fs::set_permissions(
        repo.path().join("README.md"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let modes = [(first_file.document_id, 0o100755)];
    let parent = revision(
        &vault,
        &first,
        None,
        std::slice::from_ref(&first_file),
        &modes,
    );
    vault.promote_code_revision(parent, first.id).unwrap();
    let next = next_file(&vault, &repo, &first);
    let next_file = apply_review(&vault, &next);
    let files = [first_file, next_file];
    let child = revision(&vault, &next, Some(parent), &files, &modes);
    vault.promote_code_revision(child, next.id).unwrap();
    let git = GitWire::new(&vault).unwrap();
    let handle = git.open_repo(repo_ref(&repo), repo.path()).unwrap();
    // Historical parent validation must still work after the child is current.
    let exported_parent = vault
        .export_engine_commit(&git, &handle, &request(parent), None)
        .unwrap();
    let mut child_request = request(child);
    child_request.expected_old_oid = Some(exported_parent.record.new_oid);
    let exported = vault
        .export_engine_commit(&git, &handle, &child_request, None)
        .unwrap();
    let tree =
        crate::origin::tree::read_tree_files(&git, &handle, &exported.record.new_oid).unwrap();
    assert_eq!(tree["README.md"].mode, 0o100755);
    assert_eq!(tree["README.md"].content, first.content);
    assert_eq!(tree["next.txt"].mode, 0o100644);
    assert_eq!(tree["next.txt"].content, next.content);
    // Omitting metadata cannot silently clear a reviewed executable bit either.
    let downgrade = revision(&vault, &next, Some(child), &files, &[]);
    assert!(matches!(
        vault.promote_code_revision(downgrade, first.id),
        Err(Error::InvalidClaimBody(_))
    ));
    assert!(
        vault
            .code_revision_promotions(downgrade)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn export_refuses_another_repository_before_objects_but_accepts_canonical_aliases() {
    let (_dir, vault) = open_test_vault();
    let repo = init_repo();
    let proposal = reviewed_proposal_fixture(&vault, &repo);
    let file = apply_review(&vault, &proposal);
    let id = revision(&vault, &proposal, None, &[file], &[]);
    vault.promote_code_revision(id, proposal.id).unwrap();
    let git = GitWire::new(&vault).unwrap();
    let other = init_repo();
    let other_handle = git.open_repo(repo_ref(&other), other.path()).unwrap();
    let request = request(id);
    let before = objects(&other);
    assert!(matches!(
        vault.export_engine_commit(&git, &other_handle, &request, None),
        Err(Error::InvariantViolation(_))
    ));
    assert_eq!(objects(&other), before);
    assert!(
        git.read_ref(&other_handle, &request.ref_name)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .exported_engine_commit(&other_handle, id)
            .unwrap()
            .is_none()
    );

    // A subdirectory and an old commit pin still designate the same mutation
    // repository. Compare its resolved working root, not a raw RepoRef string.
    let nested = repo.path().join("nested");
    fs::create_dir(&nested).unwrap();
    let alias_ref = RepoRef::LocalFolder {
        path: nested.to_str().unwrap().to_owned(),
        commit: RepoRef::parse(&proposal.repo)
            .unwrap()
            .commit_hash()
            .unwrap()
            .to_owned(),
    };
    let alias = git.open_repo(alias_ref, &nested.join(".")).unwrap();
    let receipt = vault
        .export_engine_commit(&git, &alias, &request, None)
        .unwrap();
    let root = git.open_repo(repo_ref(&repo), repo.path()).unwrap();
    assert_eq!(
        git.read_ref(&root, &request.ref_name).unwrap(),
        Some(receipt.record.new_oid.clone())
    );
    assert_eq!(
        vault.exported_engine_commit(&root, id).unwrap(),
        Some(receipt.record.new_oid.clone())
    );
    let tree = crate::origin::tree::read_tree_files(&git, &root, &receipt.record.new_oid).unwrap();
    assert_eq!(tree["README.md"].content, proposal.content);
    assert_eq!(tree["README.md"].mode, 0o100644);
}
