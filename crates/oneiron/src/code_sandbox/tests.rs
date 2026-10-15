use super::*;

fn host_mounts(root: &Path) -> SandboxMountTable {
    SandboxMountTable::new(
        root.join("host-workspace"),
        root.join("host-uploads"),
        root.join("host-outputs"),
        root.join("host-skills"),
    )
}

#[test]
fn code_sandbox_virtual_path_contract_keeps_guest_on_mnt_paths() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mounts = host_mounts(dir.path());
    let workspace = SandboxVirtualPath::try_new("/mnt/workspace/src/main.rs")?;
    assert_eq!(workspace.mount(), SandboxMount::Workspace);
    assert_eq!(workspace.relative_path(), "src/main.rs");
    assert_eq!(
        mounts.resolve_host_path(&workspace),
        dir.path().join("host-workspace/src/main.rs")
    );
    assert_eq!(
        mounts.guest_mount_roots(),
        [
            "/mnt/workspace",
            "/mnt/uploads",
            "/mnt/outputs",
            "/mnt/skills"
        ]
    );

    let mut adapter = FakeSandboxAdapter::new(SandboxGuestTier::Foreign, mounts);
    adapter.stage_file(workspace.clone(), b"fn main() {}".to_vec());
    let read = adapter.read_file(SandboxReadFile::new(workspace))?;
    assert_eq!(read.path.as_str(), "/mnt/workspace/src/main.rs");
    assert_eq!(read.bytes, b"fn main() {}".to_vec());
    assert!(!format!("{read:?}").contains(dir.path().to_str().expect("utf8 tempdir")));
    assert!(!format!("{adapter:?}").contains(dir.path().to_str().expect("utf8 tempdir")));

    for invalid in [
        dir.path()
            .join("host-workspace/src/main.rs")
            .display()
            .to_string(),
        "/etc/passwd".to_owned(),
        "/mnt/workspace/../secret".to_owned(),
        "/mnt/workspace/./file".to_owned(),
        "/mnt/workspace/..\\secret".to_owned(),
        "/mnt/unknown/file".to_owned(),
        "/mnt/workspace//file".to_owned(),
    ] {
        assert!(
            SandboxVirtualPath::try_new(&invalid).is_err(),
            "invalid path should reject: {invalid}"
        );
    }
    Ok(())
}

#[test]
fn code_sandbox_delete_rename_and_opaque_proposals_validate_at_review_door() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut adapter = FakeSandboxAdapter::new(SandboxGuestTier::Foreign, host_mounts(dir.path()));
    let old = SandboxVirtualPath::try_new("/mnt/workspace/old.txt")?;
    let new = SandboxVirtualPath::try_new("/mnt/workspace/new.txt")?;
    let uploads = SandboxVirtualPath::try_new("/mnt/uploads/old.txt")?;
    let root = SandboxVirtualPath::try_new("/mnt/workspace")?;
    for invalid in [
        SandboxProposalWrite::FileDelete(SandboxFileDeleteProposal {
            path: uploads.clone(),
        }),
        SandboxProposalWrite::FileDelete(SandboxFileDeleteProposal { path: root.clone() }),
        SandboxProposalWrite::FileRename(SandboxFileRenameProposal {
            from: old.clone(),
            to: old.clone(),
        }),
        SandboxProposalWrite::FileRename(SandboxFileRenameProposal {
            from: old.clone(),
            to: uploads.clone(),
        }),
        SandboxProposalWrite::DirectoryOpaque(SandboxDirectoryOpaqueProposal { path: uploads }),
    ] {
        assert!(adapter.propose_write(invalid).is_err());
    }
    assert!(adapter.proposal_deltas().is_empty());
    for (write, kind) in [
        (
            SandboxProposalWrite::FileDelete(SandboxFileDeleteProposal { path: old.clone() }),
            SandboxProposalKind::FileDelete,
        ),
        (
            SandboxProposalWrite::FileRename(SandboxFileRenameProposal { from: old, to: new }),
            SandboxProposalKind::FileRename,
        ),
        (
            SandboxProposalWrite::DirectoryOpaque(SandboxDirectoryOpaqueProposal { path: root }),
            SandboxProposalKind::DirectoryOpaque,
        ),
    ] {
        let delta = adapter.propose_write(write)?;
        assert_eq!(delta.kind(), kind);
        assert_eq!(delta.approval(), ClaimApprovalStatus::Proposed);
    }
    assert_eq!(adapter.proposal_deltas().len(), 3);
    Ok(())
}
