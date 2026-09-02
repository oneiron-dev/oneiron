use rmpv::Value;

use super::*;
use crate::{ClaimSubject, EntityId};

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
fn code_sandbox_credential_calls_serialize_handle_not_secret() -> Result<()> {
    let secret_material = "ghp_secret_value_that_must_not_cross_boundary";
    let handle = SandboxCredentialHandle::new("github-main")?;
    let call = SandboxCredentialCall::read_only(
        "github.rest.get",
        handle.clone(),
        Value::Map(vec![(Value::from("repo"), Value::from("oneiron"))]),
    )?;
    let guest_value = call.guest_abi_value();

    assert_eq!(call.operation().effect(), SandboxCredentialEffect::ReadOnly);
    assert!(format!("{guest_value:?}").contains("github-main"));
    assert!(!format!("{guest_value:?}").contains(secret_material));
    assert!(!format!("{call:?}").contains(secret_material));

    let dir = tempfile::tempdir().expect("tempdir");
    let mut adapter = FakeSandboxAdapter::new(SandboxGuestTier::Foreign, host_mounts(dir.path()));
    let outcome = adapter.call_credential(call)?;
    assert_eq!(outcome.credential(), &handle);
    assert_eq!(
        outcome.operation().effect(),
        SandboxCredentialEffect::ReadOnly
    );
    assert_eq!(adapter.credential_calls().len(), 1);
    assert!(!format!("{adapter:?}").contains(secret_material));
    Ok(())
}

#[test]
fn code_sandbox_foreign_and_untrusted_link_zero_write_imports() {
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        let contract = SandboxBoundaryContract::for_tier(tier);
        assert_eq!(contract.tier(), tier);
        assert_eq!(
            contract.runtime(),
            SandboxGuestRuntime::PlainJsQuickJsComponent
        );
        assert_eq!(
            contract.guest_language(),
            SandboxGuestLanguage::PlainJavaScript
        );
        assert_eq!(
            contract.component_boundary(),
            SandboxComponentBoundary::WasmtimeWit
        );
        assert_eq!(contract.wit_world(), SANDBOX_WIT_WORLD_NAME);
        assert!(tier.requires_zero_write_imports());
        assert!(contract.has_proposal_delta_channel());
        assert_eq!(
            contract.credential_call_effect(),
            SandboxCredentialEffect::ReadOnly
        );
        assert!(!contract.links_write_imports());
        assert!(
            contract
                .linked_imports()
                .iter()
                .all(|import| !import.class().is_write())
        );
        assert!(
            contract
                .linked_imports()
                .iter()
                .any(|import| import.name() == "oneiron.clock.now_unix_ms"
                    && import.class() == SandboxImportClass::Determinism)
        );
        assert!(
            contract
                .linked_imports()
                .iter()
                .any(|import| import.name() == "oneiron.random.bytes"
                    && import.class() == SandboxImportClass::Determinism)
        );
    }

    let first_party = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    assert_eq!(
        first_party.runtime(),
        SandboxGuestRuntime::PlainJsQuickJsComponent
    );
    assert_eq!(first_party.wit_world(), SANDBOX_WIT_WORLD_NAME);
    assert_eq!(
        first_party.guest_language(),
        SandboxGuestLanguage::PlainJavaScript
    );
    assert_eq!(
        first_party.component_boundary(),
        SandboxComponentBoundary::WasmtimeWit
    );
    assert!(!first_party.has_proposal_delta_channel());
    assert_eq!(
        first_party.credential_call_effect(),
        SandboxCredentialEffect::ReadOnly
    );
    assert!(first_party.links_write_imports());
    let all_imports = first_party
        .linked_imports()
        .iter()
        .map(|import| import.name())
        .collect::<Vec<_>>();
    assert_eq!(
        all_imports,
        vec![
            "sandbox.fs.read_file",
            "sandbox.credential.call",
            "oneiron.clock.now_unix_ms",
            "oneiron.random.bytes",
            "self.memory.search",
            "self.memory.put_claim",
            "self.memory.supersede_claim",
            "self.memory.put_edge",
            "self.ask_human",
            "self.askHuman",
            "self.speak",
            "self.think",
            "self.express",
        ]
    );
    let write_imports = first_party
        .linked_imports()
        .iter()
        .filter(|import| import.class().is_write())
        .map(|import| import.name())
        .collect::<Vec<_>>();
    assert_eq!(
        write_imports,
        vec![
            "self.memory.put_claim",
            "self.memory.supersede_claim",
            "self.memory.put_edge",
        ]
    );
    let write_effects = first_party
        .linked_imports()
        .iter()
        .filter_map(|import| import.write_trap_effect())
        .collect::<Vec<_>>();
    assert_eq!(
        write_effects,
        vec![
            SelfEffect::MemoryPutClaim,
            SelfEffect::MemorySupersedeClaim,
            SelfEffect::MemoryPutEdge,
        ]
    );
    assert_eq!(
        SandboxLinkedImport::new("self.memory.put_claim", SandboxImportClass::ReadOnly)
            .write_trap_effect(),
        None
    );
    let deterministic_imports = first_party
        .linked_imports()
        .iter()
        .filter(|import| import.class() == SandboxImportClass::Determinism)
        .map(|import| import.name())
        .collect::<Vec<_>>();
    assert_eq!(
        deterministic_imports,
        vec!["oneiron.clock.now_unix_ms", "oneiron.random.bytes"]
    );
    let durable_wait_imports = first_party
        .linked_imports()
        .iter()
        .filter(|import| import.class() == SandboxImportClass::DurableWait)
        .map(|import| import.name())
        .collect::<Vec<_>>();
    assert_eq!(
        durable_wait_imports,
        vec!["self.ask_human", "self.askHuman"]
    );
    // ONE-1686: the speech family links as its OWN class. It must never be
    // counted as a write trap (that set is pinned closed by OF-060 P3) and
    // never as a durable wait (speech does not park a run).
    let speech_imports = first_party
        .linked_imports()
        .iter()
        .filter(|import| import.class() == SandboxImportClass::Speech)
        .map(|import| import.name())
        .collect::<Vec<_>>();
    assert_eq!(
        speech_imports,
        vec!["self.speak", "self.think", "self.express"]
    );
    assert_eq!(
        first_party
            .linked_imports()
            .iter()
            .filter(|import| import.class() == SandboxImportClass::Speech)
            .filter(|import| import.class().is_write() || import.write_trap_effect().is_some())
            .count(),
        0,
        "a speech import is not a memory write trap"
    );
    for import in first_party.linked_imports() {
        for forbidden in [
            "batch",
            "bulk",
            "raw",
            "delete",
            "put_entity",
            "put_replicated",
            "set_edge_weight",
            "write_fixture",
        ] {
            assert!(
                !import.name().contains(forbidden),
                "code-mode WIT import {} must not expose {forbidden}",
                import.name()
            );
        }
    }
}

#[test]
fn code_sandbox_plain_js_prompt_surface_is_docs_only_and_host_bound() {
    let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    let dts = contract.prompt_side_dts();

    assert!(dts.contains("declare namespace self"));
    assert!(dts.contains("function search"));
    assert!(dts.contains("function put_claim"));
    assert!(dts.contains("function supersede_claim"));
    assert!(dts.contains("function put_edge"));
    assert!(dts.contains("function askHuman"));
    assert!(dts.contains("function ask_human"));
    assert!(dts.contains("namespace clock"));
    assert!(dts.contains("function now_unix_ms"));
    assert!(!dts.contains("function nowUnixMs"));
    assert!(dts.contains("namespace random"));
    assert!(dts.contains("function bytes"));
    assert!(!dts.contains("actor"));
    assert!(!dts.contains("source"));
    assert!(!dts.contains("approval"));
    assert!(!dts.contains("batch"));
    assert!(!dts.contains("bulk"));
    assert!(!dts.contains("raw"));
    assert!(!dts.contains("delete"));
    assert!(!dts.contains("putEntity"));
    assert!(!dts.contains("putReplicated"));
    assert!(!dts.contains("setEdgeWeight"));
    assert!(!dts.contains("writeFixture"));
    assert_eq!(
        SandboxGuestRuntime::PlainJsQuickJsComponent.prompt_side_dts(),
        PLAIN_JS_HOST_VERB_DTS
    );
}

#[test]
fn code_sandbox_foreign_writes_emit_one_proposed_delta() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut adapter = FakeSandboxAdapter::new(SandboxGuestTier::Foreign, host_mounts(dir.path()));
    let path = SandboxVirtualPath::try_new("/mnt/outputs/result.md")?;

    let delta = adapter.propose_write(SandboxProposalWrite::FileWrite(
        SandboxFileWriteProposal::new(path.clone(), b"proposed edit".to_vec()),
    ))?;

    assert_eq!(delta.tier(), SandboxGuestTier::Foreign);
    assert_eq!(delta.approval(), ClaimApprovalStatus::Proposed);
    assert_eq!(delta.kind(), SandboxProposalKind::FileWrite);
    assert_eq!(adapter.proposal_deltas().len(), 1);
    let SandboxProposalWrite::FileWrite(file) = adapter.proposal_deltas()[0].write() else {
        panic!("expected file write proposal");
    };
    assert_eq!(file.path, path);
    assert_eq!(file.bytes, b"proposed edit".to_vec());
    Ok(())
}

#[test]
fn code_sandbox_claim_proposals_are_deltas_not_commits() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut adapter = FakeSandboxAdapter::new(SandboxGuestTier::Untrusted, host_mounts(dir.path()));
    let claim_id = EntityId::from_bytes([0x51; 16]).expect("claim id");
    let subject = EntityId::from_bytes([0x52; 16]).expect("subject id");
    let candidate = ClaimCandidate::new(
        "profile.favorite_drink",
        ClaimSubject::Entity(subject),
        Value::from("matcha"),
        0.7,
    );

    let delta = adapter.propose_write(SandboxProposalWrite::ClaimCandidate(
        SandboxClaimProposal::new(claim_id, candidate),
    ))?;

    assert_eq!(delta.tier(), SandboxGuestTier::Untrusted);
    assert_eq!(delta.approval(), ClaimApprovalStatus::Proposed);
    assert_eq!(delta.kind(), SandboxProposalKind::ClaimCandidate);
    assert_eq!(adapter.proposal_deltas().len(), 1);
    let SandboxProposalWrite::ClaimCandidate(proposal) = adapter.proposal_deltas()[0].write()
    else {
        panic!("expected claim proposal");
    };
    assert_eq!(proposal.id, claim_id);
    Ok(())
}

#[test]
fn code_sandbox_first_party_proposal_channel_is_closed() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut adapter =
        FakeSandboxAdapter::new(SandboxGuestTier::FirstPartyDreamer, host_mounts(dir.path()));
    let path = SandboxVirtualPath::try_new("/mnt/outputs/result.md")?;

    assert!(
        adapter
            .propose_write(SandboxProposalWrite::FileWrite(
                SandboxFileWriteProposal::new(path, b"not yet".to_vec())
            ))
            .is_err()
    );
    assert!(adapter.proposal_deltas().is_empty());
    Ok(())
}
