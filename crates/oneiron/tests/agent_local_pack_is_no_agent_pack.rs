//! An agent's local pack may not be an agent pack (NOTE AGENTDEF-WRITE-GRANT,
//! U5). `put_local_pack_as_agent` checked only the agent writer and the
//! name `local`, so a travelling AgentPack named `local` reached the
//! travelling admission and minted an agent definition (disabled and
//! Proposed, but written) with no owner Grant. An agent writes a definition
//! only under its owner's Grant; its local pack carries its hooks.

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::share_travel::{AgentPackTravelProjection, BornWith};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{
    PackInstallDisposition, PackInstallReceipt, PackInstallStatus, PackKind, PackSource,
};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use rmpv::Value;
use tempfile::{TempDir, tempdir};

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "Portable agent",
        "1.0.0",
        Some("Count carefully.\n".to_owned()),
        vec![],
        vec![],
        vec![],
        None,
        AgentScope::Base,
        AgentCeiling::Auto,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![]),
        None,
        true,
        None,
    )
}

fn fixture() -> (TempDir, Vault, AuthenticatedOwner, WriteActor) {
    let dir = tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("seeded device vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("install signing keys");
    let owner_id = vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner PERSON");
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("authenticated embedded owner");
    let agent_id = EntityId::now();
    vault
        .create_agent_definition_as(
            &owner,
            &agent_id,
            &definition("fixture.local-pack-writer"),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("owner creates approved enabled agent definition");
    let stored = vault
        .get_agent_definition(&agent_id)
        .expect("read writer")
        .expect("writer exists");
    assert_eq!(stored.approval_status, ClaimApprovalStatus::Approved);
    assert_eq!(stored.lifecycle_status, ClaimLifecycleStatus::Active);
    assert!(stored.enabled);
    let agent = vault
        .observed_write_actor(WriteActor::new(agent_id, EdgeActorClass::Agent))
        .expect("eligible agent WriteActor");
    (dir, vault, owner, agent)
}

fn travelling_agent_files() -> Vec<HubFile> {
    let files = vec![
        HubFile::new(
            "PACK.md",
            b"---\nname: \"local\"\ndescription: \"Portable agent\"\nversion: \"1.0.0\"\nkind: agent\nfacets: {\"identity\":\"identity.md\",\"knowledge\":\"knowledge/selected.json\",\"policy\":\"policy.md\",\"skills\":\"skills.json\"}\n---\n",
        ),
        HubFile::new("identity.md", b"Count carefully.\n"),
        HubFile::new("knowledge/selected.json", b"[]"),
        HubFile::new(
            "policy.md",
            br#"{"schema":"oneiron.agent-pack-travel.v2","display_name":null,"policy":{"scope":"base","ceiling":"auto","connectors":[],"code_mode_mcps":[],"model_tier":null,"memory_profile":null,"dreaming":null,"dreaming_model":null,"wake_cadence":null,"refusal":null,"models":[],"compaction_model":null},"born_with":{}}"#,
        ),
        HubFile::new("skills.json", b"[]"),
    ];
    let projected = AgentPackTravelProjection::from_definition(
        &definition("local"),
        None,
        vec![],
        vec![],
        BornWith::new(),
    )
    .expect("public travel projection");
    assert_eq!(projected.files().expect("canonical exported files"), files);
    let decoded = AgentPackTravelProjection::from_files(&files).expect("canonical travel tree");
    assert_eq!(decoded.name, "local");
    assert_eq!(
        decoded
            .to_definition(None)
            .expect("Base scope needs no world")
            .agent_id,
        "local"
    );
    files
}

fn capability_files() -> Vec<HubFile> {
    vec![HubFile::new(
        "PACK.md",
        b"---\nname: local\ndescription: Agent local capability control\nversion: 2\nkind: capability\n---\n",
    )]
}

fn travelling_agent_id(source: &PackSource) -> EntityId {
    // The domain at oneiron-contracts/src/entity_id/derived_domains.rs:328.
    // oneiron::entity_id::derived_domains is crate-private; derive itself is public.
    let hash = source.content_hash();
    EntityId::derive(
        b"oneiron/agent-pack-travel/v1/",
        &[b"agent", hash.as_bytes()],
    )
    .expect("travel admission id")
}

fn installed(disposition: PackInstallDisposition) -> PackInstallReceipt {
    match disposition {
        PackInstallDisposition::Installed(receipt) => *receipt,
        other => panic!("expected active install, not a block or Candidate: {other:?}"),
    }
}

fn assert_agent_can_put_a_local_capability_pack(vault: &Vault, agent: &WriteActor) {
    let files = capability_files();
    let source = PackSource::from_tree(files.clone())
        .expect("valid Capability tree")
        .source;
    assert_eq!(source.manifest().kind, PackKind::Capability);
    let before = vault
        .installed_pack("local")
        .expect("seed receipt")
        .expect("seed exists");
    assert_ne!(before.content_hash, source.content_hash().to_hex());
    let receipt = installed(
        vault
            .put_local_pack_as_agent(agent, files)
            .expect("agent Capability put"),
    );
    assert_eq!(receipt.pack_name, "local");
    assert_eq!(receipt.kind, PackKind::Capability);
    assert_eq!(receipt.status, PackInstallStatus::Active);
    assert_eq!(receipt.candidate_reason, None);
    assert_eq!(receipt.content_hash, source.content_hash().to_hex());
    assert_eq!(receipt.agent, None);
    assert_eq!(
        vault.installed_pack("local").expect("installed control"),
        Some(receipt)
    );
}

#[test]
fn agent_local_agent_pack_is_refused_without_minting_a_definition() {
    let (_dir, vault, _owner, agent) = fixture();
    // Case B runs first, with the exact vault and WriteActor used for Case A.
    assert_agent_can_put_a_local_capability_pack(&vault, &agent);
    let files = travelling_agent_files();
    let source = PackSource::from_tree(files.clone())
        .expect("valid AgentPack tree")
        .source;
    assert_eq!(source.manifest().name, "local");
    assert_eq!(source.manifest().kind, PackKind::Agent);
    let target = travelling_agent_id(&source);
    let source_id = source.entity_id().expect("pack source id");
    let before = vault
        .installed_pack("local")
        .expect("read Capability control receipt");
    assert!(before.is_some());
    assert!(
        vault
            .get_agent_definition(&target)
            .expect("target before")
            .is_none()
    );
    assert!(
        vault
            .get_pack_source(&source_id)
            .expect("source before")
            .is_none()
    );
    assert!(
        vault
            .candidate_pack(&source)
            .expect("Candidate before")
            .is_none()
    );

    let result = vault.put_local_pack_as_agent(&agent, files);
    let created = vault
        .get_agent_definition(&target)
        .expect("target after agent put");
    assert!(
        created.is_none(),
        "agent put minted the travelling AGENT_DEF: result={result:?}, definition={created:?}",
    );
    match result {
        Err(Error::InvalidConfig(message)) => {
            assert_eq!(
                message,
                "pack source: an agent's local pack is no agent pack"
            );
        }
        other => panic!("expected the Agent-kind refusal, got {other:?}"),
    }
    assert_eq!(
        vault.installed_pack("local").expect("local after refusal"),
        before
    );
    assert!(
        vault
            .get_pack_source(&source_id)
            .expect("source after refusal")
            .is_none()
    );
    assert!(
        vault
            .candidate_pack(&source)
            .expect("Candidate after refusal")
            .is_none()
    );
}

#[test]
fn owner_can_still_put_the_same_travelling_local_agent_pack() {
    let (_dir, vault, owner, _agent) = fixture();
    let files = travelling_agent_files();
    let source = PackSource::from_tree(files.clone())
        .expect("valid AgentPack tree")
        .source;
    let target = travelling_agent_id(&source);
    assert!(
        vault
            .get_agent_definition(&target)
            .expect("owner target before")
            .is_none()
    );
    let receipt = installed(
        vault
            .put_pack(&owner, files)
            .expect("owner AgentPack put without a hub"),
    );
    assert_eq!(receipt.pack_name, "local");
    assert_eq!(receipt.kind, PackKind::Agent);
    assert_eq!(receipt.status, PackInstallStatus::Active);
    assert_eq!(receipt.candidate_reason, None);
    assert_eq!(receipt.content_hash, source.content_hash().to_hex());
    assert_eq!(receipt.agent, Some(target.to_hex()));
    assert_eq!(
        vault.installed_pack("local").expect("owner install"),
        Some(receipt)
    );
    let imported = vault
        .get_agent_definition(&target)
        .expect("read imported definition")
        .expect("owner minted AGENT_DEF");
    assert_eq!(imported.agent_id, "local");
    assert_eq!(imported.scope, AgentScope::Base);
    assert!(!imported.enabled);
    assert_eq!(imported.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(imported.lifecycle_status, ClaimLifecycleStatus::Active);
    assert_eq!(imported.ceiling, AgentCeiling::Proposed);
    assert_eq!(imported.source, ClaimSource::Imported);
}
