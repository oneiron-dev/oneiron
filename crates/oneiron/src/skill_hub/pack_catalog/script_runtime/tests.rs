use super::*;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape,
};
use crate::code_sandbox::microvm::{
    CredentialEgressProxy, CredentialReadTransport, MicroVmExit, MicroVmHandle,
    collect_overlay_writes, prepare_overlay_handle,
};
use crate::code_sandbox::{
    SandboxBoundaryContract, SandboxCredentialCall, SandboxCredentialHandle,
    SandboxCredentialOperation, SandboxProposalWrite,
};
use crate::connector_key::{ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeySpec};
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};
use crate::skill_hub::{
    ForeignSkillPublisher, HubFile, HubPin, HubRef, HubSyncPolicy, SkillHubKind, SkillHubRecord,
    SkillHubTrustTier,
};
use crate::{TimeRange, VaultConfig, test_util::entity};
use std::{path::PathBuf, sync::Mutex};

const JS: &str = include_str!("../../../../tests/fixtures/echo_pack/scripts/adapter.js");
struct Qualified(String);
impl super::super::PackQualifier for Qualified {
    fn qualify(&self, source: &PackSource) -> Result<super::super::PackQualification> {
        Ok(super::super::PackQualification {
            suite: "script-fixture".into(),
            report_hash: "12".repeat(32),
            passed: true,
            advisory_accepted: true,
            advisory: "fixture qualified".into(),
            runtime: Some(super::super::PackRuntimeRecipe {
                adapter: source.manifest().adapter.clone().unwrap(),
                runtime_id: crate::code_sandbox::SANDBOX_JS_COMPONENT_NAME.into(),
                runtime_hash: self.0.clone(),
            }),
        })
    }
}
fn source() -> Result<PackSource> {
    PackSource::from_files(vec![
        HubFile::new(
            "PACK.md",
            include_bytes!("../../../../tests/fixtures/echo_pack/PACK.md").to_vec(),
        ),
        HubFile::new("scripts/adapter.js", JS.as_bytes().to_vec()),
        HubFile::new(
            "scripts/input.json",
            include_bytes!("../../../../tests/fixtures/echo_pack/scripts/input.json").to_vec(),
        ),
    ])
}
fn setup(
    auto_install: bool,
) -> Result<(
    tempfile::TempDir,
    Arc<Vault>,
    EntityId,
    PackScriptGrant,
    GuestImage,
)> {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    let (dir, vault) = crate::test_util::open_test_vault_with(config);
    let vault = Arc::new(vault);
    let owner_id = entity(0xB1);
    let agent = entity(0xB2);
    for id in [owner_id, agent] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:script-owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: "email-token".into(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: b"host-only-secret".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: "connector:email".into(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: vec!["read".into()],
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;
    let (key_id, _) = vault.register_connector(
        ConnectorCatalogEntry {
            name: "email".into(),
            connector: "email".into(),
            summary: "test channel".into(),
            verbs: vec!["send".into()],
            call_class: ConnectorCallClass::CounterpartyComm,
            registered_at: 1,
        },
        ConnectorKeySpec {
            secret_ref: Some("email-token".into()),
            actor_entity_ref: Some(agent),
            ..ConnectorKeySpec::new("email")
        },
        1,
    )?;
    let grant = PackScriptGrant {
        requested: "email".into(),
        key_id,
        destination: CredentialDestination::new("https", "api.example.com")?,
    };
    let mut identity = ChannelIdentity::requested(
        "email",
        "agent@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(agent),
        1_800_000_000,
    );
    identity.state = ChannelIdentityState::Active;
    identity.pending_fulfillment = None;
    vault.create_channel_identity(&entity(0xB3), &identity)?;
    let hub = entity(0xB4);
    vault.configure_skill_hub(
        &owner,
        &hub,
        &SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            "https://example.invalid/packs.json",
            SkillHubTrustTier::Verified,
            HubSyncPolicy::ContentHashFrozen,
        )?,
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let publisher: ForeignSkillPublisher =
        vault.admit_skill_publisher(&owner, "publisher:script-fixture", hub)?;
    let source = source()?;
    let source_id = vault.stage_pack_source(&source, TimeRange { start: 2, end: 2 }, 2)?;
    let component = dir.path().join("component");
    std::fs::write(&component, b"pinned mock component")?;
    let digest = blake3::hash(b"pinned mock component").to_hex().to_string();
    let ask = vault.prepare_pack_install(
        source_id,
        &HubRef::new(
            hub,
            "pack",
            HubPin::ContentHash(source.content_hash().to_hex()),
        )?,
        &publisher,
        &Qualified(digest),
    )?;
    let code = if auto_install {
        super::super::PackCodeAutoInstall::EnabledAfterSandboxTests
    } else {
        super::super::PackCodeAutoInstall::Disabled
    };
    if auto_install {
        assert_eq!(
            vault.auto_install_pack(&ask, code)?,
            super::super::PackInstallDisposition::PendingConsent
        );
    } else {
        assert_eq!(
            vault.auto_install_pack(&ask, code)?,
            super::super::PackInstallDisposition::CodeCandidate(Box::new(ask.clone()))
        );
    }
    vault.approve_pack_install(&ask, &owner)?;
    let disposition = if auto_install {
        vault.auto_install_pack(&ask, code)?
    } else {
        vault.install_pack(&ask)?
    };
    assert!(matches!(
        disposition,
        super::super::PackInstallDisposition::Installed(_)
    ));
    let wake_ids =
        vault.subscribe_pack_wakes("fixture.echo", &owner, agent, std::slice::from_ref(&grant))?;
    assert_eq!(wake_ids.len(), 1);
    let image = GuestImage::new(
        dir.path().join("kernel"),
        dir.path().join("rootfs"),
        component,
    );
    std::fs::write(&image.kernel, b"pinned")?;
    std::fs::write(&image.rootfs, b"pinned")?;
    Ok((dir, vault, agent, grant, image))
}

// Deliberately a protocol double, not an isolation proof: tests the engine's
// value binding, typed output intake and wake/verb doors without KVM.
struct Sink(Arc<Mutex<Vec<u8>>>);
impl CredentialReadTransport for Sink {
    fn read(
        &self,
        _: &CredentialDestination,
        _: &SandboxCredentialOperation,
        _: &rmpv::Value,
        secret: &[u8],
    ) -> Result<()> {
        *self.0.lock().unwrap() = secret.to_vec();
        Ok(())
    }
}

struct OutputBackend {
    root: PathBuf,
    output: Vec<u8>,
    seen_secret: Arc<Mutex<Vec<u8>>>,
}
impl MicroVmBackend for OutputBackend {
    fn name(&self) -> &'static str {
        "firecracker"
    }
    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle> {
        prepare_overlay_handle(&self.root, self.name(), contract, mounts)
    }
    fn run(&self, _: &MicroVmHandle, _: &GuestImage, _: ExecutionBudget) -> Result<MicroVmExit> {
        Err(invalid("mock requires credential proxy"))
    }
    fn run_with_proxy(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        _: ExecutionBudget,
        proxy: &CredentialEgressProxy,
    ) -> Result<MicroVmExit> {
        assert_eq!(image.source, JS);
        let call = SandboxCredentialCall::read_only(
            "metadata",
            SandboxCredentialHandle::new("email-token")?,
            rmpv::Value::Map(vec![
                (rmpv::Value::from("scheme"), rmpv::Value::from("https")),
                (
                    rmpv::Value::from("host"),
                    rmpv::Value::from("api.example.com"),
                ),
            ]),
        )?;
        proxy.forward_read(vm, &call, &Sink(Arc::clone(&self.seen_secret)))?;
        std::fs::write(vm.overlay_upper().join("adapter-output.json"), &self.output)?;
        Ok(MicroVmExit {
            status: 0,
            overlay_dirty: true,
        })
    }
    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        collect_overlay_writes(
            vm.overlay_upper(),
            crate::code_sandbox::SandboxMount::Workspace,
        )
    }
    fn proxy_credentials(&self, _: &MicroVmHandle, _: &dyn CredentialResolver) -> Result<()> {
        Ok(())
    }
}
fn output() -> Vec<u8> {
    let inbound = crate::surface_event::InboundSurfaceEventInput::new(
        "message-1",
        "email",
        "agent@example.com",
        crate::surface_event::SurfaceCounterpartyStamp::unknown("sender"),
        1,
        false,
    );
    serde_json::to_vec(&serde_json::json!({
        "inbound": [inbound],
        "verbs": [{"channel":"email","verb":"send","target":"recipient","content_ref":"artifact:1"}],
        "events": [{"event_id":"arrival-1","connector":"email","event_kind":"arrived",
            "predicate":"email.message","payload":{"id":"message-1"}}]
    })).unwrap()
}
#[test]
fn installed_script_uses_key_custody_surface_verbs_and_subscription_wake() -> Result<()> {
    let (_dir, vault, agent, grant, image) = setup(false)?;
    let seen_secret = Arc::new(Mutex::new(Vec::new()));
    let scratch = tempfile::tempdir()?;
    let result = vault.run_script_pack_in_vm(
        PackScriptRun {
            name: "fixture.echo",
            agent,
            grants: std::slice::from_ref(&grant),
            image: &image,
            budget: ExecutionBudget::new(5, 128, 2),
            now: 1_800_000_123,
        },
        Box::new(OutputBackend {
            root: scratch.path().to_path_buf(),
            output: output(),
            seen_secret: Arc::clone(&seen_secret),
        }),
    )?;
    assert_eq!(&*seen_secret.lock().unwrap(), b"host-only-secret");
    assert!(matches!(
        result.inbound.as_slice(),
        [crate::surface_event::SurfaceEventAdmission::Accepted(_)]
    ));
    assert_eq!(result.verbs.len(), 1);
    assert_eq!(result.verbs[0].verb, "send");
    assert_eq!(result.verbs[0].actor, agent.to_hex());
    assert_eq!(result.wakes.len(), 1);
    assert_eq!(
        result.wakes[0].status,
        crate::connector_key::events::ConnectorWakeStatus::Enqueued
    );
    assert!(vault.surface_event_handoff_status("message-1")?.is_some());
    Ok(())
}
#[test]
fn out_of_manifest_grant_and_output_are_refused_before_any_event() -> Result<()> {
    let (_dir, vault, agent, mut grant, image) = setup(false)?;
    grant.requested = "other".into();
    let scratch = tempfile::tempdir()?;
    let seen_secret = Arc::new(Mutex::new(Vec::new()));
    let run = |grant: &PackScriptGrant, output: Vec<u8>| {
        vault.run_script_pack_in_vm(
            PackScriptRun {
                name: "fixture.echo",
                agent,
                grants: std::slice::from_ref(grant),
                image: &image,
                budget: ExecutionBudget::new(5, 128, 2),
                now: 1_800_000_123,
            },
            Box::new(OutputBackend {
                root: scratch.path().to_path_buf(),
                output,
                seen_secret: Arc::clone(&seen_secret),
            }),
        )
    };
    assert!(run(&grant, output()).is_err());
    assert!(seen_secret.lock().unwrap().is_empty());
    grant.requested = "email".into();
    let mut bad: serde_json::Value = serde_json::from_slice(&output()).unwrap();
    bad["events"][0]["event_kind"] = "not_declared".into();
    assert!(run(&grant, serde_json::to_vec(&bad).unwrap()).is_err());
    assert!(vault.surface_event_handoff_status("message-1")?.is_none());
    Ok(())
}

#[test]
fn host_enabled_code_switch_keeps_the_irreversible_consent_gate() -> Result<()> {
    let (_dir, vault, _agent, _grant, _image) = setup(true)?;
    assert!(vault.installed_pack("fixture.echo")?.is_some());
    Ok(())
}

#[test]
fn revoked_custody_refuses_a_script_before_any_inbound_handoff() -> Result<()> {
    let (_dir, vault, agent, grant, image) = setup(false)?;
    vault.revoke_secret("email-token", 1_800_000_100)?;
    let scratch = tempfile::tempdir()?;
    let secret = Arc::new(Mutex::new(Vec::new()));
    assert!(
        vault
            .run_script_pack_in_vm(
                PackScriptRun {
                    name: "fixture.echo",
                    agent,
                    grants: std::slice::from_ref(&grant),
                    image: &image,
                    budget: ExecutionBudget::new(5, 128, 2),
                    now: 1_800_000_123,
                },
                Box::new(OutputBackend {
                    root: scratch.path().to_path_buf(),
                    output: output(),
                    seen_secret: Arc::clone(&secret)
                })
            )
            .is_err()
    );
    assert!(secret.lock().unwrap().is_empty());
    assert!(vault.surface_event_handoff_status("message-1")?.is_none());
    Ok(())
}
#[test]
fn foreign_script_cannot_route_to_a_different_channel_agent() -> Result<()> {
    let (_dir, vault, agent, grant, image) = setup(false)?;
    let other = entity(0xB5);
    vault.put_entity(
        &other,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"other agent",
    )?;
    let mut identity = ChannelIdentity::requested(
        "email",
        "other@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(other),
        1_800_000_000,
    );
    identity.state = ChannelIdentityState::Active;
    identity.pending_fulfillment = None;
    vault.create_channel_identity(&entity(0xB6), &identity)?;
    let mut wrong: serde_json::Value = serde_json::from_slice(&output()).unwrap();
    wrong["inbound"][0]["receiving_address_or_handle"] = "other@example.com".into();
    let scratch = tempfile::tempdir()?;
    assert!(
        vault
            .run_script_pack_in_vm(
                PackScriptRun {
                    name: "fixture.echo",
                    agent,
                    grants: std::slice::from_ref(&grant),
                    image: &image,
                    budget: ExecutionBudget::new(5, 128, 2),
                    now: 1_800_000_123,
                },
                Box::new(OutputBackend {
                    root: scratch.path().to_path_buf(),
                    output: serde_json::to_vec(&wrong).unwrap(),
                    seen_secret: Arc::new(Mutex::new(Vec::new()))
                })
            )
            .is_err()
    );
    assert!(vault.surface_event_handoff_status("message-1")?.is_none());
    Ok(())
}
