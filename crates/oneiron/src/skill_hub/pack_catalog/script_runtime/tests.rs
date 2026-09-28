use super::*;
use crate::Error;
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
use crate::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeySpec, SlateDataClass, SlateToolManifest,
    draft_connector_slate,
};
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
struct Qualified(String, bool);
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
impl super::super::PackFitPolicy for Qualified {
    fn evaluate(
        &self,
        _source: &PackSource,
        _card: &super::super::PackPermissions,
    ) -> Result<super::super::PackFitVerdict> {
        Ok(super::super::PackFitVerdict {
            fits: true,
            rules_hit: false,
            code_auto_install: self.1,
        })
    }
    fn qualify_script(
        &self,
        source: &PackSource,
    ) -> Result<Option<super::super::PackQualification>> {
        Ok(Some(super::super::PackQualifier::qualify(self, source)?))
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
    setup_with_secret(auto_install, "email-token")
}
fn setup_with_secret(
    auto_install: bool,
    secret_ref: &str,
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
    // Keep the fixture's established normal-criticality gate posture while
    // supplying the seeded pack-install rows that local admission now reads.
    let (dir, vault) = crate::test_util::open_test_vault_with(config);
    let defaults = crate::gate::default_policy_manifest();
    let mut manifest = rmpv::decode::read_value(&mut defaults.as_slice())
        .map_err(|_| crate::Error::InvariantViolation("decode test policy"))?;
    let rmpv::Value::Map(entries) = &mut manifest else {
        return Err(crate::Error::InvariantViolation("test policy map"));
    };
    let Some(rmpv::Value::Map(axes)) = entries
        .iter_mut()
        .find_map(|(key, value)| (key.as_str() == Some("defaults")).then_some(value))
    else {
        return Err(crate::Error::InvariantViolation("test policy defaults"));
    };
    let Some((_, criticality)) = axes
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("criticality"))
    else {
        return Err(crate::Error::InvariantViolation("test policy criticality"));
    };
    *criticality = rmpv::Value::from("normal");
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest)
        .map_err(|_| crate::Error::InvariantViolation("encode test policy"))?;
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )?;
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
        name: secret_ref.into(),
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
    let manifest = vec![SlateToolManifest {
        name: "send".into(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(serde_json::json!({"type":"object",
            "properties":{"idempotency_key":{"type":"string"}}})),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: true,
        legacy_ask: false,
    }];
    let slate = vault.store_connector_slate(
        &manifest,
        &serde_json::to_string(&draft_connector_slate(&manifest))
            .map_err(|_| Error::InvariantViolation("pack fixture slate encoding"))?,
    )?;
    vault.override_connector_slate(&owner, slate, 0, &std::collections::BTreeMap::new())?;
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
            secret_ref: Some(secret_ref.into()),
            actor_entity_ref: Some(agent),
            slate_ref: Some(slate),
            protocol_revision: Some("2026-09-01".into()),
            ..ConnectorKeySpec::new("email")
        },
        1,
    )?;
    let (connector, plan, oracle) =
        crate::connector_key::qualification::tests::support::passing_suite("send");
    let (active, _) = vault
        .qualify_connector_key(
            &key_id,
            "2026-09-01",
            connector.as_ref(),
            &plan,
            oracle.as_ref(),
            2,
        )
        .map_err(|_| Error::InvariantViolation("pack fixture connector qualification"))?;
    assert_eq!(
        active.status,
        crate::connector_key::ConnectorKeyStatus::Active
    );
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
    let reference = HubRef::new(
        hub,
        "pack",
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    vault.with_write_txn(|txn| {
        vault.record_pack_fetch_in_txn(txn, &source_id, &reference, &publisher)
    })?;
    let component = dir.path().join("component");
    std::fs::write(&component, b"pinned mock component")?;
    let digest = blake3::hash(b"pinned mock component").to_hex().to_string();
    let ask = vault.prepare_pack_install(
        source_id,
        &reference,
        &publisher,
        &Qualified(digest, auto_install),
    )?;
    let disposition = vault.install_pack(&ask)?;
    if auto_install {
        let super::super::PackInstallDisposition::Installed(receipt) = disposition else {
            panic!("qualified fit installs Active")
        };
        assert!(receipt.runtime.is_some());
    } else {
        let super::super::PackInstallDisposition::Candidate(receipt) = disposition else {
            panic!("code flag off keeps Candidate")
        };
        assert_eq!(
            receipt.candidate_reason,
            Some(super::super::PackCandidateReason::CodeAutoInstallOff)
        );
        assert_eq!(receipt.permissions, ask.permissions().clone());
        assert!(vault.installed_pack("fixture.echo")?.is_none());
        assert!(receipt.runtime.is_none());
    }
    if auto_install {
        let wake_ids = vault.subscribe_pack_wakes(
            "fixture.echo",
            &owner,
            agent,
            std::slice::from_ref(&grant),
        )?;
        assert_eq!(wake_ids.len(), 1);
    }
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
    after_run: Option<Box<dyn Fn() + Send + Sync>>,
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
        let (prefix, original) = image
            .source
            .split_once(");\n")
            .ok_or_else(|| invalid("missing injected grant mapping"))?;
        assert_eq!(original, JS);
        let mapping: serde_json::Value = serde_json::from_str(
            prefix
                .strip_prefix("const packGrants = Object.freeze(")
                .ok_or_else(|| invalid("missing grant object"))?,
        )
        .map_err(|_| invalid("invalid grant mapping"))?;
        let token = mapping["email"]["handle"]
            .as_str()
            .ok_or_else(|| invalid("missing opaque handle"))?;
        assert_ne!(token, "email-token");
        let call = SandboxCredentialCall::read_only(
            "metadata",
            SandboxCredentialHandle::new(token)?,
            rmpv::Value::Map(vec![
                (rmpv::Value::from("scheme"), rmpv::Value::from("https")),
                (
                    rmpv::Value::from("host"),
                    rmpv::Value::from("api.example.com"),
                ),
            ]),
        )?;
        proxy.forward_read(vm, &call, &Sink(Arc::clone(&self.seen_secret)))?;
        if let Some(change) = &self.after_run {
            change();
        }
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
        )?
        .into_iter()
        .map(|write| {
            let SandboxProposalWrite::FileWrite(file) = write else {
                unreachable!()
            };
            Ok(file.lower_to_edit(b"")?.map(SandboxProposalWrite::FileEdit))
        })
        .collect::<Result<Vec<_>>>()
        .map(|edits| edits.into_iter().flatten().collect())
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
    let (_dir, vault, agent, grant, image) = setup(true)?;
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
            after_run: None,
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
    let (_dir, vault, agent, mut grant, image) = setup(true)?;
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
                after_run: None,
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
fn host_code_switch_keeps_candidate_inert_and_fit_install_active() -> Result<()> {
    let (_off_dir, off, agent, grant, _image) = setup(false)?;
    assert!(off.installed_pack("fixture.echo")?.is_none());
    assert!(off.candidate_pack(&source()?)?.is_some());
    assert!(
        off.subscribe_pack_wakes(
            "fixture.echo",
            &off.authenticate_owner(
                entity(0xB1),
                "principal:script-owner",
                true,
                crate::store::GateDecisionId::now()
            )?,
            agent,
            std::slice::from_ref(&grant)
        )
        .is_err()
    );
    let (_on_dir, on, _agent, _grant, _image) = setup(true)?;
    assert!(on.installed_pack("fixture.echo")?.is_some());
    Ok(())
}

#[test]
fn revoked_custody_refuses_a_script_before_any_inbound_handoff() -> Result<()> {
    let (_dir, vault, agent, grant, image) = setup(true)?;
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
                    seen_secret: Arc::clone(&secret),
                    after_run: None
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
    let (_dir, vault, agent, grant, image) = setup(true)?;
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
                    seen_secret: Arc::new(Mutex::new(Vec::new())),
                    after_run: None
                })
            )
            .is_err()
    );
    assert!(vault.surface_event_handoff_status("message-1")?.is_none());
    Ok(())
}

#[test]
fn same_pack_receives_run_local_grants_for_two_vault_custody_names() -> Result<()> {
    for secret_ref in ["email-token", "work-mail-token"] {
        let (_dir, vault, agent, grant, image) = setup_with_secret(true, secret_ref)?;
        let scratch = tempfile::tempdir()?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let outcome = vault.run_script_pack_in_vm(
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
                seen_secret: Arc::clone(&seen),
                after_run: None,
            }),
        )?;
        assert_eq!(outcome.wakes.len(), 1);
        assert_eq!(&*seen.lock().unwrap(), b"host-only-secret");
    }
    Ok(())
}

#[test]
fn malformed_wake_cannot_commit_preceding_inbound_or_wake() -> Result<()> {
    for malformed_position in [0, 1] {
        let (_dir, vault, agent, grant, image) = setup(true)?;
        let mut output: serde_json::Value = serde_json::from_slice(&output()).unwrap();
        let valid = output["events"][0].clone();
        output["events"].as_array_mut().unwrap().push(valid);
        output["events"][1]["event_id"] = "arrival-2".into();
        output["events"][malformed_position]["event_id"] = "".into();
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
                        output: serde_json::to_vec(&output).unwrap(),
                        seen_secret: Arc::new(Mutex::new(Vec::new())),
                        after_run: None
                    })
                )
                .is_err()
        );
        assert!(vault.surface_event_handoff_status("message-1")?.is_none());
        assert!(
            vault
                .store
                .gate_decisions(100)?
                .iter()
                .all(|receipt| receipt.content_kind != "connector_wake")
        );
    }
    Ok(())
}

#[test]
fn pack_wake_never_fans_out_to_another_agents_matching_subscription() -> Result<()> {
    use crate::connector_key::{ConnectorDispatchTelemetry, ConnectorKeyRecord, EffectorBudget};
    let (_dir, vault, agent, grant, image) = setup(true)?;
    let other = entity(0xB7);
    vault.put_entity(
        &other,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"other",
    )?;
    let other_key = entity(0xB8);
    vault.register_connector_key(
        &other_key,
        ConnectorKeyRecord::active("email", Some(other), vec![EffectorBudget::rate(1, 600)], 1),
    )?;
    let owner = vault.authenticate_owner(
        entity(0xB1),
        "principal:script-owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.subscribe_connector_event(
        &owner,
        other,
        other_key,
        ConnectorEventFilter {
            connector: "email".into(),
            event_kind: Some("arrived".into()),
            predicate: None,
        },
    )?;
    let scratch = tempfile::tempdir()?;
    let outcome = vault.run_script_pack_in_vm(
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
            seen_secret: Arc::new(Mutex::new(Vec::new())),
            after_run: None,
        }),
    )?;
    assert_eq!(outcome.wakes.len(), 1);
    assert_eq!(outcome.wakes[0].agent, agent);
    let spend = vault.admit_connector_key_dispatches(
        &other_key,
        "email",
        1,
        ConnectorDispatchTelemetry::default(),
    )?;
    assert_eq!(
        spend.admitted, 1,
        "ungranted B key retains full wake budget"
    );
    Ok(())
}

#[test]
fn key_revocation_between_guest_run_and_admission_refuses_all_output() -> Result<()> {
    let (_dir, vault, agent, grant, image) = setup(true)?;
    let scratch = tempfile::tempdir()?;
    let key_id = grant.key_id;
    let to_revoke = Arc::clone(&vault);
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
            seen_secret: Arc::new(Mutex::new(Vec::new())),
            after_run: Some(Box::new(move || {
                to_revoke
                    .revoke_connector_key(&key_id, 1_800_000_122)
                    .unwrap();
            })),
        }),
    );
    assert!(result.is_err());
    assert!(vault.surface_event_handoff_status("message-1")?.is_none());
    assert!(
        vault
            .store
            .gate_decisions(100)?
            .iter()
            .all(|receipt| receipt.content_kind != "connector_wake")
    );
    Ok(())
}

#[test]
fn stored_wake_id_conflict_rolls_back_new_inbound() -> Result<()> {
    let (_dir, vault, agent, grant, image) = setup(true)?;
    vault.ingest_connector_event(&crate::connector_key::events::ConnectorEvent {
        event_id: "arrival-1".into(),
        connector: "email".into(),
        event_kind: "arrived".into(),
        predicate: "email.message".into(),
        payload: serde_json::json!({"id":"different"}),
    })?;
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
            seen_secret: Arc::new(Mutex::new(Vec::new())),
            after_run: None,
        }),
    );
    assert!(result.is_err());
    assert!(vault.surface_event_handoff_status("message-1")?.is_none());
    Ok(())
}

#[test]
fn delegated_mailbox_reassignment_after_guest_run_cannot_route_to_new_agent() -> Result<()> {
    use crate::channel_identity::{
        ChannelIdentityFulfillment, DelegatedGrant, DelegatedGrantScope, DelegatedProvisionRequest,
        delegated_custody_scopes,
    };
    let (_dir, vault, agent, grant, image) = setup(true)?;
    let mailbox = "member@member-owned.example";
    let delegated = DelegatedGrant::new("member-oauth", vec![DelegatedGrantScope::MailRead]);
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: "member-oauth".into(),
        class: CustodyClass::CrossVault,
        device_only: true,
        value_bytes: b"member-token".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1_800_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: "connector:gmail".into(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: delegated_custody_scopes("email", mailbox),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;
    let first = entity(0xB9);
    vault.provision_delegated_identity(
        &first,
        DelegatedProvisionRequest {
            channel: "email".into(),
            address_or_handle: mailbox.into(),
            binding: ChannelIdentityBinding::agent(agent),
            grant: delegated.clone(),
        },
        1_800_000_000,
    )?;
    vault.transition_channel_identity(
        &first,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_010,
        None,
    )?;
    vault.transition_channel_identity(
        &first,
        ChannelIdentityState::Active,
        None,
        1_800_000_020,
        None,
    )?;
    let other = entity(0xBA);
    vault.put_entity(
        &other,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"other",
    )?;
    let mut output: serde_json::Value = serde_json::from_slice(&output()).unwrap();
    output["inbound"][0]["receiving_address_or_handle"] = mailbox.into();
    let change = Arc::clone(&vault);
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
            output: serde_json::to_vec(&output).unwrap(),
            seen_secret: Arc::new(Mutex::new(Vec::new())),
            after_run: Some(Box::new(move || {
                change
                    .transition_channel_identity(
                        &first,
                        ChannelIdentityState::Released,
                        None,
                        1_800_000_030,
                        None,
                    )
                    .unwrap();
                let second = entity(0xBB);
                change
                    .provision_delegated_identity(
                        &second,
                        DelegatedProvisionRequest {
                            channel: "email".into(),
                            address_or_handle: mailbox.into(),
                            binding: ChannelIdentityBinding::agent(other),
                            grant: delegated.clone(),
                        },
                        1_800_000_040,
                    )
                    .unwrap();
                change
                    .transition_channel_identity(
                        &second,
                        ChannelIdentityState::PendingFulfillment,
                        Some(ChannelIdentityFulfillment::Api),
                        1_800_000_050,
                        None,
                    )
                    .unwrap();
                change
                    .transition_channel_identity(
                        &second,
                        ChannelIdentityState::Active,
                        None,
                        1_800_000_060,
                        None,
                    )
                    .unwrap();
            })),
        }),
    );
    assert!(result.is_err());
    assert!(vault.surface_event_handoff_status("message-1")?.is_none());
    Ok(())
}

#[test]
fn replaced_install_after_source_selection_refuses_old_program_and_wake() -> Result<()> {
    let (_dir, vault, agent, grant, image) = setup(true)?;
    // Capture exactly the source/receipt pair the runtime will execute. A
    // newer, separately consented install removes the declared wake before
    // the runner reaches the sandbox; the old script must not run as B.
    let selected = vault.installed_script_pack("fixture.echo")?;
    let mut files = source()?.files().to_vec();
    let pack = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    let updated = String::from_utf8(pack.content.clone())
        .unwrap()
        .replace("version: 1", "version: 2")
        .replace("wakes: [\"email.arrived\"]", "wakes: []");
    pack.content = updated.into_bytes();
    let replacement = PackSource::from_files(files)?;
    let id = vault.stage_pack_source(&replacement, TimeRange { start: 4, end: 4 }, 4)?;
    let owner = vault.authenticate_owner(
        entity(0xB1),
        "principal:script-owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let hub = entity(0xB4);
    let publisher =
        vault.admit_skill_publisher(&owner, "publisher:script-fixture-revision", hub)?;
    let reference = HubRef::new(
        hub,
        "pack",
        HubPin::ContentHash(replacement.content_hash().to_hex()),
    )?;
    let digest = blake3::hash(b"pinned mock component").to_hex().to_string();
    vault.with_write_txn(|txn| vault.record_pack_fetch_in_txn(txn, &id, &reference, &publisher))?;
    let ask = vault.prepare_pack_install(id, &reference, &publisher, &Qualified(digest, true))?;
    assert!(matches!(
        vault.install_pack(&ask)?,
        super::super::PackInstallDisposition::Installed(_)
    ));
    assert_ne!(
        vault.installed_pack("fixture.echo")?,
        Some(selected.2.clone())
    );
    let scratch = tempfile::tempdir()?;
    let outcome = vault.run_selected_script_pack_in_vm(
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
            seen_secret: Arc::new(Mutex::new(Vec::new())),
            after_run: None,
        }),
        selected,
    );
    assert!(outcome.is_err());
    assert!(vault.surface_event_handoff_status("message-1")?.is_none());
    assert!(
        vault
            .store
            .gate_decisions(100)?
            .iter()
            .all(|row| row.content_kind != "connector_wake")
    );
    Ok(())
}
