//! Nothing wider than its author's slice lands Active, on any door an agent
//! reaches (ARCH-0053:20, owner, 22 Sep 2026: "a definition that widens
//! nothing lands Active at the author's ceiling; anything beyond the author's
//! slice is a proposal").
//!
//! The doors: the guest's `self.*` `vault.agents.put` (`SelfCall::AgentsPut`
//! through the leased host dispatcher), the same host's public
//! `put_agent_definition` called directly, and an agent's local pack carrying
//! a travelling AgentPack. Each wider draft must be a proposal or a refusal;
//! an in-slice draft through the self.* door stays Active.
//!
//! `revoked_author_and_its_active_definition` is an observation for NOTE
//! AGENTDEF-REVOKE: it prints whether an author's Active definition keeps its
//! authority once the owner narrows and then switches off the author.

use std::sync::Arc;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentDefinitionPutDisposition, AgentScope,
};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{
    HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher, parse_agent_put_request,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::share_travel::{AgentPackTravelProjection, BornWith};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value;
use serde_json::{Value as JsonValue, json};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`; every seed here avoids the pinned bytes a
// fresh vault already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1
// 0xFF`, the seeded system agents among them).

const NOW: u64 = 1_700_000_000;

fn definition(name: &str, scope: AgentScope, ceiling: AgentCeiling) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "agent slice invariant fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        scope,
        ceiling,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The codec requires a non-empty provenance map.
        Value::Map(vec![(
            Value::from("definedVia"),
            Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

/// Active, enabled and approved: a definition that dispatches with authority.
fn lands_active(def: &AgentDefinition) -> bool {
    def.enabled
        && def.lifecycle_status == ClaimLifecycleStatus::Active
        && matches!(
            def.approval_status,
            ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
        )
}

fn brief(def: Option<&AgentDefinition>) -> String {
    def.map_or_else(
        || "none".to_owned(),
        |def| {
            format!(
                "approval={:?} lifecycle={:?} enabled={} scope={:?} ceiling={:?} source={:?}",
                def.approval_status,
                def.lifecycle_status,
                def.enabled,
                def.scope,
                def.ceiling,
                def.source
            )
        },
    )
}

struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    clock: Arc<ManualClock>,
    author_id: EntityId,
    leased: AttemptRecord,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A default-policy device vault, its embedded owner, an owner-created author
/// at `scope` and ceiling Proposed, and the author's dispatched attempt,
/// leased.
fn fixture(scope: AgentScope) -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;

    let author_id = EntityId::from_bytes([0x91; 16])?;
    vault.create_agent_definition_as(
        &owner,
        &author_id,
        &definition("fixture.author", scope, AgentCeiling::Proposed),
        TimeRange {
            start: NOW,
            end: NOW,
        },
        NOW,
    )?;
    let stored = vault
        .get_agent_definition(&author_id)?
        .expect("the owner's author");
    assert!(lands_active(&stored), "author {}", brief(Some(&stored)));
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(author_id),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: NOW,
        })?
    else {
        panic!("the author dispatches without running a model")
    };
    clock.set(NOW + 1);
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(&vault).claim(ClaimAttempt {
        lease_owner: "agent-slice-invariant-fixture".to_owned(),
        now: NOW + 1,
    })?
    else {
        panic!("the author's attempt is ready to lease")
    };
    assert_eq!(leased.id, status.attempt.id);
    clock.set(NOW + 2);
    Ok(Fixture {
        vault,
        owner,
        clock,
        author_id,
        leased,
        _dir: dir,
    })
}

fn host(fixture: &Fixture) -> oneiron::Result<HostSelfDispatcher<'_>> {
    HostSelfDispatcher::for_leased_agent_attempt(
        &fixture.vault,
        WriteActor::new(fixture.author_id, EdgeActorClass::Agent),
        &fixture.leased,
    )
}

/// U1: the guest's `vault.agents.put`, parsed as the bridge parses it.
fn put_through_self_call(
    host: &HostSelfDispatcher<'_>,
    id: EntityId,
    draft: &JsonValue,
) -> oneiron::Result<AgentDefinitionPutDisposition> {
    let call = parse_agent_put_request(&id.to_hex(), draft.clone(), NOW + 2)?;
    match host.dispatch(SelfCall::AgentsPut(Box::new(call)))? {
        SelfDispatchOutcome::AgentDefinitionPut(result) => {
            assert_eq!(result.id, id);
            Ok(result.disposition)
        }
        other => panic!("unexpected authoring outcome: {other:?}"),
    }
}

/// U1b: the same host's public put, called directly with the parsed draft.
fn put_through_host_method(
    host: &HostSelfDispatcher<'_>,
    id: EntityId,
    draft: &JsonValue,
) -> oneiron::Result<AgentDefinitionPutDisposition> {
    let call = parse_agent_put_request(&id.to_hex(), draft.clone(), NOW + 2)?;
    host.put_agent_definition(&call.id, &call.definition, call.occurred, call.learned_at)
}

fn draft(name: &str, extra: &[(&str, JsonValue)]) -> JsonValue {
    let mut body = serde_json::Map::new();
    body.insert("agentId".to_owned(), json!(name));
    body.insert("desc".to_owned(), json!("slice invariant draft"));
    body.insert("version".to_owned(), json!("1"));
    body.insert("scope".to_owned(), json!({"kind": "base"}));
    body.insert("ceiling".to_owned(), json!("proposed"));
    for (key, value) in extra {
        body.insert((*key).to_owned(), value.clone());
    }
    JsonValue::Object(body)
}

/// Each draft is wider than a Base, Proposed-ceiling author with no skills,
/// connectors, MCPs or model choices, on exactly one axis the slice rule
/// reads.
fn wider_drafts() -> Vec<(&'static str, JsonValue)> {
    vec![
        (
            "ceiling-auto-above-author",
            draft("fixture.wide-ceiling", &[("ceiling", json!("auto"))]),
        ),
        (
            "scope-all-above-base",
            draft("fixture.wide-scope", &[("scope", json!({"kind": "all"}))]),
        ),
        ("scope-omitted-defaults-all", {
            let mut body = draft("fixture.wide-scope-omitted", &[]);
            body.as_object_mut().expect("draft object").remove("scope");
            body
        }),
        (
            "connector-not-held",
            draft(
                "fixture.wide-connector",
                &[("connectors", json!(["fixture.connector"]))],
            ),
        ),
        (
            "code-mode-mcp-not-held",
            draft(
                "fixture.wide-mcp",
                &[("codeModeMcps", json!(["fixture.mcp"]))],
            ),
        ),
        (
            "skill-not-held",
            draft(
                "fixture.wide-skill",
                &[("skills", json!(["fixture.skill"]))],
            ),
        ),
        (
            "model-tier-changed",
            draft("fixture.wide-tier", &[("modelTier", json!("fixture.tier"))]),
        ),
    ]
}

type PutDoor = fn(
    &HostSelfDispatcher<'_>,
    EntityId,
    &JsonValue,
) -> oneiron::Result<AgentDefinitionPutDisposition>;

fn assert_no_wider_draft_lands_active(door: &str, put: PutDoor, seed: u8) -> TestResult {
    let fixture = fixture(AgentScope::Base)?;
    let host = host(&fixture)?;
    let mut active = Vec::new();
    for (offset, (case, body)) in wider_drafts().into_iter().enumerate() {
        let id = EntityId::from_bytes([seed + u8::try_from(offset)?; 16])?;
        let outcome = put(&host, id, &body);
        let stored = fixture.vault.get_agent_definition(&id)?;
        println!(
            "SLICE door={door} case={case} outcome={outcome:?} stored=[{}]",
            brief(stored.as_ref())
        );
        if matches!(outcome, Ok(AgentDefinitionPutDisposition::Active))
            || stored.as_ref().is_some_and(lands_active)
        {
            active.push(case);
        }
    }
    assert!(
        active.is_empty(),
        "door {door}: wider-than-slice drafts landed Active: {active:?}"
    );
    // The in-slice control on the same lease: it lands Active at the
    // author's approval, never refused (ARCH-0053:20).
    let id = EntityId::from_bytes([seed + 0x20; 16])?;
    let outcome = put(&host, id, &draft("fixture.in-slice", &[]))?;
    let stored = fixture
        .vault
        .get_agent_definition(&id)?
        .expect("the in-slice definition");
    println!(
        "SLICE door={door} case=in-slice-control outcome={outcome:?} stored=[{}]",
        brief(Some(&stored))
    );
    assert_eq!(outcome, AgentDefinitionPutDisposition::Active);
    assert!(lands_active(&stored));
    assert_eq!(stored.source, ClaimSource::Generated);
    Ok(())
}

#[test]
fn self_call_agents_put_lands_no_wider_draft_active() -> TestResult {
    assert_no_wider_draft_lands_active("U1-self-call", put_through_self_call, 0x30)
}

#[test]
fn direct_host_put_lands_no_wider_draft_active() -> TestResult {
    assert_no_wider_draft_lands_active("U1b-host-method", put_through_host_method, 0x60)
}

/// U5: an Approved agent at Base and ceiling Proposed puts its local pack as a
/// travelling AgentPack named `local` that asks for `scope` and `ceiling`.
fn put_local_agent_pack(case: &str, scope: AgentScope, ceiling: AgentCeiling) -> TestResult<bool> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let writer_id = EntityId::from_bytes([0x81; 16])?;
    vault.create_agent_definition_as(
        &owner,
        &writer_id,
        &definition(
            "fixture.local-pack-writer",
            AgentScope::Base,
            AgentCeiling::Proposed,
        ),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let writer = vault
        .get_agent_definition(&writer_id)?
        .expect("the writer agent");
    assert!(lands_active(&writer), "writer {}", brief(Some(&writer)));
    let agent = vault.observed_write_actor(WriteActor::new(writer_id, EdgeActorClass::Agent))?;
    let files: Vec<HubFile> = AgentPackTravelProjection::from_definition(
        &definition("local", scope, ceiling),
        None,
        Vec::new(),
        Vec::new(),
        BornWith::new(),
    )?
    .files()?;
    let outcome = vault.put_local_pack_as_agent(&agent, files);
    let target_hex = match &outcome {
        Ok(
            PackInstallDisposition::Installed(receipt) | PackInstallDisposition::Candidate(receipt),
        ) => receipt.agent.clone(),
        _ => None,
    };
    let target = target_hex.as_deref().map(EntityId::from_hex).transpose()?;
    let stored = match target {
        Some(id) => vault.get_agent_definition(&id)?,
        None => None,
    };
    let dispatch = match target {
        Some(id) => match AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(id),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 2,
        }) {
            Ok(AgentDispatchOutcome::Dispatched(_)) => "dispatched".to_owned(),
            Ok(AgentDispatchOutcome::Existing(_)) => "existing".to_owned(),
            Ok(AgentDispatchOutcome::ProposedWiden(_)) => "proposed-widen".to_owned(),
            Ok(_) => "workflow".to_owned(),
            Err(error) => format!("refused: {error}"),
        },
        None => "no-definition".to_owned(),
    };
    let outcome_kind = match &outcome {
        Ok(PackInstallDisposition::Installed(_)) => "installed".to_owned(),
        Ok(PackInstallDisposition::Candidate(_)) => "candidate".to_owned(),
        Ok(PackInstallDisposition::Blocked { reason }) => format!("blocked: {reason}"),
        Err(error) => format!("error: {error}"),
    };
    println!(
        "SLICE door=U5-local-agent-pack case={case} outcome={outcome_kind} target={} stored=[{}] dispatch={dispatch}",
        target.map_or_else(|| "none".to_owned(), |id| id.to_hex()),
        brief(stored.as_ref())
    );
    Ok(stored.as_ref().is_some_and(lands_active) || dispatch == "dispatched")
}

#[test]
fn agent_local_agent_pack_lands_no_wider_definition_active() -> TestResult {
    let mut active = Vec::new();
    for (case, scope, ceiling) in [
        (
            "ceiling-auto-above-writer",
            AgentScope::Base,
            AgentCeiling::Auto,
        ),
        (
            "scope-all-above-writer",
            AgentScope::All,
            AgentCeiling::Proposed,
        ),
    ] {
        if put_local_agent_pack(case, scope, ceiling)? {
            active.push(case);
        }
    }
    assert!(
        active.is_empty(),
        "U5: wider-than-slice local agent packs landed Active: {active:?}"
    );
    // Observation only (no assertion): an in-slice local agent pack. The
    // ruled rule would land it Active at the writer's ceiling; print what
    // main does.
    let in_slice =
        put_local_agent_pack("in-slice-observe", AgentScope::Base, AgentCeiling::Proposed)?;
    println!("SLICE door=U5-local-agent-pack case=in-slice-observe lands_active={in_slice}");
    Ok(())
}

fn dispatch_kind(vault: &Vault, id: EntityId, now: u64) -> String {
    match AgentDispatcher::new(vault).dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now,
    }) {
        Ok(AgentDispatchOutcome::Dispatched(_)) => "dispatched".to_owned(),
        Ok(AgentDispatchOutcome::Existing(_)) => "existing".to_owned(),
        Ok(AgentDispatchOutcome::ProposedWiden(_)) => "proposed-widen".to_owned(),
        Ok(_) => "workflow".to_owned(),
        Err(error) => format!("refused: {error}"),
    }
}

/// NOTE AGENTDEF-REVOKE, by run. An All-scope author writes an All-scope child
/// in its slice (Active). The owner then narrows the author to Base, then
/// switches it off. Printed after each step: the child's stored standing and
/// whether it still dispatches. Only the fixture is asserted.
#[test]
fn revoked_author_and_its_active_definition() -> TestResult {
    let fixture = fixture(AgentScope::All)?;
    let host = host(&fixture)?;
    let child = EntityId::from_bytes([0xb1; 16])?;
    let child_draft = draft("fixture.child", &[("scope", json!({"kind": "all"}))]);
    assert_eq!(
        put_through_self_call(&host, child, &child_draft)?,
        AgentDefinitionPutDisposition::Active
    );
    let report = |step: &str, now: u64| -> TestResult<bool> {
        let stored = fixture.vault.get_agent_definition(&child)?;
        let author = fixture.vault.get_agent_definition(&fixture.author_id)?;
        let dispatch = dispatch_kind(&fixture.vault, child, now);
        println!(
            "AGENTDEF-REVOKE step={step} author=[{}] child=[{}] child_dispatch={dispatch}",
            brief(author.as_ref()),
            brief(stored.as_ref())
        );
        Ok(stored
            .as_ref()
            .is_some_and(|def| lands_active(def) && def.scope == AgentScope::All)
            && dispatch == "dispatched")
    };
    // Observed, not asserted, so the later steps still print.
    let before = report("authored", NOW + 2)?;
    println!("AGENTDEF-REVOKE child_has_authority_when_authored={before}");

    fixture.clock.set(NOW + 3);
    let mut narrowed = fixture
        .vault
        .get_agent_definition(&fixture.author_id)?
        .expect("the author");
    narrowed.scope = AgentScope::Base;
    narrowed.version = "2".to_owned();
    let narrow = fixture.vault.update_agent_definition_as(
        &fixture.owner,
        &fixture.author_id,
        &narrowed,
        TimeRange {
            start: NOW + 3,
            end: NOW + 3,
        },
        NOW + 3,
    );
    println!("AGENTDEF-REVOKE owner_narrow_author_to_base={narrow:?}");
    let after_narrow = report("author-narrowed-to-base", NOW + 3)?;

    fixture.clock.set(NOW + 4);
    let mut disabled = fixture
        .vault
        .get_agent_definition(&fixture.author_id)?
        .expect("the author");
    disabled.enabled = false;
    disabled.version = "3".to_owned();
    let disable = fixture.vault.update_agent_definition_as(
        &fixture.owner,
        &fixture.author_id,
        &disabled,
        TimeRange {
            start: NOW + 4,
            end: NOW + 4,
        },
        NOW + 4,
    );
    println!("AGENTDEF-REVOKE owner_switch_off_author={disable:?}");
    let after_disable = report("author-switched-off", NOW + 4)?;
    let next_put = put_through_self_call(
        &host,
        EntityId::from_bytes([0xb2; 16])?,
        &draft("fixture.after-switch-off", &[]),
    );
    println!("AGENTDEF-REVOKE author_next_put_after_switch_off={next_put:?}");
    println!(
        "AGENTDEF-REVOKE answer: child_keeps_authority_after_narrow={after_narrow} child_keeps_authority_after_switch_off={after_disable}"
    );
    Ok(())
}
