//! `vault.agents.put` from guest code through the SDK bridge into the leased
//! host dispatcher: dispositions, no child, and the lease-generation fence.

use super::*;
use crate::agent_def::{AgentAuthorLease, AgentDefinitionPutDisposition};
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases, CompleteAttempt,
    CompleteOutcome,
};
use crate::code_run::{HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher};
use crate::engine_executor::{JsCodeModeHost, SelfDispatchResponse};
use crate::{EdgeActorClass, VaultConfig, WriteActor};
use serde_json::json;

struct SdkHost<'a>(HostSelfDispatcher<'a>);
impl JsCodeModeHost for SdkHost<'_> {
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        Ok(SelfDispatchResponse {
            outcome: self.0.dispatch(call)?,
            budget: None,
        })
    }
}

/// One guest `vault.agents.put` through the pinned first-party QuickJS
/// component and its typed host import.
#[cfg(feature = "code-sandbox-wasmtime")]
fn guest_put(host: &mut SdkHost<'_>, id: EntityId, definition: &JsonValue) -> Result<String> {
    use crate::code_run::CodeRunDeterminism;
    use crate::code_sandbox::quickjs::QuickJsRuntimeFactory;
    use crate::code_sandbox::wasmtime_runtime::ComponentBudget;
    use crate::code_sandbox::{SandboxBoundaryContract, SandboxGuestTier};
    use crate::engine_executor::{JsCodeModeRuntime, JsCodeModeStep};
    use sha2::{Digest, Sha256};

    let path = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        std::path::PathBuf::from,
    );
    let manifest: JsonValue = serde_json::from_slice(&std::fs::read(path.join("manifest.json"))?)
        .expect("pinned manifest");
    let artifact = &manifest["artifacts"]["first-party"];
    let bytes = std::fs::read(path.join(artifact["file"].as_str().expect("pinned filename")))?;
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    let mut runtime =
        QuickJsRuntimeFactory::from_component(&bytes, pin, ComponentBudget::default())?
            .runtime()?;
    let script = format!(
        "const out = await vault.agents.put({{id: {}, definition: {definition}}});\n\
         finish(JSON.stringify(out));",
        json!(id.to_hex())
    );
    let outcome = runtime.run_step(
        JsCodeModeStep {
            run_id: EntityId::from_bytes([0x5a; 16])?,
            seq: 0,
            script: &script,
            boundary: SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer),
            determinism: CodeRunDeterminism::new(1_700_000_000_000, [3; 32]),
        },
        host,
    )?;
    assert!(outcome.done, "{}", outcome.observation);
    let out: JsonValue = serde_json::from_str(&outcome.observation).expect("JSON reply");
    assert_eq!(out["id"], json!(id.to_hex()));
    Ok(out["disposition"].as_str().expect("disposition").to_owned())
}

/// Featureless tier: the same bridge parser the typed import feeds.
#[cfg(not(feature = "code-sandbox-wasmtime"))]
fn guest_put(host: &mut SdkHost<'_>, id: EntityId, definition: &JsonValue) -> Result<String> {
    let call = parse_agent_put_request(&id.to_hex(), definition.clone(), 1_700_000_000)?;
    match host
        .dispatch_self(SelfCall::AgentsPut(Box::new(call)))?
        .outcome
    {
        SelfDispatchOutcome::AgentDefinitionPut(result) => {
            assert_eq!(result.id, id);
            Ok(result.disposition.as_str().to_owned())
        }
        other => panic!("unexpected authoring outcome: {other:?}"),
    }
}

fn put_call(id: EntityId) -> Result<SelfCall> {
    Ok(SelfCall::AgentsPut(Box::new(parse_agent_put_request(
        &id.to_hex(),
        json!({"agentId":"fixture.helper","desc":"bounded helper","version":"1","scope":{"kind":"base"}}),
        1_700_000_000,
    )?)))
}

#[test]
fn guest_agents_put_reaches_the_leased_host_and_fences_stale_leases() -> Result<()> {
    let clock = crate::ports::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let author_id = crate::test_util::entity(0x91);
    let author = AgentDefinition::new(
        "fixture.author",
        "Authoring fixture",
        "1",
        None,
        vec![SkillDependency::new("fixture.known-skill")],
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(
            Value::from("definedVia"),
            Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    );
    vault.put_agent_definition(&author_id, &author, TimeRange { start: 1, end: 1 }, 1)?;
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(author_id),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })?
    else {
        panic!("author attempt dispatched")
    };
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".into(),
        now: 11,
    })?
    else {
        panic!("author attempt leased")
    };
    assert_eq!(leased.id, status.attempt.id);
    let actor = WriteActor::new(author_id, EdgeActorClass::Agent);

    let mut host = SdkHost(HostSelfDispatcher::for_leased_agent_attempt(
        &vault, actor, &leased,
    )?);
    let in_slice = crate::test_util::entity(0x92);
    assert_eq!(
        guest_put(
            &mut host,
            in_slice,
            &json!({"agentId":"fixture.narrow","desc":"narrow helper","version":"1",
                "scope":{"kind":"base"},"skills":["fixture.known-skill"]}),
        )?,
        "active"
    );
    let stored = vault.get_agent_definition(&in_slice)?.expect("active row");
    assert_eq!(stored.ceiling, author.ceiling);
    assert_eq!(stored.approval_status, author.approval_status);
    let wider = crate::test_util::entity(0x93);
    assert_eq!(
        guest_put(
            &mut host,
            wider,
            &json!({"agentId":"fixture.wide","desc":"wide helper","version":"1",
                "scope":{"kind":"base"},"ceiling":"auto","skills":["fixture.unknown-skill"]}),
        )?,
        "proposed"
    );
    let proposal = vault.get_agent_definition(&wider)?.expect("proposal row");
    assert_eq!(proposal.approval_status, ClaimApprovalStatus::Proposed);
    // Authoring launches nothing: the author's own attempt is the only row.
    assert_eq!(queue.list()?.len(), 1);

    // The lease times out and the same worker name reclaims the same try at a
    // new generation. The old dispatcher cannot author on the new lease.
    queue.cleanup_leases(CleanupAttemptLeases {
        now: {
            clock.set(30);
            30
        },
        lease_timeout_secs: 1,
    })?;
    let ClaimOutcome::Claimed(relet) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".into(),
        now: {
            clock.set(31);
            31
        },
    })?
    else {
        panic!("author attempt re-leased")
    };
    assert_eq!(relet.id, leased.id);
    assert_ne!(relet.attempt_count, leased.attempt_count);
    let stale_put = crate::test_util::entity(0x94);
    assert!(host.0.dispatch(put_call(stale_put)?).is_err());
    assert!(vault.get_agent_definition(&stale_put)?.is_none());
    assert!(HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &leased).is_err());

    let current = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &relet)?;
    let fresh = crate::test_util::entity(0x95);
    assert!(matches!(
        current.dispatch(put_call(fresh)?)?,
        SelfDispatchOutcome::AgentDefinitionPut(result)
            if result.disposition == AgentDefinitionPutDisposition::Active
    ));

    // Terminalization fences the writer inside the definition's own write
    // transaction, not only at the dispatcher's earlier status read.
    assert!(matches!(
        queue.complete(CompleteAttempt {
            id: relet.id,
            lease_owner: "worker-a".into(),
            attempt_count: relet.attempt_count,
            now: 32,
        })?,
        CompleteOutcome::Completed(_)
    ));
    let after_close = crate::test_util::entity(0x96);
    assert!(current.dispatch(put_call(after_close)?).is_err());
    let (_, definition) = match put_call(after_close)? {
        SelfCall::AgentsPut(call) => (call.id, call.definition),
        _ => unreachable!("authoring call"),
    };
    assert!(
        vault
            .put_agent_definition_for_author_with_scope(
                &author_id,
                &after_close,
                &definition,
                false,
                Some(&AgentAuthorLease::from_leased(&relet)?),
                TimeRange { start: 33, end: 33 },
                33,
            )
            .is_err()
    );
    assert!(vault.get_agent_definition(&after_close)?.is_none());
    Ok(())
}
