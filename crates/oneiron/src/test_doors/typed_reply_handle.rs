//! Doors for `tests/typed_reply_handle.rs` (census L8-13): a Redact post-hook
//! binder with a fake hook runtime, and a stored wait-set feedback probe
//! running the host's real pre-record spill. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use std::sync::Arc;

use crate::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord, ExecutorStorage, GatedActorWrite,
    ProgramStepFeedback, ProgramStepIdentity, SelfCall, SelfDispatchOutcome, TaskWaitFinding,
    TaskWaitSetCall, TaskWaitSetResult, TypeDiagnostics, code_run_replay_abi_layout_checks,
    decode_code_run_replay_record, encode_code_run_replay_record,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::runtime_hooks::{HookBodyRun, HookBodyRuntime, HookRunContext};
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::{
    HookAuthor, HookOutcomeKind, HookPhase, HookRenderClass, HookSelector, PackHookBinding,
    PackSource,
};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::{EdgeActorClass, WriteActor};

/// A hook runtime answering every body with a Redact of fixed paths. It
/// reads nothing and runs no sandbox.
pub struct RedactRuntime {
    paths: Vec<String>,
}

impl HookBodyRuntime for RedactRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> Result<HookBodyRun> {
        let outcome_json = serde_json::to_string(&serde_json::json!({
            "kind": "redact",
            "paths": self.paths,
        }))
        .map_err(|error| {
            Error::InvalidConfig(format!("redact outcome does not encode: {error}"))
        })?;
        Ok(HookBodyRun {
            outcome_json,
            fuel_used: Some(0),
            host_calls: 1,
        })
    }
}

/// Binds one post hook on `verb` whose body answers a Redact, as an owner's
/// pack bind writes it: its pack source is staged first, so the body's bytes
/// read back. Answers the binding's id.
///
/// # Errors
///
/// The owner's proof no longer valid, the pack source's, or the write's
/// refusal.
pub fn bind_redact_post_hook(
    vault: &Vault,
    owner: EntityId,
    proof: &AuthenticatedOwner,
    verb: &str,
) -> Result<EntityId> {
    let body_bytes = b"return { kind: \"redact\", paths: [\"/output/title\"] };\n";
    let pack_md = "---\nname: test.typed-reply\ndescription: Redact test pack for typed reply handles\nversion: 1.0.0\nkind: capability\nhooks: [\"redact-title\"]\n---\nTest pack body.\n"
        .to_owned();
    let hook_md = format!(
        "---\nname: redact-title\nversion: 1.0.0\nverbs: [\"{verb}\"]\nphase: post\npriority: 0\nbudget_ms: 200\nblocking: false\noutcomes: [\"redact\"]\n---\nHides the title for the redaction test.\n"
    );
    let source = PackSource::from_files(vec![
        HubFile::new("PACK.md", pack_md.into_bytes()),
        HubFile::new("hooks/redact-title/HOOK.md", hook_md.into_bytes()),
        HubFile::new("hooks/redact-title/body.js", body_bytes.to_vec()),
    ])?;
    let at = 1_719_000_001;
    let source_id = vault.stage_pack_source(&source, TimeRange { start: at, end: at }, at)?;
    let body_hash = *blake3::hash(body_bytes).as_bytes();
    let binding = PackHookBinding {
        // HOOK_BINDING_VERSION; the chain reads only the pack, the hook and
        // the author.
        version: 2,
        code: EntityId::now(),
        owner,
        source: source_id,
        pack: "test.typed-reply".to_owned(),
        hook: "redact-title".to_owned(),
        hook_version: "1.0.0".to_owned(),
        body_hash: blake3::Hash::from(body_hash).to_hex().to_string(),
        selector: HookSelector {
            verbs: vec![verb.to_owned()],
            actors: Vec::new(),
            scope: None,
            phase: HookPhase::Post,
            priority: 0,
            budget_ms: 200,
            blocking: false,
            outcomes: vec![HookOutcomeKind::Redact],
            served: Vec::new(),
            render_class: HookRenderClass::default(),
        },
        enabled: true,
        author: HookAuthor::Owner,
    };
    let id = vault.bind_hook_row_for_test(proof, &binding, body_hash)?;
    vault.verb_hook_bindings_changed();
    Ok(id)
}

/// Hands `vault`'s verb hooks the Redact runtime redacting `paths`. The
/// runtime is per vault: each test vault installs its own.
///
/// # Errors
///
/// Another sandbox already installed on the vault.
pub fn install_redact_runtime(vault: &Vault, paths: Vec<String>) -> Result<()> {
    vault
        .install_hook_runtime(Arc::new(RedactRuntime { paths }))
        .map_err(Error::InvalidConfig)
}

/// What the stored wait-set feedback probe found: the inline wait set's
/// encoded size, the spilled stored form's size and record round trip, and
/// the stored findings body's read-back.
pub struct StoredFeedbackProbe {
    /// The MessagePack bytes of the wait set's inline outcome.
    pub inline_len: usize,
    /// The MessagePack bytes of the spilled stored-reply outcome.
    pub stored_outcome_len: usize,
    /// Whether the record carrying the stored outcome encoded: its bridge
    /// row validates, so the new source kind decodes.
    pub record_encode_ok: bool,
    /// The record's bytes when it encoded, else zero.
    pub record_len: usize,
    /// The decoded outcome's source kind, empty when the record did not encode.
    pub source_kind: String,
    /// How many feedback items the decoded `program_steps` entry holds.
    pub program_steps_len: usize,
    /// The stored findings body's bytes.
    pub body_len: usize,
    /// Whether the body read back parses to the stored findings.
    pub body_matches_findings: bool,
    /// Whether the body carries a `program_steps` member.
    pub body_has_program_steps: bool,
}

/// Runs the host's pre-record spill on a wait set whose findings total
/// `findings_len` bytes with one type-feedback item, then probes the stored
/// wait-set feedback form: the spilled outcome inline and as the stored
/// reply the spill writes (a card with the feedback typed beside it).
///
/// # Errors
///
/// The row's, the spill's, the body's, or the store's.
pub fn probe_stored_wait_set_feedback(
    vault: &Vault,
    run_id: &EntityId,
    findings_len: usize,
) -> Result<StoredFeedbackProbe> {
    let task = EntityId::now();
    let step = ProgramStepIdentity {
        run: run_id.to_hex(),
        program_seq: 0,
        invocation: 0,
    };
    let feedback = ProgramStepFeedback {
        check_ref: step.check_ref(),
        step,
        preparation_note: None,
        type_diagnostics: TypeDiagnostics::Unavailable {
            reason: crate::code_run::TYPE_CHECK_OFF.to_owned(),
            detail: None,
        },
    };
    let finding = TaskWaitFinding {
        task,
        finding: format!("finding:{}", task.to_hex()),
        bytes: findings_len as u64,
        reason: Some("f".repeat(findings_len)),
    };
    let result = TaskWaitSetResult {
        ready: vec![finding],
        partial: Vec::new(),
        failed: Vec::new(),
        pending: Vec::new(),
        done: true,
        reason: Some("all".to_owned()),
        until: 0,
        program_steps: vec![feedback],
    };
    let call = TaskWaitSetCall {
        tasks: vec![task.to_hex()],
        all: Some(true),
        n_of: None,
        until: None,
        step_key: "probe".to_owned(),
        request: None,
        agents: None,
    };
    let inline_row = CodeRunBridgeCall::record(
        0,
        &SelfCall::TasksWaitSet(call.clone()),
        &SelfDispatchOutcome::TaskWaitSet(result.clone()),
        1_719_000_001_000,
        1_719_000_001_000,
    )?;
    let inline_len = rmpv_len(&inline_row.outcome)?;
    let gated = GatedActorWrite::new(
        vault,
        WriteActor::new(*run_id, EdgeActorClass::Agent),
        "spill-probe",
    )?;
    let storage = ExecutorStorage::Canonical(vault);
    let (spilled, output) = crate::engine_executor::spill_before_record(
        &gated,
        &storage,
        *run_id,
        0,
        SelfDispatchOutcome::TaskWaitSet(result.clone()),
    )?;
    let mut row = CodeRunBridgeCall::record(
        0,
        &SelfCall::TasksWaitSet(call),
        &spilled,
        1_719_000_001_000,
        1_719_000_001_000,
    )?;
    let stored_outcome_len = rmpv_len(&row.outcome)?;
    let mut record = CodeRunReplayRecord::new(
        *run_id,
        CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]),
    );
    record.bridge_calls = vec![row];
    record.abi_layout_checks = code_run_replay_abi_layout_checks();
    let encoded = encode_code_run_replay_record(&record).ok();
    let record_encode_ok = encoded.is_some();
    let record_len = encoded.as_ref().map_or(0, Vec::len);
    let (source_kind, program_steps_len) = match encoded {
        Some(ref bytes) => {
            let back = decode_code_run_replay_record(bytes)?;
            let outcome = &back
                .bridge_calls
                .first()
                .ok_or(Error::CorruptedIndex("probe record lost its row"))?
                .outcome;
            (
                stored_source_kind(outcome),
                stored_program_steps_len(outcome)?,
            )
        }
        None => (String::new(), 0),
    };
    let mut findings = result.clone();
    findings.program_steps = Vec::new();
    let expected = serde_json::to_value(&findings)
        .map_err(|error| Error::InvalidConfig(format!("probe findings do not encode: {error}")))?;
    let Some(output) = output else {
        return Ok(StoredFeedbackProbe {
            inline_len,
            stored_outcome_len,
            record_encode_ok,
            record_len,
            source_kind,
            program_steps_len,
            body_len: 0,
            body_matches_findings: false,
            body_has_program_steps: true,
        });
    };
    let body_bytes = storage
        .get_code_run_raw_output(&output)?
        .ok_or(Error::CorruptedIndex("probe findings body missing"))?;
    let body_text = String::from_utf8(body_bytes)
        .map_err(|_| Error::InvalidClaimBody("probe findings body is not utf8"))?;
    let body_len = body_text.len();
    let body_value: serde_json::Value = serde_json::from_str(&body_text)
        .map_err(|_| Error::InvalidClaimBody("probe findings body is not json"))?;
    Ok(StoredFeedbackProbe {
        inline_len,
        stored_outcome_len,
        record_encode_ok,
        record_len,
        source_kind,
        program_steps_len,
        body_len,
        body_matches_findings: body_value.get("output") == Some(&expected),
        body_has_program_steps: body_text.contains("program_steps"),
    })
}

/// The MessagePack bytes of `value`.
fn rmpv_len(value: &rmpv::Value) -> Result<usize> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvalidConfig("probe outcome does not encode".to_owned()))?;
    Ok(bytes.len())
}

/// A stored outcome's source kind, empty for any other map.
fn stored_source_kind(outcome: &rmpv::Value) -> String {
    let rmpv::Value::Map(entries) = outcome else {
        return String::new();
    };
    match entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some("source_kind"))
            .then_some(value)
            .and_then(rmpv::Value::as_str)
    }) {
        Some(kind) => kind.to_owned(),
        None => String::new(),
    }
}

/// How many feedback items a stored outcome's `program_steps` entry holds.
fn stored_program_steps_len(outcome: &rmpv::Value) -> Result<usize> {
    let rmpv::Value::Map(entries) = outcome else {
        return Ok(0);
    };
    let Some(text) = entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some("program_steps"))
            .then_some(value)
            .and_then(rmpv::Value::as_str)
    }) else {
        return Ok(0);
    };
    let steps: Vec<ProgramStepFeedback> = serde_json::from_str(text)
        .map_err(|_| Error::InvalidClaimBody("probe program steps do not decode"))?;
    Ok(steps.len())
}
