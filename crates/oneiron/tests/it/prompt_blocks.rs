use std::collections::BTreeMap;
use std::fs;
use std::io;

use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, LlmMessage,
    LlmMessageRole, LlmRequest, LlmToolSpec, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, off_record::OffRecordBackendClass, off_record::OffRecordMode,
    prompt::PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION, prompt::SessionPromptParts,
    prompt::build_session_request, prompt::resolve_prompt,
};

const HOST_OFF_RECORD_SESSION_MARKER_LINE: &str = "This session is OFF-RECORD: nothing said here is written to memory, and the transcript is deleted when the session closes. Outbound actions and commitments are disabled while off-record; taking an action requires exiting off-record mode. The user may explicitly promote a single turn into memory.";
const HOST_LOCAL_DISCLOSURE_LINE: &str = "Evaporation is real on this backend: inference is local, nothing leaves this device, and nothing is retained after close.";
const HOST_REMOTE_PROVIDER_DISCLOSURE_LINE: &str = "This engine persists nothing after close, but inference transits a cloud provider; the provider's own retention policy applies to what crossed its API.";

fn host_off_record_context_marker(
    mode: OffRecordMode,
    backend: OffRecordBackendClass,
) -> Option<String> {
    if mode == OffRecordMode::OnRecord {
        return None;
    }
    let disclosure_line = match backend {
        OffRecordBackendClass::Local => HOST_LOCAL_DISCLOSURE_LINE,
        OffRecordBackendClass::RemoteProvider => HOST_REMOTE_PROVIDER_DISCLOSURE_LINE,
    };
    Some(format!(
        "{HOST_OFF_RECORD_SESSION_MARKER_LINE}\n{disclosure_line}"
    ))
}

const HOST_PROMPT_PATH: &str = "session.md";

#[test]
fn host_prompt_resolves_includes_from_an_arbitrary_package_root()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("prompts");
    fs::create_dir_all(package_root.join("blocks"))?;
    fs::write(
        package_root.join(HOST_PROMPT_PATH),
        "# Host prompt\n@include blocks/policy.md\n",
    )?;
    fs::write(
        package_root.join("blocks/policy.md"),
        "host-provided policy\n",
    )?;
    let resolved = resolve_prompt(package_root.join(HOST_PROMPT_PATH), &package_root)?;
    assert_eq!(resolved.text, "# Host prompt\nhost-provided policy\n");
    assert_eq!(resolved.stamp.prompt_path, HOST_PROMPT_PATH);
    assert_eq!(
        resolved.stamp.source_paths,
        vec!["blocks/policy.md", HOST_PROMPT_PATH]
    );
    Ok(())
}

#[test]
fn prompt_resolver_rejects_includes_outside_package_root() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(&package_root)?;
    fs::create_dir_all(temp.path().join("packages"))?;
    fs::write(temp.path().join("packages/outside.md"), "outside\n")?;
    fs::write(
        package_root.join(HOST_PROMPT_PATH),
        "@include ../outside.md\n",
    )?;

    let err = resolve_prompt(package_root.join(HOST_PROMPT_PATH), &package_root)
        .expect_err("include traversal outside package root must fail");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    Ok(())
}

#[test]
fn prompt_resolver_rejects_absolute_include_paths() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(&package_root)?;
    fs::create_dir_all(package_root.join("blocks"))?;
    let absolute_block_path = package_root.join("blocks/wellbeing-consent.md");
    fs::write(&absolute_block_path, "block\n")?;
    fs::write(
        package_root.join(HOST_PROMPT_PATH),
        format!("@include {}\n", absolute_block_path.display()),
    )?;

    let err = resolve_prompt(package_root.join(HOST_PROMPT_PATH), &package_root)
        .expect_err("absolute include paths must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    Ok(())
}

#[test]
fn request_time_prompt_uses_resolved_block_and_tracks_block_edits()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(&package_root)?;
    fs::create_dir_all(package_root.join("blocks"))?;
    fs::write(
        package_root.join(HOST_PROMPT_PATH),
        "# Host prompt\n\n@include blocks/persona.md\n",
    )?;
    fs::write(
        package_root.join("blocks/persona.md"),
        "original persona line\n",
    )?;

    let history = vec![user_message("hello")];
    let first = build_session_request(
        sample_request(),
        package_root.join(HOST_PROMPT_PATH),
        &package_root,
        SessionPromptParts {
            activated_memory: vec!["activated memory alpha".to_owned()],
            history: history.clone(),
            host_sections: Vec::new(),
        },
    )?;
    let first_system = system_text(&first.request);
    assert!(first_system.contains("original persona line"));
    assert!(first_system.contains("activated memory alpha"));
    assert_eq!(first.request.messages[1], history[0]);

    fs::write(
        package_root.join("blocks/persona.md"),
        "updated persona line\n",
    )?;
    let second = build_session_request(
        sample_request(),
        package_root.join(HOST_PROMPT_PATH),
        &package_root,
        SessionPromptParts {
            activated_memory: vec!["activated memory alpha".to_owned()],
            history,
            host_sections: Vec::new(),
        },
    )?;
    let second_system = system_text(&second.request);
    assert!(second_system.contains("updated persona line"));
    assert!(!second_system.contains("original persona line"));
    assert_ne!(
        first.stamp.source_fingerprint,
        second.stamp.source_fingerprint
    );
    assert_ne!(first.request.messages[0], second.request.messages[0]);
    Ok(())
}

#[test]
fn session_prompt_order_is_soul_then_activated_memory_then_history_and_stamp()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(&package_root)?;
    fs::create_dir_all(package_root.join("blocks"))?;
    fs::write(
        package_root.join(HOST_PROMPT_PATH),
        "# Host prompt\n\n@include blocks/persona.md\n",
    )?;
    fs::write(
        package_root.join("blocks/persona.md"),
        "host session text\n",
    )?;

    let stamped = build_session_request(
        sample_request(),
        package_root.join(HOST_PROMPT_PATH),
        &package_root,
        SessionPromptParts {
            activated_memory: vec!["activated memory beta".to_owned()],
            history: vec![user_message("history turn")],
            host_sections: Vec::new(),
        },
    )?;
    let system = system_text(&stamped.request);
    let soul_index = system.find("host session text").expect("soul section");
    let memory_index = system
        .find("activated memory beta")
        .expect("memory section");
    assert!(soul_index < memory_index);
    assert_eq!(stamped.request.messages[0].role, LlmMessageRole::System);
    assert_eq!(stamped.request.messages[1].role, LlmMessageRole::User);
    assert_eq!(
        stamped.stamp.schema_version,
        PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION
    );
    assert_eq!(stamped.stamp.prompt_path, HOST_PROMPT_PATH);
    assert_eq!(
        stamped.stamp.source_paths,
        vec!["blocks/persona.md", HOST_PROMPT_PATH]
    );
    assert!(!stamped.stamp.source_fingerprint.is_empty());
    assert!(!stamped.stamp.resolved_fingerprint.is_empty());
    Ok(())
}

#[test]
fn off_record_marker_renders_as_session_section() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(&package_root)?;
    fs::write(package_root.join(HOST_PROMPT_PATH), "host session text\n")?;

    let marker = host_off_record_context_marker(
        OffRecordMode::OffRecord,
        OffRecordBackendClass::RemoteProvider,
    )
    .expect("off-record mode requires a host marker");
    let stamped = build_session_request(
        sample_request(),
        package_root.join(HOST_PROMPT_PATH),
        &package_root,
        SessionPromptParts {
            activated_memory: Vec::new(),
            history: vec![user_message("history turn")],
            host_sections: vec![format!("# Off-Record Session\n\n{marker}")],
        },
    )?;
    let system = system_text(&stamped.request);
    let soul_index = system.find("host session text").expect("soul section");
    let section_index = system
        .find("# Off-Record Session")
        .expect("off-record section");
    assert!(soul_index < section_index);
    assert!(system.contains(&marker));
    assert!(
        system.contains(HOST_REMOTE_PROVIDER_DISCLOSURE_LINE),
        "backend-relative disclosure line must ride the marker"
    );

    let plain = build_session_request(
        sample_request(),
        package_root.join(HOST_PROMPT_PATH),
        &package_root,
        SessionPromptParts {
            activated_memory: Vec::new(),
            history: Vec::new(),
            host_sections: host_off_record_context_marker(
                OffRecordMode::OnRecord,
                OffRecordBackendClass::RemoteProvider,
            )
            .into_iter()
            .collect(),
        },
    )?;
    assert!(!system_text(&plain.request).contains("# Off-Record Session"));
    Ok(())
}

fn sample_request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("openai/gpt-4.1@2026-07-02").expect("model id"),
        envelope: CallEnvelope {
            scope: oneiron::llm::Scope::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: "local-summary".to_owned(),
                    config: None,
                },
            },
            tier: TierPrecedence {
                per_seat: None,
                vault_policy: None,
                purpose_default: None,
                global_default: ModelTierRef("default".to_owned()),
            },
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![user_message("placeholder")],
        tools: Vec::<LlmToolSpec>::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

fn user_message(text: &str) -> LlmMessage {
    LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: text.to_owned(),
        }],
    }
}

fn system_text(request: &LlmRequest) -> &str {
    assert_eq!(request.messages[0].role, LlmMessageRole::System);
    match &request.messages[0].content[0] {
        ContentPart::Text { text } => text,
        _ => panic!("system prompt must be text"),
    }
}
