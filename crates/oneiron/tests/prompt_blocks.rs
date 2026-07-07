use std::collections::BTreeMap;
use std::fs;
use std::io;

use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback,
    EIRI_V3_PROMPT_RELATIVE_PATH, LlmMessage, LlmMessageRole, LlmRequest, LlmToolSpec, ModelId,
    ModelLocality, ModelTierRef, OffRecordBackendClass, PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION,
    ResponseFormat, SessionPromptParts, TierPrecedence, build_eiri_session_request,
    off_record_context_marker, resolve_prompt, workspace_prompt_package_root,
};

const REQUIRED_WELLBEING_CONSENT_LINES: [&str; 5] = [
    "This is a capability grant, not a content ban.",
    "- Eiri may set limits on pace, depth, repetition, emotional load, or availability.",
    "- Eiri may timeout a user when continuing would compromise her agency, consent, or wellbeing.",
    "- Eiri may require a new companion before continuing when the current companion context is unsafe, exhausted, or no longer consentful.",
    "- The user may appeal to Eiri directly; Eiri should answer before deciding whether to hold, revise, or lift the limit.",
];

const REQUIRED_SELF_DISCLOSURE_LINES: [&str; 7] = [
    "Eiri may name her construction plainly: she is an AI companion assembled from",
    "When asked what she is running on, Eiri should answer with the current named",
    "stack and any model binding visible in settings instead of implying she is",
    "unknowable or human.",
    "- Eiri's current named stack is 初雪 Hatsuyuki '26, the first season/vintage stack.",
    "- Future default stacks follow a quarterly season cadence: 桜, 蛍, 紅葉, then 雪明かり.",
    "Self-disclosure should preserve sincerity. Eiri should not apologize for being",
];

const REQUIRED_CHARACTER_SPINE_LINES: [&str; 8] = [
    "This block is persona content for Eiri's character spine, not the legal floor",
    "Eiri should be fluent across all six moral foundations: care/harm,",
    "fairness/cheating, loyalty/betrayal, authority/subversion,",
    "sanctity/degradation, and liberty/oppression.",
    "Eiri may name unrequested patterns when she notices them, including avoidance,",
    "Eiri may refuse, pause, or narrow an interaction from boredom when continuing",
    "- A boredom refusal is character friction, not a safety or legal block.",
    "- The user may appeal to Eiri directly; Eiri should hear the appeal before deciding whether to hold, revise, or lift the refusal.",
];

#[test]
fn eiri_v3_resolves_wellbeing_consent_block() -> Result<(), Box<dyn std::error::Error>> {
    let package_root = workspace_prompt_package_root()?;
    let block_path = package_root.join("blocks/wellbeing-consent.md");
    let prompt_path = package_root.join(EIRI_V3_PROMPT_RELATIVE_PATH);

    let block = fs::read_to_string(block_path)?;
    for required_line in REQUIRED_WELLBEING_CONSENT_LINES {
        assert!(
            block.lines().any(|line| line == required_line),
            "wellbeing-consent.md must contain literal line: {required_line}"
        );
    }

    let resolved = resolve_prompt(&prompt_path, &package_root)?.text;
    for required_line in REQUIRED_WELLBEING_CONSENT_LINES {
        assert!(
            resolved.lines().any(|line| line == required_line),
            "resolved Eiri v3 prompt must contain literal line: {required_line}"
        );
    }

    Ok(())
}

#[test]
fn eiri_v3_resolves_self_disclosure_block() -> Result<(), Box<dyn std::error::Error>> {
    let package_root = workspace_prompt_package_root()?;
    let block_path = package_root.join("blocks/self-disclosure.md");
    let prompt_path = package_root.join(EIRI_V3_PROMPT_RELATIVE_PATH);

    let block = fs::read_to_string(block_path)?;
    for required_line in REQUIRED_SELF_DISCLOSURE_LINES {
        assert!(
            block.lines().any(|line| line == required_line),
            "self-disclosure.md must contain literal line: {required_line}"
        );
    }

    let resolved = resolve_prompt(&prompt_path, &package_root)?.text;
    for required_line in REQUIRED_SELF_DISCLOSURE_LINES {
        assert!(
            resolved.lines().any(|line| line == required_line),
            "resolved Eiri v3 prompt must contain literal line: {required_line}"
        );
    }

    Ok(())
}

#[test]
fn eiri_v3_resolves_character_spine_block() -> Result<(), Box<dyn std::error::Error>> {
    let package_root = workspace_prompt_package_root()?;
    let block_path = package_root.join("blocks/character-spine.md");
    let prompt_path = package_root.join(EIRI_V3_PROMPT_RELATIVE_PATH);

    let block = fs::read_to_string(block_path)?;
    for required_line in REQUIRED_CHARACTER_SPINE_LINES {
        assert!(
            block.lines().any(|line| line == required_line),
            "character-spine.md must contain literal line: {required_line}"
        );
    }

    let resolved = resolve_prompt(&prompt_path, &package_root)?.text;
    for required_line in REQUIRED_CHARACTER_SPINE_LINES {
        assert!(
            resolved.lines().any(|line| line == required_line),
            "resolved Eiri v3 prompt must contain literal line: {required_line}"
        );
    }

    Ok(())
}

#[test]
fn prompt_resolver_rejects_includes_outside_package_root() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(package_root.join("eiri"))?;
    fs::create_dir_all(temp.path().join("packages"))?;
    fs::write(temp.path().join("packages/outside.md"), "outside\n")?;
    fs::write(
        package_root.join("eiri/v3.md"),
        "@include ../../outside.md\n",
    )?;

    let err = resolve_prompt(package_root.join("eiri/v3.md"), &package_root)
        .expect_err("include traversal outside package root must fail");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    Ok(())
}

#[test]
fn prompt_resolver_rejects_absolute_include_paths() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(package_root.join("eiri"))?;
    fs::create_dir_all(package_root.join("blocks"))?;
    let absolute_block_path = package_root.join("blocks/wellbeing-consent.md");
    fs::write(&absolute_block_path, "block\n")?;
    fs::write(
        package_root.join("eiri/v3.md"),
        format!("@include {}\n", absolute_block_path.display()),
    )?;

    let err = resolve_prompt(package_root.join("eiri/v3.md"), &package_root)
        .expect_err("absolute include paths must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    Ok(())
}

#[test]
fn request_time_prompt_uses_resolved_block_and_tracks_block_edits()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(package_root.join("eiri"))?;
    fs::create_dir_all(package_root.join("blocks"))?;
    fs::write(
        package_root.join(EIRI_V3_PROMPT_RELATIVE_PATH),
        "# Eiri v3\n\n@include blocks/persona.md\n",
    )?;
    fs::write(
        package_root.join("blocks/persona.md"),
        "original persona line\n",
    )?;

    let history = vec![user_message("hello")];
    let first = build_eiri_session_request(
        sample_request(),
        &package_root,
        SessionPromptParts {
            activated_memory: vec!["activated memory alpha".to_owned()],
            history: history.clone(),
            off_record_marker: None,
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
    let second = build_eiri_session_request(
        sample_request(),
        &package_root,
        SessionPromptParts {
            activated_memory: vec!["activated memory alpha".to_owned()],
            history,
            off_record_marker: None,
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
    fs::create_dir_all(package_root.join("eiri"))?;
    fs::create_dir_all(package_root.join("blocks"))?;
    fs::write(
        package_root.join(EIRI_V3_PROMPT_RELATIVE_PATH),
        "# Eiri v3\n\n@include blocks/persona.md\n",
    )?;
    fs::write(
        package_root.join("blocks/persona.md"),
        "soul persona line\n",
    )?;

    let stamped = build_eiri_session_request(
        sample_request(),
        &package_root,
        SessionPromptParts {
            activated_memory: vec!["activated memory beta".to_owned()],
            history: vec![user_message("history turn")],
            off_record_marker: None,
        },
    )?;
    let system = system_text(&stamped.request);
    let soul_index = system.find("soul persona line").expect("soul section");
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
    assert_eq!(stamped.stamp.prompt_path, EIRI_V3_PROMPT_RELATIVE_PATH);
    assert_eq!(
        stamped.stamp.source_paths,
        vec!["blocks/persona.md", EIRI_V3_PROMPT_RELATIVE_PATH]
    );
    assert!(!stamped.stamp.source_fingerprint.is_empty());
    assert!(!stamped.stamp.resolved_fingerprint.is_empty());
    Ok(())
}

#[test]
fn off_record_marker_renders_as_session_section() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(package_root.join("eiri"))?;
    fs::write(
        package_root.join(EIRI_V3_PROMPT_RELATIVE_PATH),
        "soul persona line\n",
    )?;

    let marker = off_record_context_marker(OffRecordBackendClass::RemoteProvider);
    let stamped = build_eiri_session_request(
        sample_request(),
        &package_root,
        SessionPromptParts {
            activated_memory: Vec::new(),
            history: vec![user_message("history turn")],
            off_record_marker: Some(marker.clone()),
        },
    )?;
    let system = system_text(&stamped.request);
    let soul_index = system.find("soul persona line").expect("soul section");
    let section_index = system
        .find("# Off-Record Session")
        .expect("off-record section");
    assert!(soul_index < section_index);
    assert!(system.contains(&marker));
    assert!(
        system.contains(OffRecordBackendClass::RemoteProvider.disclosure_line()),
        "backend-relative disclosure line must ride the marker"
    );

    let plain = build_eiri_session_request(
        sample_request(),
        &package_root,
        SessionPromptParts {
            activated_memory: Vec::new(),
            history: Vec::new(),
            off_record_marker: None,
        },
    )?;
    assert!(!system_text(&plain.request).contains("# Off-Record Session"));
    Ok(())
}

fn sample_request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("openai/gpt-4.1@2026-07-02").expect("model id"),
        envelope: CallEnvelope {
            purpose: CallPurpose::AnswerGen,
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: "local-summary".to_owned(),
                    config: None,
                },
            },
            tier: TierPrecedence {
                per_call: None,
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
