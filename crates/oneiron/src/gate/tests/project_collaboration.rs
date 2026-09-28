//! Manifest-resident project talk and widening defaults.
use super::*;
use crate::gate::{LeaderChatDefault, ProjectWidenAskFallback};

fn map_mut(value: &mut rmpv::Value) -> &mut Vec<(rmpv::Value, rmpv::Value)> {
    let rmpv::Value::Map(fields) = value else {
        panic!("fixture map")
    };
    fields
}

fn with_row(default: &str, fallback: &str) -> Vec<u8> {
    let mut manifest: rmpv::Value =
        rmp_serde::from_slice(&default_policy_manifest().unwrap()).unwrap();
    let fields = map_mut(&mut manifest);
    let row = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("project_collaboration"))
        .unwrap();
    row.1 = rmpv::Value::Map(vec![
        (
            "leader_chat".into(),
            rmpv::Value::Map(vec![
                ("default".into(), default.into()),
                ("precedence".into(), "nested_narrowing".into()),
                ("holder_override_cap".into(), "vault".into()),
            ]),
        ),
        (
            "cross_project_ask".into(),
            rmpv::Value::Map(vec![("fallback".into(), fallback.into())]),
        ),
    ]);
    rmp_serde::to_vec_named(&manifest).unwrap()
}

#[test]
fn shipped_row_decodes_and_owner_replacement_changes_the_fallback() -> Result<()> {
    let shipped = decode_policy_manifest(&default_policy_manifest().unwrap()).unwrap();
    let row = shipped.project_collaboration.unwrap();
    assert_eq!(row.leader_chat_default, LeaderChatDefault::Allow);
    assert_eq!(row.widen_ask_fallback, ProjectWidenAskFallback::Hold);
    let (_dir, vault) = temp_vault();
    assert!(resolve(&vault)?.project_collaboration().is_none());
    put_policy_manifest_bytes(&vault, test_id(0xE9), &with_row("allow", "hold"))?;
    let prior_frontier = resolve(&vault)?.read_frontier_hash()?;
    put_policy_manifest_bytes(&vault, test_id(0xE9), &with_row("allow", "ask_me"))?;
    assert_ne!(prior_frontier, resolve(&vault)?.read_frontier_hash()?);
    assert_eq!(
        resolve(&vault)?
            .project_collaboration()
            .unwrap()
            .widen_ask_fallback,
        ProjectWidenAskFallback::AskMe
    );
    Ok(())
}

#[test]
fn restrictive_manifest_fold_wins_and_malformed_precedence_fails_closed() -> Result<()> {
    let (_dir, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xE9), &with_row("allow", "ask_me"))?;
    put_policy_manifest_bytes(&vault, test_id(0xEA), &with_row("deny", "hold"))?;
    let resolved = resolve(&vault)?.project_collaboration().unwrap();
    assert_eq!(resolved.leader_chat_default, LeaderChatDefault::Deny);
    assert_eq!(resolved.widen_ask_fallback, ProjectWidenAskFallback::Hold);
    for invalid in ["closest_override", "last_writer_wins"] {
        let mut value: rmpv::Value = rmp_serde::from_slice(&with_row("allow", "hold")).unwrap();
        let fields = map_mut(&mut value);
        let (_, collaboration) = fields
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("project_collaboration"))
            .unwrap();
        let (_, chat) = map_mut(collaboration)
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("leader_chat"))
            .unwrap();
        map_mut(chat)
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("precedence"))
            .unwrap()
            .1 = invalid.into();
        assert!(decode_policy_manifest(&rmp_serde::to_vec_named(&value).unwrap()).is_none());
    }
    let mut dup: rmpv::Value = rmp_serde::from_slice(&with_row("allow", "hold")).unwrap();
    let (_, collaboration) = map_mut(&mut dup)
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("project_collaboration"))
        .unwrap();
    let (_, chat) = map_mut(collaboration)
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("leader_chat"))
        .unwrap();
    map_mut(chat).push(("default".into(), "deny".into()));
    let malformed = rmp_serde::to_vec_named(&dup).unwrap();
    assert!(decode_policy_manifest(&malformed).is_none());
    put_policy_manifest_bytes(&vault, test_id(0xEB), &malformed)?;
    assert!(resolve(&vault)?.project_collaboration().is_none());
    Ok(())
}
