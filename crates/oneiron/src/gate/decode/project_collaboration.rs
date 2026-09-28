//! Exact project coordination policy row decoder. No free-form rule text is executed.
use super::decode_map_util::{MapValue, single_map_value};
use crate::gate::resolution::{
    LeaderChatDefault, ProjectCollaborationPolicy, ProjectWidenAskFallback,
};
use rmpv::Value;

pub(super) fn parse(value: &Value) -> Option<ProjectCollaborationPolicy> {
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() != 2 {
        return None;
    }
    let MapValue::Present(Value::Map(chat)) = single_map_value(entries, "leader_chat") else {
        return None;
    };
    let MapValue::Present(Value::Map(ask)) = single_map_value(entries, "cross_project_ask") else {
        return None;
    };
    if chat.len() != 3 || ask.len() != 1 {
        return None;
    }
    let MapValue::Present(default) = single_map_value(chat, "default") else {
        return None;
    };
    let leader_chat_default = match default.as_str()? {
        "allow" => LeaderChatDefault::Allow,
        "deny" => LeaderChatDefault::Deny,
        _ => return None,
    };
    let MapValue::Present(precedence) = single_map_value(chat, "precedence") else {
        return None;
    };
    let MapValue::Present(cap) = single_map_value(chat, "holder_override_cap") else {
        return None;
    };
    // Nested narrowing and vault cap are the contract's only supported
    // authority laws. An unknown alternative is malformed, not a fallback.
    if precedence.as_str()? != "nested_narrowing" || cap.as_str()? != "vault" {
        return None;
    }
    let MapValue::Present(fallback) = single_map_value(ask, "fallback") else {
        return None;
    };
    let widen_ask_fallback = match fallback.as_str()? {
        "hold" => ProjectWidenAskFallback::Hold,
        "ask_me" => ProjectWidenAskFallback::AskMe,
        _ => return None,
    };
    Some(ProjectCollaborationPolicy {
        leader_chat_default,
        widen_ask_fallback,
    })
}
