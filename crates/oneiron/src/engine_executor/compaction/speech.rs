//! The speech words a compaction reads off a run's recorded bridge calls.

/// The text one speech call dispatched: a hook's rewrite where one rewrote
/// it, else the guest's own request.
pub(in crate::engine_executor) fn speech_call_text(
    call: &crate::code_run::CodeRunBridgeCall,
) -> Option<&str> {
    let rmpv::Value::Map(entries) = call.rewritten_request.as_ref().unwrap_or(&call.request) else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("text"))
        .and_then(|(_, value)| value.as_str())
}
