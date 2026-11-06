//! The speech words a compaction reads off a run's recorded bridge calls.

/// The text one speech call dispatched: a hook's rewrite where one rewrote
/// it, else the guest's own request. A call whose request words an erase
/// took has none (FIX 6534): its erased form is never read as a request.
pub(in crate::engine_executor) fn speech_call_text(
    call: &crate::code_run::CodeRunBridgeCall,
) -> Option<&str> {
    let rmpv::Value::Map(entries) = call.dispatched_request()? else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("text"))
        .and_then(|(_, value)| value.as_str())
}
