//! The ask rows of the engine's `[limits]` (ARCH-0044 C5, OF-520). An ask or
//! an answer of any count or size is served whole: past a row it asks, through
//! the vault's [`LimitWatch`], whether everything is okay. Only the physical
//! width of an LMDB key still refuses.
//!
//! An ask or answer is measured once where it is kept: the raw-put guard
//! every local admission and every replicated group or answer passes through.
//! The read-only `can(ask)` preflight, which resolves the same work, measures
//! it too, and a wait identity is measured at the door that binds it.

use super::{TaskAskSpec, TaskAskWord};
use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::memory::{MemoryError, MemoryResult};

/// A count or byte length as a row measures it.
fn measured(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The question class keys `requested` and `effective` name, each held to the
/// width a band key leaves it in this vault's LMDB environment.
pub(super) fn check_ask_keys(
    store: &crate::store::Store,
    requested: &TaskAskSpec,
    effective: &TaskAskSpec,
) -> MemoryResult<()> {
    let max_key_bytes = store.env.max_key_size();
    for spec in [requested, effective] {
        for key in spec
            .what
            .class_key
            .iter()
            .chain(spec.class.iter().map(|class| &class.key))
        {
            super::ask_band::check_class_key(max_key_bytes, key)?;
        }
    }
    Ok(())
}

/// [`check_ask_keys`], then the ask's rows: its options, its longest option
/// text, its context references and its MessagePack bytes as its caller sent
/// them, the `recipients` it resolved to, and the reminders it carries once
/// its class's are inherited. A crossing asks; the ask is served either way.
pub(super) fn check_ask_work(
    store: &crate::store::Store,
    requested: &TaskAskSpec,
    effective: &TaskAskSpec,
    recipients: usize,
) -> MemoryResult<()> {
    check_ask_keys(store, requested, effective)?;
    let watch = &store.limit_watch;
    let what = &requested.what;
    watch.measure(EngineLimit::AskOptions, measured(what.options.len()));
    if let Some(longest) = what.options.values().map(String::len).max() {
        watch.measure(EngineLimit::AskOptionTextBytes, measured(longest));
    }
    watch.measure(
        EngineLimit::AskContextRefs,
        measured(what.context_refs.len()),
    );
    watch.measure(EngineLimit::AskRecipients, measured(recipients));
    let bytes =
        rmp_serde::to_vec_named(requested).map_err(|_| MemoryError::bad_request("ask encoding"))?;
    watch.measure(EngineLimit::AskSpecMsgpackBytes, measured(bytes.len()));
    watch.measure(
        EngineLimit::AskReminders,
        measured(effective.remind.as_deref().map_or(0, <[u64]>::len)),
    );
    Ok(())
}

/// The provenance references `word` cites, every one of them kept.
pub(super) fn measure_answer_provenance(watch: &LimitWatch, word: &TaskAskWord) {
    watch.measure(
        EngineLimit::AnswerProvenanceRefs,
        measured(word.provenance_refs.len()),
    );
}
