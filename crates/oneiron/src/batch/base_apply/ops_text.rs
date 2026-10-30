//! Base-apply Text arm: trusted text-index updates.

use super::indexes::apply_text_index_update;
use super::*;
use zeroize::Zeroizing;

pub(super) fn apply_text_arm(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    state: &mut BatchApplyState,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    id: EntityId,
    fields: Vec<(String, String)>,
    text_index_trusted: bool,
) -> Result<()> {
    let fields = Zeroizing::new(fields);
    let analyzed = state
        .pre_analyzed_text
        .get_mut(&id)
        .and_then(VecDeque::pop_front)
        .flatten();
    apply_text_index_update(
        store,
        wtxn,
        (analyzer, analyzed.as_ref()),
        &id,
        &fields,
        text_index_trusted,
        &mut state.text_manifest_checked,
    )?;
    Ok(())
}
