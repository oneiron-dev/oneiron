//! Text-index clear, PPR cleanup, and postings compaction.

use crate::Vault;
use crate::error::Result;
use crate::ppr;
use crate::vault::write_text_index_manifest;

pub(super) struct ClearTextIndexCounts {
    pub(super) postings: u64,
    pub(super) meta: u64,
    pub(super) forward: u64,
    pub(super) doc_field_lengths: u64,
    pub(super) field_stats: u64,
}

pub(super) fn clear_text_index(vault: &Vault) -> Result<ClearTextIndexCounts> {
    let mut wtxn = vault.store.env.write_txn()?;

    let postings = vault.store.text_postings.len(&wtxn)?;
    vault.store.text_postings.clear(&mut wtxn)?;

    let meta = vault.store.text_meta.len(&wtxn)?;
    vault.store.text_meta.clear(&mut wtxn)?;

    let forward = vault.store.text_forward.len(&wtxn)?;
    vault.store.text_forward.clear(&mut wtxn)?;

    let doc_field_lengths = vault.store.text_doc_field_lengths.len(&wtxn)?;
    vault.store.text_doc_field_lengths.clear(&mut wtxn)?;

    let field_stats = vault.store.text_bm25_field_stats.len(&wtxn)?;
    vault.store.text_bm25_field_stats.clear(&mut wtxn)?;

    write_text_index_manifest(&vault.store, &mut wtxn, &vault.analyzer)?;

    wtxn.commit()?;

    // The on-disk manifest now matches the in-memory analyzer; subsequent
    // search_text calls within the same Vault instance can proceed. See
    // `Vault::text_index_trusted`.
    vault
        .text_index_trusted
        .store(true, std::sync::atomic::Ordering::Release);

    Ok(ClearTextIndexCounts {
        postings,
        meta,
        forward,
        doc_field_lengths,
        field_stats,
    })
}

pub(super) fn cleanup_ppr_cache(vault: &Vault, max_age_secs: u64) -> Result<(u64, u64)> {
    let mut wtxn = vault.store.env.write_txn()?;
    let now = crate::unix_seconds_now();
    let counts = ppr::cleanup_ppr_cache(&vault.store, &mut wtxn, max_age_secs, now)?;
    wtxn.commit()?;
    Ok(counts)
}

pub(super) fn compact_postings(vault: &Vault) -> Result<u64> {
    let mut wtxn = vault.store.env.write_txn()?;
    // `text_postings` is DUP_SORT (storage ABI v4): `iter` yields one
    // (term, item) pair per duplicate. Remove only the degenerate empty
    // items — a term key whose sole duplicate is empty disappears with
    // it, while valid sibling duplicates are preserved.
    let mut empty_item_terms = Vec::new();
    for entry in vault.store.text_postings.iter(&wtxn)? {
        let (term, posting) = entry?;
        if posting.is_empty() {
            empty_item_terms.push(term.to_vec());
        }
    }

    for term in &empty_item_terms {
        vault
            .store
            .text_postings
            .delete_one_duplicate(&mut wtxn, term, &[])?;
    }

    wtxn.commit()?;
    Ok(empty_item_terms.len() as u64)
}
