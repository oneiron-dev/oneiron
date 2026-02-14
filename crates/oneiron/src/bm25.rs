use std::collections::HashMap;
use std::str;

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{EntityId, ScoredEntity};

const POSTING_ENTRY_LEN: usize = 20;
const DOC_META_LEN: usize = 8;
const TOTAL_DOCS_LEN: usize = 4;
const TOTAL_LENGTH_LEN: usize = 8;

const K1: f64 = 1.2;
const B: f64 = 0.75;

const TOTAL_DOCS_KEY: [u8; 16] = [0x00; 16];
const TOTAL_LENGTH_KEY: [u8; 16] = [0xFF; 16];

pub(crate) fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|token| !token.is_empty())
        .collect()
}

pub(crate) fn index_text(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    fields: &[(String, String)],
) -> Result<()> {
    if store.text_forward.get(wtxn, id.as_bytes())?.is_some() {
        deindex_text(store, wtxn, id)?;
    }

    let mut terms = Vec::new();
    for (_, value) in fields {
        terms.extend(tokenize(value));
    }

    let doc_len = u32::try_from(terms.len()).map_err(|_| Error::InvalidKey)?;
    let field_count = u32::try_from(fields.len()).map_err(|_| Error::InvalidKey)?;

    let mut term_freq = HashMap::<String, u32>::new();
    for term in terms {
        let tf = term_freq.entry(term).or_insert(0);
        *tf = tf.checked_add(1).ok_or(Error::InvalidKey)?;
    }

    let mut unique_terms: Vec<String> = term_freq.keys().cloned().collect();
    unique_terms.sort();

    for term in &unique_terms {
        let tf = *term_freq.get(term).ok_or(Error::InvalidKey)?;
        let existing = store.text_postings.get(wtxn, term.as_bytes())?;
        let mut posting = existing.map_or_else(Vec::new, |bytes| bytes.to_vec());
        if !posting.len().is_multiple_of(POSTING_ENTRY_LEN) {
            return Err(Error::InvalidKey);
        }

        posting.extend_from_slice(id.as_bytes());
        posting.extend_from_slice(&tf.to_le_bytes());
        store.text_postings.put(wtxn, term.as_bytes(), &posting)?;
    }

    let mut doc_meta = [0_u8; DOC_META_LEN];
    doc_meta[..4].copy_from_slice(&doc_len.to_le_bytes());
    doc_meta[4..].copy_from_slice(&field_count.to_le_bytes());
    store.text_meta.put(wtxn, id.as_bytes(), &doc_meta)?;

    let mut forward = Vec::new();
    for (idx, term) in unique_terms.iter().enumerate() {
        if idx > 0 {
            forward.push(0_u8);
        }
        forward.extend_from_slice(term.as_bytes());
    }
    store.text_forward.put(wtxn, id.as_bytes(), &forward)?;

    let total_docs = match store.text_meta.get(wtxn, &TOTAL_DOCS_KEY)? {
        Some(raw) => decode_u32(raw)?,
        None => 0,
    };
    let total_length = match store.text_meta.get(wtxn, &TOTAL_LENGTH_KEY)? {
        Some(raw) => decode_u64(raw)?,
        None => 0,
    };

    let total_docs = total_docs.checked_add(1).ok_or(Error::InvalidKey)?;
    let total_length = total_length
        .checked_add(u64::from(doc_len))
        .ok_or(Error::InvalidKey)?;

    store
        .text_meta
        .put(wtxn, &TOTAL_DOCS_KEY, &total_docs.to_le_bytes())?;
    store
        .text_meta
        .put(wtxn, &TOTAL_LENGTH_KEY, &total_length.to_le_bytes())?;

    Ok(())
}

pub(crate) fn deindex_text(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    let Some(forward_raw) = store.text_forward.get(wtxn, id.as_bytes())? else {
        return Ok(());
    };

    let terms = decode_forward_terms(forward_raw)?;

    let doc_meta = store
        .text_meta
        .get(wtxn, id.as_bytes())?
        .ok_or(Error::InvalidKey)?;
    let (doc_len, _) = decode_doc_meta(doc_meta)?;

    for term in terms {
        let posting = store
            .text_postings
            .get(wtxn, term.as_bytes())?
            .ok_or(Error::InvalidKey)?;
        if !posting.len().is_multiple_of(POSTING_ENTRY_LEN) {
            return Err(Error::InvalidKey);
        }

        let mut retained = Vec::with_capacity(posting.len());
        let mut removed = false;
        for chunk in posting.chunks_exact(POSTING_ENTRY_LEN) {
            if &chunk[..16] == id.as_bytes() {
                removed = true;
                continue;
            }
            retained.extend_from_slice(chunk);
        }

        if !removed {
            return Err(Error::InvalidKey);
        }

        if retained.is_empty() {
            store.text_postings.delete(wtxn, term.as_bytes())?;
        } else {
            store.text_postings.put(wtxn, term.as_bytes(), &retained)?;
        }
    }

    let total_docs = match store.text_meta.get(wtxn, &TOTAL_DOCS_KEY)? {
        Some(raw) => decode_u32(raw)?,
        None => 0,
    };
    let total_length = match store.text_meta.get(wtxn, &TOTAL_LENGTH_KEY)? {
        Some(raw) => decode_u64(raw)?,
        None => 0,
    };

    let total_docs = total_docs.checked_sub(1).ok_or(Error::InvalidKey)?;
    let total_length = total_length
        .checked_sub(u64::from(doc_len))
        .ok_or(Error::InvalidKey)?;

    store
        .text_meta
        .put(wtxn, &TOTAL_DOCS_KEY, &total_docs.to_le_bytes())?;
    store
        .text_meta
        .put(wtxn, &TOTAL_LENGTH_KEY, &total_length.to_le_bytes())?;

    store.text_meta.delete(wtxn, id.as_bytes())?;
    store.text_forward.delete(wtxn, id.as_bytes())?;

    Ok(())
}

pub(crate) fn search_text(
    store: &Store,
    rtxn: &RoTxn<'_>,
    query: &str,
    limit: usize,
) -> Result<Vec<ScoredEntity>> {
    if limit == 0 {
        return Ok(Vec::new());
    }

    let mut tokens = tokenize(query);
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    tokens.sort();
    tokens.dedup();

    let total_docs = match store.text_meta.get(rtxn, &TOTAL_DOCS_KEY)? {
        Some(raw) => decode_u32(raw)?,
        None => 0,
    };
    if total_docs == 0 {
        return Ok(Vec::new());
    }

    let total_length = match store.text_meta.get(rtxn, &TOTAL_LENGTH_KEY)? {
        Some(raw) => decode_u64(raw)?,
        None => 0,
    };
    let avgdl = total_length as f64 / total_docs as f64;

    let mut scores = HashMap::<EntityId, f64>::new();

    for token in tokens {
        let Some(posting) = store.text_postings.get(rtxn, token.as_bytes())? else {
            continue;
        };
        if !posting.len().is_multiple_of(POSTING_ENTRY_LEN) {
            return Err(Error::InvalidKey);
        }

        let df = posting.len() / POSTING_ENTRY_LEN;
        if df == 0 {
            continue;
        }
        let n = total_docs as f64;
        let df = df as f64;
        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();

        for chunk in posting.chunks_exact(POSTING_ENTRY_LEN) {
            let id = EntityId::from_bytes(chunk[..16].try_into().map_err(|_| Error::InvalidKey)?);
            let tf = u32::from_le_bytes(chunk[16..20].try_into().map_err(|_| Error::InvalidKey)?);
            if tf == 0 {
                return Err(Error::InvalidKey);
            }

            let doc_meta = store
                .text_meta
                .get(rtxn, id.as_bytes())?
                .ok_or(Error::InvalidKey)?;
            let (dl, _) = decode_doc_meta(doc_meta)?;

            let tf = tf as f64;
            let dl = dl as f64;
            let norm = if avgdl > 0.0 { dl / avgdl } else { 0.0 };
            let denom = tf + K1 * (1.0 - B + B * norm);
            if denom == 0.0 {
                return Err(Error::InvalidKey);
            }
            let score = idf * (tf * (K1 + 1.0)) / denom;
            *scores.entry(id).or_insert(0.0) += score;
        }
    }

    let mut ranked: Vec<(EntityId, f64)> = scores.into_iter().collect();
    ranked.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
    });
    ranked.truncate(limit);

    Ok(ranked
        .into_iter()
        .map(|(id, score)| ScoredEntity {
            id,
            score: score as f32,
        })
        .collect())
}

fn decode_doc_meta(raw: &[u8]) -> Result<(u32, u32)> {
    if raw.len() != DOC_META_LEN {
        return Err(Error::InvalidKey);
    }

    let doc_len = u32::from_le_bytes(raw[..4].try_into().map_err(|_| Error::InvalidKey)?);
    let field_count = u32::from_le_bytes(raw[4..8].try_into().map_err(|_| Error::InvalidKey)?);
    Ok((doc_len, field_count))
}

fn decode_u32(raw: &[u8]) -> Result<u32> {
    if raw.len() != TOTAL_DOCS_LEN {
        return Err(Error::InvalidKey);
    }
    Ok(u32::from_le_bytes(
        raw.try_into().map_err(|_| Error::InvalidKey)?,
    ))
}

fn decode_u64(raw: &[u8]) -> Result<u64> {
    if raw.len() != TOTAL_LENGTH_LEN {
        return Err(Error::InvalidKey);
    }
    Ok(u64::from_le_bytes(
        raw.try_into().map_err(|_| Error::InvalidKey)?,
    ))
}

fn decode_forward_terms(raw: &[u8]) -> Result<Vec<String>> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    raw.split(|b| *b == 0)
        .map(|chunk| {
            if chunk.is_empty() {
                return Err(Error::InvalidKey);
            }
            str::from_utf8(chunk)
                .map(str::to_owned)
                .map_err(|_| Error::InvalidKey)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HnswConfig, TimeRange, VaultConfig};
    use crate::{Error, Vault};

    fn test_config() -> VaultConfig {
        VaultConfig {
            map_size: 16 * 1024 * 1024,
            dimensions: 4,
            embedding_model: None,
            max_readers: 16,
            hnsw: HnswConfig {
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
        }
    }

    fn test_time_range(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    fn contains_id(results: &[ScoredEntity], id: &EntityId) -> bool {
        results.iter().any(|result| result.id == *id)
    }

    fn put_text_doc(vault: &Vault, id: &EntityId, text: &str) -> Result<()> {
        vault
            .batch()
            .put(id, 0, test_time_range(1, 1), 2, b"text-doc")
            .text(id, &[("body", text)])
            .commit()
    }

    fn repeated(term: &str, count: usize) -> String {
        std::iter::repeat_n(term, count)
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn tokenizer_basic() {
        assert_eq!(tokenize("Hello World"), vec!["hello", "world"]);
        assert_eq!(tokenize("Rust, BM25! 2026"), vec!["rust", "bm25", "2026"]);
        assert_eq!(
            tokenize("Caf\u{e9} \u{41f}\u{440}\u{438}\u{432}\u{435}\u{442}"),
            vec!["caf\u{e9}", "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}"]
        );
    }

    #[test]
    fn index_and_search_basic() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id1 = EntityId::now();
        let id2 = EntityId::now();
        let id3 = EntityId::now();

        put_text_doc(&vault, &id1, "rust language and systems")?;
        put_text_doc(&vault, &id2, "bm25 ranking in search")?;
        put_text_doc(&vault, &id3, "graph traversal only")?;

        let results = vault.search_text("rust", 10)?;
        assert!(contains_id(&results, &id1));
        assert!(!contains_id(&results, &id2));
        assert!(!contains_id(&results, &id3));

        Ok(())
    }

    #[test]
    fn search_ranking_100_docs() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let mut batch = vault.batch();
        let best_idx = 42;
        let mut best_id = None;

        for idx in 0..100 {
            let id = EntityId::now();
            if idx == best_idx {
                best_id = Some(id);
            }
            let tf = if idx == best_idx { 20 } else { 1 };
            let text = repeated("apple", tf);
            batch = batch
                .put(
                    &id,
                    0,
                    test_time_range(idx as u64, idx as u64),
                    idx as u64,
                    b"doc",
                )
                .text(&id, &[("body", &text)]);
        }
        batch.commit()?;

        let best_id = best_id.ok_or(Error::InvalidKey)?;
        let results = vault.search_text("apple", 10)?;
        assert!(!results.is_empty());
        assert_eq!(results[0].id, best_id);

        Ok(())
    }

    #[test]
    fn deindex_removes_from_search() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "deindex me please")?;
        let before = vault.search_text("deindex", 10)?;
        assert!(contains_id(&before, &id));

        assert!(vault.delete_entity(&id)?);
        let after = vault.search_text("deindex", 10)?;
        assert!(!contains_id(&after, &id));

        Ok(())
    }

    #[test]
    fn multi_term_query() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id_both = EntityId::now();
        let id_alpha = EntityId::now();
        let id_beta = EntityId::now();

        put_text_doc(&vault, &id_both, "alpha beta")?;
        put_text_doc(&vault, &id_alpha, "alpha")?;
        put_text_doc(&vault, &id_beta, "beta")?;

        let results = vault.search_text("alpha beta", 10)?;
        assert_eq!(results[0].id, id_both);

        Ok(())
    }

    #[test]
    fn empty_query_returns_empty() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "hello world")?;

        let results = vault.search_text("", 10)?;
        assert!(results.is_empty());

        Ok(())
    }

    #[test]
    fn empty_document() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        vault
            .batch()
            .put(&id, 0, test_time_range(1, 1), 2, b"empty")
            .text(&id, &[("title", ""), ("body", "")])
            .commit()?;

        let results = vault.search_text("anything", 10)?;
        assert!(!contains_id(&results, &id));

        Ok(())
    }

    #[test]
    fn single_term_document() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "solitary")?;
        let results = vault.search_text("solitary", 10)?;
        assert!(contains_id(&results, &id));

        Ok(())
    }

    #[test]
    fn collection_stats_accuracy() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id1 = EntityId::now();
        let id2 = EntityId::now();
        let id3 = EntityId::now();

        put_text_doc(&vault, &id1, "alpha beta")?;
        put_text_doc(&vault, &id2, "gamma")?;
        put_text_doc(&vault, &id3, "")?;

        let rtxn = vault.store.env.read_txn()?;
        let total_docs = vault
            .store
            .text_meta
            .get(&rtxn, &TOTAL_DOCS_KEY)?
            .ok_or(Error::InvalidKey)?;
        let total_length = vault
            .store
            .text_meta
            .get(&rtxn, &TOTAL_LENGTH_KEY)?
            .ok_or(Error::InvalidKey)?;

        assert_eq!(decode_u32(total_docs)?, 3);
        assert_eq!(decode_u64(total_length)?, 3);

        Ok(())
    }

    #[test]
    fn reindex_overwrites_cleanly() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "foo bar")?;
        vault.batch().text(&id, &[("body", "baz qux")]).commit()?;

        let foo_results = vault.search_text("foo", 10)?;
        let baz_results = vault.search_text("baz", 10)?;

        assert!(!contains_id(&foo_results, &id));
        assert!(contains_id(&baz_results, &id));

        Ok(())
    }
}
