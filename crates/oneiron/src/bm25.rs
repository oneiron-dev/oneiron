use std::borrow::Cow;
use std::collections::HashMap;
use std::str;

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{short_id_prefix, EntityId, ScoredEntity};

const POSTING_ENTRY_LEN: usize = 20;
const DOC_META_LEN: usize = 8;

const K1: f64 = 1.2;
const B: f64 = 0.75;

const TOTAL_DOCS_KEY: [u8; 16] = [0x00; 16];
const TOTAL_LENGTH_KEY: [u8; 16] = [0xFF; 16];

fn tokenize(text: &str) -> Tokenizer<'_> {
    Tokenizer {
        text,
        offset: 0,
        cjk_state: None,
    }
}

pub(crate) fn index_text(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    fields: &[(String, String)],
) -> Result<()> {
    validate_text_doc_id(id)?;

    if store.text_forward.get(wtxn, id.as_bytes())?.is_some() {
        deindex_text(store, wtxn, id)?;
    }

    let mut doc_len = 0_u32;
    let field_count =
        u32::try_from(fields.len()).map_err(|_| Error::ArithmeticOverflow("bm25 field count"))?;
    let mut term_freq = HashMap::<String, u32>::new();
    for (_, value) in fields {
        for term in tokenize(value) {
            doc_len = doc_len
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("bm25 doc length"))?;
            if let Some(count) = term_freq.get_mut(term.as_ref()) {
                *count += 1;
            } else {
                term_freq.insert(term.into_owned(), 1);
            }
        }
    }

    if term_freq.is_empty() {
        return Ok(());
    }

    let mut unique_terms: Vec<String> = term_freq.keys().cloned().collect();
    unique_terms.sort();

    for term in &unique_terms {
        let tf = term_freq[term];
        let mut posting = read_posting(store, wtxn, term)?;
        posting.extend_from_slice(id.as_bytes());
        posting.extend_from_slice(&tf.to_le_bytes());
        store.text_postings.put(wtxn, term.as_bytes(), &posting)?;
    }

    let mut doc_meta = [0_u8; DOC_META_LEN];
    doc_meta[..4].copy_from_slice(&doc_len.to_le_bytes());
    doc_meta[4..].copy_from_slice(&field_count.to_le_bytes());
    store.text_meta.put(wtxn, id.as_bytes(), &doc_meta)?;

    let forward: Vec<u8> = unique_terms.join("\0").into_bytes();
    store.text_forward.put(wtxn, id.as_bytes(), &forward)?;

    let (total_docs, total_length) = read_collection_stats(store, wtxn)?;
    let total_docs = total_docs
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("bm25 total_docs"))?;
    let total_length = total_length
        .checked_add(u64::from(doc_len))
        .ok_or(Error::ArithmeticOverflow("bm25 total_length"))?;
    write_collection_stats(store, wtxn, total_docs, total_length)?;

    Ok(())
}

pub(crate) fn deindex_text(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    validate_text_doc_id(id)?;

    let Some(forward_raw) = store.text_forward.get(wtxn, id.as_bytes())? else {
        if store.text_meta.get(wtxn, id.as_bytes())?.is_some() {
            return Err(corrupted("missing forward index for indexed document"));
        }
        return Ok(());
    };

    let terms = decode_forward_terms(forward_raw)?;

    let doc_meta = store
        .text_meta
        .get(wtxn, id.as_bytes())?
        .ok_or_else(|| corrupted("missing text metadata for deindex"))?;
    let (doc_len, _) = decode_doc_meta(doc_meta)?;
    if terms.is_empty() && doc_len > 0 {
        return Err(corrupted(
            "empty forward index cannot describe non-empty document",
        ));
    }

    for term in terms {
        let Some(posting) = store.text_postings.get(wtxn, term.as_bytes())? else {
            continue;
        };
        validate_posting_alignment(posting)?;

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
            continue;
        }

        if retained.is_empty() {
            store.text_postings.delete(wtxn, term.as_bytes())?;
        } else {
            store.text_postings.put(wtxn, term.as_bytes(), &retained)?;
        }
    }

    let (total_docs, total_length) = read_collection_stats(store, wtxn)?;
    let total_docs = total_docs
        .checked_sub(1)
        .ok_or_else(|| corrupted("total_docs underflow during deindex"))?;
    let total_length = total_length
        .checked_sub(u64::from(doc_len))
        .ok_or_else(|| corrupted("total_length underflow during deindex"))?;
    write_collection_stats(store, wtxn, total_docs, total_length)?;

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

    let mut tokens: Vec<Cow<'_, str>> = tokenize(query).collect();
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    tokens.sort();
    tokens.dedup();

    let (total_docs, total_length) = read_collection_stats(store, rtxn)?;
    if total_docs == 0 {
        return Ok(Vec::new());
    }

    let n = f64::from(total_docs);
    // BM25 scoring already uses f64; precision beyond 2^53 tokens is not
    // material for the local corpora this engine targets.
    let avgdl = total_length as f64 / n;

    let mut scores = HashMap::<EntityId, f64>::new();
    let mut doc_len_cache = HashMap::<EntityId, u32>::new();

    for token in tokens {
        let Some(posting) = store.text_postings.get(rtxn, token.as_ref().as_bytes())? else {
            continue;
        };
        validate_posting_alignment(posting)?;

        if scores.is_empty() {
            scores = HashMap::with_capacity(posting.len() / POSTING_ENTRY_LEN);
        }

        let df = posting.len() / POSTING_ENTRY_LEN;
        if df == 0 {
            continue;
        }
        let df = df as f64;
        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();

        for chunk in posting.chunks_exact(POSTING_ENTRY_LEN) {
            let (id, tf) = decode_posting_entry(chunk)?;
            if tf == 0 {
                return Err(corrupted("posting entry has zero term frequency"));
            }

            let dl = if let Some(&cached) = doc_len_cache.get(&id) {
                cached
            } else {
                let doc_meta = store
                    .text_meta
                    .get(rtxn, id.as_bytes())?
                    .ok_or_else(|| corrupted("missing text metadata during scoring"))?;
                let (dl, _) = decode_doc_meta(doc_meta)?;
                doc_len_cache.insert(id, dl);
                dl
            };

            let tf = f64::from(tf);
            let dl = f64::from(dl);
            let norm = if avgdl > 0.0 { dl / avgdl } else { 0.0 };
            let denom = tf + K1 * (1.0 - B + B * norm);
            if denom == 0.0 {
                return Err(corrupted("bm25 denominator is zero"));
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

fn validate_posting_alignment(posting: &[u8]) -> Result<()> {
    if !posting.len().is_multiple_of(POSTING_ENTRY_LEN) {
        return Err(corrupted("posting list has invalid byte length"));
    }
    Ok(())
}

fn decode_posting_entry(chunk: &[u8]) -> Result<(EntityId, u32)> {
    let id = EntityId::from_bytes(
        chunk[..16]
            .try_into()
            .map_err(|_| corrupted("posting entry is missing entity id bytes"))?,
    )
    .map_err(|_| corrupted("posting entry has invalid entity id"))?;
    let tf = u32::from_le_bytes(
        chunk[16..20]
            .try_into()
            .map_err(|_| corrupted("posting entry is missing tf bytes"))?,
    );
    Ok((id, tf))
}

fn read_posting(store: &Store, txn: &RoTxn<'_>, term: &str) -> Result<Vec<u8>> {
    let existing = store.text_postings.get(txn, term.as_bytes())?;
    let posting = existing.map_or_else(
        || Vec::with_capacity(POSTING_ENTRY_LEN),
        |bytes| {
            let mut posting = Vec::with_capacity(bytes.len() + POSTING_ENTRY_LEN);
            posting.extend_from_slice(bytes);
            posting
        },
    );
    validate_posting_alignment(&posting)?;
    Ok(posting)
}

fn read_collection_stats(store: &Store, txn: &RoTxn<'_>) -> Result<(u32, u64)> {
    let total_docs = match store.text_meta.get(txn, &TOTAL_DOCS_KEY)? {
        Some(raw) => u32::from_le_bytes(
            raw.try_into()
                .map_err(|_| corrupted("total_docs sentinel has invalid length"))?,
        ),
        None => 0,
    };
    let total_length = match store.text_meta.get(txn, &TOTAL_LENGTH_KEY)? {
        Some(raw) => u64::from_le_bytes(
            raw.try_into()
                .map_err(|_| corrupted("total_length sentinel has invalid length"))?,
        ),
        None => 0,
    };
    Ok((total_docs, total_length))
}

fn write_collection_stats(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    total_docs: u32,
    total_length: u64,
) -> Result<()> {
    store
        .text_meta
        .put(wtxn, &TOTAL_DOCS_KEY, &total_docs.to_le_bytes())?;
    store
        .text_meta
        .put(wtxn, &TOTAL_LENGTH_KEY, &total_length.to_le_bytes())?;
    Ok(())
}

fn corrupted(message: &'static str) -> Error {
    Error::CorruptedIndex(message)
}

fn validate_text_doc_id(id: &EntityId) -> Result<()> {
    let bytes = id.as_bytes();
    if bytes == &TOTAL_DOCS_KEY
        || bytes == &TOTAL_LENGTH_KEY
        || (bytes[1..].iter().all(|&b| b == 0xFF) && short_id_prefix(bytes[0]).is_ok())
    {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

struct Tokenizer<'a> {
    text: &'a str,
    offset: usize,
    cjk_state: Option<CjkState<'a>>,
}

struct CjkState<'a> {
    run: &'a str,
    boundaries: Vec<usize>,
    next_index: usize,
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Cow<'a, str>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(state) = &mut self.cjk_state {
            if let Some(token) = state.next_token() {
                return Some(Cow::Borrowed(token));
            }
            self.cjk_state = None;
        }

        while self.offset < self.text.len() {
            let tail = &self.text[self.offset..];
            let ch = tail.chars().next()?;
            self.offset += ch.len_utf8();

            if !ch.is_alphanumeric() {
                continue;
            }

            let start = self.offset - ch.len_utf8();
            let cjk = is_cjk(ch);
            while self.offset < self.text.len() {
                let next = self.text[self.offset..]
                    .chars()
                    .next()
                    .expect("offset stays on a valid char boundary");
                if !next.is_alphanumeric() || is_cjk(next) != cjk {
                    break;
                }
                self.offset += next.len_utf8();
            }

            let run = &self.text[start..self.offset];
            if cjk {
                let mut state = CjkState::new(run);
                let token = state.next_token().expect("cjk runs are non-empty");
                self.cjk_state = Some(state);
                return Some(Cow::Borrowed(token));
            }

            return Some(normalize_non_cjk(run));
        }

        None
    }
}

impl<'a> CjkState<'a> {
    fn new(run: &'a str) -> Self {
        let mut boundaries = run.char_indices().map(|(idx, _)| idx).collect::<Vec<_>>();
        boundaries.push(run.len());
        Self {
            run,
            boundaries,
            next_index: 0,
        }
    }

    fn next_token(&mut self) -> Option<&'a str> {
        let char_count = self.boundaries.len().checked_sub(1)?;
        if char_count == 0 {
            return None;
        }

        if char_count == 1 {
            if self.next_index == 0 {
                self.next_index = 1;
                return Some(self.run);
            }
            return None;
        }

        if self.next_index < char_count {
            let start = self.boundaries[self.next_index];
            let end = self.boundaries[self.next_index + 1];
            self.next_index += 1;
            return Some(&self.run[start..end]);
        }

        let bigram_index = self.next_index - char_count;
        if bigram_index + 2 >= self.boundaries.len() {
            return None;
        }

        let start = self.boundaries[bigram_index];
        let end = self.boundaries[bigram_index + 2];
        self.next_index += 1;
        Some(&self.run[start..end])
    }
}

fn normalize_non_cjk<'a>(run: &'a str) -> Cow<'a, str> {
    if run.is_ascii() && !run.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Borrowed(run)
    } else {
        Cow::Owned(run.to_lowercase())
    }
}

fn is_cjk(ch: char) -> bool {
    matches!(
        ch as u32,
        0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0x20000..=0x2A6DF
            | 0xF900..=0xFAFF
            | 0x3040..=0x309F
            | 0x30A0..=0x30FF
            | 0xAC00..=0xD7AF
    )
}

fn decode_doc_meta(raw: &[u8]) -> Result<(u32, u32)> {
    if raw.len() != DOC_META_LEN {
        return Err(corrupted("document metadata has invalid byte length"));
    }
    let doc_len = u32::from_le_bytes(
        raw[..4]
            .try_into()
            .map_err(|_| corrupted("document metadata is missing doc_len bytes"))?,
    );
    let field_count = u32::from_le_bytes(
        raw[4..8]
            .try_into()
            .map_err(|_| corrupted("document metadata is missing field_count bytes"))?,
    );
    Ok((doc_len, field_count))
}

#[cfg(test)]
fn decode_u32(raw: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        raw.try_into()
            .map_err(|_| Error::CorruptedIndex("bm25 test decode"))?,
    ))
}

#[cfg(test)]
fn decode_u64(raw: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(
        raw.try_into()
            .map_err(|_| Error::CorruptedIndex("bm25 test decode"))?,
    ))
}

fn decode_forward_terms(raw: &[u8]) -> Result<Vec<String>> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    raw.split(|b| *b == 0)
        .map(|chunk| {
            if chunk.is_empty() {
                return Err(corrupted("forward index contains an empty term segment"));
            }
            str::from_utf8(chunk)
                .map(str::to_owned)
                .map_err(|_| corrupted("forward index contains non-utf8 term bytes"))
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

    fn collect_tokens(text: &str) -> Vec<String> {
        tokenize(text).map(Cow::into_owned).collect()
    }

    fn encoded_doc_meta(doc_len: u32, field_count: u32) -> [u8; DOC_META_LEN] {
        let mut raw = [0_u8; DOC_META_LEN];
        raw[..4].copy_from_slice(&doc_len.to_le_bytes());
        raw[4..].copy_from_slice(&field_count.to_le_bytes());
        raw
    }

    #[test]
    fn tokenizer_basic() {
        assert_eq!(collect_tokens("Hello World"), vec!["hello", "world"]);
        assert_eq!(
            collect_tokens("Rust, BM25! 2026"),
            vec!["rust", "bm25", "2026"]
        );
        assert_eq!(
            collect_tokens("Caf\u{e9} \u{41f}\u{440}\u{438}\u{432}\u{435}\u{442}"),
            vec!["caf\u{e9}", "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}"]
        );
    }

    #[test]
    fn tokenizer_cjk_bigrams() {
        assert_eq!(
            collect_tokens("東京塔"),
            vec!["東", "京", "塔", "東京", "京塔"]
        );
        assert_eq!(collect_tokens("東"), vec!["東"]);
        assert_eq!(
            collect_tokens("とう東京"),
            vec!["と", "う", "東", "京", "とう", "う東", "東京"]
        );
    }

    #[test]
    fn tokenizer_mixed_cjk_boundaries() {
        assert_eq!(collect_tokens("東京abc"), vec!["東", "京", "東京", "abc"]);
        assert_eq!(collect_tokens("abc東京"), vec!["abc", "東", "京", "東京"]);
        assert_eq!(
            collect_tokens("Rust東京2026"),
            vec!["rust", "東", "京", "東京", "2026"]
        );
    }

    #[test]
    fn tokenizer_extended_cjk_ranges() {
        assert_eq!(collect_tokens("㐀"), vec!["㐀"]);
        assert_eq!(collect_tokens("𠀀"), vec!["𠀀"]);
        assert_eq!(collect_tokens("神"), vec!["神"]);
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
    fn zero_limit_returns_empty() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "hello world")?;

        let results = vault.search_text("hello", 0)?;
        assert!(results.is_empty());

        Ok(())
    }

    #[test]
    fn empty_vault_query_returns_empty() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let results = vault.search_text("hello", 10)?;
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
    fn cjk_query_matches_bigrams() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "東京塔")?;
        let results = vault.search_text("東京", 10)?;
        assert!(contains_id(&results, &id));

        Ok(())
    }

    #[test]
    fn single_character_cjk_document_is_searchable() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "東")?;
        let results = vault.search_text("東", 10)?;
        assert!(contains_id(&results, &id));

        Ok(())
    }

    #[test]
    fn single_character_query_matches_inside_multi_char_cjk_run() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "東京塔")?;
        let results = vault.search_text("京", 10)?;
        assert!(contains_id(&results, &id));

        Ok(())
    }

    #[test]
    fn reserved_bm25_doc_ids_are_rejected() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let mut short_id_sentinel = [0xFF; 16];
        short_id_sentinel[0] = 1;

        for raw_id in [TOTAL_DOCS_KEY, TOTAL_LENGTH_KEY, short_id_sentinel] {
            let id = EntityId::from_bytes_unchecked(raw_id);
            let err = vault
                .batch()
                .text(&id, &[("body", "reserved")])
                .commit()
                .unwrap_err();
            assert!(matches!(err, Error::InvalidKey));
        }

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(read_collection_stats(&vault.store, &rtxn)?, (0, 0));

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

        assert_eq!(decode_u32(total_docs)?, 2);
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

    #[test]
    fn malformed_posting_returns_corrupted_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"bad", &[1, 2, 3])?;
        write_collection_stats(&vault.store, &mut wtxn, 1, 1)?;
        wtxn.commit()?;

        let err = vault.search_text("bad", 10).unwrap_err();
        assert!(matches!(err, Error::CorruptedIndex(_)));

        Ok(())
    }

    #[test]
    fn zero_tf_posting_returns_corrupted_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        let mut posting = Vec::new();
        posting.extend_from_slice(id.as_bytes());
        posting.extend_from_slice(&0_u32.to_le_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"alpha", &posting)?;
        vault
            .store
            .text_meta
            .put(&mut wtxn, id.as_bytes(), &encoded_doc_meta(1, 1))?;
        write_collection_stats(&vault.store, &mut wtxn, 1, 1)?;
        wtxn.commit()?;

        let err = vault.search_text("alpha", 10).unwrap_err();
        assert!(matches!(err, Error::CorruptedIndex(_)));

        Ok(())
    }

    #[test]
    fn missing_doc_meta_returns_corrupted_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        let mut posting = Vec::new();
        posting.extend_from_slice(id.as_bytes());
        posting.extend_from_slice(&1_u32.to_le_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"alpha", &posting)?;
        write_collection_stats(&vault.store, &mut wtxn, 1, 1)?;
        wtxn.commit()?;

        let err = vault.search_text("alpha", 10).unwrap_err();
        assert!(matches!(err, Error::CorruptedIndex(_)));

        Ok(())
    }

    #[test]
    fn malformed_doc_meta_returns_corrupted_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        let mut posting = Vec::new();
        posting.extend_from_slice(id.as_bytes());
        posting.extend_from_slice(&1_u32.to_le_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"alpha", &posting)?;
        vault
            .store
            .text_meta
            .put(&mut wtxn, id.as_bytes(), &[1, 2, 3])?;
        write_collection_stats(&vault.store, &mut wtxn, 1, 1)?;
        wtxn.commit()?;

        let err = vault.search_text("alpha", 10).unwrap_err();
        assert!(matches!(err, Error::CorruptedIndex(_)));

        Ok(())
    }

    #[test]
    fn malformed_forward_index_returns_corrupted_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_forward
            .put(&mut wtxn, id.as_bytes(), b"alpha\0\0beta")?;
        vault
            .store
            .text_meta
            .put(&mut wtxn, id.as_bytes(), &encoded_doc_meta(1, 1))?;
        write_collection_stats(&vault.store, &mut wtxn, 1, 1)?;

        let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
        assert!(matches!(err, Error::CorruptedIndex(_)));

        Ok(())
    }

    #[test]
    fn empty_forward_index_for_non_empty_doc_returns_corrupted_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_forward
            .put(&mut wtxn, id.as_bytes(), b"")?;
        vault
            .store
            .text_meta
            .put(&mut wtxn, id.as_bytes(), &encoded_doc_meta(1, 1))?;
        write_collection_stats(&vault.store, &mut wtxn, 1, 1)?;

        let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
        assert!(matches!(err, Error::CorruptedIndex(_)));

        Ok(())
    }

    #[test]
    fn missing_forward_index_for_indexed_doc_returns_corrupted_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_meta
            .put(&mut wtxn, id.as_bytes(), &encoded_doc_meta(1, 1))?;
        write_collection_stats(&vault.store, &mut wtxn, 1, 1)?;

        let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
        assert!(matches!(err, Error::CorruptedIndex(_)));

        Ok(())
    }

    #[test]
    fn deindex_skips_missing_posting_list() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_forward
            .put(&mut wtxn, id.as_bytes(), b"alpha")?;
        vault
            .store
            .text_meta
            .put(&mut wtxn, id.as_bytes(), &encoded_doc_meta(1, 1))?;
        write_collection_stats(&vault.store, &mut wtxn, 1, 1)?;

        deindex_text(&vault.store, &mut wtxn, &id)?;
        wtxn.commit()?;

        let rtxn = vault.store.env.read_txn()?;
        assert!(vault
            .store
            .text_forward
            .get(&rtxn, id.as_bytes())?
            .is_none());
        assert!(vault.store.text_meta.get(&rtxn, id.as_bytes())?.is_none());
        assert_eq!(read_collection_stats(&vault.store, &rtxn)?, (0, 0));

        Ok(())
    }

    #[test]
    fn deindex_skips_entity_missing_from_posting() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let other_id = EntityId::now();

        let mut posting = Vec::new();
        posting.extend_from_slice(other_id.as_bytes());
        posting.extend_from_slice(&1_u32.to_le_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"alpha", &posting)?;
        vault
            .store
            .text_forward
            .put(&mut wtxn, id.as_bytes(), b"alpha")?;
        vault
            .store
            .text_meta
            .put(&mut wtxn, id.as_bytes(), &encoded_doc_meta(1, 1))?;
        write_collection_stats(&vault.store, &mut wtxn, 1, 1)?;

        deindex_text(&vault.store, &mut wtxn, &id)?;
        wtxn.commit()?;

        let rtxn = vault.store.env.read_txn()?;
        assert!(vault
            .store
            .text_forward
            .get(&rtxn, id.as_bytes())?
            .is_none());
        assert!(vault.store.text_meta.get(&rtxn, id.as_bytes())?.is_none());
        assert_eq!(read_collection_stats(&vault.store, &rtxn)?, (0, 0));
        assert_eq!(
            vault.store.text_postings.get(&rtxn, b"alpha")?,
            Some(posting.as_slice())
        );

        Ok(())
    }
}
