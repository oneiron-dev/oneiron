//! What a live connector exchange presented, across its sends and its
//! resumes (fix list row 10550, the FIX 10550 resume scrub).
//!
//! A live exchange's worker keeps the value its send presented and clears
//! everything the connector says next of it. A restart loses that value, and
//! the resumed exchange presents its credential again: after a rotation that
//! is another value, while the connector may still echo the one it was
//! first sent. So the call's row keeps each presentation the exchange made,
//! value-free (the custody record and the rotation generation its door
//! released), and a resumed worker clears every earlier one through its
//! record's known-value history (#4461), which matches a superseded value
//! by its keyed fingerprints, without its bytes. A history that does not
//! cover an earlier presentation whole leaves the round uncertain rather
//! than resumed: nothing is cleared of the current value alone.

use std::collections::BTreeMap;
use std::ops::Range;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::known_value_index::KnownValues;

/// One credential presentation a live connector exchange made: the custody
/// record its door released and that record's rotation generation, and
/// whether the released bytes read the same trimmed. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentGeneration {
    /// The custody record presented.
    pub custody: EntityId,
    /// The record's rotation generation its door released.
    pub generation: u32,
    /// The released bytes read the same trimmed. The known-value history
    /// keys the stored bytes, so only then does it cover the trimmed copy a
    /// sender presents and a connector may echo.
    pub trimmed: bool,
}

impl SentGeneration {
    /// Whether `other` presented the same value: the same record at the
    /// same generation.
    #[must_use]
    pub fn same_value(&self, other: &Self) -> bool {
        self.custody == other.custody && self.generation == other.generation
    }
}

/// What a live connector exchange presented, as its call's row keeps it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SentGenerations {
    /// Not known: a row kept before presentations were, or a send whose
    /// door released a value without naming its record. Such an exchange
    /// is never resumed.
    #[default]
    Unknown,
    /// The exchange presented no credential.
    CredentialFree,
    /// Each distinct presentation it made, the first send's first.
    Presented(Vec<SentGeneration>),
}

impl SentGenerations {
    /// What one send presented: `None` when it presented nothing.
    #[must_use]
    pub fn of(sent: Option<SentGeneration>) -> Self {
        match sent {
            Some(sent) => Self::Presented(vec![sent]),
            None => Self::CredentialFree,
        }
    }

    /// These and `sent`, a resume's presentation, too. An unknown set stays
    /// unknown.
    #[must_use]
    pub fn with(self, sent: SentGeneration) -> Self {
        match self {
            Self::Unknown => Self::Unknown,
            Self::CredentialFree => Self::Presented(vec![sent]),
            Self::Presented(mut presented) => {
                if !presented.iter().any(|known| known.same_value(&sent)) {
                    presented.push(sent);
                }
                Self::Presented(presented)
            }
        }
    }
}

/// The earlier presentations of a resumed exchange, as their records'
/// known-value histories match them: each value, in any spelling the index
/// finds, becomes its record's handle text. It holds keyed fingerprints,
/// never a value, and lives no longer than the pass that clears with it.
pub struct ConnectorSentClearer {
    matchers: Vec<(KnownValues, String)>,
}

/// `data` with each of `spans` replaced by its text, or `None` when there
/// is none. Spans that overlap or touch are replaced as one, by the first
/// one's text, so no copy of a value is left cut by another's replacement:
/// a value that contains another, or that another contains, goes whole
/// (fix list row 10550).
#[must_use]
pub fn replace_spans(data: &[u8], mut spans: Vec<(Range<usize>, &str)>) -> Option<Vec<u8>> {
    if spans.is_empty() {
        return None;
    }
    spans.sort_by_key(|(span, _)| (span.start, std::cmp::Reverse(span.end)));
    let mut out = Vec::with_capacity(data.len());
    let mut at = 0;
    let mut open: Option<(Range<usize>, &str)> = None;
    for (span, text) in spans {
        if let Some((current, _)) = open.as_mut()
            && span.start <= current.end
        {
            current.end = current.end.max(span.end);
            continue;
        }
        if let Some((current, text)) = open.take() {
            out.extend_from_slice(&data[at..current.start]);
            out.extend_from_slice(text.as_bytes());
            at = current.end;
        }
        open = Some((span, text));
    }
    if let Some((current, text)) = open {
        out.extend_from_slice(&data[at..current.start]);
        out.extend_from_slice(text.as_bytes());
        at = current.end;
    }
    out.extend_from_slice(&data[at..]);
    Some(out)
}

impl ConnectorSentClearer {
    /// Where each earlier value sits in `data`, in any spelling the index
    /// finds, beside its record's text: what a pass that clears these and
    /// the value presented now at once replaces together
    /// ([`replace_spans`]).
    #[must_use]
    pub fn spans(&self, data: &[u8]) -> Vec<(Range<usize>, &str)> {
        let mut spans = Vec::new();
        for (matcher, text) in &self.matchers {
            spans.extend(
                matcher
                    .spans(data)
                    .into_iter()
                    .map(|hit| (hit.span, text.as_str())),
            );
        }
        spans
    }

    /// `data` with each earlier value replaced by its record's text, every
    /// record's matched against the untouched bytes, or `None` when none is
    /// in it.
    fn cleared(&self, data: &[u8]) -> Option<Vec<u8>> {
        replace_spans(data, self.spans(data))
    }

    /// Each earlier value in `string`.
    pub fn clear_string(&self, string: &mut String) {
        if let Some(bytes) = self.cleared(string.as_bytes()) {
            *string = String::from_utf8(bytes)
                .unwrap_or_else(|error| String::from_utf8_lossy(&error.into_bytes()).into_owned());
        }
    }

    /// Each earlier value in `json`, in a string or a key at any depth.
    pub fn clear_json(&self, json: &mut Value) {
        match json {
            Value::String(string) => self.clear_string(string),
            Value::Array(items) => items.iter_mut().for_each(|item| self.clear_json(item)),
            Value::Object(fields) => {
                let taken = std::mem::take(fields);
                for (mut key, mut field) in taken {
                    self.clear_string(&mut key);
                    self.clear_json(&mut field);
                    fields.insert(key, field);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Each earlier value in a raw reply body: a JSON body as its parsed
    /// strings and keys are, written again only when that changed it; any
    /// other body byte for byte.
    pub fn clear_bytes(&self, bytes: &mut Vec<u8>) {
        if let Ok(mut parsed) = serde_json::from_slice::<Value>(bytes) {
            let before = parsed.clone();
            self.clear_json(&mut parsed);
            if parsed != before
                && let Ok(cleared) = serde_json::to_vec(&parsed)
            {
                *bytes = cleared;
            }
            return;
        }
        if let Some(cleared) = self.cleared(bytes) {
            *bytes = cleared;
        }
    }
}

/// Why a resumed exchange's earlier presentations cannot be cleared whole.
fn uncovered() -> Error {
    Error::InvalidConfig(
        "an earlier presentation of the exchange is not in its record's known-value history whole"
            .to_owned(),
    )
}

impl Vault {
    /// Runs `clear` with the clearer of `sent`, the earlier presentations
    /// of a resumed connector exchange (fix list row 10550). Each must be
    /// covered whole: its bytes read the same trimmed, and its record's
    /// known-value history holds a live entry at its generation under a
    /// handle. The history is read in a writer of its own, released before
    /// `clear` runs; no value is loaded.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when one presentation is not covered whole
    /// (a record that keeps no history, a retired entry, no handle, or
    /// bytes that did not read the same trimmed); storage and custody
    /// errors.
    pub fn with_connector_sent_clearer<R>(
        &self,
        sent: &[SentGeneration],
        clear: impl FnOnce(&ConnectorSentClearer) -> R,
    ) -> Result<R> {
        if sent.iter().any(|presented| !presented.trimmed) {
            return Err(uncovered());
        }
        let mut records: BTreeMap<EntityId, Vec<u32>> = BTreeMap::new();
        for presented in sent {
            let generations = records.entry(presented.custody).or_default();
            if !generations.contains(&presented.generation) {
                generations.push(presented.generation);
            }
        }
        // Each record's text, read before the writer opens.
        let texts: Vec<(EntityId, Vec<u32>, String)> = records
            .into_iter()
            .map(|(custody, generations)| {
                let text = self.secret_clear_text(Some(&custody));
                (custody, generations, text)
            })
            .collect();
        let mut matchers = Vec::with_capacity(sent.len());
        {
            let txn = self.store.env.write_txn()?;
            for (custody, generations, text) in texts {
                let Some((_, entries)) = self.store.known_entries_for_in_writer(&txn, &custody)?
                else {
                    return Err(uncovered());
                };
                // One matcher per generation: a matcher keeps the longest
                // of the values it knows at each place and skips the rest,
                // so two generations that overlap in a reply are each found
                // on the untouched text, and replaced together.
                for generation in generations {
                    if !entries.iter().any(|(at, _)| *at == generation) {
                        return Err(uncovered());
                    }
                    let Some(matcher) = KnownValues::load_for_in_writer(
                        &self.store,
                        &txn,
                        &custody,
                        &[generation],
                    )?
                    else {
                        return Err(uncovered());
                    };
                    matchers.push((matcher, text.clone()));
                }
            }
        }
        Ok(clear(&ConnectorSentClearer { matchers }))
    }
}
