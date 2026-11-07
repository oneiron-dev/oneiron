//! The Coach's unclear-note clustering state (FIX 7824): where a pass
//! resumes, which pattern each judged note joined, each pattern's exemplar
//! and filed proposal, and each note's support for its pattern. No table holds
//! note text: a pass reads the words from the unclear ledger, so an erase of
//! the ledger row takes them out of every pattern at once.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// Where the next pass resumes. Key: ().
pub(super) const CURSOR: SideTable<(), LabelCursor, Named> =
    SideTable::new(&side_table::COACH_ATTRIBUTION_LABEL_CURSOR);
/// Each judged note. Key: [`member_key`].
pub(super) const MEMBER: SideTable<Vec<u8>, NoteMember, Named> =
    SideTable::new(&side_table::COACH_ATTRIBUTION_LABEL_MEMBER);
/// Each pattern. Key: [`pattern_key`].
pub(super) const PATTERN: SideTable<Vec<u8>, NotePattern, Named> =
    SideTable::new(&side_table::COACH_ATTRIBUTION_LABEL_PATTERN);
/// Each note's support for its pattern. Key: [`support_key`].
pub(super) const SUPPORT: SideTable<Vec<u8>, NoteSupport, Named> =
    SideTable::new(&side_table::COACH_ATTRIBUTION_LABEL_SUPPORT);

/// The unclear-ledger key of the last outcome a pass finished; none at the
/// ledger's start.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LabelCursor {
    pub(super) after: Option<String>,
}

/// One judged note: its scope's group, the pattern it joined (none when the
/// choice found it names no pattern) and the fingerprint it was judged at. A
/// note whose fingerprint changed is judged again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct NoteMember {
    pub(super) group: [u8; 32],
    pub(super) pattern: Option<[u8; 16]>,
    pub(super) fingerprint: [u8; 32],
}

/// One recurring pattern within one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct NotePattern {
    /// The member key of the note the choice shows the pattern by; none once
    /// every supporting note left.
    pub(super) exemplar: Option<Vec<u8>>,
    /// The proposal filed for the pattern, which suppresses a second filing.
    pub(super) proposal: Option<[u8; 16]>,
    /// The member keys whose notes the proposal quotes.
    pub(super) filed: Vec<Vec<u8>>,
    /// Every entity the quoted notes' contexts name (actor, skill, project,
    /// read rows), frozen at filing: an erase of any of them erases the
    /// proposal, even once its notes have left the ledger.
    pub(super) sources: Vec<[u8; 16]>,
}

/// One note's support for its pattern: the outcome it counts as, so two notes
/// about one attempt count once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct NoteSupport {
    pub(super) outcome: String,
}

/// Every member key of the notes filed under unclear-ledger key `outcome`.
pub(super) fn note_prefix(outcome: &str) -> Vec<u8> {
    let len = u32::try_from(outcome.len()).unwrap_or(u32::MAX);
    let mut key = Vec::with_capacity(4 + outcome.len() + 4);
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(outcome.as_bytes());
    key
}

/// Note `index` of the outcome under unclear-ledger key `outcome`.
pub(super) fn member_key(outcome: &str, index: u32) -> Vec<u8> {
    let mut key = note_prefix(outcome);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

/// The unclear-ledger key and note index a member key names.
pub(super) fn member_note(key: &[u8]) -> Option<(String, usize)> {
    let len = usize::try_from(u32::from_be_bytes(key.get(..4)?.try_into().ok()?)).ok()?;
    let outcome = key.get(4..4 + len)?;
    let index = key.get(4 + len..)?;
    let index = u32::from_be_bytes(index.try_into().ok()?);
    Some((
        String::from_utf8(outcome.to_vec()).ok()?,
        usize::try_from(index).ok()?,
    ))
}

pub(super) fn pattern_key(group: &[u8; 32], pattern: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(48);
    key.extend_from_slice(group);
    key.extend_from_slice(pattern);
    key
}

pub(super) fn support_key(group: &[u8; 32], pattern: &[u8; 16], member: &[u8]) -> Vec<u8> {
    let mut key = pattern_key(group, pattern);
    key.extend_from_slice(member);
    key
}

/// Takes every member row of the outcome under `outcome` out of the table,
/// returning the ones that decode; one that does not names nothing a pattern
/// could count.
pub(super) fn take_members_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    outcome: &str,
) -> Result<Vec<(Vec<u8>, NoteMember)>> {
    let rows = MEMBER
        .iter_raw_from(store, &*txn, &note_prefix(outcome))?
        .collect::<Result<Vec<_>>>()?;
    let mut taken = Vec::with_capacity(rows.len());
    for (key, value) in rows {
        MEMBER.delete(store, txn, &key)?;
        if let Ok(member) = MEMBER.decode_value(&value) {
            taken.push((key, member));
        }
    }
    Ok(taken)
}

/// Takes `member`'s support out of its pattern. A pattern shown by the note
/// is shown by its next supporting note instead, and one left with no note
/// and no proposal goes. Returns the pattern the note had joined.
pub(super) fn unlink_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8],
    member: &NoteMember,
) -> Result<Option<[u8; 16]>> {
    let Some(pattern_id) = member.pattern else {
        return Ok(None);
    };
    SUPPORT.delete(store, txn, &support_key(&member.group, &pattern_id, key))?;
    let held = pattern_key(&member.group, &pattern_id);
    let Some(mut pattern) = PATTERN.get(store, &*txn, &held)? else {
        return Ok(Some(pattern_id));
    };
    if pattern.exemplar.as_deref() == Some(key) {
        pattern.exemplar = SUPPORT
            .scan_keys(store, &*txn, &held)?
            .into_iter()
            .next()
            .map(|support| support[held.len()..].to_vec());
        if pattern.exemplar.is_none() && pattern.proposal.is_none() {
            PATTERN.delete(store, txn, &held)?;
            return Ok(Some(pattern_id));
        }
        PATTERN.put(store, txn, &held, &pattern)?;
    }
    Ok(Some(pattern_id))
}
