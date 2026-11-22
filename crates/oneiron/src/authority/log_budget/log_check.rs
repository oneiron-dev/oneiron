//! The typed checks on the stored authority log's bounds (OF-520), and the
//! signer label they and the doors' refusals name a key by.

use super::policy_bounds::headroom;
use super::*;

/// A short, stable label for `key` in owner-facing refusals.
#[must_use]
pub(crate) fn authority_signer_label(key: &AuthorityKey) -> String {
    let (suite, bytes) = match key {
        AuthorityKey::Ed25519(bytes) => ("ed25519", &bytes[..]),
        AuthorityKey::P256(bytes) => ("p256", &bytes[..]),
    };
    let hex: String = bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{suite}:{hex}")
}

/// A typed OF-520 question about the authority log's bounds, read from the
/// stored log: evidence for the owner, never a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityLogCheck {
    /// [`Self::SIGNER_BOUND`], [`Self::UNPINNED_ROOTS`],
    /// [`Self::FOLD_HEADROOM`] or [`Self::OWNER_RESERVE`].
    pub kind: &'static str,
    /// For a headroom check, what reached its row: [`Self::ROWS`],
    /// [`Self::HANDOFFS`] or [`Self::ANCESTOR_PAIRS`].
    pub scope: Option<&'static str>,
    /// The signer at its bound, for a signer-bound check.
    pub signer: Option<String>,
    /// The signer's stored rows, the strangers' rows, the log's counted
    /// rows, slip-issuer handoffs or counted ancestor pairs, or, for the
    /// owner reserve, the projected fold peak in bytes of the stored log, or
    /// of the log with the row the door last held at the reserve in it while
    /// that row is not stored, whichever is more.
    pub count: u64,
    /// The policy row `count` reached, or, for the owner reserve, the
    /// memory floor less the reserve, in bytes.
    pub threshold: u64,
}

impl AuthorityLogCheck {
    /// A key that is no slip issuer reached the `authority_log_signer_bound`
    /// row. Its further rows land as before: the check only asks
    /// ([`AUTHORITY_LOG_SIGNER_COUNT_ADVISORY`]).
    pub const SIGNER_BOUND: &'static str = "authority_log_signer_bound";
    /// The rows of anchors this install does not pin reached the
    /// `authority_log_signer_bound` row they share: their root records, their
    /// marks, and their machines' world rows. Further ones wait until this
    /// install pins their root or the owner raises the row, and then land on
    /// the next drain.
    pub const UNPINNED_ROOTS: &'static str = "authority_log_unpinned_roots";
    /// The log's counted rows, its slip issuers' handoffs, or its counted
    /// ancestor pairs reached their `authority_log_fold_headroom` policy row.
    /// The fold still reads them all; past the
    /// `authority_log_fold_memory_floor` row it refuses the log.
    pub const FOLD_HEADROOM: &'static str = "authority_log_fold_headroom";
    /// The stored log's projected fold peak, or the peak of the log with a
    /// row the door held in it, passed the `authority_log_fold_memory_floor`
    /// row less the owner's reserve under it: every row but the owner's work
    /// that would take the log past it waits until the owner raises that
    /// row, and then lands on the next drain.
    pub const OWNER_RESERVE: &'static str = "authority_log_owner_reserve";
    /// The scope of a headroom check on counted rows.
    pub const ROWS: &'static str = "rows";
    /// The scope of a headroom check on slip issuers' handoffs.
    pub const HANDOFFS: &'static str = "handoffs";
    /// The scope of a headroom check on counted ancestor pairs.
    pub const ANCESTOR_PAIRS: &'static str = "ancestor_pairs";
}

impl crate::Vault {
    /// The open checks on the stored authority log: each key no slip issuer
    /// vouches for that reached its bound, the strangers' shared bound, one
    /// per headroom scope that reached its policy row, and the owner's
    /// reserve under the memory floor once the log reached it.
    pub fn authority_log_checks(&self) -> crate::error::Result<Vec<AuthorityLogCheck>> {
        let txn = self.store.env.read_txn()?;
        let view = door_view(&self.store, &txn)?;
        let bound = signer_bound(&self.store, &txn)?;
        let mut checks: Vec<_> = view
            .rows
            .iter()
            .filter(|(signer, rows)| **rows >= bound && !view.structure.issuers.contains(*signer))
            .map(|(signer, rows)| AuthorityLogCheck {
                kind: AuthorityLogCheck::SIGNER_BOUND,
                scope: None,
                signer: Some(authority_signer_label(signer)),
                count: *rows as u64,
                threshold: bound as u64,
            })
            .collect();
        if view.strangers >= bound {
            checks.push(AuthorityLogCheck {
                kind: AuthorityLogCheck::UNPINNED_ROOTS,
                scope: None,
                signer: None,
                count: view.strangers as u64,
                threshold: bound as u64,
            });
        }
        let reserve_start = owner_reserve_start(&self.store, &txn)?;
        let held = self
            .store
            .authority_owner_reserve_hold
            .lock()
            .ok()
            .and_then(|hold| *hold)
            .filter(|hold| hold.stands(&view.projection))
            .map_or(0, |hold| hold.projected);
        let projected_bytes = view.projection.bytes().max(held);
        if projected_bytes > reserve_start {
            checks.push(AuthorityLogCheck {
                kind: AuthorityLogCheck::OWNER_RESERVE,
                scope: None,
                signer: None,
                count: projected_bytes,
                threshold: reserve_start,
            });
        }
        let (rows_at, handoffs_at, pairs_at) = headroom(&self.store, &txn)?;
        let pairs = self
            .authority_view_readonly_in_txn(&txn)?
            .counted_ancestor_pairs;
        for (scope, count, at) in [
            (AuthorityLogCheck::ROWS, view.counted as u64, rows_at),
            (
                AuthorityLogCheck::HANDOFFS,
                view.issuer_handoffs as u64,
                handoffs_at,
            ),
            (AuthorityLogCheck::ANCESTOR_PAIRS, pairs, pairs_at),
        ] {
            if count >= at {
                checks.push(AuthorityLogCheck {
                    kind: AuthorityLogCheck::FOLD_HEADROOM,
                    scope: Some(scope),
                    signer: None,
                    count,
                    threshold: at,
                });
            }
        }
        Ok(checks)
    }
}
