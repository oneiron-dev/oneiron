//! The tally a rung-2 thread's replies spend (INBOX-RESIDUE PR-3b-3c-2,
//! RUNG2-REPLY-CAP = B).
//!
//! A visitor's reply on the thread a rung-2 first send began counts against
//! the page's own session caps (`ConstraintFrontConfig::max_turns` and
//! `max_model_calls`), as the session's turns on the page did. The page's
//! counters are the host's, in memory, and expire after idle minutes, while
//! an email thread outlives them, so the thread keeps its tally in the vault,
//! one row per send. The tally starts at the least the session spent on the
//! page, its no-fit turn (one turn, one parse), and each admitted reply adds
//! one turn and two model calls: the reply's parse and the agent's answer.
//! A reply event counts once, so a rerun of its job spends no second count.

use serde::{Deserialize, Serialize};

use crate::booking::constraint::{ConstraintSessionCaps, ConstraintSessionState};
use crate::side_table::{self, SideTable, VersionedNamed};
use crate::{Result, Vault};

/// Row-format byte on the reply tally's `vault_meta` value.
const REPLY_TALLY_ROW_VERSION: u8 = 1;

/// The derive-key context of a tally's key, the hash of its send ref.
const REPLY_TALLY_KEY_CONTEXT: &str = "oneiron booking rung2 reply tally v1";

/// The model calls one reply spends: its parse and the agent's answer.
const REPLY_MODEL_CALLS: usize = 2;

/// One send's tally. Key: hash32 of the send ref.
const REPLY_TALLY: SideTable<[u8; 32], Rung2ReplyTally, VersionedNamed<REPLY_TALLY_ROW_VERSION>> =
    SideTable::new(&side_table::BOOKING_RUNG2_REPLY_TALLY);

/// What a rung-2 session spent so far: on the page, then on its thread's
/// admitted replies, each event named once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rung2ReplyTally {
    turns_used: u16,
    model_calls_used: u16,
    /// The reply events admitted, in the order they came.
    event_ids: Vec<String>,
}

impl Rung2ReplyTally {
    /// The tally before any reply: the session's no-fit turn on the page.
    fn after_the_page() -> Self {
        Self {
            turns_used: 1,
            model_calls_used: 1,
            event_ids: Vec::new(),
        }
    }
}

/// Whether a reply on a rung-2 thread may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung2ReplyAdmission {
    /// Counted now, or by an earlier run of the same event: the reply may
    /// parse and answer.
    Admitted,
    /// Past the page's caps: the reply makes no model call.
    PastCap,
}

impl Vault {
    /// Admits the reply event `event_id` on the thread the rung-2 first send
    /// `send_ref` began, against the page's session `caps`: one turn and two
    /// model calls, counted with the session's no-fit turn and every reply
    /// admitted before. An event admitted before is admitted again and counts
    /// nothing more. A reply past the caps is counted nowhere.
    ///
    /// # Errors
    ///
    /// Storage errors, and a stored tally that does not decode.
    pub fn admit_booking_rung2_reply(
        &self,
        send_ref: &str,
        event_id: &str,
        caps: &ConstraintSessionCaps,
    ) -> Result<Rung2ReplyAdmission> {
        let key = reply_tally_key(send_ref);
        self.with_write_txn_grouped(|txn| {
            let mut tally = REPLY_TALLY
                .get(&self.store, txn, &key)?
                .unwrap_or_else(Rung2ReplyTally::after_the_page);
            if tally.event_ids.iter().any(|admitted| admitted == event_id) {
                return Ok(Rung2ReplyAdmission::Admitted);
            }
            let mut spent = ConstraintSessionState {
                turns_used: tally.turns_used,
                model_calls_used: tally.model_calls_used,
            };
            let fits = spent.admit_turn(caps).is_ok()
                && (0..REPLY_MODEL_CALLS).all(|_| spent.admit_model_call(caps).is_ok());
            if !fits {
                return Ok(Rung2ReplyAdmission::PastCap);
            }
            tally.turns_used = spent.turns_used;
            tally.model_calls_used = spent.model_calls_used;
            tally.event_ids.push(event_id.to_owned());
            REPLY_TALLY.put(&self.store, txn, &key, &tally)?;
            Ok(Rung2ReplyAdmission::Admitted)
        })
    }
}

fn reply_tally_key(send_ref: &str) -> [u8; 32] {
    blake3::Hasher::new_derive_key(REPLY_TALLY_KEY_CONTEXT)
        .update(send_ref.as_bytes())
        .finalize()
        .into()
}
