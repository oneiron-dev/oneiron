//! Sealing one lineage's batch at its local log position (KS-4): every
//! member group behind it gets a head of the live entries and retirement
//! facts its recipients admit, every erased credential's fact, every holder
//! debt (FIX 11206) and the world pad compartments a restore here left
//! unopened (PAD-3), all from one census under the read guard.

use crate::error::Result;
use crate::store::Store;

use super::super::credential_faults::head_entry;
use super::super::files::{EntryState, LocalCustody};
use super::super::head::{CustodyRecipients, seal_head};
use super::super::log::{CustodyPosition, Journal};
use super::super::protocol::CustodyBatch;
use super::Sealed;

impl Store {
    /// Under the read guard: the local position, then, for each group of
    /// `groups` whose target `behind` says lacks a head there, a head sealed
    /// at it for that group's recipients, all from one census: every entry
    /// a frame up to the position mints is published before its frame, and
    /// no retirement runs until the heads are sealed.
    pub(super) fn seal_batch(
        &self,
        custody: LocalCustody<'_>,
        journal: &Journal,
        groups: &[&CustodyRecipients],
        revision: u64,
        behind: impl FnOnce(&CustodyPosition) -> Vec<bool>,
    ) -> Result<Sealed> {
        let _guard = self.core.key_custody.read_guard()?;
        let position = journal.position()?;
        let census = custody.census()?;
        // A pad retired here is carried no further, whatever a carried copy
        // an interrupted retirement left says (PAD-3).
        let mut carried = custody.carried()?;
        carried.retain(|pad| {
            !census
                .binary_search_by(|(id, _)| id.cmp(pad.id()))
                .is_ok_and(|at| census[at].1 == EntryState::Retired)
        });
        if position.seq == 0 && census.is_empty() && carried.is_empty() {
            return Ok(Sealed::Nothing);
        }
        // Every member's head carries every erased credential's fact,
        // outside key eligibility (FIX 10584 item 3).
        let evidence = custody.erase_evidence()?;
        // And every holder debt standing here, whatever its key's state, so
        // a landing keeps each copy owed (FIX 11206).
        let holders = custody.holder_debts()?;
        let mut sealed = Vec::with_capacity(groups.len());
        for (recipients, behind) in groups.iter().zip(behind(&position)) {
            if !behind {
                sealed.push(None);
                continue;
            }
            let control = journal.control_or_create()?;
            let mut entries = Vec::new();
            let mut retired = Vec::new();
            for (id, state) in &census {
                match state {
                    // KS-5: a pad its world keeps off this member stays out
                    // of its head. KS-6: a credential key that does not read
                    // stays local this pass, warned.
                    EntryState::Live if recipients.keeps_local(id) => {}
                    EntryState::Live => entries.extend(head_entry(&custody, id)?),
                    // KS-6: a credential key kept off this member keeps its
                    // retirement fact off too; an owner-only compartment
                    // seals to the root alone. A pad's fact always rides
                    // (FIX 9178: `CustodyRecipients::fact_scope`).
                    EntryState::Retired if recipients.keeps_fact_local(id) => {}
                    EntryState::Retired => retired.push(id.clone()),
                    EntryState::Missing => {}
                }
            }
            let released = journal.recipient_facts()?;
            let history = journal.head_history(&control, &position, &census)?;
            sealed.push(Some(
                seal_head(
                    &position, &control, entries, retired, released, &history, &evidence, &holders,
                    &carried, recipients,
                )
                .map(|head| CustodyBatch {
                    position,
                    head,
                    set_revision: revision,
                    journal: journal.dir().to_path_buf(),
                    data_key: recipients.data_key.is_some(),
                })
                .map_err(|error| error.to_string()),
            ));
        }
        Ok(Sealed::At(position, sealed))
    }
}
