//! What the reads of one machine CLAIM target's controls check of its
//! history, each part read on first ask (FIX
//! MACHINE-HISTORY-PAGE-PER-CONTROL-RESOLVE).
//!
//! A selector judges every control of a machine CLAIM's history before it
//! ships the target or serves a history page (RULING
//! SECREAD-HOME-MACHINE-HISTORY = A). Each control's causal check
//! (`authority::machine_claim_read_admitted`) and its disclosure scope
//! (`federation::record_scope`) rest on the target's verified history, which
//! is the same for every control of one target in one read transaction. A
//! [`TargetHistory`] holds what those checks read of one target. Asked once,
//! it reads what that one check needs; kept for a whole read (the selector's
//! `MachineHistoryReadCache`), it resolves the history once for every control.

use std::cell::OnceCell;

use super::*;

/// What the reads of one machine CLAIM target's controls check of its
/// history, in one read transaction under one authority fold. Each part is
/// read on first ask, so a caller asking once pays what it asks for.
pub(crate) struct TargetHistory {
    target: EntityId,
    /// The pin and the control ids its rows name, when the rows and the pin
    /// read and the pin names the rows' birth in the fold's vault; `None`
    /// admits no control.
    pinned: OnceCell<Option<PinnedControls>>,
    /// The resolved history ([`resolved_machine_history`]).
    resolution: OnceCell<HistoryResolution>,
    /// The ids of the pin's verified handoff chain; `None` when it does not
    /// verify.
    handoffs: OnceCell<Option<BTreeSet<EntityId>>>,
}

/// The trusted pin of a target and the control ids its history rows name.
struct PinnedControls {
    packet: ClaimHistoryHandoff,
    /// The birth event's id, when it computes.
    birth: Option<EntityId>,
    /// The id of each resident transition event the chain's union lists.
    transitions: BTreeSet<EntityId>,
}

/// How a target's history resolved.
enum HistoryResolution {
    Resolved(Box<ClaimTransitionProjection>),
    /// Incomplete, or its proof does not verify: its controls are withheld.
    Withheld,
    /// Any other error, such as a storage error. [`TargetHistory::resolved`]
    /// resolves again to return that error itself.
    Failed,
}

impl TargetHistory {
    pub(crate) fn new(target: EntityId) -> Self {
        Self {
            target,
            pinned: OnceCell::new(),
            resolution: OnceCell::new(),
            handoffs: OnceCell::new(),
        }
    }

    fn resolution(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> &HistoryResolution {
        self.resolution.get_or_init(|| {
            match resolved_machine_history(store, txn, fold, self.target) {
                Ok(projection) => HistoryResolution::Resolved(Box::new(projection)),
                Err(Error::Claim(
                    ClaimError::MachineClaimHistoryIncomplete
                    | ClaimError::InvalidMachineClaimProof,
                )) => HistoryResolution::Withheld,
                Err(_) => HistoryResolution::Failed,
            }
        })
    }

    /// The target's resolved history; `None` when it is incomplete or its
    /// proof does not verify.
    ///
    /// # Errors
    ///
    /// Any other error resolving it, such as a storage error.
    pub(crate) fn resolved(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Result<Option<&ClaimTransitionProjection>> {
        match self.resolution(store, txn, fold) {
            HistoryResolution::Resolved(projection) => Ok(Some(&**projection)),
            HistoryResolution::Withheld => Ok(None),
            // One transaction resolves alike every time, so this returns the
            // error the first resolution met; a resolution that now succeeds
            // still withholds.
            HistoryResolution::Failed => {
                resolved_machine_history(store, txn, fold, self.target).map(|_| None)
            }
        }
    }

    fn pinned(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Option<&PinnedControls> {
        self.pinned
            .get_or_init(|| {
                let rows = machine_history_rows(store, txn, self.target).ok()?;
                let packet = trusted_machine_handoff(store, txn, self.target).ok()?;
                if packet.births.len() != 1
                    || packet.births[0].digest != rows.birth.digest
                    || fold.vault_id != Some(rows.birth.vault_id)
                {
                    return None;
                }
                // Membership in the whole history: the chain's union, not the
                // tip's delta.
                let transitions = rows
                    .events
                    .iter()
                    .filter(|event| {
                        machine_claim_transition_event_hash(event)
                            .is_ok_and(|hash| rows.transitions.contains_key(&hash))
                    })
                    .filter_map(|event| machine_claim_transition_event_id(event).ok())
                    .collect();
                Some(PinnedControls {
                    birth: rows.birth.event_id().ok(),
                    transitions,
                    packet,
                })
            })
            .as_ref()
    }

    fn handoffs(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        packet: &ClaimHistoryHandoff,
    ) -> Option<&BTreeSet<EntityId>> {
        self.handoffs
            .get_or_init(|| {
                let chain = verified_handoff_chain(store, txn, packet, fold).ok()?;
                Some(
                    chain
                        .iter()
                        .filter_map(|packet| {
                            let hash = packet.content_hash().ok()?;
                            EntityId::from_bytes(hash[..16].try_into().ok()?).ok()
                        })
                        .collect(),
                )
            })
            .as_ref()
    }

    /// Whether this history admits `id` as a control of `kind`: the pin names
    /// the rows' birth in the fold's vault, the history resolves, and `id` is
    /// its birth, a transition of the chain's union, or a handoff of the pin's
    /// verified chain, as `kind` says. The caller has checked that the stored
    /// bytes of `id` are the control's body
    /// ([`crate::authority::history_control_read_admitted`]).
    pub(crate) fn admits_control(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        kind: MachineHistoryKind,
        id: &EntityId,
    ) -> bool {
        let Some(pinned) = self.pinned(store, txn, fold) else {
            return false;
        };
        if !matches!(
            self.resolution(store, txn, fold),
            HistoryResolution::Resolved(_)
        ) {
            return false;
        }
        match kind {
            MachineHistoryKind::Birth => pinned.birth == Some(*id),
            MachineHistoryKind::Transition => pinned.transitions.contains(id),
            MachineHistoryKind::Handoff => self
                .handoffs(store, txn, fold, &pinned.packet)
                .is_some_and(|handoffs| handoffs.contains(id)),
        }
    }
}
