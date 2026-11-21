//! One Arc attempt's work in one wake: its parts' contract, a part's step
//! and opening, saving and resetting rows, and the parts' params hash.

use super::*;

/// The identity an Arc composed in parts is known by: its parts' contract.
pub(super) const ARC_PARTS_DOMAIN: &str = "oneiron:arc-summary-parts:v1";

/// Where one part stands after a run.
pub(super) enum ChildStep {
    Done,
    /// It split in two: the replacement parts' rows, by id.
    Split(Vec<(u32, ArcChildRow)>),
    Exit(DreamerAttemptExecution),
}

/// What opening a part's turns came to.
pub(super) enum Opening {
    /// Opened; whether the manifest gained a member.
    Opened(bool),
    /// The part has no room to read them: it splits.
    Split,
    Exit(DreamerAttemptExecution),
}

impl ArcRun<'_> {
    /// Co-commits part `id`'s `row`, with the manifest when it `changed`;
    /// the exit when the write does not hold.
    pub(super) fn save(
        &self,
        ctx: &WakeAttemptContext<'_>,
        id: u32,
        row: &ArcChildRow,
        changed: bool,
    ) -> Option<DreamerAttemptExecution> {
        let manifest = changed.then_some(&self.manifest);
        ctx.vault
            .save_arc_work(&self.work, manifest, &[(id, row)], None, None)
            .err()
            .map(|error| store_exit(&error, &self.charges, ctx.now_ms))
    }

    /// The member index a TURN already has: read in place of a line, or
    /// opened before.
    pub(super) fn turn_member(&self, turn: EntityId) -> Option<u32> {
        let handle = turn.to_hex();
        self.manifest
            .members
            .iter()
            .position(|member| {
                matches!(&member.kind,
                    MemberKind::Fallback { turn } | MemberKind::Opened { turn } if *turn == handle)
            })
            .map(|index| index as u32)
    }

    /// Every claim member, in order.
    pub(super) fn claims(&self) -> Vec<u32> {
        (0_u32..)
            .zip(&self.manifest.members)
            .filter(|(_, member)| matches!(member.kind, MemberKind::Claim { .. }))
            .map(|(index, _)| index)
            .collect()
    }

    /// Resets part `id`'s `row` once this wake (FIX 8288): its compose
    /// steps from `composed`, and with `reviewed` its reviews from there,
    /// are dropped, so the part composes again from them; every other part
    /// and every earlier step stand. `Some` exit when it was reset already,
    /// which parks Retry as an unread step did, or the write did not hold.
    pub(super) fn reset_part(
        &mut self,
        ctx: &WakeAttemptContext<'_>,
        id: u32,
        row: &mut ArcChildRow,
        (composed, reviewed): (usize, Option<usize>),
    ) -> Option<DreamerAttemptExecution> {
        if !self.reset.insert(id) {
            return Some(
                self.charges
                    .park_for("an arc part's step did not read", DreamerParkCause::Retry),
            );
        }
        tracing::info!(
            part = id,
            code = "arc_part_step_unread",
            "an arc part composes again from a step that did not read"
        );
        if let Some(reviewed) = reviewed {
            row.reviewed.truncate(reviewed);
            row.parts = 0;
        }
        row.composed.truncate(composed);
        row.done = false;
        self.save(ctx, id, row, false)
    }

    /// The Arc's window, and why it is too small.
    pub(super) fn too_small(&self) -> ArcPendingCause {
        ArcPendingCause::WindowTooSmall {
            window: self.manifest.pins.window,
            frame_tokens: self.frame,
        }
    }
}

/// An Arc composed in parts: its params JSON (instruction, model, schema,
/// `ARC_PARTS_DOMAIN`, window), with no tag written
/// (`purposes::dreamer_consolidation::ARC_PARTS_PARAMS`).
pub(super) fn arc_parts_params_hash(params: &[u8]) -> [u8; 32] {
    LegacyDigest::new(purposes::dreamer_consolidation::ARC_PARTS_PARAMS)
        .raw(params)
        .finish()
}
