//! Hydration with an additional reader-bound row filter before projection.

use super::*;

impl Memory<'_> {
    /// Hydrates under the ordinary reader and keeps only rows `admits` shows.
    /// The filter sees the exact raw revision projected in the same snapshot.
    /// Absent or ordinarily withheld refs still fail with the read receipt;
    /// additional filter denials return separately by id.
    pub(crate) fn hydrate_filtered(
        &self,
        refs: &[String],
        mut admits: impl FnMut(&ReadRow) -> crate::Result<bool>,
    ) -> MemoryResult<ScopedReadResult<(Vec<EntityView>, Vec<EntityId>)>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let targets = refs
            .iter()
            .map(|reference| match reference.rsplit_once('@') {
                Some((reference, revision)) => self.read_target(
                    reference,
                    ReadMode::Pinned(crate::vault::RevisionRef::from_hex(revision)?),
                ),
                None => self.read_target(reference, ReadMode::Live),
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        let ScopedReadResult { value, mut receipt } =
            lane.read_named_projected(&point_reads(&targets), None, |txn, value| {
                let mut slots = value.into_iter();
                let mut projections: Vec<(NamedView, Option<EntityId>)> =
                    Vec::with_capacity(targets.len());
                for target in &targets {
                    let projection = match target.map(|(_, mode)| (mode, slots.next())) {
                        Some((mode, Some(Ok(Some(row))))) => {
                            if row.body.is_some() {
                                match admits(&row) {
                                    Ok(true) => {}
                                    Ok(false) => {
                                        projections.push((Ok(None), Some(row.id)));
                                        continue;
                                    }
                                    Err(error) => {
                                        projections.push((Err(error), None));
                                        continue;
                                    }
                                }
                            }
                            (Ok(self.slot_view_in(&lane, txn, row, mode, false)?), None)
                        }
                        Some((_, Some(Err(refusal)))) => (Err(refusal), None),
                        _ => (Ok(None), None),
                    };
                    projections.push(projection);
                }
                Ok::<_, MemoryError>(projections)
            })?;
        let mut shown = Vec::with_capacity(value.len());
        let mut shown_targets = Vec::with_capacity(value.len());
        let mut withheld = Vec::new();
        for ((reference, target), (view, denied)) in refs.iter().zip(&targets).zip(value) {
            if let Some(id) = denied {
                withheld.push(id);
                continue;
            }
            let refusal = match view {
                Ok(Some(view)) => {
                    shown.push(view);
                    shown_targets.push(*target);
                    continue;
                }
                Ok(None) => {
                    MemoryError::not_found(format!("entity {reference:?} does not resolve"))
                }
                Err(refusal) => MemoryError::from(refusal),
            };
            return Err(refusal.with_read_receipt(receipt));
        }
        self.serve_hydrated_assets(&lane, &shown_targets, &mut shown, &mut receipt)?;
        Ok(ScopedReadResult {
            value: (shown, withheld),
            receipt,
        })
    }
}
