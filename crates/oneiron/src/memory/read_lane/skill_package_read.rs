//! `self.skills.package`'s lane read: one admitted skill's record and runtime package.

use super::*;

/// The verb a Grant lists to name a skill package read: the row's own name. This
/// method exists only for that row, so the check names it directly.
const SKILL_PACKAGE_READ_VERB: &str = "self.skills.package";

impl Memory<'_> {
    /// Reads `entity` as its skill record with its runtime package, in the lane's
    /// snapshot: the caller's live owner Grant naming the verb is checked in the
    /// same snapshot, and without one the read is refused. Readability is judged
    /// before the type: a ref that resolves to nothing, a row the lane withholds,
    /// and a row that is no SKILL answer `None`, exactly like a missing target;
    /// the receipt counts only rows the key could read. An admitted SKILL answers
    /// its record and package only while it is loadable and has one:
    /// a candidate, stale, quarantined, superseded or unapproved record, and
    /// a skill with no stored package answer `None`. A resident-owned fork the
    /// lane admits reads as its package: the runtime loads resident forks.
    /// A package that does not read (custody or hash) answers `None`, never an
    /// error, as a reader's skill list does. A caller that sees stored keys
    /// masked is served no package whose files hold one (in their bytes or
    /// their paths): that skill answers `None`, as `vault.skills.get`
    /// withholds it. A carrier-sourced package answers
    /// only while the lane admits its carrier ASSET in the same snapshot;
    /// otherwise it answers `None`. There is no revision pin: the row is read
    /// live. Record verbs serve every claim status, so the lane is `Recorded`
    /// as `vault.get` opens it.
    pub(crate) fn skill_package_read(
        &self,
        entity: &EntityId,
    ) -> MemoryResult<ScopedReadResult<Option<crate::skill_hub::HubPackage>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let outer = lane.read_projected(&[PointRead::id(*entity)], None, |txn, rows| {
            let standing = crate::authority::principal_standing_in_txn(
                self.vault(),
                txn,
                self.actor(),
                self.actor_class(),
                SKILL_PACKAGE_READ_VERB,
            )?;
            if standing.is_none() {
                return Err(skill_package_read_refused());
            }
            let Some(skill_row) = rows.into_iter().next().flatten() else {
                return Ok::<_, MemoryError>((None, None));
            };
            if skill_row.entity_type != crate::registry::ENTITY_TYPE_SKILL {
                return Ok((None, None));
            }
            let skill_candidate = self.read_world_candidate(&lane, txn, &skill_row);
            let record = match self.vault().get_skill_record_in_txn(txn, entity) {
                Ok(Some(record)) => record,
                Ok(None) => return Ok((None, None)),
                Err(error)
                    if matches!(
                        &error,
                        crate::error::Error::Artifact(
                            crate::error::ArtifactError::InvalidSkillBody(_)
                        )
                    ) =>
                {
                    return Ok((None, None));
                }
                Err(error) => return Err(MemoryError::from(error)),
            };
            if !crate::skill::skill_loadable(&record) {
                return Ok((None, None));
            }
            let package = match self
                .vault()
                .runtime_skill_package_sourced_in_txn(txn, entity, &record)
            {
                Ok((Some(package), _)) => package,
                Ok((None, _)) => return Ok((None, None)),
                Err(error)
                    if matches!(
                        &error,
                        crate::error::Error::Artifact(
                            crate::error::ArtifactError::InvalidSkillBody(_)
                        )
                    ) =>
                {
                    tracing::warn!(
                        %error,
                        skill = %entity.to_hex(),
                        "a skill's stored package did not read; no reader is served it"
                    );
                    return Ok((None, None));
                }
                Err(error) => return Err(MemoryError::from(error)),
            };
            // A caller that sees stored keys masked is served no package whose
            // files hold one: package files carry no custody marks to mask by,
            // so the skill answers `None`, as `vault.skills.get` withholds it
            // (#7149 review round 1).
            if self.secret_sight_in_txn(txn)? == crate::secret_custody::SecretSight::Masked
                && crate::snapshot_read::package_holds_credential(&package)
            {
                return Ok((None, None));
            }
            let Some(carrier) = self
                .vault()
                .runtime_package_carrier_in_txn(txn, entity, &record)?
            else {
                if let Some(candidate) = skill_candidate {
                    candidate.served();
                }
                self.produced_from([*entity]);
                return Ok((Some(package), None));
            };
            let inner = lane.read_projected_in_txn(
                txn,
                &[PointRead::id(carrier)],
                None,
                |_, carrier_rows| Ok::<_, MemoryError>(carrier_rows.into_iter().next().flatten()),
            )?;
            let ScopedReadResult {
                value: carrier_row,
                receipt: carrier_receipt,
            } = inner;
            let Some(carrier_row) = carrier_row else {
                return Ok((None, Some(carrier_receipt)));
            };
            let carrier_candidate = self.read_world_candidate(&lane, txn, &carrier_row);
            if let Some(candidate) = skill_candidate {
                candidate.served();
            }
            if let Some(candidate) = carrier_candidate {
                candidate.served();
            }
            self.produced_from([*entity, carrier]);
            Ok((Some(package), Some(carrier_receipt)))
        })?;
        let (value, inner_receipt) = outer.value;
        let mut receipt = outer.receipt;
        if let Some(inner) = inner_receipt {
            receipt.restrict_with(&inner);
        }
        Ok(ScopedReadResult { value, receipt })
    }
}

/// The read's refusal of a caller with no live Grant naming the verb.
fn skill_package_read_refused() -> MemoryError {
    MemoryError::new(
        crate::memory::MEMORY_CODE_FORBIDDEN,
        format!(
            "{SKILL_PACKAGE_READ_VERB} takes a live Grant naming the verb: no live Grant from a live owner names this caller and lists the verb"
        ),
        &["Have the owner grant this caller the verb by name."],
    )
}
