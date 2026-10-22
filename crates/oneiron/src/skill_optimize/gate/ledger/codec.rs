//! Stored skill-edit verdict decoding and displacement markers.
//! Entry function: `decode_verdict_with_marker`.
//! The gate owns verdict types; the ledger parent owns its row tables.

use super::*;

fn decode_verdict(id: EntityId, raw: &[u8]) -> Result<HeldOutVerdict> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    let Value::Map(entries) = &value else {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    if field(KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(VERDICT_SCHEMA_VERSION) {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    }
    let entity = |name: &str| {
        field(name)
            .and_then(Value::as_str)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
    };
    let score = |name: &str| match field(name) {
        Some(&Value::F32(score)) => Ok(score),
        _ => Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
    };
    // STRICT, entry by entry: a row whose array holds a non-string member is a
    // corrupt row, not a shorter one. Dropping the member silently would hand
    // a reader an evidence list that no longer matches the COUNT and DIGEST
    // standing beside it in the same row — a verdict that still binds, still
    // admits, and no longer says what it was ruled over.
    let strings = |name: &str| -> Result<Vec<String>> {
        let Some(Value::Array(entries)) = field(name) else {
            return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
        };
        entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
            })
            .collect()
    };
    let disposition = field(KEY_DISPOSITION)
        .and_then(Value::as_str)
        .and_then(SkillEditDisposition::parse)
        .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    let text = |name: &str| {
        field(name)
            .and_then(Value::as_str)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
            .map(str::to_owned)
    };
    let held_out_count = field(KEY_HELD_OUT_COUNT)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    let measurements = match field(KEY_MEASUREMENTS) {
        Some(Value::Nil) => None,
        Some(value) => {
            let decoded: JudgeMeasurements = serde_json::from_str(
                value
                    .as_str()
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            )
            .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
            validate_measurements(&decoded, held_out_count)
                .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
            Some(decoded)
        }
        None => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
    };
    if measurements.is_none()
        && (disposition != SkillEditDisposition::RefusedStaleTarget
            || field(KEY_ACCEPTED_VERDICT) != Some(&Value::Nil))
    {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    }
    let goal_axes: BTreeMap<String, GoalAxisScore> = serde_json::from_str(
        field(KEY_GOAL_AXES)
            .and_then(Value::as_str)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
    )
    .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    if measurements.is_some() {
        if field(KEY_GOAL_REVISION)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
        }
        validate_goal_vector(&goal_axes).map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
        // The resolution is validated below, together with the vector.
        let headline = goal_axes
            .values()
            .find(|axis| axis.kind == GoalAxisKind::Primary)
            .expect("validated primary axis");
        if score(KEY_BEFORE)? != headline.before || score(KEY_AFTER)? != headline.after {
            return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
        }
    } else if !goal_axes.is_empty() || field(KEY_GOAL_REVISION).and_then(Value::as_str) != Some("")
    {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    }
    let goal_id = match field(KEY_GOAL_ID) {
        Some(Value::Nil) if measurements.is_none() => None,
        Some(value) if measurements.is_some() => Some(
            value
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
        ),
        _ => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
    };
    let tradeoff_resolution: Option<TradeoffResolution> = match field(KEY_TRADEOFF_RESOLUTION) {
        Some(Value::Nil) => None,
        Some(value) => Some(
            serde_json::from_str(
                value
                    .as_str()
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            )
            .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
        ),
        None => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
    };
    // Required even when Nil: a v6 row cannot say whether Jev ruled it.
    let tradeoff_jev: Option<JevTradeoffVerdict> = match field(KEY_TRADEOFF_JEV) {
        Some(Value::Nil) => None,
        Some(value) => Some(
            serde_json::from_str(
                value
                    .as_str()
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            )
            .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
        ),
        None => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
    };
    if measurements.is_some() {
        validate_tradeoff_verdict(
            disposition,
            &goal_axes,
            tradeoff_resolution.as_ref(),
            tradeoff_jev.as_ref(),
        )
        .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    } else if tradeoff_resolution.is_some() || tradeoff_jev.is_some() {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    }
    let scored = measurements.is_some();
    Ok(HeldOutVerdict {
        goal_id,
        tradeoff_resolution,
        tradeoff_jev,
        goal_axes,
        goal_revision: text(KEY_GOAL_REVISION)?,
        before: score(KEY_BEFORE)?,
        after: score(KEY_AFTER)?,
        measurements,
        accepted: disposition.admits(),
        judge_revision: match field(KEY_JUDGE_REVISION) {
            Some(Value::Nil) if !scored => None,
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?
                    .to_owned(),
            ),
            None => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
        },
        displaced_by_revision: None,
        id,
        proposal: entity(KEY_PROPOSAL)?,
        skill: entity(KEY_SKILL)?,
        disposition,
        cycle: text(KEY_CYCLE)?,
        held_out_receipts: strings(KEY_HELD_OUT)?,
        held_out_count,
        held_out_digest: text(KEY_HELD_OUT_DIGEST)?,
        held_out_truncated: field(KEY_HELD_OUT_TRUNCATED)
            .and_then(Value::as_bool)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
        proposal_digest: text(KEY_PROPOSAL_DIGEST)?,
        target_digest: text(KEY_TARGET_DIGEST)?,
        // Nil is AMBIGUOUS or basis-less, and both are unadmittable; an absent
        // key is a row from another schema, and an unparseable tier is
        // corruption. Only the explicit spellings decode.
        proposal_tier: match field(KEY_PROPOSAL_TIER) {
            None => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
            Some(Value::Nil) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(SkillGovernanceTier::parse)
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            ),
        },
        // Nil is the ordinary shape: only a post-score refusal names the
        // acceptance it answers. A present-but-unreadable id is corruption,
        // not absence — reading it as "no reference" would quietly turn a
        // derived refusal back into the orphan row this field exists to end.
        accepted_verdict: match field(KEY_ACCEPTED_VERDICT) {
            Some(Value::Nil) | None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            ),
        },
        // Strict on both axes, for the reason above: an id that does not parse
        // is corruption, and a source refusal that quietly lost the very id it
        // refuses over is an audit record that cannot be audited.
        missing_sources: strings(KEY_MISSING_SOURCES)?
            .iter()
            .map(|hex| {
                EntityId::from_hex(hex).map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))
            })
            .collect::<Result<Vec<EntityId>>>()?,
        at: field(KEY_AT)
            .and_then(Value::as_u64)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
    })
}

pub(super) fn decode_verdict_with_marker(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<HeldOutVerdict> {
    let mut verdict = decode_verdict(id, raw)?;
    verdict.displaced_by_revision = DISPLACED_VERDICT
        .get(&vault.store, txn, &verdict.id)?
        .map(|mark| mark.0);
    Ok(verdict)
}
