//! Physical verdict and displacement rows from the same source snapshot.

use super::*;

/// Native ledger data, not an ENTITY row or a read grant. The marker's
/// absence is part of the witness: a later retirement changes this source.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanonicalSkillEditVerdict {
    key: Vec<u8>,
    body: Vec<u8>,
    displacement_key: Vec<u8>,
    displacement_body: Option<Vec<u8>>,
    verdict: HeldOutVerdict,
}

impl CanonicalSkillEditVerdict {
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn displacement_key(&self) -> &[u8] {
        &self.displacement_key
    }

    pub(crate) fn displacement_body(&self) -> Option<&[u8]> {
        self.displacement_body.as_deref()
    }

    pub(crate) fn verdict(&self) -> &HeldOutVerdict {
        &self.verdict
    }

    pub(crate) fn read_position(&self) -> Option<&SkillVerdictReadPosition> {
        self.verdict.read_position.as_ref()
    }

    pub(crate) fn into_verdict(self) -> HeldOutVerdict {
        self.verdict
    }

    pub(crate) fn source(&self) -> crate::store::attempt_sources::SkillEditVerdictSource {
        crate::store::attempt_sources::SkillEditVerdictSource {
            id: self.verdict.id,
            key: self.key.clone(),
            body_hash: *blake3::hash(&self.body).as_bytes(),
            displacement_key: self.displacement_key.clone(),
            displacement_hash: self
                .displacement_body
                .as_deref()
                .map(|bytes| *blake3::hash(bytes).as_bytes()),
        }
    }
}

/// The actual native primary row and the marker its normal decoder consults.
/// Neither supporting SKILL access nor the UUID-shaped id admits these bytes.
pub(crate) fn canonical_skill_edit_verdict_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<CanonicalSkillEditVerdict>> {
    let Some(raw) = VERDICTS.get_bytes(&vault.store, txn, id)? else {
        return Ok(None);
    };
    canonical_from_raw_in_txn(vault, txn, *id, raw).map(Some)
}

/// The brief's original eager scan, including every row filtered out later.
/// The exact prefix is returned only after all original native reads decode.
pub(crate) fn canonical_skill_edit_verdicts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<(Vec<CanonicalSkillEditVerdict>, &'static [u8])> {
    let rows = VERDICTS
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(id, raw)| canonical_from_raw_in_txn(vault, txn, id, raw))
        .collect::<Result<Vec<_>>>()?;
    Ok((rows, VERDICTS.decl().prefix))
}

fn canonical_from_raw_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: Vec<u8>,
) -> Result<CanonicalSkillEditVerdict> {
    let mut verdict = codec::decode_verdict(id, &raw)?;
    let displacement_body = DISPLACED_VERDICT.get_bytes(&vault.store, txn, &id)?;
    verdict.displaced_by_revision = displacement_body
        .as_deref()
        .map(|raw| DISPLACED_VERDICT.decode_value(raw).map(|mark| mark.0))
        .transpose()?;
    Ok(CanonicalSkillEditVerdict {
        key: VERDICTS.key_bytes(&id),
        body: raw,
        displacement_key: DISPLACED_VERDICT.key_bytes(&id),
        displacement_body,
        verdict,
    })
}

/// Original reads only. Callbacks borrow the full physical rows synchronously;
/// they must not reenter the store or treat either row as a permission.
pub(crate) enum VerdictRead<'row> {
    Row(&'row CanonicalSkillEditVerdict),
    /// The whole original scan and every native decode completed successfully.
    ScanComplete {
        prefix: &'row [u8],
    },
}

pub(crate) type VerdictReadObserver<'observer> = dyn for<'row> FnMut(VerdictRead<'row>) + 'observer;

pub(super) fn verdict_rows_observed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    observer: Option<&mut VerdictReadObserver<'_>>,
) -> Result<Vec<HeldOutVerdict>> {
    let Some(observer) = observer else {
        return VERDICTS
            .scan(&vault.store, txn)?
            .into_iter()
            .map(|(id, raw)| decode_verdict_with_marker(vault, txn, id, &raw))
            .collect();
    };
    // Keep the original eager primary scan before the per-row marker reads.
    let verdicts = VERDICTS
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(id, raw)| {
            let row = canonical_from_raw_in_txn(vault, txn, id, raw)?;
            observer(VerdictRead::Row(&row));
            Ok(row.into_verdict())
        })
        .collect::<Result<Vec<_>>>()?;
    observer(VerdictRead::ScanComplete {
        prefix: VERDICTS.decl().prefix,
    });
    Ok(verdicts)
}
