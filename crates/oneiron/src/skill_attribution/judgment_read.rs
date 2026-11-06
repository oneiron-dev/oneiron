//! Physical attribution-judgment rows from the original eager scanner.

use crate::store::attempt_sources::AttributionJudgmentSource;
use crate::{Result, Vault};

use super::codec::JUDGMENT;
use super::types::{AttributionJudgment, AttributionJudgmentReadPosition};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalAttributionJudgment {
    sequence: u64,
    key: Vec<u8>,
    body: Vec<u8>,
    judgment: AttributionJudgment,
}

impl CanonicalAttributionJudgment {
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn judgment(&self) -> &AttributionJudgment {
        &self.judgment
    }

    pub(crate) fn read_position(&self) -> Option<&AttributionJudgmentReadPosition> {
        self.judgment.read_position.as_ref()
    }

    pub(crate) fn into_judgment(self) -> AttributionJudgment {
        self.judgment
    }

    pub(crate) fn source(&self) -> AttributionJudgmentSource {
        AttributionJudgmentSource {
            sequence: self.sequence,
            id: self.judgment.row_id,
            key: self.key.clone(),
            body_hash: *blake3::hash(&self.body).as_bytes(),
        }
    }
}

pub(crate) fn canonical_attribution_judgment_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sequence: u64,
) -> Result<Option<CanonicalAttributionJudgment>> {
    let Some(body) = JUDGMENT.get_bytes(&vault.store, txn, &sequence)? else {
        return Ok(None);
    };
    let judgment = JUDGMENT.decode_value(&body)?;
    Ok(Some(CanonicalAttributionJudgment {
        sequence,
        key: JUDGMENT.key_bytes(&sequence),
        body,
        judgment,
    }))
}

/// No auxiliary marker tables: the ordinary decoder consults only these rows.
pub(crate) fn canonical_attribution_judgments_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<(Vec<CanonicalAttributionJudgment>, &'static [u8])> {
    let rows = JUDGMENT
        .scan_with_bytes(&vault.store, txn)?
        .into_iter()
        .map(
            |(sequence, judgment, key, body)| CanonicalAttributionJudgment {
                sequence,
                key,
                body,
                judgment,
            },
        )
        .collect();
    Ok((rows, JUDGMENT.decl().prefix))
}
