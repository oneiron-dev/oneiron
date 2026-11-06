//! The original attributed-outcome fold's complete physical read set.

use crate::side_table::{Raw, RawValue, SideKey, SideTable};
use crate::store::attempt_sources::{OutcomeReadKind, OutcomeReadSource};
use crate::{EntityId, Result, Vault};

use super::RuleOutcomeReadPosition;
use super::amended::{AMENDED, AmendedRow};
use super::ledger::{
    AttributedOutcome, DISPLACED, DisplacedMark, OUTCOME, OutcomeRef, PAIRED_OUTCOME,
};
use super::outcome_position::{OutcomePlacement, OutcomeReadPosition};
use super::outcome_row::LedgerOutcomeRow;

pub(super) enum DependencyPlacement {
    Original(OutcomePlacement),
    Rule {
        id: Option<EntityId>,
        position: Option<RuleOutcomeReadPosition>,
    },
    Unknown,
}

pub(super) trait OutcomeNativeRow {
    fn dependency_placement(&self) -> DependencyPlacement;
}

impl OutcomeNativeRow for LedgerOutcomeRow {
    fn dependency_placement(&self) -> DependencyPlacement {
        match self {
            Self::Original(row) => DependencyPlacement::Original(row.placement.clone()),
            Self::Rule {
                native: Some(row), ..
            } => DependencyPlacement::Rule {
                id: row.row_id,
                position: row.read_position.clone(),
            },
            Self::Rule { native: None, .. } => DependencyPlacement::Unknown,
        }
    }
}

impl OutcomeNativeRow for AmendedRow {
    fn dependency_placement(&self) -> DependencyPlacement {
        DependencyPlacement::Original(self.placement.clone())
    }
}

pub(crate) struct CanonicalOutcomeDependency {
    kind: OutcomeReadKind,
    key: Vec<u8>,
    body: Option<Vec<u8>>,
    placement: DependencyPlacement,
}

impl CanonicalOutcomeDependency {
    pub(crate) fn source(&self) -> OutcomeReadSource {
        OutcomeReadSource {
            kind: self.kind,
            key: self.key.clone(),
            body_hash: self
                .body
                .as_ref()
                .map(|body| *blake3::hash(body).as_bytes()),
        }
    }

    pub(crate) fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    pub(crate) fn row_id(&self) -> Option<EntityId> {
        match &self.placement {
            DependencyPlacement::Original(position) => position.row_id,
            DependencyPlacement::Rule { id, .. } => *id,
            DependencyPlacement::Unknown => None,
        }
    }

    pub(crate) fn original_position(&self) -> Option<&OutcomeReadPosition> {
        match &self.placement {
            DependencyPlacement::Original(position) => position.read_position.as_ref(),
            _ => None,
        }
    }

    pub(crate) fn rule_position(&self) -> Option<&RuleOutcomeReadPosition> {
        match &self.placement {
            DependencyPlacement::Rule { position, .. } => position.as_ref(),
            _ => None,
        }
    }
}

pub(crate) struct CanonicalOutcomeReads {
    prefixes: Vec<Vec<u8>>,
    rows: Vec<CanonicalOutcomeDependency>,
}

impl CanonicalOutcomeReads {
    pub(crate) fn prefixes(&self) -> &[Vec<u8>] {
        &self.prefixes
    }
    pub(crate) fn rows(&self) -> &[CanonicalOutcomeDependency] {
        &self.rows
    }
    pub(crate) fn sources(&self) -> Vec<OutcomeReadSource> {
        self.rows
            .iter()
            .map(CanonicalOutcomeDependency::source)
            .collect()
    }
}

/// The scan stays eager: all original key/value decodes finish before the
/// caller can take any per-row displacement branch.
pub(super) fn scan_rows<K: SideKey, V: RawValue + OutcomeNativeRow>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    table: &SideTable<K, V, Raw>,
    prefix: &[u8],
    kind: OutcomeReadKind,
    observed: Option<&mut CanonicalOutcomeReads>,
) -> Result<Vec<(K, V)>> {
    let Some(observed) = observed else {
        return table.scan_from(&vault.store, txn, prefix);
    };
    let rows = table.scan_from_with_raw(&vault.store, txn, prefix)?;
    let mut full_prefix = table.decl().prefix.to_vec();
    full_prefix.extend_from_slice(prefix);
    observed.prefixes.push(full_prefix);
    Ok(rows
        .into_iter()
        .map(|(key, row, full_key, body)| {
            observed.rows.push(CanonicalOutcomeDependency {
                kind,
                key: full_key,
                body: Some(body),
                placement: row.dependency_placement(),
            });
            (key, row)
        })
        .collect())
}

/// Only called where the original fold called contains, after its amendment
/// short-circuit. A present malformed marker still suppresses the outcome;
/// only its optional native capture becomes unknown.
pub(super) fn displaced_read(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    outcome: &OutcomeRef,
    observed: Option<&mut CanonicalOutcomeReads>,
) -> Result<bool> {
    let Some(observed) = observed else {
        return DISPLACED.contains(&vault.store, txn, outcome);
    };
    let body = DISPLACED.get_bytes(&vault.store, txn, outcome)?;
    let present = body.is_some();
    observed
        .rows
        .push(marker_dependency(DISPLACED.key_bytes(outcome), body));
    Ok(present)
}

fn marker_dependency(key: Vec<u8>, body: Option<Vec<u8>>) -> CanonicalOutcomeDependency {
    let placement = body
        .as_ref()
        .and_then(|body| DisplacedMark::from_raw(body).ok())
        .map(|row| DependencyPlacement::Original(row.placement))
        .unwrap_or(DependencyPlacement::Unknown);
    CanonicalOutcomeDependency {
        kind: OutcomeReadKind::Displaced,
        key,
        body,
        placement,
    }
}

pub(crate) fn canonical_attributed_outcomes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<(Vec<(String, AttributedOutcome)>, CanonicalOutcomeReads)> {
    let mut reads = CanonicalOutcomeReads {
        prefixes: Vec::new(),
        rows: Vec::new(),
    };
    let (outcomes, _) = super::ledger::weighted_read(vault, txn, skill, Some(&mut reads))?;
    Ok((outcomes, reads))
}

/// Re-read a single physical source without treating its native ID as ENTITY
/// authority. The family fixes the table and its actual typed key decoder.
pub(crate) fn canonical_outcome_dependency_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &OutcomeReadSource,
) -> Result<Option<CanonicalOutcomeDependency>> {
    match source.kind {
        OutcomeReadKind::Outcome => {
            let Some(suffix) = source.key.strip_prefix(OUTCOME.decl().prefix) else {
                return Ok(None);
            };
            let Some(key) = <(EntityId, String)>::decode_key(suffix) else {
                return Ok(None);
            };
            let Some(body) = OUTCOME.get_bytes(&vault.store, txn, &key)? else {
                return Ok(None);
            };
            let row = OUTCOME.decode_value(&body)?;
            Ok(Some(CanonicalOutcomeDependency {
                kind: source.kind,
                key: source.key.clone(),
                body: Some(body),
                placement: row.dependency_placement(),
            }))
        }
        OutcomeReadKind::Paired => {
            let Some(suffix) = source.key.strip_prefix(PAIRED_OUTCOME.decl().prefix) else {
                return Ok(None);
            };
            let Some(key) = super::ledger::PairedOutcomeKey::decode_key(suffix) else {
                return Ok(None);
            };
            let Some(body) = PAIRED_OUTCOME.get_bytes(&vault.store, txn, &key)? else {
                return Ok(None);
            };
            let row = PAIRED_OUTCOME.decode_value(&body)?;
            Ok(Some(CanonicalOutcomeDependency {
                kind: source.kind,
                key: source.key.clone(),
                body: Some(body),
                placement: row.dependency_placement(),
            }))
        }
        OutcomeReadKind::Amended => {
            let Some(suffix) = source.key.strip_prefix(AMENDED.decl().prefix) else {
                return Ok(None);
            };
            let Some(key) = OutcomeRef::decode_key(suffix) else {
                return Ok(None);
            };
            let Some(body) = AMENDED.get_bytes(&vault.store, txn, &key)? else {
                return Ok(None);
            };
            let row = AMENDED.decode_value(&body)?;
            Ok(Some(CanonicalOutcomeDependency {
                kind: source.kind,
                key: source.key.clone(),
                body: Some(body),
                placement: row.dependency_placement(),
            }))
        }
        OutcomeReadKind::Displaced => {
            let Some(suffix) = source.key.strip_prefix(DISPLACED.decl().prefix) else {
                return Ok(None);
            };
            let Some(key) = OutcomeRef::decode_key(suffix) else {
                return Ok(None);
            };
            Ok(Some(marker_dependency(
                source.key.clone(),
                DISPLACED.get_bytes(&vault.store, txn, &key)?,
            )))
        }
    }
}
