//! Immutable, content-addressed centroid inputs beside vault-local telemetry.
//! Current vectors can change; replay never consults them.
use super::{
    DiagnosticSourceKind,
    tiered::{DetectorPolicy, ProposedDiagnostic, ProposedTier, propose, valid_runs},
};
use crate::{EntityId, Error, Result, Vault, store::RetrievalRunRecord};
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"self_heal:centroid_evidence:v1:";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct VectorEvidence {
    id: [u8; 16],
    vector: Vec<f32>,
}

/// A versioned, immutable copy of every byte used by the centroid verdict.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct CentroidEvidence {
    version: u8,
    run: RetrievalRunRecord,
    candidate: VectorEvidence,
    labeled: Vec<VectorEvidence>,
    min_similarity: f32,
    similarity: f64,
}

/// The exact historic inputs and recomputed verdict, independent of current vectors.
#[derive(Clone, Debug)]
pub struct CentroidReplay {
    pub run: RetrievalRunRecord,
    pub candidate: EntityId,
    pub candidate_vector: Vec<f32>,
    pub labeled: Vec<(EntityId, Vec<f32>)>,
    pub min_similarity: f32,
    pub similarity: f64,
    pub matched: bool,
}

fn key(hash: &[u8; 32]) -> Vec<u8> {
    [PREFIX, hash].concat()
}

/// Read-time custody of the immutable centroid inputs used by a tier-1
/// observation. The producer performs the full replay check before minting.
pub(crate) fn snapshot_live_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    hash: &[u8; 32],
) -> Result<bool> {
    let Some(raw) = store.vault_meta.get(txn, &key(hash))? else {
        return Ok(false);
    };
    if blake3::hash(&raw).as_bytes() != hash {
        return Ok(false);
    }
    let evidence: CentroidEvidence =
        rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("centroid evidence body"))?;
    let canonical = rmp_serde::to_vec_named(&evidence)
        .map_err(|_| Error::CorruptedIndex("centroid evidence body"))?;
    Ok(evidence.version == 1 && raw.as_ref() == canonical)
}

fn similarity(candidate: &[f32], labeled: &[VectorEvidence]) -> Option<f64> {
    if candidate.is_empty() || labeled.is_empty() || candidate.iter().any(|x| !x.is_finite()) {
        return None;
    }
    let mut centroid = vec![0_f64; candidate.len()];
    for entry in labeled {
        if entry.vector.len() != centroid.len() || entry.vector.iter().any(|x| !x.is_finite()) {
            return None;
        }
        for (sum, value) in centroid.iter_mut().zip(&entry.vector) {
            *sum += f64::from(*value);
        }
    }
    let dot: f64 = centroid
        .iter()
        .zip(candidate)
        .map(|(a, b)| *a * f64::from(*b))
        .sum();
    let cn: f64 = centroid.iter().map(|x| x * x).sum();
    let vn: f64 = candidate
        .iter()
        .map(|x| f64::from(*x) * f64::from(*x))
        .sum();
    if cn <= 0.0 || vn <= 0.0 || !cn.is_finite() || !vn.is_finite() {
        return None;
    }
    let score = dot / (cn.sqrt() * vn.sqrt());
    score.is_finite().then_some(score)
}

impl Vault {
    /// T2a reads existing vectors, pins their bytes and threshold, then emits
    /// a proposal whose replay hash addresses that immutable snapshot.
    pub fn classify_centroid(
        &self,
        policy: &DetectorPolicy,
        labeled: &[EntityId],
        candidate: EntityId,
        run: &RetrievalRunRecord,
        min_similarity: f32,
    ) -> Result<Option<ProposedDiagnostic>> {
        policy.validate()?;
        valid_runs(self, std::slice::from_ref(run), 1)?;
        // The event's evidence_refs include the run and candidate in addition
        // to the labels; cap before persisting the immutable snapshot.
        if labeled.is_empty()
            || labeled.len() > 62
            || !min_similarity.is_finite()
            || !(-1.0..=1.0).contains(&min_similarity)
        {
            return Err(Error::InvalidConfig("invalid centroid detector".into()));
        }
        if !run.result_ids.iter().any(|id| id == candidate.as_bytes()) {
            return Err(Error::InvalidConfig(
                "candidate is not in retrieval run".into(),
            ));
        }
        let Some(vector) = self.get_vector(&candidate)? else {
            return Ok(None);
        };
        let mut labeled_vectors = Vec::with_capacity(labeled.len());
        for id in labeled {
            let Some(vector) = self.get_vector(id)? else {
                return Ok(None);
            };
            labeled_vectors.push(VectorEvidence {
                id: *id.as_bytes(),
                vector,
            });
        }
        labeled_vectors.sort_by_key(|item| item.id);
        if labeled_vectors
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id)
        {
            return Err(Error::InvalidConfig("duplicate centroid label".into()));
        }
        let Some(score) = similarity(&vector, &labeled_vectors) else {
            return Ok(None);
        };
        if score < f64::from(min_similarity) {
            return Ok(None);
        }
        let snapshot = CentroidEvidence {
            version: 1,
            run: run.clone(),
            candidate: VectorEvidence {
                id: *candidate.as_bytes(),
                vector,
            },
            labeled: labeled_vectors,
            min_similarity,
            similarity: score,
        };
        let bytes = rmp_serde::to_vec_named(&snapshot)
            .map_err(|_| Error::InvariantViolation("centroid evidence encode"))?;
        let hash = *blake3::hash(&bytes).as_bytes();
        self.with_write_txn(|txn| {
            let evidence_key = key(&hash);
            if let Some(prior) = self.store.vault_meta.get(txn, &evidence_key)? {
                if prior.as_ref() != bytes {
                    return Err(Error::CorruptedIndex("centroid evidence collision"));
                }
            } else {
                self.store.vault_meta.put(txn, &evidence_key, &bytes)?;
            }
            Ok(())
        })?;
        let mut refs = vec![EntityId::from_bytes(run.run_id.as_bytes())?, candidate];
        refs.extend(labeled.iter().copied());
        refs.sort();
        refs.dedup();
        propose(
            self,
            ProposedTier::Centroid,
            policy,
            std::slice::from_ref(run),
            Some((hash, refs)),
        )
    }

    /// Reconstructs the exact inputs used by a stored centroid finding.
    /// Missing or modified historical evidence is an error, never a fallback to
    /// today's vectors. This cannot sign or authorize a T1 detector run.
    pub fn replay_centroid_finding(&self, event_id: &EntityId) -> Result<CentroidReplay> {
        let event = self.reviewed_diagnostic(event_id)?;
        if event.source != DiagnosticSourceKind::RetrievalTelemetry
            || !event.detector_id.starts_with("t2a.")
        {
            return Err(Error::InvalidConfig("not a centroid finding".into()));
        }
        let txn = self.store.env.read_txn()?;
        let raw = self
            .store
            .vault_meta
            .get(&txn, &key(&event.replay.content_hash))?
            .ok_or(Error::CorruptedIndex("centroid evidence missing"))?;
        if *blake3::hash(&raw).as_bytes() != event.replay.content_hash {
            return Err(Error::CorruptedIndex("centroid evidence hash"));
        }
        let evidence: CentroidEvidence = rmp_serde::from_slice(&raw)
            .map_err(|_| Error::CorruptedIndex("centroid evidence body"))?;
        let canonical = rmp_serde::to_vec_named(&evidence)
            .map_err(|_| Error::CorruptedIndex("centroid evidence body"))?;
        if evidence.version != 1 || raw.as_ref() != canonical {
            return Err(Error::CorruptedIndex("centroid evidence canonical form"));
        }
        let mut refs = vec![
            EntityId::from_bytes(evidence.run.run_id.as_bytes())?,
            EntityId::from_bytes(evidence.candidate.id)?,
        ];
        refs.extend(
            evidence
                .labeled
                .iter()
                .map(|item| EntityId::from_bytes(item.id))
                .collect::<Result<Vec<_>>>()?,
        );
        refs.sort();
        refs.dedup();
        let score = similarity(&evidence.candidate.vector, &evidence.labeled)
            .ok_or(Error::CorruptedIndex("centroid evidence vectors"))?;
        if refs != event.evidence_refs
            || evidence.run.version != 0
            || event.replay.run_ref.as_deref() != Some(evidence.run.run_id.to_hex().as_str())
            || score.to_bits() != evidence.similarity.to_bits()
            || !evidence.min_similarity.is_finite()
            || !(-1.0..=1.0).contains(&evidence.min_similarity)
            || score < f64::from(evidence.min_similarity)
            || !evidence.run.result_ids.contains(&evidence.candidate.id)
            || evidence.labeled.is_empty()
            || evidence
                .labeled
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(Error::CorruptedIndex("centroid evidence mismatch"));
        }
        Ok(CentroidReplay {
            run: evidence.run,
            candidate: EntityId::from_bytes(evidence.candidate.id)?,
            candidate_vector: evidence.candidate.vector,
            labeled: evidence
                .labeled
                .into_iter()
                .map(|item| Ok((EntityId::from_bytes(item.id)?, item.vector)))
                .collect::<Result<Vec<_>>>()?,
            min_similarity: evidence.min_similarity,
            similarity: score,
            matched: true,
        })
    }
}
