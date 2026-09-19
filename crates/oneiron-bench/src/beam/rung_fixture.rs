//! Deterministic-arm conformance across first attach and remote rung changes.
use super::{BeamResult, util::beam_vault_config};
use oneiron::embed::{
    EgressDecision, EgressPredicate, Embedder, EmbedderLocality, PendingEmbeddingInput,
    PendingEmbeddingReconciler, RemoteRung,
};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use serde::Serialize;
use std::{path::Path, sync::Arc};
struct FixtureEmbedder {
    locality: EmbedderLocality,
    fail: bool,
}
impl Embedder for FixtureEmbedder {
    fn model_id(&self) -> &str {
        "oneiron/eval-contract@v1"
    }
    fn dimensions(&self) -> usize {
        4
    }
    fn locality(&self) -> EmbedderLocality {
        self.locality
    }
    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        if self.fail {
            return Err(oneiron::Error::InvalidConfig(
                "fixture remote unavailable".into(),
            ));
        }
        Ok(inputs.iter().map(|_| vec![1.0, 0.0, 0.0, 0.0]).collect())
    }
}
struct HostAllows;
impl EgressPredicate for HostAllows {
    fn decide(&self, _input: &PendingEmbeddingInput) -> EgressDecision {
        EgressDecision::Allow
    }
}
#[derive(Debug, Serialize)]
pub(super) struct RungReport {
    pub before: Vec<String>,
    pub local: Vec<String>,
    pub remote: Vec<String>,
    pub fallback: Vec<String>,
}
fn ids(vault: &Vault) -> oneiron::Result<Vec<String>> {
    Ok(vault
        .query()
        .search_text("rung transition", 3)
        .limit(3)
        .run()?
        .iter()
        .map(|e| e.id.to_hex())
        .collect())
}
fn put_claim(vault: &Vault, id: &EntityId, subject: EntityId, text: &str) -> oneiron::Result<()> {
    let candidate = ClaimCandidate::new(
        "test.rung",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        0.9,
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(subject, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from("rung-transition"),
        )]))?,
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(id, candidate, &envelope, TimeRange { start: 1, end: 1 }, 1)
        .text(id, &[("val", text)])
        .commit()?;
    Ok(())
}
pub(super) fn run(_path: &Path) -> BeamResult<RungReport> {
    let dir = tempfile::tempdir()?;
    let mut config = beam_vault_config();
    config.embedding_model = None;
    let subject = EntityId::now();
    let claim_ids = [EntityId::now(), EntityId::now(), EntityId::now()];
    let before = {
        let vault = Vault::open(dir.path(), config)?;
        vault.put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({"name":"fixture subject"}))?,
        )?;
        for (index, id) in claim_ids.iter().enumerate() {
            put_claim(&vault, id, subject, &format!("rung transition {index}"))?;
        }
        ids(&vault)?
    };
    let vault = Arc::new(Vault::open(dir.path(), beam_vault_config())?);
    if vault.cold_attach_embedder()? != 3 {
        return Err(super::BeamError::Comparability {
            reason: "cold attach did not queue every claim".into(),
        });
    }
    let local = PendingEmbeddingReconciler::new(
        vault.clone(),
        Arc::new(FixtureEmbedder {
            locality: EmbedderLocality::OnDevice,
            fail: false,
        }),
    );
    local.reconcile_once()?;
    let local_ids = ids(&vault)?;
    for (index, id) in claim_ids.iter().enumerate() {
        put_claim(
            &vault,
            id,
            subject,
            &format!("rung transition {index} remote"),
        )?;
    }
    let remote = PendingEmbeddingReconciler::new(
        vault.clone(),
        Arc::new(FixtureEmbedder {
            locality: EmbedderLocality::OnDevice,
            fail: false,
        }),
    )
    .with_remote_rung(RemoteRung::new(
        Arc::new(FixtureEmbedder {
            locality: EmbedderLocality::OwnerServer,
            fail: false,
        }),
        Arc::new(HostAllows),
    ))?;
    remote.reconcile_once()?;
    let remote_ids = ids(&vault)?;
    for (index, id) in claim_ids.iter().enumerate() {
        put_claim(
            &vault,
            id,
            subject,
            &format!("rung transition {index} fallback"),
        )?;
    }
    let fallback = PendingEmbeddingReconciler::new(
        vault.clone(),
        Arc::new(FixtureEmbedder {
            locality: EmbedderLocality::OnDevice,
            fail: false,
        }),
    )
    .with_remote_rung(RemoteRung::new(
        Arc::new(FixtureEmbedder {
            locality: EmbedderLocality::OwnerServer,
            fail: true,
        }),
        Arc::new(HostAllows),
    ))?;
    fallback.reconcile_once()?;
    let fallback_ids = ids(&vault)?;
    Ok(RungReport {
        before,
        local: local_ids,
        remote: remote_ids,
        fallback: fallback_ids,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_arm_survives_cold_attach_remote_and_local_fallback() {
        let report = run(Path::new("fixture")).unwrap();
        assert_eq!(report.before.len(), 3);
        assert_eq!(report.before, report.local);
        assert_eq!(report.local, report.remote);
        assert_eq!(report.remote, report.fallback);
    }
}
