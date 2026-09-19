//! Signed host-scheduled T1 runs. Broken/unsigned output is silent, never authority.
use super::{
    DeterministicDetector, DiagnosticEvent, DiagnosticWorkingSet, MAX_EVENTS_PER_RUN,
    decode_diagnostic_event_body, diagnostic_event_id, encode_diagnostic_event_body,
};
use crate::{EntityId, Error, Result, Vault};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDetectorRun {
    pub instance: String,
    pub run_ref: String,
    pub public_key: [u8; 32],
    pub event_bodies: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}
impl SignedDetectorRun {
    fn transcript(&self) -> Vec<u8> {
        let mut out = b"oneiron/self-heal/detector-run/v1".to_vec();
        for bytes in [
            self.instance.as_bytes(),
            self.run_ref.as_bytes(),
            &self.public_key,
        ] {
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        out.extend_from_slice(&(self.event_bodies.len() as u64).to_be_bytes());
        for body in &self.event_bodies {
            out.extend_from_slice(&(body.len() as u64).to_be_bytes());
            out.extend_from_slice(body);
        }
        out
    }
}
impl Vault {
    /// The scheduled engine instance signs exactly the validated detector output.
    pub fn sign_detector_run(
        &self,
        instance: &str,
        input: &DiagnosticWorkingSet<'_>,
        detectors: &[&dyn DeterministicDetector],
    ) -> Result<SignedDetectorRun> {
        super::validate_token(instance, "invalid scheduled detector instance")?;
        super::validate_working_set(input)?;
        let mut event_bodies = Vec::new();
        for detector in detectors {
            for event in detector.detect(input) {
                if event.detector_id != detector.detector_id() {
                    return Err(Error::InvariantViolation("detector identity mismatch"));
                }
                event_bodies.push(encode_diagnostic_event_body(&event)?);
                if event_bodies.len() > MAX_EVENTS_PER_RUN {
                    return Err(Error::InvariantViolation("detector event limit"));
                }
            }
        }
        event_bodies.sort();
        event_bodies.dedup();
        let identity = crate::identity::ensure_device_identity(self)?;
        let mut run = SignedDetectorRun {
            instance: instance.into(),
            run_ref: input.scope_ref.into(),
            public_key: identity.signing_key.verifying_key().to_bytes(),
            event_bodies,
            signature: vec![],
        };
        run.signature = identity
            .signing_key
            .sign(&run.transcript())
            .to_bytes()
            .to_vec();
        Ok(run)
    }
    fn verified_run(
        &self,
        run: &SignedDetectorRun,
    ) -> Result<Option<Vec<(EntityId, DiagnosticEvent)>>> {
        if super::validate_token(&run.instance, "invalid instance").is_err()
            || super::validate_ref(&run.run_ref).is_err()
            || run.event_bodies.len() > MAX_EVENTS_PER_RUN
        {
            return Ok(None);
        }
        let txn = self.store.env.read_txn()?;
        if !self
            .store
            .sync_state
            .get(&txn, crate::identity::KEY_DEVICE_PK)?
            .is_some_and(|pk| pk.as_ref() == run.public_key)
        {
            return Ok(None);
        }
        let Ok(key) = VerifyingKey::from_bytes(&run.public_key) else {
            return Ok(None);
        };
        let Ok(signature) = Signature::from_slice(&run.signature) else {
            return Ok(None);
        };
        if key.verify_strict(&run.transcript(), &signature).is_err() {
            return Ok(None);
        }
        let mut events = Vec::new();
        for body in &run.event_bodies {
            let Ok(event) = decode_diagnostic_event_body(body) else {
                return Ok(None);
            };
            if encode_diagnostic_event_body(&event).ok().as_ref() != Some(body) {
                return Ok(None);
            }
            events.push((diagnostic_event_id(&event.detector_id, body), event));
        }
        Ok(Some(events))
    }
    /// Unsigned, foreign-device, malformed and tampered runs persist nothing.
    pub fn accept_signed_detector_run(&self, run: &SignedDetectorRun) -> Result<Vec<EntityId>> {
        let Some(events) = self.verified_run(run)? else {
            return Ok(vec![]);
        };
        // Staging validates the complete run before the first entity is emitted.
        let mut ids = Vec::new();
        for (id, event) in events {
            self.emit_diagnostic_event(&id, &event)?;
            ids.push(id);
        }
        let receipt = rmp_serde::to_vec_named(run)
            .map_err(|_| Error::InvariantViolation("detector receipt encode"))?;
        self.with_write_txn(|txn| {
            for id in &ids {
                let mut key = b"self_heal:signed:v1:".to_vec();
                key.extend_from_slice(id.as_bytes());
                self.store.vault_meta.put(txn, &key, &receipt)?;
            }
            Ok(())
        })?;
        Ok(ids)
    }
    /// Only locally verified scheduled tripwires can feed the future auto arm.
    /// This is eligibility, not permission to execute a repair.
    pub fn is_signed_tripwire(&self, id: &EntityId) -> Result<bool> {
        let mut key = b"self_heal:signed:v1:".to_vec();
        key.extend_from_slice(id.as_bytes());
        let raw = {
            let txn = self.store.env.read_txn()?;
            self.store.vault_meta.get(&txn, &key)?.map(|v| v.to_vec())
        };
        let Some(raw) = raw else {
            return Ok(false);
        };
        let Ok(run) = rmp_serde::from_slice::<SignedDetectorRun>(&raw) else {
            return Ok(false);
        };
        Ok(self
            .verified_run(&run)?
            .is_some_and(|events| events.iter().any(|(event_id, _)| event_id == id)))
    }
}
