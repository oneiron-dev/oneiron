//! Code-emission admission and the deterministic admission record the free lane cites.

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::TimeRange;
use crate::code_run::consent;
use crate::code_run::consent::CodeSourceTrust;
use crate::code_run::storage::ExecutorStorage;
use crate::code_sandbox::SandboxGuestTier;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::vault::LiveEntityRow;

use super::HostSelfDispatcher;
use crate::error::CodeError;

/// Domain of the code-emission admission record's id, kept separate from the
/// emission's own identity so a record handle can never collide with — or be
/// mistaken for — the claim, edge or gate ids of the write it witnesses.
const CODE_EMISSION_RECORD_ID_DOMAIN: &[u8] = b"oneiron:self-code-emission-record:v1";

/// Body keys of the code-emission admission record: what the host DECIDED
/// (lane inputs) and which run it decided for.
const CODE_EMISSION_RECORD_KEYS: [&str; 5] =
    ["kind", "tier", "source_trust", "dreamer_run_id", "run_ref"];

impl HostSelfDispatcher<'_> {
    pub(super) fn code_emission_admission(&self) -> Result<Option<consent::CodeEmissionAdmission>> {
        let Some((emission, review)) = &self.code_emission else {
            return Ok(None);
        };
        let review_input = review
            .as_ref()
            .map(consent::ReviewContext::as_input)
            .transpose()?;
        let emission_record = self.ensure_code_emission_record(emission)?;
        consent::admit_code_emission(
            emission.tier,
            emission.source_trust,
            emission.dreamer_run_id.as_deref(),
            &emission.touched_symbols,
            review_input.as_ref(),
            emission_record,
        )
        .map(Some)
    }

    /// Persists the free lane's evidence — the host's own admission decision —
    /// and returns the record's handle.
    ///
    /// The free lane has no model-authored evidence to cite, but it does have a
    /// truthful host fact: THIS run, at THIS tier and source trust, was admitted
    /// to write. That fact lives only in memory until it is persisted here, as
    /// one typed entity with a deterministic domain-separated id, in its OWN
    /// transaction — committed before `dispatch_memory_put_claim` or
    /// `dispatch_memory_write_fixture` opens the gate that cites it, so the
    /// door's in-transaction resolver always sees it.
    ///
    /// Minting is idempotent by construction: the id is a function of the
    /// admission identity, so a second dispatch of the same admission finds the
    /// record already there and cites it rather than writing a duplicate. What
    /// it cites is VERIFIED, never assumed from a surviving row: reuse requires
    /// a live entity (not an ARCH-0038 soft-delete shell) of exactly
    /// `ENTITY_TYPE_ASSET` whose body is byte-equal to this admission's own
    /// record body. Any other occupant of the id — deleted, foreign type, or
    /// divergent body — is a host-invariant refusal here, never a citation and
    /// never a remint over the id. The put is a direct typed entity write,
    /// NEVER a claim or batch candidate, so it adds no gate decision and no
    /// pending-consent row.
    ///
    /// The review lane returns `None`: its evidence is the blast-radius walk's
    /// own artifact refs, and a record it would never cite is a write nobody
    /// asked for.
    pub(super) fn ensure_code_emission_record(
        &self,
        emission: &consent::CodeEmissionContext,
    ) -> Result<Option<EntityId>> {
        if consent::consent_lane_for(emission.tier, emission.source_trust)
            != consent::ConsentLane::Free
        {
            return Ok(None);
        }
        // Same trim and same refusal the admission itself makes, so a run
        // without a handle is refused before anything is written.
        let dreamer_run_id = emission
            .dreamer_run_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .ok_or(Error::Code(CodeError::CodeEmissionMissingDreamerRunId))?;
        // A code-emission context is bound at construction to the canonical
        // vault (`with_code_emission_context`), and the session arm hands out
        // no entity door: an admission arriving on it would be a binding this
        // dispatcher never made.
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(Error::InvariantViolation(
                "code emission admission requires canonical storage",
            ));
        };
        let record_id = code_emission_record_id(
            emission.tier,
            emission.source_trust,
            dreamer_run_id,
            &self.run_ref,
        )?;
        // The record's identity IS its body, so the expected bytes are
        // computed once: they verify an occupant of the deterministic id, and
        // they are what an absent id is minted with.
        let expected_body = code_emission_record_body(
            emission.tier,
            emission.source_trust,
            dreamer_run_id,
            &self.run_ref,
        )?;
        match vault.live_entity_row(&record_id)? {
            // Nothing occupies the id: mint, exactly as before.
            LiveEntityRow::Absent => {}
            // The record this admission would have written is already there,
            // proven by its own bytes rather than by a surviving header.
            LiveEntityRow::Live { entity_type, body }
                if entity_type == ENTITY_TYPE_ASSET && body == expected_body =>
            {
                return Ok(Some(record_id));
            }
            // A soft-delete shell, a foreign entity type, or a divergent body
            // is NOT this admission's record. Citing it would make the free
            // lane's only evidence a lie, and reminting over it would
            // resurrect a tombstoned entity (ARCH-0038) or overwrite an
            // entity nobody asked to lose — so the dispatch fails closed here,
            // before any claim, Proposed row, pending consent or gate receipt
            // exists.
            LiveEntityRow::Live { .. } | LiveEntityRow::DeletedShell => {
                return Err(Error::InvariantViolation(
                    "code emission record id holds a deleted or divergent entity",
                ));
            }
        }
        let now = crate::unix_seconds_now();
        vault.put_entity(
            &record_id,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &expected_body,
        )?;
        Ok(Some(record_id))
    }

    pub(super) fn non_candidate_code_emission_admission(
        &self,
    ) -> Result<Option<consent::CodeEmissionAdmission>> {
        let Some((emission, _)) = &self.code_emission else {
            return Ok(None);
        };
        let dreamer_run_id = emission
            .dreamer_run_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .ok_or(Error::Code(CodeError::CodeEmissionMissingDreamerRunId))?;
        Ok(Some(consent::CodeEmissionAdmission {
            lane: consent::consent_lane_for(emission.tier, emission.source_trust),
            dreamer_run_id: dreamer_run_id.to_owned(),
            candidate_evidence: None,
            // The memory VERBS this admission stamps persist no claim
            // candidate, so there is no candidate evidence for a record to be
            // cited by, and nothing to mint.
            emission_record: None,
        }))
    }
}

/// The code-emission admission record's id: a domain-separated digest over the
/// admission identity (tier, source trust, Dreamer run, host run ref).
///
/// Deterministic so the record is minted at most once per admission, and
/// length-prefixed so two different identities can never hash to the same
/// material. A digest that lands on a reserved sentinel is re-salted rather
/// than truncated into one.
fn code_emission_record_id(
    tier: SandboxGuestTier,
    source_trust: CodeSourceTrust,
    dreamer_run_id: &str,
    run_ref: &str,
) -> Result<EntityId> {
    for salt in 0..=u8::MAX {
        let mut hasher = Sha256::new();
        hasher.update(CODE_EMISSION_RECORD_ID_DOMAIN);
        hasher.update([salt]);
        for part in [
            tier.as_str().as_bytes(),
            source_trust.as_str().as_bytes(),
            dreamer_run_id.as_bytes(),
            run_ref.as_bytes(),
        ] {
            let len = u64::try_from(part.len())
                .map_err(|_| Error::ArithmeticOverflow("code emission record id material"))?;
            hasher.update(len.to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "code emission record id derivation failed",
    ))
}

/// The record body: exactly the admission identity its id is derived from, so
/// a reader of the entity can check what the host decided rather than trust the
/// handle.
fn code_emission_record_body(
    tier: SandboxGuestTier,
    source_trust: CodeSourceTrust,
    dreamer_run_id: &str,
    run_ref: &str,
) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[0]),
            Value::from(consent::CODE_EMISSION_EVIDENCE_KIND),
        ),
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[1]),
            Value::from(tier.as_str()),
        ),
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[2]),
            Value::from(source_trust.as_str()),
        ),
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[3]),
            Value::from(dreamer_run_id),
        ),
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[4]),
            Value::from(run_ref),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &value)
        .map_err(|_| Error::InvariantViolation("code emission record encode failed"))?;
    Ok(encoded)
}
