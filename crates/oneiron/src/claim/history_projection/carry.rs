//! The in-chain re-root carry-forward: an empty delta signed under the new authority head.

use super::*;

/// Explicit in-chain re-root carry-forward: the current host signs an empty
/// delta on the exact previously trusted chain under its NEW authority head,
/// with the same birth anchor and heads. An event authored later by the
/// retired root is outside this chain and cannot gain historical standing by
/// claiming an old timestamp/frontier. The packet is a plain `Handoff`: only
/// `re_root_host` signs a `ReRootCarry`, the same empty delta.
impl Vault {
    pub fn carry_machine_history_after_re_root(
        &self,
        target: EntityId,
        issuer: &crate::authority::HostSlipIssuer,
        challenge: [u8; 32],
    ) -> Result<[u8; 32]> {
        let mut txn = self.store.env.write_txn()?;
        let hash = self.carry_machine_history_in_txn(
            &mut txn,
            target,
            issuer,
            challenge,
            HandoffKind::Handoff,
        )?;
        txn.commit()?;
        Ok(hash)
    }

    pub(crate) fn carry_machine_history_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        target: EntityId,
        issuer: &crate::authority::HostSlipIssuer,
        challenge: [u8; 32],
        kind: HandoffKind,
    ) -> Result<[u8; 32]> {
        let rows = machine_history_rows(&self.store, txn, target)?;
        let prior = trusted_machine_handoff(&self.store, txn, target)?;
        let prior_hash = prior.content_hash().map_err(|_| bad())?;
        let (vault_id, authority_head) = crate::authority::machine_history_host_context(
            &self.store,
            self.privacy_posture(),
            txn,
            &issuer.public_key(),
        )?;
        if vault_id != rows.birth.vault_id
            || prior.vault_id != vault_id
            || prior.births.len() != 1
            || prior.births[0].id != target
            || prior.births[0].digest != rows.birth.digest
            || rows.transitions.len() != rows.events.len()
            || rows.events.iter().any(|event| {
                machine_claim_transition_event_hash(event)
                    .ok()
                    .is_none_or(|hash| !rows.transitions.contains_key(&hash))
            })
        {
            return Err(missing());
        }
        let original = super::super::decode_claim_body(&rows.birth.initial_body, true)?;
        if prior.scope != super::super::history_store::machine_history_scope_bytes(&original)? {
            return Err(bad());
        }
        let signature = crate::authority::AuthoritySignature {
            suite: prior.signer.suite(),
            public_key: prior.signer.clone(),
            signature: prior.signature.to_vec(),
        };
        if !crate::authority::verify_authority_signature(
            &signature,
            &prior.transcript().map_err(|_| bad())?,
        ) {
            return Err(bad());
        }
        let mut nonce = [0; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let previous_heads = prior.heads.clone();
        // An empty delta: the carry adds no transition, so the heads stay.
        let mut next = prior;
        next.kind = kind;
        next.transitions = Vec::new();
        next.authority_head = authority_head;
        next.previous_handoff_hash = Some(prior_hash);
        next.nonce = nonce;
        next.challenge = challenge;
        next.signer = issuer.public_key();
        next.signature = [0; 64];
        next.signature = issuer.sign_claim_handoff(&next.transcript().map_err(|_| bad())?);
        let pin = ClaimHistoryHandoffPin {
            vault_id: &vault_id,
            genesis_hash: &vault_id,
            expected_signer: &next.signer,
            scope: &next.scope,
            previous_handoff_hash: Some(prior_hash),
            previous_heads: &previous_heads,
            challenge: &challenge,
        };
        if !matches!(
            verify_claim_history_handoff(&next, &pin, |_| HandoffStanding::OwnerAndComplete),
            HandoffVerification::Verified(_)
        ) {
            return Err(bad());
        }
        let bytes = next.encode().map_err(|_| bad())?;
        let hash = next.content_hash().map_err(|_| bad())?;
        let id =
            EntityId::from_bytes(hash[..16].try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        let record = super::super::history_store::machine_history_claim(
            MachineHistoryKind::Handoff,
            target,
            &original,
            bytes.clone(),
        )?;
        let now = self.store.clock.now_recorded_at();
        crate::batch::apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![
                crate::batch::BatchOp::Put {
                    id,
                    entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                    occurred: crate::TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    data: super::super::encode_claim_body(&record)?,
                    allow_maintenance: false,
                    allow_reserved_predicate: true,
                    hub_sync_imported: false,
                },
                crate::batch::BatchOp::Edge {
                    src: id,
                    kind: crate::edge::EdgeKind::FacetOf,
                    tgt: original.scope_facet,
                    weight: 1.0,
                    vad: crate::affect::Vad::NEUTRAL,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            crate::batch::ApplyOpsGateMode::new(false, false),
        )?;
        self.store.vault_meta.put(txn, &pin_key(target), &bytes)?;
        Ok(hash)
    }
}
