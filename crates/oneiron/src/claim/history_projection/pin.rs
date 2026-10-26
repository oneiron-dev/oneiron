//! The trusted pin: its key, and the door that pins a host packet before its claim bytes arrive.

use super::*;

pub(crate) const PIN_PREFIX: &[u8] = b"claim:machine-history-pin:v1:";

pub(crate) fn pin_key(target: EntityId) -> Vec<u8> {
    [PIN_PREFIX, target.as_bytes()].concat()
}

/// Pin a challenge-bound host packet before receiving any claim bytes.
/// Its rows may still be missing; the pin only WITHHOLDS that target until
/// the full signed closure is fetched and adopted. A peer cannot assert an
/// empty history or select its own signer through this door. A successor of
/// the stored pin must name that pin's heads as its previous heads.
impl Vault {
    pub fn pin_machine_history_handoff_pending(
        &self,
        target: EntityId,
        packet: &ClaimHistoryHandoff,
        pin: &ClaimHistoryHandoffPin<'_>,
        issuer: &crate::authority::HostSlipIssuer,
    ) -> Result<[u8; 32]> {
        if packet.births.len() != 1
            || packet.births[0].id != target
            || packet.signer != issuer.public_key()
        {
            return Err(bad());
        }
        let txn = self.store.env.read_txn()?;
        let (vault_id, current_head) = crate::authority::machine_history_host_context(
            &self.store,
            self.privacy_posture(),
            &txn,
            &issuer.public_key(),
        )?;
        if packet.vault_id != vault_id
            || !self
                .authority_fold_readonly_in_txn(&txn)?
                .valid_entries
                .contains(&packet.authority_head)
            || packet.authority_head != current_head
                && !crate::authority::machine_history_authority_descends(
                    &self.store,
                    &txn,
                    &packet.authority_head,
                    &current_head,
                )?
        {
            return Err(bad());
        }
        drop(txn);
        let verdict =
            verify_claim_history_handoff(packet, pin, |_| HandoffStanding::MissingParents);
        if !matches!(verdict, HandoffVerification::MissingParents) {
            return Err(bad());
        }
        let hash = packet.content_hash().map_err(|_| bad())?;
        let mut txn = self.store.env.write_txn()?;
        if let Some(raw) = self.store.vault_meta.get(&txn, &pin_key(target))? {
            let previous = ClaimHistoryHandoff::decode(&raw).map_err(|_| bad())?;
            let previous_hash = previous.content_hash().map_err(|_| bad())?;
            if hash != previous_hash
                && (packet.previous_handoff_hash != Some(previous_hash)
                    || pin.previous_heads != previous.heads.as_slice())
            {
                return Err(bad());
            }
        }
        self.store.vault_meta.put(
            &mut txn,
            &pin_key(target),
            &packet.encode().map_err(|_| bad())?,
        )?;
        txn.commit()?;
        Ok(hash)
    }
}
