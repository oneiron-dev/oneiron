//! Adopting an authenticated handoff closure as the trusted pin.

use super::*;

/// Adopt a host/pairing-authenticated exact closure. The untrusted packet
/// cannot select its own signer, scope, predecessor pin, previous heads or
/// challenge. Its whole chain and every signed CLAIM control the chain names
/// must already be resident and verified.
impl Vault {
    pub fn adopt_machine_history_handoff(
        &self,
        target: EntityId,
        packet: &ClaimHistoryHandoff,
        pin: &ClaimHistoryHandoffPin<'_>,
    ) -> Result<VerifiedClaimHistoryHandoff> {
        let mut txn = self.store.env.write_txn()?;
        let verified = self.adopt_machine_history_handoff_in_txn(
            &mut txn,
            target,
            packet,
            pin,
            Succession::Strict,
            &StoreRows,
        )?;
        txn.commit()?;
        Ok(verified)
    }

    /// The one adoption core, in the caller's writer: verify `packet`'s
    /// whole chain and closure against `pin`, check it succeeds the stored
    /// pin as `succession` says, store it, and heal the live CLAIM row under
    /// it. The history's controls are read through `source`. On an error the
    /// caller drops whatever this staged.
    pub(crate) fn adopt_machine_history_handoff_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        target: EntityId,
        packet: &ClaimHistoryHandoff,
        pin: &ClaimHistoryHandoffPin<'_>,
        succession: Succession,
        source: &dyn ControlRows,
    ) -> Result<VerifiedClaimHistoryHandoff> {
        // The candidate's own chain names the rows: its whole history, not
        // its delta and not the old pin's.
        let rows = machine_history_rows_at(source, &self.store, txn, target, packet)?;
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let original = super::super::decode_claim_body(&rows.birth.initial_body, true)?;
        let exact = packet.births.len() == 1
            && packet.births[0].id == target
            && packet.births[0].digest == rows.birth.digest
            && packet.vault_id == rows.birth.vault_id
            && packet.scope == super::super::history_store::machine_history_scope_bytes(&original)?
            && events_match_chain(&rows);
        // A local storage error inside the callback leaves through this.
        let mut local = None;
        let read: &heed::RoTxn<'_> = txn;
        let verdict = verify_claim_history_handoff(packet, pin, |handoff| {
            if !exact
                || fold.vault_id != Some(handoff.vault_id)
                || !fold.valid_entries.contains(&handoff.authority_head)
            {
                return HandoffStanding::MissingParents;
            }
            // The chain's shape already proved itself above: a wrong chain
            // refused there. An absent ancestor or authority not yet held
            // waits; a bad signature or vault refuses (FIX 3823).
            let chain = match verified_handoff_chain_from(source, &self.store, read, handoff, &fold)
            {
                Ok(chain) => chain,
                Err(error) if chain_awaits(&error) => return HandoffStanding::MissingParents,
                Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                    return HandoffStanding::Refused;
                }
                Err(error) => {
                    local = Some(error);
                    return HandoffStanding::MissingParents;
                }
            };
            if !chain
                .iter()
                .any(|packet| packet.births == handoff.births && packet.scope == handoff.scope)
            {
                return HandoffStanding::Refused;
            }
            let Some(root) = fold.roster.get(&handoff.signer) else {
                return HandoffStanding::Refused;
            };
            if root.revoked || root.roles & ROLE_OWNER == 0 {
                return HandoffStanding::Refused;
            }
            HandoffStanding::OwnerAndComplete
        });
        if let Some(error) = local {
            return Err(error);
        }
        let HandoffVerification::Verified(verified) = verdict else {
            return Err(match verdict {
                HandoffVerification::MissingParents => missing(),
                _ => bad(),
            });
        };
        let bytes = packet.encode().map_err(|_| bad())?;
        let stored = self
            .store
            .vault_meta
            .get(txn, &pin_key(target))?
            .map(std::borrow::Cow::into_owned);
        match succession {
            Succession::Strict => {
                let previous = stored.ok_or_else(missing)?;
                let prior = ClaimHistoryHandoff::decode(&previous).map_err(|_| bad())?;
                if bytes != previous
                    && (packet.previous_handoff_hash
                        != Some(prior.content_hash().map_err(|_| bad())?)
                        || pin.previous_heads != prior.heads.as_slice())
                {
                    return Err(bad());
                }
            }
            // The stored pin is a packet of the candidate's verified chain,
            // or the candidate is another branch and the pin stays.
            Succession::OwnReceive => {
                if let Some(previous) = stored
                    && !rows
                        .chain
                        .iter()
                        .any(|link| link.encode().is_ok_and(|encoded| encoded == previous))
                {
                    return Err(bad());
                }
            }
        }
        self.store.vault_meta.put(txn, &pin_key(target), &bytes)?;
        // The live claim id is a derived view. Heal a stale or missing LWW
        // snapshot under the SAME authenticated pin before publishing it.
        let projection = resolved_machine_history_from(source, &self.store, txn, &fold, target)?;
        let projected = project_machine_claim(&projection);
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &target)?
        else {
            // Own receive pins a verified history before its live row lands,
            // so the row is admitted under the pin when it does.
            return match succession {
                Succession::OwnReceive => Ok(verified),
                Succession::Strict => Err(missing()),
            };
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("machine projection header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(bad());
        }
        let previous = super::super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        // A superseded history's same-id successor owns the live row.
        let successor = projection.admits_successor_by(crate::memory::claim_author(&previous))
            && !crate::authority::machine_claim_needs_history(&self.store, txn, &previous)?;
        if previous != projected && !successor {
            crate::batch::apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                txn,
                vec![crate::batch::BatchOp::Put {
                    id: target,
                    entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                    occurred: crate::TimeRange {
                        start: header.occurred_start,
                        end: projected
                            .valid_to
                            .unwrap_or(header.occurred_end)
                            .max(header.occurred_start),
                    },
                    learned_at: header.learned_at,
                    data: super::super::encode_claim_body(&projected)?,
                    allow_maintenance: true,
                    allow_reserved_predicate: true,
                    hub_sync_imported: false,
                }],
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                false,
            )?;
        }
        Ok(verified)
    }
}
