//! `self.identity.settle` ([`Memory::identity_act_now`]): before an agent
//! acts on a person it knows by a name, the newest saved mention of that
//! name says who it is, or an act-now ask opens.

use super::*;

impl Memory<'_> {
    /// `self.identity.settle`: before an agent sends to, pays, invites or
    /// shares with a person it knows by a name, the newest saved mention of
    /// that name (in the conversation, when one is named) says who it is. A
    /// mention that names one entity, or that a hint settles, answers at
    /// once. An uncertain one opens an act-now ask the host decides first;
    /// once that reaches the person, the answer carries their choice card.
    /// One the host cannot decide that some owner cannot open, such as one
    /// raised from a member's own mailbox, reaches the person at once.
    pub fn identity_act_now(&self, input: &IdentityActNowRequest) -> MemoryResult<IdentityActNow> {
        let name = input.name.trim();
        if name.is_empty() {
            return Err(MemoryError::bad_request("name is not empty"));
        }
        let conversation = input
            .conversation
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()
            .map_err(|_| MemoryError::bad_request("conversation is 32 hex"))?;
        let copy = IdentityCardCopy {
            prompt: input.prompt.clone(),
            someone_new: input.someone_new.clone(),
            provisional: input.provisional.clone(),
        };
        let vault = self.vault();
        let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, name.len() as u64);
        let hits = vault.tagged_mentions_of_name(ENTITY_TYPE_PERSON, name)?;
        // The caller's own lane (FIX 8711): a mention, candidate or hint word
        // it does not read looks absent.
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let now = vault.now_recorded_at();
        let effect = input.effect;
        self.with_verified_actor_write_txn(|txn| {
            let admit = admission::Admit::in_txn(&lane, txn)?;
            let mut newest: Option<&crate::tagging::MentionHit> = None;
            for hit in &hits {
                if let Some(conversation) = &conversation
                    && crate::conversation_dag::conversation_of(&vault.store, txn, &hit.turn).ok()
                        != Some(*conversation)
                {
                    continue;
                }
                if newest.is_none_or(|held| hit.turn > held.turn)
                    && admit.reads_source(txn, &hit.turn, &hit.mention.message)?
                {
                    newest = Some(hit);
                }
            }
            let Some(hit) = newest else {
                return Ok(IdentityActNow::Unknown);
            };
            let mention = &hit.mention;
            let key = ask_key(&hit.turn, &mention.message, mention.start, mention.end);
            if let Some(held) = ASKS.get(&vault.store, txn, &key)? {
                let Some(seen) = admission::admitted_in_txn(vault, &admit, txn, held)? else {
                    return Ok(IdentityActNow::Unknown);
                };
                let mut held = seen.stored;
                if held.escalated_at.is_some() {
                    let options = options_in_txn(vault, txn, &seen.ask)?;
                    let card = serde_json::to_value(card(&key, &seen.ask, &options, &copy)?)
                        .map_err(|_| invalid("choice card encoding"))?;
                    return Ok(IdentityActNow::NeedsPerson {
                        ask: key_hex(&key),
                        card,
                    });
                }
                // A nightly ask, kept separate or not, is taken up for the
                // effect: decided now as an outbound effect's question.
                if held.reason == IdentityAskReason::Unsettled {
                    held.reason = IdentityAskReason::ActNow { effect };
                    held.retry_at = 0;
                    held.kept_separate_at = None;
                    // No membership sync (FIX 10376): a take-up stamps the
                    // reason, retry and kept-separate mark only, none of
                    // which the ask's erase reads.
                    ASKS.put(&vault.store, txn, &key, &held)?;
                }
                if undecidable_member_ask_in_txn(vault, txn, &held)? {
                    escalate_in_txn(vault, txn, &key, held, now)?;
                    let options = options_in_txn(vault, txn, &seen.ask)?;
                    let card = serde_json::to_value(card(&key, &seen.ask, &options, &copy)?)
                        .map_err(|_| invalid("choice card encoding"))?;
                    return Ok(IdentityActNow::NeedsPerson {
                        ask: key_hex(&key),
                        card,
                    });
                }
                return Ok(IdentityActNow::Deciding { ask: key_hex(&key) });
            }
            let current = crate::tagging::readable_view_in_txn(&vault.store, txn, &hit.turn)?
                .and_then(|tags| {
                    tags.mentions.into_iter().find(|each| {
                        each.message == mention.message
                            && each.start == mention.start
                            && each.end == mention.end
                    })
                });
            let Some(current) = current else {
                return Ok(IdentityActNow::Unknown);
            };
            let Some(text) =
                crate::tagging::message_text_in_txn(vault, txn, &hit.turn, &current.message)?
            else {
                return Ok(IdentityActNow::Unknown);
            };
            let Some(ask) = ask_for_mention_in_txn(
                vault,
                txn,
                &hit.turn,
                &current,
                &text,
                IdentityAskReason::ActNow { effect },
                now,
            )?
            else {
                // One entity answers only when the lane reads it, as it
                // stands: nothing here restores an archived one.
                if let [entity] = current.link.entities()
                    && admission::linked_in_txn(vault, &admit, txn, entity)?
                {
                    return Ok(IdentityActNow::Settled {
                        entity: entity.to_hex(),
                    });
                }
                return Ok(IdentityActNow::Unknown);
            };
            // The hint's settle answers the agent at once, and leaves the
            // Dreamer's receipt the owner reverts (FIX 3327): only from the
            // candidates and hint words the lane reads, on an ask whose spans
            // it reads.
            if let Some(seen) = admission::admitted_in_txn(vault, &admit, txn, ask.clone())?
                && let Some(entity) = hints::pick(&seen.hints, &seen.ask.candidates, &ask.context)
            {
                let entity = settle_undo::settle_in_txn(
                    vault,
                    txn,
                    &ask,
                    Answer::Is(entity),
                    (ClaimSource::Inferred, &dreamer_seal()),
                    now,
                )?;
                return Ok(IdentityActNow::Settled {
                    entity: entity.to_hex(),
                });
            }
            measure_ask(vault, &ask);
            index::sync_ask_membership(&vault.store, txn, &key, None, Some(&ask))?;
            ASKS.put(&vault.store, txn, &key, &ask)?;
            if undecidable_member_ask_in_txn(vault, txn, &ask)?
                && let Some(seen) = admission::admitted_in_txn(vault, &admit, txn, ask.clone())?
            {
                escalate_in_txn(vault, txn, &key, ask, now)?;
                let options = options_in_txn(vault, txn, &seen.ask)?;
                let card = serde_json::to_value(card(&key, &seen.ask, &options, &copy)?)
                    .map_err(|_| invalid("choice card encoding"))?;
                return Ok(IdentityActNow::NeedsPerson {
                    ask: key_hex(&key),
                    card,
                });
            }
            Ok(IdentityActNow::Deciding { ask: key_hex(&key) })
        })
    }
}

/// Whether an act-now `ask` goes to the person at once, as an abstention
/// sends it (RECIPIENT-NOTICE-READ-BY-ANY-READER): some live owner's lane
/// does not open it, so it goes to the people who can (`route`), and the
/// Dreamer's lane does not read it whole, so the host's ladder never takes
/// it up ([`Vault::identity_asks_due`]). An ask every owner opens waits for
/// the host, or for the owner's strip, as before.
fn undecidable_member_ask_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
) -> Result<bool> {
    if route::route_in_txn(vault, txn, ask)?
        .closed_owners
        .is_empty()
    {
        return Ok(false);
    }
    let dreamer = admission::dreamer_reader(vault)?;
    let admit = admission::Admit::in_txn(&dreamer, txn)?;
    Ok(
        !admission::admitted_in_txn(vault, &admit, txn, ask.clone())?
            .is_some_and(|seen| seen.whole()),
    )
}
