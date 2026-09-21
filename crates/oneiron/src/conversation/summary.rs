//! Caller-authored scoped summaries, landed as gated claim headers.
use super::*;
use crate::claim::ClaimSubject;
use crate::{ClaimCandidate, EdgeKind, WriteEnvelope};
use rmpv::Value;
impl Vault {
    /// Mint a summary directly onto its target. The scoped record set, claim
    /// admission and evidence edges are captured in one write transaction.
    /// The engine never generates the prose and never bypasses claim policy.
    pub fn mint_scope_summary(
        &self,
        scope: &ScopeSelector,
        trunk: EntityId,
        text: &str,
        envelope: &WriteEnvelope,
        at: u64,
    ) -> Result<EntityId> {
        self.with_write_txn(|txn| {
            authorize(self, txn, envelope.actor())?;
            let room = visibility::room_for_record_in(self, txn, trunk)?
                .ok_or(state("summary target has no room"))?;
            ownership::claim_in(&self.store, txn, room, ownership::Owner::Room)?;
            let sub_session_reply = if let ScopeSelector::SubSession(session) = scope {
                let spawning = dag::peers(self, txn, *session, EdgeKind::SpawnedBy, false)?;
                if spawning.as_slice() != [trunk] {
                    return Err(state(
                        "sub-session summary must land on its spawning record",
                    ));
                }
                true
            } else {
                false
            };
            if let ScopeSelector::Canonical(conversation) = scope {
                body::body_in(self, txn, *conversation)?;
                dag::backfill_in(self, txn, *conversation)?;
            }
            let covers = dag::resolve_in(self, txn, scope, false)?;
            for id in &covers {
                dag::require_room(self, txn, *id, room)?;
            }
            if text.trim().is_empty() || covers.is_empty() {
                return Err(invalid("summary text and scope must not be empty"));
            }
            let id = EntityId::now();
            let value = Value::Map(vec![
                (Value::from("text"), Value::from(text)),
                (
                    Value::from("scope"),
                    rmpv::decode::read_value(&mut std::io::Cursor::new(encode(scope)?))
                        .map_err(|_| invalid("scope encoding"))?,
                ),
                (
                    Value::from("reply_to"),
                    if sub_session_reply {
                        Value::from(trunk.to_hex())
                    } else {
                        Value::Nil
                    },
                ),
                (
                    Value::from("covers"),
                    Value::Array(
                        covers
                            .iter()
                            .map(|id| Value::Binary(id.as_bytes().to_vec()))
                            .collect(),
                    ),
                ),
            ]);
            let candidate = ClaimCandidate::new(
                "conversation.summary",
                ClaimSubject::Entity(trunk),
                value,
                1.0,
            );
            self.batch_in()
                .claim_candidate(
                    &id,
                    candidate,
                    envelope,
                    crate::TimeRange { start: at, end: at },
                    at,
                )
                .text(&id, &[("body", text)])
                .apply(txn)?;
            dag::put_edge(self, txn, id, EdgeKind::ClaimOf, trunk, at)?;
            if sub_session_reply {
                dag::put_edge(self, txn, id, EdgeKind::RepliesTo, trunk, at)?;
            }
            for covered in covers {
                dag::put_edge(self, txn, id, EdgeKind::DerivedFrom, covered, at)?;
            }
            Ok(id)
        })
    }
    pub fn summarize_thread(
        &self,
        trunk: EntityId,
        text: &str,
        envelope: &WriteEnvelope,
        at: u64,
    ) -> Result<EntityId> {
        let root = self
            .thread_roots(trunk)?
            .first()
            .copied()
            .ok_or(state("no thread to summarize"))?;
        self.mint_scope_summary(&ScopeSelector::Branch(root), trunk, text, envelope, at)
    }
}
