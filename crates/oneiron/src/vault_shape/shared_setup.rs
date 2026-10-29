//! Sharing the vault from its shape (ARCH-0070), and the creator's answer to
//! the conversation-learning question in the same apply (FIX 5603).
//!
//! Sharing invites, in its own writer, each new member the same apply
//! approves: the founding members. A creator who answers the question in his
//! own apply has the answer written once the creation has committed, through
//! the setting's own setter, under the same owner proof and the surface his
//! request reached this install on. The apply's receipt states what happened.
//! A creation without an answer leaves the setting as it stands and asks
//! nothing; preset and member rows never stand for an answer.
use super::apply::{ShapeApplier, ShapeApplyItem, ShapeApplyReceipt, ShapeItemState, open};
use super::plan::{ShapeChange, ShapePlanItem};
use super::{ShapeRow, invalid};
use crate::authority::{ActSurface, ConversationLearningView};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::federation::InitialSharedMember;
use crate::{EntityId, Vault};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What an apply did with the conversation-learning answer it carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeLearningOutcome {
    /// The answer: `true` turns conversation learning on, `false` off.
    pub requested: bool,
    /// Whether the setting's setter wrote it.
    pub written: bool,
    /// Whether the answer went unread: an actor's apply, or one that created
    /// no shared vault.
    pub ignored: bool,
    /// The setting as read after; `None` when it could not be read.
    pub resulting: Option<ShapeLearningSetting>,
    /// Why the answer was not written, when it was not.
    pub reason: Option<String>,
}

/// The vault's conversation-learning setting, as an apply's receipt states
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeLearningSetting {
    /// Whether it is on.
    pub on: bool,
    /// Its revision, 64 hex.
    pub revision: String,
    /// The authority entry of the choice in force, 64 hex; `None` while none
    /// counts.
    pub act: Option<String>,
}

impl From<ConversationLearningView> for ShapeLearningSetting {
    fn from(view: ConversationLearningView) -> Self {
        Self {
            on: view.on,
            revision: bytes_to_hex_lower(&view.revision.0),
            act: view.act.as_ref().map(|act| bytes_to_hex_lower(act)),
        }
    }
}

/// A creator's explicit answer, and where his request reached this install.
#[derive(Clone, Copy)]
pub(super) struct CreatorAnswer {
    on: bool,
    surface: ActSurface,
}

/// The one rule for an apply's conversation-learning answer (Engine call,
/// FIX 5603): only an explicit typed answer on the owner's own current
/// apply reaches the setter, and only once that apply creates the shared
/// vault; an explicit `false` is written as off. An absent answer asks
/// nothing and leaves the setting as it stands. An actor's answer is never
/// the creator's: it is reported ignored, never refused. A setter that
/// fails keeps the creation landed, with the outcome on the receipt.
pub(super) fn creator_answer(
    applier: &ShapeApplier<'_>,
    requested: Option<bool>,
) -> Option<CreatorAnswer> {
    match (applier, requested) {
        (ShapeApplier::Owner { surface, .. }, Some(on)) => Some(CreatorAnswer {
            on,
            surface: *surface,
        }),
        _ => None,
    }
}

/// States on the receipt an answer its apply did not act on, unless a
/// creation already recorded its outcome: a resumed apply never replays an
/// answer. Set on the receipt the apply returns once its journal is
/// written, so no journal keeps an answer nothing acted on.
pub(super) fn report_unread(
    receipt: &mut ShapeApplyReceipt,
    applier: &ShapeApplier<'_>,
    requested: Option<bool>,
) {
    let (None, Some(requested)) = (&receipt.conversation_learning, requested) else {
        return;
    };
    let reason = match applier {
        ShapeApplier::Owner { .. } => "this apply created no shared vault",
        ShapeApplier::Actor { .. } => "an actor's apply carries no creator's answer",
    };
    receipt.conversation_learning = Some(ShapeLearningOutcome {
        requested,
        written: false,
        ignored: true,
        resulting: None,
        reason: Some(reason.to_owned()),
    });
}

/// The member rows a first sharing invites in its own writer: each new
/// member the same apply approves. Under a preset the creator is its Owner
/// already, so their own row is left to read as landed.
fn founding_members(
    items: &[ShapeApplyItem],
    shared: &ShapePlanItem,
    approve: &[u32],
    creator: EntityId,
) -> Vec<(usize, InitialSharedMember)> {
    let preset = matches!(
        shared.after,
        Some(ShapeRow::Shared {
            preset: Some(_),
            ..
        })
    );
    items
        .iter()
        .enumerate()
        .filter_map(|(at, entry)| {
            let (ShapeChange::Create, Some(ShapeRow::Member { member, role, .. })) =
                (entry.item.change, &entry.item.after)
            else {
                return None;
            };
            if !open(&entry.state) || !approve.contains(&entry.item.seq) {
                return None;
            }
            let member = EntityId::from_hex(member).ok()?;
            (!(preset && member == creator)).then(|| {
                (
                    at,
                    InitialSharedMember {
                        member_ref: member,
                        role: Some((*role).into()),
                    },
                )
            })
        })
        .collect()
}

impl Vault {
    /// Shares the vault as `item` declares, inviting the founding members
    /// in the same writer and marking each landed, then writes the creator's
    /// `answer`, when he gave one, onto `journal`'s outcome. The shared
    /// item's own state comes back; a refused creation writes no answer.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn land_shared_vault(
        &self,
        owner: &AuthenticatedOwner,
        journal: &mut ShapeApplyReceipt,
        item: &ShapePlanItem,
        approve: &[u32],
        creator: EntityId,
        answer: Option<CreatorAnswer>,
        now: u64,
    ) -> ShapeItemState {
        let founding = founding_members(&journal.items, item, approve, creator);
        let receipt = match self.share_vault(owner, item, &founding, now) {
            Ok(receipt) => receipt,
            Err(error) => {
                return ShapeItemState::Refused {
                    reason: error.to_string(),
                };
            }
        };
        for (at, _) in &founding {
            journal.items[*at].state = ShapeItemState::Landed {
                at: now,
                receipt: "founding member".to_owned(),
            };
        }
        if let Some(answer) = answer {
            journal.conversation_learning = Some(self.answer_conversation_learning(owner, answer));
        }
        ShapeItemState::Landed { at: now, receipt }
    }

    /// Shares the vault as `item` declares, inviting `founding` in the
    /// same writer.
    fn share_vault(
        &self,
        owner: &AuthenticatedOwner,
        item: &ShapePlanItem,
        founding: &[(usize, InitialSharedMember)],
        now: u64,
    ) -> Result<String> {
        let (ShapeChange::Create, Some(ShapeRow::Shared { vault_id, preset })) =
            (item.change, &item.after)
        else {
            return Err(invalid(
                "a shared vault is shared once; no seed reshares it",
            ));
        };
        let members: Vec<InitialSharedMember> =
            founding.iter().map(|(_, member)| member.clone()).collect();
        let creation = self.initialize_shared_vault(
            owner,
            *vault_id,
            (*preset).map(Into::into),
            &members,
            now,
        )?;
        Ok(creation.vault_id.to_string())
    }

    /// Writes the creator's answer after the creation committed, through
    /// the setting's own setter: the same owner proof, the surface his
    /// request reached this install on, and the revision read just before.
    /// A read or a write that fails is the outcome's reason, never the
    /// creation's refusal. After a failed write the setting is read back
    /// once; one that cannot be read is unknown, never off.
    fn answer_conversation_learning(
        &self,
        owner: &AuthenticatedOwner,
        answer: CreatorAnswer,
    ) -> ShapeLearningOutcome {
        let written = self.conversation_learning_view(owner).and_then(|seen| {
            self.set_conversation_learning(
                owner,
                answer.surface,
                answer.on,
                false,
                Some(seen.revision),
            )
        });
        let (resulting, reason) = match written {
            Ok(view) => (Some(view), None),
            Err(error) => (
                self.conversation_learning_view(owner).ok(),
                Some(error.to_string()),
            ),
        };
        ShapeLearningOutcome {
            requested: answer.on,
            written: reason.is_none(),
            ignored: false,
            resulting: resulting.map(Into::into),
            reason,
        }
    }
}
