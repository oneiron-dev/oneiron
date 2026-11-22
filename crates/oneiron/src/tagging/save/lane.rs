//! The link a lane is served for a saved mention (FIX
//! TAG-LINK-DECIDED-OVER-UNREADABLE-PERSONS; the lead's ruling A of 21 Nov).
//!
//! A save decides each mention's link over every entity in a world the turn
//! is in, readable or not ([`Linker`]). Served narrowed to the entities a
//! lane reads and no more, such a link tells a narrower lane that a person
//! it cannot read is there: one holding the mention's exact name leaves a
//! tag where the lane, deciding alone, would mint, and one that sounds like
//! the name turns a lone sound match into candidates. Under the Engine's
//! rule of 2026-10-15 (ARCH-0067:367), a contact the reader cannot read
//! counts as absent. So a mention whose link names an entity the lane does
//! not read is decided again for the lane, by the save's own arms and rungs
//! in the save's own order, over the entities the lane reads; every other
//! link is served as stored. The decision writes nothing: where the save
//! would mint, the lane is served [`LaneLink::Unmatched`]. The stored link,
//! and every reader of it inside the engine, stay as they are.
//!
//! A mention whose link came from outside the turn (a context or speaker
//! reference) is served narrowed: the tag set keeps no coordinates of the
//! earlier span, so its decision cannot be made again here. So is one whose
//! antecedent the lane does not see, so that no decision rests on words the
//! lane does not read.

use std::collections::BTreeMap;

use super::{HintRead, Linker, RoleRung, role_rung};
use crate::claim::ScopedRead;
use crate::error::Result;
use crate::gate::PolicyManifestResolution;
use crate::tagging::marker::TaggingMarkerConfig;
use crate::tagging::tags::{MentionLink, TaggedMention, TurnTags, message_text_in_txn};
use crate::tagging::{provisional, role};
use crate::{EntityId, Vault};

/// A mention's link as one lane is served it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::tagging) enum LaneLink {
    /// A link that names only entities the lane reads.
    Link(MentionLink),
    /// The lane's own decision found no entity of `kind` that the lane
    /// reads, where the save would have minted a provisional entity; the
    /// vault holds none for it.
    Unmatched { kind: u8 },
}

impl LaneLink {
    fn kind(&self) -> Option<u8> {
        match self {
            Self::Link(link) => link.kind(),
            Self::Unmatched { kind } => Some(*kind),
        }
    }

    fn entities(&self) -> &[EntityId] {
        match self {
            Self::Link(link) => link.entities(),
            Self::Unmatched { .. } => &[],
        }
    }
}

/// The links `lane` is served for the mentions of `tags`, by stored index;
/// `None` for a mention whose MESSAGE the lane does not read (`shown` is
/// false). A link that names only entities the lane reads is served as
/// stored. One that names an entity the lane does not read is decided again
/// over the entities it reads, or, where that cannot be done, served
/// without the entities it does not read, a link left naming nothing as a
/// tag.
pub(in crate::tagging) fn lane_links_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    tags: &TurnTags,
    shown: &[bool],
    lane: &ScopedRead<'_>,
    policy: &PolicyManifestResolution,
) -> Result<Vec<Option<LaneLink>>> {
    let mut reads = LaneReads {
        vault,
        lane,
        policy,
        judged: BTreeMap::new(),
    };
    let mut decision: Option<LaneDecision<'_>> = None;
    let mut links: Vec<Option<LaneLink>> = Vec::with_capacity(tags.mentions.len());
    for (index, mention) in tags.mentions.iter().enumerate() {
        if !shown.get(index).copied().unwrap_or(false) {
            links.push(None);
            continue;
        }
        let mut narrowed = mention.link.clone();
        for entity in mention.link.entities() {
            if !reads.reads(txn, entity)? {
                narrowed = narrowed.without(entity);
            }
        }
        if narrowed == mention.link {
            links.push(Some(LaneLink::Link(narrowed)));
            continue;
        }
        if decision.is_none() {
            decision = Some(LaneDecision::new(vault, txn, tags)?);
        }
        let decided = match decision.as_mut() {
            Some(decision) => decision.decide(txn, mention, &links, &mut reads)?,
            None => None,
        };
        links.push(Some(decided.unwrap_or(LaneLink::Link(narrowed))));
    }
    Ok(links)
}

/// What the lane reads, each entity judged once. A provisional entity,
/// local to this vault, shows with its mention, as the narrowed link keeps
/// it.
struct LaneReads<'a, 'r> {
    vault: &'a Vault,
    lane: &'a ScopedRead<'r>,
    policy: &'a PolicyManifestResolution,
    judged: BTreeMap<EntityId, bool>,
}

impl LaneReads<'_, '_> {
    fn reads(&mut self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        if let Some(readable) = self.judged.get(id) {
            return Ok(*readable);
        }
        let readable = provisional::exists_in_txn(&self.vault.store, txn, id)?
            || self
                .lane
                .is_entity_readable_with_policy_in(txn, self.policy, id)?;
        self.judged.insert(*id, readable);
        Ok(readable)
    }

    /// `ids` kept to those the lane reads, in their order.
    fn retain(&mut self, txn: &heed::RoTxn<'_>, ids: Vec<EntityId>) -> Result<Vec<EntityId>> {
        let mut kept = Vec::with_capacity(ids.len());
        for id in ids {
            if self.reads(txn, &id)? {
                kept.push(id);
            }
        }
        Ok(kept)
    }
}

/// The save's arms and rungs, run again for one lane with no write.
struct LaneDecision<'v> {
    linker: Linker<'v>,
    /// The label table the save maps labels to entity kinds by; `None`
    /// when tagging is not configured.
    config: Option<TaggingMarkerConfig>,
    /// Each MESSAGE's text, read once; `None` inside when the turn no
    /// longer reads.
    texts: BTreeMap<EntityId, Option<String>>,
}

impl<'v> LaneDecision<'v> {
    /// The decision for `tags`, its role edges read at the save's instant.
    fn new(vault: &'v Vault, txn: &heed::RoTxn<'_>, tags: &TurnTags) -> Result<Self> {
        Ok(Self {
            linker: Linker::new(vault, txn, tags.turn, tags.saved_at)?,
            config: vault.tagging_marker_config(),
            texts: BTreeMap::new(),
        })
    }

    /// The lane's link for `mention`, by the save's arm for it
    /// (`save_with_hint_read_in_txn`); `links` holds the lane's links of the
    /// mentions before it. `None` when the decision cannot be made again:
    /// the link came from outside the turn, its antecedent is one the lane
    /// does not see, or the words or the label table are gone.
    fn decide(
        &mut self,
        txn: &heed::RoTxn<'_>,
        mention: &TaggedMention,
        links: &[Option<LaneLink>],
        reads: &mut LaneReads<'_, '_>,
    ) -> Result<Option<LaneLink>> {
        if mention.reference.is_some() {
            return Ok(None);
        }
        let inherited = match mention.antecedent {
            None => None,
            Some(antecedent) => match links.get(antecedent) {
                Some(Some(link)) => Some(link.clone()),
                _ => return Ok(None),
            },
        }
        .filter(|link| *link != LaneLink::Link(MentionLink::Tag));
        let Some(config) = self.config.as_ref() else {
            return Ok(None);
        };
        if !self.texts.contains_key(&mention.message) {
            let turn = self.linker.turn;
            let text = message_text_in_txn(self.linker.vault, txn, &turn, &mention.message)?;
            self.texts.insert(mention.message, text);
        }
        let Some(Some(message_text)) = self.texts.get(&mention.message) else {
            return Ok(None);
        };
        let Some(text) = message_text.get(mention.start..mention.end).map(str::trim) else {
            return Ok(None);
        };
        let own = config
            .labels
            .get(&mention.label)
            .copied()
            .filter(|_| !text.is_empty());
        let lane = reads.lane;
        let words = (text, message_text.as_str(), mention);
        let link = match (inherited, own) {
            (None, None) => LaneLink::Link(MentionLink::Tag),
            (None, Some(kind)) => {
                let link = self
                    .linker
                    .lane_link(txn, kind, text, &mention.message, reads)?;
                self.linker.lane_ordered(txn, link, Some(words), lane)?
            }
            (Some(inherited), None) => inherited,
            (Some(inherited), Some(kind)) => {
                let vault = self.linker.vault;
                let possessor = role::possessor_in_txn(vault, txn, kind, text, &mention.message)?;
                let keyed = self.linker.candidates(txn, kind, text, possessor)?;
                let hits = reads.retain(txn, keyed)?;
                if !hits.is_empty() {
                    let link = LaneLink::Link(MentionLink::Candidates {
                        kind,
                        entities: hits,
                    });
                    self.linker.lane_ordered(txn, link, Some(words), lane)?
                } else if inherited.kind() == Some(kind)
                    && !provisional::names_other_possessor_in_txn(
                        &vault.store,
                        txn,
                        inherited.entities(),
                        possessor,
                    )?
                {
                    inherited
                } else {
                    let link = self
                        .linker
                        .lane_link(txn, kind, text, &mention.message, reads)?;
                    self.linker.lane_ordered(txn, link, None, lane)?
                }
            }
        };
        Ok(Some(link))
    }
}

impl Linker<'_> {
    /// [`Self::link`] over the entities `reads` admits, with no write: the
    /// key's hits the lane reads; else, for a mention of the speaker's
    /// relationship, the role rung over the edges and persons the lane
    /// reads; else the phonetic rung's persons the lane reads, when two or
    /// more; else [`LaneLink::Unmatched`] where the save mints.
    fn lane_link(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: u8,
        mention: &str,
        message: &EntityId,
        reads: &mut LaneReads<'_, '_>,
    ) -> Result<LaneLink> {
        let possessor = role::possessor_in_txn(self.vault, txn, kind, mention, message)?;
        let keyed = self.candidates(txn, kind, mention, possessor)?;
        let mut entities = reads.retain(txn, keyed)?;
        let unsure_role =
            match self.lane_role_rung(txn, kind, mention, message, reads, &entities)? {
                RoleRung::Link(link) => return Ok(LaneLink::Link(link)),
                RoleRung::Unsure => true,
                RoleRung::Abstain => false,
            };
        if entities.is_empty() && !unsure_role {
            let sounding = self.sounds_like(txn, kind, mention)?;
            entities = reads.retain(txn, sounding)?;
            if entities.len() < 2 {
                entities.clear();
            }
        }
        Ok(if entities.is_empty() {
            LaneLink::Unmatched { kind }
        } else {
            LaneLink::Link(MentionLink::Candidates { kind, entities })
        })
    }

    /// [`Self::role_link`] over what the lane reads: the edges whose claim
    /// it reads ([`HintRead::Caller`]), and of their persons those it
    /// reads. `keyed` holds the key's hits the lane reads.
    fn lane_role_rung(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: u8,
        mention: &str,
        message: &EntityId,
        reads: &mut LaneReads<'_, '_>,
        keyed: &[EntityId],
    ) -> Result<RoleRung> {
        let Some(word) = role::role_word(kind, mention) else {
            return Ok(RoleRung::Abstain);
        };
        for id in keyed {
            if provisional::get_in_txn(&self.vault.store, txn, id)?.is_none() {
                return Ok(RoleRung::Abstain);
            }
        }
        let lane = reads.lane;
        let edges = self.role_hits(txn, kind, &word, message, HintRead::Caller(Some(lane)))?;
        let mut hits = BTreeMap::new();
        for (person, approved) in edges {
            if reads.reads(txn, &person)? {
                hits.insert(person, approved);
            }
        }
        Ok(role_rung(kind, hits))
    }

    /// `link` narrowed by a saved identity hint the lane reads, when `words`
    /// is given, and ordered by the vector rung over candidates the lane
    /// reads, as the save does after [`Self::link`]; a link the lane
    /// matches to no one stays as it is.
    fn lane_ordered(
        &self,
        txn: &heed::RoTxn<'_>,
        link: LaneLink,
        words: Option<(&str, &str, &TaggedMention)>,
        lane: &ScopedRead<'_>,
    ) -> Result<LaneLink> {
        let LaneLink::Link(link) = link else {
            return Ok(link);
        };
        let hint_read = HintRead::Caller(Some(lane));
        let link = match words {
            Some((name, text, mention)) => self.hinted(
                txn,
                link,
                (name, &mention.message),
                text,
                mention.start,
                mention.end,
                hint_read,
            )?,
            None => link,
        };
        Ok(LaneLink::Link(self.ranked(txn, link, hint_read)?))
    }
}
