//! A reference model of the vault and seeded step sequences checked against
//! the engine (Fable's verdict 52, section 5 item 1; F3.12 step 1).
//!
//! [`VaultModel`] holds plain maps: persons with their merges and splits, and
//! claims with their question, value, audience, writer, status, supersedes
//! link and split assignment. It was written from the promise text (canon
//! ARCH-0003, ARCH-0055, ARCH-0038, ARCH-0040, ARCH-0057 and the E2E memory
//! journeys), not from the engine's code, by a different model family from
//! the engine's builders; `PROMISES.md` beside this file cites the promise
//! behind each rule, the assumptions made where the text is silent, and the
//! cases the model leaves [`Outcome::Unspecified`].
//!
//! [`generator::sequence`] draws a deterministic step sequence from a seed,
//! keeping only steps the model applies. [`engine::EngineVault`] applies the
//! same steps to a real vault and reads its state back as an [`Observed`];
//! after each step the three invariants compare the two:
//! - I1 counts conserve ([`VaultModel::i1_counts_conserve`]): the live claims
//!   and each entity's assigned and remaining claims are equal, so a merge
//!   then a split keeps every claim;
//! - I2 one live version per question ([`VaultModel::i2_one_live_version`]):
//!   at most one standing head, and equal statuses and supersedes links, so
//!   an approval closes the head it replaces;
//! - I3 no audience widens ([`VaultModel::i3_no_audience_widens`]): each
//!   claim keeps its exact stored scope.

pub mod engine;
pub mod generator;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ent(pub u8);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClaimKey(pub u32);
/// Predicate within a question; values never form part of the question key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct QKey(pub u8);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Aud(pub u8);
impl Aud {
    /// Observation sentinel, never a scope accepted by a write.
    pub const ABSENT: Self = Self(u8::MAX);
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Actor {
    Owner,
    Agent(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Standing,
    Proposed,
    Superseded,
    Rejected,
    Deleted,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Refused(&'static str),
    Unspecified(&'static str),
}
/// Exact audience separates otherwise identical questions; ids have no order of authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Question {
    pub subject: Ent,
    pub predicate: QKey,
    pub audience: Aud,
}
pub type Value = u32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Universe {
    pub persons: u8,
    pub predicates: u8,
    pub agents: u8,
    pub audiences: u8,
}
impl Default for Universe {
    fn default() -> Self {
        Self {
            persons: 6,
            predicates: 3,
            agents: 2,
            audiences: 2,
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entity {
    pub merged_into: Option<Ent>,
    pub split_heads: Vec<Ent>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub subject: Ent,
    pub question: QKey,
    pub value: Value,
    pub audience: Aud,
    pub writer: Actor,
    pub status: Status,
    pub supersedes: Option<ClaimKey>,
    pub assignment: Option<Ent>,
}
impl Claim {
    pub fn question_key(&self) -> Question {
        Question {
            subject: self.subject,
            predicate: self.question,
            audience: self.audience,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultModel {
    universe: Universe,
    entities: BTreeMap<Ent, Entity>,
    claims: BTreeMap<ClaimKey, Claim>,
}
impl VaultModel {
    pub fn new(universe: &Universe) -> Self {
        Self {
            universe: universe.clone(),
            entities: (0..universe.persons)
                .map(|n| (Ent(n), Entity::default()))
                .collect(),
            claims: BTreeMap::new(),
        }
    }
    pub fn entities(&self) -> &BTreeMap<Ent, Entity> {
        &self.entities
    }
    pub fn claims(&self) -> &BTreeMap<ClaimKey, Claim> {
        &self.claims
    }
    fn involved(&self, ent: Ent) -> bool {
        self.entities
            .get(&ent)
            .is_some_and(|e| e.merged_into.is_some() || !e.split_heads.is_empty())
            || self
                .entities
                .values()
                .any(|e| e.merged_into == Some(ent) || e.split_heads.contains(&ent))
    }
    pub fn fresh_entities(&self) -> Vec<Ent> {
        self.entities
            .keys()
            .copied()
            .filter(|e| !self.involved(*e) && !self.claims.values().any(|c| c.subject == *e))
            .collect()
    }
    pub fn writable_entities(&self) -> Vec<Ent> {
        self.entities
            .keys()
            .copied()
            .filter(|e| !self.involved(*e))
            .collect()
    }
    fn reaches(&self, mut subject: Ent, entity: Ent) -> bool {
        // Only active roots are merged, so this bounded walk cannot contain a cycle.
        for _ in 0..self.entities.len() {
            if subject == entity {
                return true;
            }
            match self.entities.get(&subject).and_then(|e| e.merged_into) {
                Some(next) => subject = next,
                None => return false,
            }
        }
        false
    }
    fn in_split(&self, ent: Ent) -> bool {
        self.entities
            .get(&ent)
            .is_some_and(|e| !e.split_heads.is_empty())
            || self.entities.values().any(|e| e.split_heads.contains(&ent))
    }
    fn permits(&self, actor: Actor, aud: Aud) -> bool {
        match actor {
            Actor::Owner => aud.0 < self.universe.audiences && matches!(aud.0, 0 | 1),
            Actor::Agent(n) => {
                n < self.universe.agents && aud == Aud(1) && self.universe.audiences > 1
            }
        }
    }
    fn write(&mut self, id: ClaimKey, key: Question, value: Value, writer: Actor) -> Outcome {
        if self.claims.contains_key(&id) {
            return Outcome::Refused("claim id already used");
        }
        if !self.entities.contains_key(&key.subject) || key.predicate.0 >= self.universe.predicates
        {
            return Outcome::Refused("unknown subject or predicate");
        }
        if key.audience.0 >= self.universe.audiences {
            return Outcome::Refused("unknown audience");
        }
        if key.audience.0 > 1 {
            return Outcome::Unspecified("scope has no fixture mapping");
        }
        if !self.permits(writer, key.audience) {
            return Outcome::Refused("Grant does not carry scope");
        }
        if self.involved(key.subject) {
            return Outcome::Unspecified("write after topology change");
        }
        if self.claims.values().any(|c| {
            c.question_key() == key
                && c.value == value
                && matches!(c.status, Status::Standing | Status::Proposed)
        }) {
            return Outcome::Unspecified("exact restatement may deduplicate");
        }
        let status = if writer == Actor::Owner {
            Status::Standing
        } else {
            Status::Proposed
        };
        let supersedes = if status == Status::Standing {
            self.close_head(key)
        } else {
            None
        };
        self.claims.insert(
            id,
            Claim {
                subject: key.subject,
                question: key.predicate,
                value,
                audience: key.audience,
                writer,
                status,
                supersedes,
                assignment: None,
            },
        );
        Outcome::Applied
    }
    /// A direct owner correction closes the previous standing version immediately.
    pub fn owner_write(
        &mut self,
        id: ClaimKey,
        subject: Ent,
        question: QKey,
        value: Value,
        aud: Aud,
    ) -> Outcome {
        self.write(
            id,
            Question {
                subject,
                predicate: question,
                audience: aud,
            },
            value,
            Actor::Owner,
        )
    }
    /// A propose-mode Grant records data, but does not replace standing truth.
    pub fn agent_propose(
        &mut self,
        agent: u8,
        id: ClaimKey,
        subject: Ent,
        question: QKey,
        value: Value,
        aud: Aud,
    ) -> Outcome {
        self.write(
            id,
            Question {
                subject,
                predicate: question,
                audience: aud,
            },
            value,
            Actor::Agent(agent),
        )
    }
    fn close_head(&mut self, question: Question) -> Option<ClaimKey> {
        let old = self.standing_heads(question).first().copied();
        if let Some(c) = old.and_then(|id| self.claims.get_mut(&id)) {
            c.status = Status::Superseded;
        }
        old
    }
    fn settle(&mut self, id: ClaimKey, approve: bool) -> Outcome {
        let Some(claim) = self.claims.get(&id) else {
            return Outcome::Refused("unknown claim");
        };
        if claim.status != Status::Proposed {
            return Outcome::Refused("claim is not Proposed");
        }
        if self.involved(claim.subject) {
            return Outcome::Unspecified("settlement after topology change");
        }
        let question = claim.question_key();
        let old = if approve {
            self.close_head(question)
        } else {
            None
        };
        if let Some(claim) = self.claims.get_mut(&id) {
            claim.status = if approve {
                Status::Standing
            } else {
                Status::Rejected
            };
            claim.supersedes = old;
        }
        Outcome::Applied
    }
    /// Owner-only settlement makes the reviewed proposal standing and closes its predecessor.
    pub fn owner_approve(&mut self, id: ClaimKey) -> Outcome {
        self.settle(id, true)
    }
    pub fn owner_reject(&mut self, id: ClaimKey) -> Outcome {
        self.settle(id, false)
    }
    /// Merge changes redirects, never claim subjects or audiences.
    pub fn merge(&mut self, sources: &[Ent], survivor: Ent) -> Outcome {
        let unique: BTreeSet<_> = sources.iter().copied().collect();
        if sources.is_empty() || unique.len() != sources.len() || sources.contains(&survivor) {
            return Outcome::Refused("merge needs distinct sources and survivor");
        }
        let participants: Vec<_> = sources.iter().copied().chain([survivor]).collect();
        for ent in participants {
            let Some(state) = self.entities.get(&ent) else {
                return Outcome::Refused("unknown merge entity");
            };
            if state.merged_into.is_some() {
                return Outcome::Unspecified("merge of already-merged entity");
            }
            if self.in_split(ent) {
                return Outcome::Unspecified("merge involving a split");
            }
        }
        for ent in sources {
            if let Some(state) = self.entities.get_mut(ent) {
                state.merged_into = Some(survivor);
            }
        }
        Outcome::Applied
    }
    /// Split assigns any held claim, including inherited claims; omitted claims remain.
    pub fn split(&mut self, entity: Ent, heads: &[Ent], assign: &[(ClaimKey, Ent)]) -> Outcome {
        let Some(state) = self.entities.get(&entity) else {
            return Outcome::Refused("unknown split entity");
        };
        if state.merged_into.is_some() || self.in_split(entity) {
            return Outcome::Unspecified("repeated, nested or merged-shell split");
        }
        let unique: BTreeSet<_> = heads.iter().copied().collect();
        if heads.len() < 2 {
            return Outcome::Unspecified("zero or one split head");
        }
        if unique.len() != heads.len() || heads.contains(&entity) {
            return Outcome::Refused("split heads must be distinct from original");
        }
        let fresh = self.fresh_entities();
        for head in heads {
            if !self.entities.contains_key(head) {
                return Outcome::Refused("unknown split head");
            }
            if !fresh.contains(head) {
                return Outcome::Unspecified("split head is not fresh");
            }
        }
        let held: BTreeSet<_> = self.claims_held_by(entity).into_iter().collect();
        let mut assigned = BTreeSet::new();
        for (id, head) in assign {
            if !unique.contains(head) || !held.contains(id) || !assigned.insert(*id) {
                return Outcome::Refused("assignment is foreign, repeated or outside heads");
            }
        }
        if let Some(state) = self.entities.get_mut(&entity) {
            state.split_heads = unique.into_iter().collect();
        }
        for (id, head) in assign {
            if let Some(claim) = self.claims.get_mut(id) {
                claim.assignment = Some(*head);
            }
        }
        Outcome::Applied
    }
    /// User delete removes a claim from all live views; it never resurrects a predecessor.
    pub fn delete(&mut self, id: ClaimKey) -> Outcome {
        let Some(claim) = self.claims.get(&id) else {
            return Outcome::Refused("unknown claim");
        };
        if claim.status == Status::Deleted {
            return Outcome::Unspecified("repeated delete");
        }
        if claim.supersedes.is_some() || self.claims.values().any(|c| c.supersedes == Some(id)) {
            return Outcome::Unspecified("delete touches supersession history");
        }
        if let Some(claim) = self.claims.get_mut(&id) {
            claim.status = Status::Deleted;
            claim.assignment = None;
        }
        Outcome::Applied
    }
    /// All modeled state is durable, including proposals, redirects and deletions.
    pub fn restart(&mut self) -> Outcome {
        Outcome::Applied
    }
    pub fn standing_heads(&self, question: Question) -> Vec<ClaimKey> {
        self.claims
            .iter()
            .filter(|(_, c)| c.status == Status::Standing && c.question_key() == question)
            .map(|(id, _)| *id)
            .collect()
    }
    pub fn status(&self, id: ClaimKey) -> Option<Status> {
        self.claims.get(&id).map(|c| c.status)
    }
    pub fn supersedes(&self, id: ClaimKey) -> Option<ClaimKey> {
        self.claims.get(&id).and_then(|c| c.supersedes)
    }
    pub fn live_claims(&self) -> Vec<ClaimKey> {
        self.claims
            .iter()
            .filter(|(_, c)| c.status != Status::Deleted)
            .map(|(id, _)| *id)
            .collect()
    }
    /// Direct and inbound-merge membership, overridden by explicit split assignment.
    /// This accounting view is not resolver expansion or discounted residue recall.
    pub fn claims_held_by(&self, entity: Ent) -> Vec<ClaimKey> {
        if !self.entities.contains_key(&entity) {
            return Vec::new();
        }
        self.claims
            .iter()
            .filter(|(_, c)| {
                c.status != Status::Deleted
                    && match c.assignment {
                        Some(head) => head == entity,
                        None => self.reaches(c.subject, entity),
                    }
            })
            .map(|(id, _)| *id)
            .collect()
    }
    pub fn remaining_on(&self, entity: Ent) -> Vec<ClaimKey> {
        self.claims_held_by(entity)
            .into_iter()
            .filter(|id| self.claims.get(id).is_some_and(|c| c.assignment.is_none()))
            .collect()
    }
    pub fn assigned_to(&self, head: Ent) -> Vec<ClaimKey> {
        self.claims
            .iter()
            .filter(|(_, c)| c.status != Status::Deleted && c.assignment == Some(head))
            .map(|(id, _)| *id)
            .collect()
    }
    pub fn audience(&self, id: ClaimKey) -> Aud {
        self.claims
            .get(&id)
            .filter(|c| c.status != Status::Deleted)
            .map_or(Aud::ABSENT, |c| c.audience)
    }
    /// This is recall eligibility, not the owner's proposal-review/history door.
    pub fn visible_to(&self, actor: Actor) -> Vec<ClaimKey> {
        self.claims
            .iter()
            .filter(|(_, c)| c.status == Status::Standing && self.permits(actor, c.audience))
            .map(|(id, _)| *id)
            .collect()
    }
    pub fn observe(&self) -> Observed {
        let questions: BTreeSet<_> = self.claims.values().map(Claim::question_key).collect();
        let actors =
            std::iter::once(Actor::Owner).chain((0..self.universe.agents).map(Actor::Agent));
        Observed {
            live: Some(self.live_claims()),
            held: self
                .entities
                .keys()
                .map(|e| (*e, self.claims_held_by(*e)))
                .collect(),
            remaining: self
                .entities
                .keys()
                .map(|e| (*e, self.remaining_on(*e)))
                .collect(),
            assigned: self
                .entities
                .keys()
                .map(|e| (*e, self.assigned_to(*e)))
                .collect(),
            standing_heads: questions
                .into_iter()
                .map(|q| (q, self.standing_heads(q)))
                .collect(),
            statuses: self
                .claims
                .keys()
                .map(|id| (*id, self.status(*id)))
                .collect(),
            supersedes: self
                .claims
                .keys()
                .map(|id| (*id, self.supersedes(*id)))
                .collect(),
            audience: self
                .live_claims()
                .into_iter()
                .map(|id| (id, self.audience(id)))
                .collect(),
            visible: actors.map(|a| (a, self.visible_to(a))).collect(),
        }
    }
    pub fn i1_counts_conserve(&self, observed: &Observed) -> Result<(), Violation> {
        if let Some(live) = &observed.live {
            equal_set("I1", "live claims", live, &self.live_claims())?;
        }
        for (entity, actual) in &observed.held {
            equal_set(
                "I1",
                &format!("held by {entity:?}"),
                actual,
                &self.claims_held_by(*entity),
            )?;
        }
        for (entity, actual) in &observed.remaining {
            equal_set(
                "I1",
                &format!("remaining on {entity:?}"),
                actual,
                &self.remaining_on(*entity),
            )?;
        }
        for (head, actual) in &observed.assigned {
            equal_set(
                "I1",
                &format!("assigned to {head:?}"),
                actual,
                &self.assigned_to(*head),
            )?;
        }
        Ok(())
    }
    pub fn i2_one_live_version(&self, observed: &Observed) -> Result<(), Violation> {
        for (question, actual) in &observed.standing_heads {
            if actual.len() > 1 {
                return Err(Violation::new(
                    "I2",
                    format!(
                        "{question:?} has {} standing heads: {actual:?}",
                        actual.len()
                    ),
                ));
            }
            equal_set(
                "I2",
                &format!("standing heads for {question:?}"),
                actual,
                &self.standing_heads(*question),
            )?;
        }
        for (id, actual) in &observed.statuses {
            equal(
                "I2",
                &format!("status of {id:?}"),
                actual,
                &self.status(*id),
            )?;
        }
        for (id, actual) in &observed.supersedes {
            equal(
                "I2",
                &format!("supersedes of {id:?}"),
                actual,
                &self.supersedes(*id),
            )?;
        }
        Ok(())
    }
    pub fn i3_no_audience_widens(&self, observed: &Observed) -> Result<(), Violation> {
        for (id, actual) in &observed.audience {
            equal(
                "I3",
                &format!("audience of {id:?}"),
                actual,
                &self.audience(*id),
            )?;
        }
        for (actor, actual) in &observed.visible {
            let allowed: BTreeSet<_> = self.visible_to(*actor).into_iter().collect();
            let leaked: Vec<_> = actual
                .iter()
                .filter(|id| !allowed.contains(id))
                .copied()
                .collect();
            if !leaked.is_empty() {
                return Err(Violation::new(
                    "I3",
                    format!("{actor:?} read disallowed claims {leaked:?}"),
                ));
            }
        }
        Ok(())
    }
}
/// Missing map entries mean not observed, NOT observed empty. Some([]) is an empty live read.
/// statuses[id] = None means the engine observed an absent row, not an omitted observation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    pub live: Option<Vec<ClaimKey>>,
    pub held: BTreeMap<Ent, Vec<ClaimKey>>,
    pub remaining: BTreeMap<Ent, Vec<ClaimKey>>,
    pub assigned: BTreeMap<Ent, Vec<ClaimKey>>,
    pub standing_heads: BTreeMap<Question, Vec<ClaimKey>>,
    pub statuses: BTreeMap<ClaimKey, Option<Status>>,
    pub supersedes: BTreeMap<ClaimKey, Option<ClaimKey>>,
    pub audience: BTreeMap<ClaimKey, Aud>,
    pub visible: BTreeMap<Actor, Vec<ClaimKey>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub invariant: &'static str,
    pub message: String,
}
impl Violation {
    fn new(invariant: &'static str, message: String) -> Self {
        Self { invariant, message }
    }
}
fn equal<T: PartialEq + std::fmt::Debug>(
    rule: &'static str,
    what: &str,
    actual: &T,
    expected: &T,
) -> Result<(), Violation> {
    if actual == expected {
        Ok(())
    } else {
        Err(Violation::new(
            rule,
            format!("{what}: expected {expected:?}, observed {actual:?}"),
        ))
    }
}
fn equal_set(
    rule: &'static str,
    what: &str,
    actual: &[ClaimKey],
    expected: &[ClaimKey],
) -> Result<(), Violation> {
    let mut sorted = actual.to_vec();
    sorted.sort_unstable();
    // Do not deduplicate: duplicate rows are a count-conservation failure too.
    equal(rule, what, &sorted, &expected.to_vec())
}
