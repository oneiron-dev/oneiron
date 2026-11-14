use crate::model::{Aud, ClaimKey, Ent, Outcome, QKey, Status, Universe, Value, VaultModel};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    OwnerWrite {
        claim: ClaimKey,
        subject: Ent,
        question: QKey,
        value: Value,
        aud: Aud,
    },
    AgentPropose {
        agent: u8,
        claim: ClaimKey,
        subject: Ent,
        question: QKey,
        value: Value,
        aud: Aud,
    },
    OwnerApprove {
        claim: ClaimKey,
    },
    OwnerReject {
        claim: ClaimKey,
    },
    Merge {
        sources: Vec<Ent>,
        survivor: Ent,
    },
    Split {
        entity: Ent,
        heads: Vec<Ent>,
        assign: Vec<(ClaimKey, Ent)>,
    },
    Delete {
        claim: ClaimKey,
    },
    Restart,
}
impl Step {
    pub fn apply(&self, model: &mut VaultModel) -> Outcome {
        match self {
            Self::OwnerWrite {
                claim,
                subject,
                question,
                value,
                aud,
            } => model.owner_write(*claim, *subject, *question, *value, *aud),
            Self::AgentPropose {
                agent,
                claim,
                subject,
                question,
                value,
                aud,
            } => model.agent_propose(*agent, *claim, *subject, *question, *value, *aud),
            Self::OwnerApprove { claim } => model.owner_approve(*claim),
            Self::OwnerReject { claim } => model.owner_reject(*claim),
            Self::Merge { sources, survivor } => model.merge(sources, *survivor),
            Self::Split {
                entity,
                heads,
                assign,
            } => model.split(*entity, heads, assign),
            Self::Delete { claim } => model.delete(*claim),
            Self::Restart => model.restart(),
        }
    }
}
struct SplitMix64(u64);
impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn choose<T: Copy>(&mut self, items: &[T]) -> Option<T> {
        items.get(self.below(items.len())).copied()
    }
}
fn owner(claim: ClaimKey, subject: Ent, question: QKey, aud: Aud) -> Step {
    Step::OwnerWrite {
        claim,
        subject,
        question,
        value: claim.0,
        aud,
    }
}
fn proposal(agent: u8, claim: ClaimKey, subject: Ent, question: QKey) -> Step {
    Step::AgentPropose {
        agent,
        claim,
        subject,
        question,
        value: claim.0,
        aud: Aud(1),
    }
}
/// Draw short lifecycle motifs as well as single verbs, so prerequisites do not rely on luck.
fn draw(rng: &mut SplitMix64, model: &VaultModel, universe: &Universe) -> Option<Vec<Step>> {
    let roll = rng.below(16);
    let id = ClaimKey(match model.claims().keys().next_back() {
        Some(last) => last.0.checked_add(1)?,
        None => 1,
    });
    let question = QKey(rng.below(usize::from(universe.predicates)) as u8);
    let aud = Aud(rng.below(usize::from(universe.audiences.min(2))) as u8);
    let agent = rng.below(usize::from(universe.agents)) as u8;
    match roll {
        0..=5 => {
            if universe.agents == 0 || universe.audiences < 2 {
                return None;
            }
            let subject = rng.choose(&model.writable_entities())?;
            let next = ClaimKey(id.0.checked_add(1)?);
            Some(vec![
                owner(id, subject, question, Aud(1)),
                proposal(agent, next, subject, question),
                Step::OwnerApprove { claim: next },
            ])
        }
        6..=9 => {
            let mut fresh = model.fresh_entities();
            if fresh.len() < 4 {
                return None;
            }
            let mut take = || fresh.remove(rng.below(fresh.len()));
            let (source, survivor, north, south) = (take(), take(), take(), take());
            let inherited = ClaimKey(id.0.checked_add(1)?);
            let mut assign = vec![(id, north)];
            if rng.below(2) == 0 {
                assign.push((inherited, south));
            }
            Some(vec![
                owner(id, survivor, question, aud),
                owner(inherited, source, question, aud),
                Step::Merge {
                    sources: vec![source],
                    survivor,
                },
                Step::Split {
                    entity: survivor,
                    heads: vec![north, south],
                    assign,
                },
            ])
        }
        10 => Some(vec![owner(
            id,
            rng.choose(&model.writable_entities())?,
            question,
            aud,
        )]),
        11 => {
            if universe.agents == 0 || universe.audiences < 2 {
                return None;
            }
            Some(vec![proposal(
                agent,
                id,
                rng.choose(&model.writable_entities())?,
                question,
            )])
        }
        12 => {
            let proposed: Vec<_> = model
                .claims()
                .iter()
                .filter(|(_, c)| c.status == Status::Proposed)
                .map(|(id, _)| *id)
                .collect();
            let claim = rng.choose(&proposed)?;
            Some(vec![if rng.below(2) == 0 {
                Step::OwnerApprove { claim }
            } else {
                Step::OwnerReject { claim }
            }])
        }
        13 => Some(vec![Step::Delete {
            claim: rng.choose(&model.live_claims())?,
        }]),
        14 => {
            let mut active = model.writable_entities();
            if active.len() < 2 {
                return None;
            }
            let source = active.remove(rng.below(active.len()));
            Some(vec![Step::Merge {
                sources: vec![source],
                survivor: rng.choose(&active)?,
            }])
        }
        _ => Some(vec![Step::Restart]),
    }
}
/// Every emitted step is Applied. Rejected draws leave the working model untouched.
/// The 32-draw bound falls back to Restart, including for an empty/exhausted universe.
pub fn sequence(seed: u64, len: usize, universe: &Universe) -> Vec<Step> {
    let mut rng = SplitMix64(seed);
    let mut model = VaultModel::new(universe);
    let mut steps = Vec::new();
    while steps.len() < len {
        let mut accepted = None;
        for _ in 0..32 {
            let Some(plan) = draw(&mut rng, &model, universe) else {
                continue;
            };
            let plan: Vec<_> = plan.into_iter().take(len - steps.len()).collect();
            let mut trial = model.clone();
            if !plan.is_empty()
                && plan
                    .iter()
                    .all(|step| step.apply(&mut trial) == Outcome::Applied)
            {
                accepted = Some((trial, plan));
                break;
            }
        }
        match accepted {
            Some((trial, plan)) => {
                model = trial;
                steps.extend(plan);
            }
            None => {
                model.restart();
                steps.push(Step::Restart);
            }
        }
    }
    steps
}
