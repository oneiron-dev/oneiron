//! The read shape a model works through (ARCH-0051 #decision-r9-bench): the
//! typed memory verbs or the graph_fs mount over the same memory. Both stay in
//! the base. Which one a run works through is one arm family of the one bandit
//! (ARCH-0053 #one-bandit-pick-rules): picked once per agent run for the run's
//! model by Thompson Sampling, and rebuilt at sleep from attribution-gated
//! labels in the same pass as the retrieval action posterior. It is never a
//! second ranking path (retrieval.md #filesystem): recall ranks the same way
//! whichever shape the run reads through.

use std::collections::BTreeMap;

use oneiron_store::retrieval_policy::posterior::{MIN_CONTEXT_MASS, RewardPosterior};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::error::{Error, Result};
use crate::learning_setting::setting_value_in_txn;
use crate::llm::ModelId;
use crate::posterior::{Posterior, beta_mean};
use crate::side_table::{self, Named, SideTable};
use crate::store::setting_seed::SettingSpec;
use crate::store::{Store, active_write_txn_depth, attempt_record_read};

/// The token cost term's weight λ in a read-shape reward (ARCH-0051
/// #decision-r9-bench): campaign 5 measured a shape's cost in tokens, so an
/// attempt that spent more than its model's median pays up to λ.
pub const READ_SHAPE_TOKEN_COST: SettingSpec = SettingSpec {
    key: "read_shape_token_cost",
    min: 0.0,
    max: 1.0,
    seed: 0.25,
};

/// The share of a model's wakes that read through the mount while that
/// model's mount evidence is below the pick floor (Engine RULING
/// L9-37-EXPLORE = B). The owner may pin it to 0.
pub const READ_SHAPE_EXPLORE_SHARE: SettingSpec = SettingSpec {
    key: "read_shape_explore_share",
    min: 0.0,
    max: 1.0,
    seed: 0.05,
};

/// What a run reads memory through. Both shapes reach the same memory under
/// the run's grant; the shape is the environment the run's brief names.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ReadShape {
    /// The typed memory verbs: the seeded default (RD-12).
    Verbs,
    /// The graph_fs mount, read with coreutils.
    Mount,
}

impl ReadShape {
    /// Both arms, the seeded default first: a tied draw picks the verbs.
    pub const ALL: [Self; 2] = [Self::Verbs, Self::Mount];
}

/// Which evidence decided a pick.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReadShapeTier {
    /// The owner pinned this model's shape.
    Pinned,
    /// This model's own labelled attempts.
    Model,
    /// Every model's labelled attempts in this vault. Only this account's
    /// evidence; no cross-vault or cross-account lookup.
    Global,
    /// The exploration share sent a model with too little mount evidence to
    /// the mount.
    Explore,
    /// Too little evidence anywhere: the seeded default, the typed verbs.
    Seed,
}

/// One pick: the shape and the tier that decided it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReadShapePick {
    pub shape: ReadShape,
    pub tier: ReadShapeTier,
}

/// The pick one attempt's run works under, written when the run first wakes
/// and kept by every later wake of the same attempt. The sleep rebuild
/// credits the attempt's gated reward to `(model, shape)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReadShapeStamp {
    pub model: ModelId,
    pub shape: ReadShape,
    pub tier: ReadShapeTier,
    /// The model units the attempt's run settled, as its host recorded them
    /// when the run ended; `None` until then. The token cost term reads it.
    #[serde(default)]
    pub model_units: Option<u64>,
}

/// One owner pin: `model` always reads through `shape`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadShapePin {
    pub model: ModelId,
    pub shape: ReadShape,
}

/// The stored owner pins over the read-shape picks, one per model.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadShapePins {
    #[serde(default)]
    pub pins: Vec<ReadShapePin>,
}

impl ReadShapePins {
    /// The pinned shape for `model`, if the owner pinned one.
    #[must_use]
    pub fn shape_for(&self, model: &ModelId) -> Option<ReadShape> {
        self.pins
            .iter()
            .find(|pin| pin.model == *model)
            .map(|pin| pin.shape)
    }

    /// Pins `model` to `shape`, or clears its pin when `shape` is absent.
    pub(crate) fn set(&mut self, model: &ModelId, shape: Option<ReadShape>) {
        self.pins.retain(|pin| pin.model != *model);
        if let Some(shape) = shape {
            self.pins.push(ReadShapePin {
                model: model.clone(),
                shape,
            });
            self.pins.sort_by(|a, b| a.model.cmp(&b.model));
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self
            .pins
            .windows(2)
            .any(|pair| pair[0].model >= pair[1].model)
        {
            return Err(Error::CorruptedIndex("read shape pins"));
        }
        Ok(())
    }
}

/// One arm's gated evidence, as fractional Bernoulli outcomes: each labelled
/// attempt adds `weight * reward` successes and `weight * (1 - reward)`
/// failures, and one pull.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReadShapeArm {
    pub model: ModelId,
    pub shape: ReadShape,
    pub successes: f64,
    pub failures: f64,
    pub pulls: u32,
}

impl ReadShapeArm {
    /// The arm's evidence mass: the summed attribution-gate weight.
    #[must_use]
    pub fn mass(&self) -> f64 {
        self.successes + self.failures
    }

    /// The posterior mean reward under the uniform prior.
    #[must_use]
    pub fn mean(&self) -> f64 {
        beta_mean(1.0 + self.successes, 1.0 + self.failures)
    }
}

/// The read-shape arm family's posterior: one arm per `(model, shape)` with
/// labelled evidence, sorted by model then shape. Rebuilt whole at sleep.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ReadShapePosterior {
    pub tuned_at: u64,
    pub labeled_attempts: usize,
    pub(crate) arms: Vec<ReadShapeArm>,
}

impl ReadShapePosterior {
    /// Every arm with evidence, sorted by model then shape.
    #[must_use]
    pub fn arms(&self) -> &[ReadShapeArm] {
        &self.arms
    }

    /// Credits one labelled attempt's shaped reward to `(model, shape)`.
    pub(crate) fn observe(
        &mut self,
        model: &ModelId,
        shape: ReadShape,
        reward: f64,
        weight: f64,
    ) -> Result<()> {
        RewardPosterior::default().update((reward, weight))?;
        let index = match self
            .arms
            .binary_search_by(|arm| (&arm.model, arm.shape).cmp(&(model, shape)))
        {
            Ok(index) => index,
            Err(index) => {
                self.arms.insert(
                    index,
                    ReadShapeArm {
                        model: model.clone(),
                        shape,
                        successes: 0.0,
                        failures: 0.0,
                        pulls: 0,
                    },
                );
                index
            }
        };
        let arm = &mut self.arms[index];
        arm.successes += weight * reward;
        arm.failures += weight * (1.0 - reward);
        arm.pulls = arm.pulls.saturating_add(1);
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let corrupted = || Error::CorruptedIndex("read shape posterior");
        if self
            .arms
            .windows(2)
            .any(|pair| (&pair[0].model, pair[0].shape) >= (&pair[1].model, pair[1].shape))
        {
            return Err(corrupted());
        }
        for arm in &self.arms {
            if !arm.successes.is_finite()
                || !arm.failures.is_finite()
                || arm.successes < 0.0
                || arm.failures < 0.0
            {
                return Err(corrupted());
            }
        }
        Ok(())
    }

    /// The summed evidence of `shape`'s arms, over `model`'s arms only or,
    /// with no model, over every model's.
    fn evidence(&self, model: Option<&ModelId>, shape: ReadShape) -> RewardPosterior {
        let mut posterior = RewardPosterior::default();
        for arm in &self.arms {
            if arm.shape == shape && model.is_none_or(|model| arm.model == *model) {
                posterior.alpha += arm.successes;
                posterior.beta += arm.failures;
            }
        }
        posterior
    }

    /// Picks the shape `model`'s next run reads through: the owner's pin;
    /// else, while the model's mount mass is below the floor, the
    /// exploration share's draw of the mount; else a Thompson draw over the
    /// model's own arms once they hold the floor's mass, then over every
    /// model's; else the seeded verbs.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] on an exploration share outside 0..=1 or a
    /// posterior that cannot be sampled.
    pub fn pick<R: Rng + ?Sized>(
        &self,
        model: &ModelId,
        pin: Option<ReadShape>,
        explore_share: f64,
        rng: &mut R,
    ) -> Result<ReadShapePick> {
        if let Some(shape) = pin {
            return Ok(ReadShapePick {
                shape,
                tier: ReadShapeTier::Pinned,
            });
        }
        if !explore_share.is_finite() || !(0.0..=1.0).contains(&explore_share) {
            return Err(Error::InvalidConfig(
                "read shape exploration share must be within 0..=1".into(),
            ));
        }
        let mount_mass = mass(&self.evidence(Some(model), ReadShape::Mount));
        if mount_mass < MIN_CONTEXT_MASS && explore_share > 0.0 && rng.gen_bool(explore_share) {
            return Ok(ReadShapePick {
                shape: ReadShape::Mount,
                tier: ReadShapeTier::Explore,
            });
        }
        for (tier, scope) in [
            (ReadShapeTier::Model, Some(model)),
            (ReadShapeTier::Global, None),
        ] {
            let arms = ReadShape::ALL.map(|shape| self.evidence(scope, shape));
            if arms.iter().map(mass).sum::<f64>() < MIN_CONTEXT_MASS {
                continue;
            }
            let mut best: Option<(ReadShape, f64)> = None;
            for (shape, arm) in ReadShape::ALL.into_iter().zip(arms) {
                let draw = arm.sample(rng)?;
                if best.is_none_or(|(_, score)| draw > score) {
                    best = Some((shape, draw));
                }
            }
            if let Some((shape, _)) = best {
                return Ok(ReadShapePick { shape, tier });
            }
        }
        Ok(ReadShapePick {
            shape: ReadShape::Verbs,
            tier: ReadShapeTier::Seed,
        })
    }
}

/// Evidence mass above the uniform prior.
fn mass(posterior: &RewardPosterior) -> f64 {
    posterior.alpha + posterior.beta - 2.0
}

const PINS: SideTable<(), ReadShapePins, Named> = SideTable::new(&side_table::READ_SHAPE_PINS);
const POSTERIOR: SideTable<(), ReadShapePosterior, Named> =
    SideTable::new(&side_table::READ_SHAPE_POSTERIOR);
const STAMP: SideTable<AttemptId, ReadShapeStamp, Named> =
    SideTable::new(&side_table::READ_SHAPE_STAMP);

/// One attempt's labelled retrieval runs, as the sleep rebuild gathers them:
/// each run's gated reward mapped to 0..=1 and its mean gate score.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AttemptRunEvidence {
    reward: f64,
    gate: f64,
    runs: u32,
}

impl AttemptRunEvidence {
    pub(crate) fn add_run(&mut self, reward: f64, gate: f64) {
        self.reward += reward;
        self.gate += gate;
        self.runs += 1;
    }
}

impl Store {
    /// The read-shape posterior as the last sleep rebuilt it.
    pub(crate) fn read_shape_posterior(&self) -> Result<ReadShapePosterior> {
        let txn = self.env.read_txn()?;
        let posterior = POSTERIOR.get(self, &txn, &())?.unwrap_or_default();
        posterior.validate()?;
        Ok(posterior)
    }

    /// The owner's read-shape pins.
    pub(crate) fn read_shape_pins(&self) -> Result<ReadShapePins> {
        let txn = self.env.read_txn()?;
        read_shape_pins_in_txn(self, &txn)
    }

    /// Pins `model` to `shape`, or clears its pin when `shape` is absent,
    /// merging against the pins read inside the same write transaction.
    pub(crate) fn put_read_shape_pin(
        &self,
        model: &ModelId,
        shape: Option<ReadShape>,
    ) -> Result<ReadShapePins> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "read shape pin skipped inside active write transaction",
            ));
        }
        let mut txn = self.env.write_txn()?;
        let mut pins = read_shape_pins_in_txn(self, &txn)?;
        pins.set(model, shape);
        pins.validate()?;
        PINS.put(self, &mut txn, &(), &pins)?;
        txn.commit()?;
        Ok(pins)
    }

    /// Picks the shape `model`'s next run reads through, from the owner's
    /// pin, the learned posterior and the exploration share in force.
    pub(crate) fn pick_read_shape<R: Rng + ?Sized>(
        &self,
        model: &ModelId,
        rng: &mut R,
    ) -> Result<ReadShapePick> {
        let txn = self.env.read_txn()?;
        let posterior = POSTERIOR.get(self, &txn, &())?.unwrap_or_default();
        posterior.validate()?;
        let pin = read_shape_pins_in_txn(self, &txn)?.shape_for(model);
        let explore_share = setting_value_in_txn(self, &txn, &READ_SHAPE_EXPLORE_SHARE)?;
        drop(txn);
        posterior.pick(model, pin, explore_share, rng)
    }

    /// Stamps `attempt` with `pick` unless it already holds a stamp, and
    /// returns the stamp in force: a re-leased attempt keeps the shape its
    /// first wake picked. A stamp for another model than the attempt's
    /// executor stamp, or than its own earlier stamp, is refused.
    pub(crate) fn stamp_read_shape(
        &self,
        attempt: AttemptId,
        model: &ModelId,
        pick: ReadShapePick,
    ) -> Result<ReadShapeStamp> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "read shape stamp skipped inside active write transaction",
            ));
        }
        let mut txn = self.env.write_txn()?;
        let record = attempt_record_read::get_in_txn(self, &txn, attempt)?
            .ok_or_else(|| Error::InvalidConfig("unknown attempt".to_owned()))?;
        if record
            .executor_model
            .as_deref()
            .is_some_and(|stamped| stamped != model.as_str())
        {
            return Err(Error::InvalidConfig(
                "read shape stamp names another model than the attempt's executor".to_owned(),
            ));
        }
        if let Some(existing) = STAMP.get(self, &txn, &attempt)? {
            if existing.model != *model {
                return Err(Error::InvalidConfig(
                    "read shape stamp names another model than the attempt's first wake".to_owned(),
                ));
            }
            return Ok(existing);
        }
        let stamp = ReadShapeStamp {
            model: model.clone(),
            shape: pick.shape,
            tier: pick.tier,
            model_units: None,
        };
        STAMP.put(self, &mut txn, &attempt, &stamp)?;
        txn.commit()?;
        Ok(stamp)
    }

    /// Records the model units `attempt`'s run settled. A run's settled total
    /// only grows, so a later report keeps the larger total. An attempt with
    /// no stamp is refused.
    pub(crate) fn record_read_shape_units(&self, attempt: AttemptId, units: u64) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "read shape units skipped inside active write transaction",
            ));
        }
        let mut txn = self.env.write_txn()?;
        let mut stamp = STAMP
            .get(self, &txn, &attempt)?
            .ok_or_else(|| Error::InvalidConfig("attempt holds no read shape stamp".to_owned()))?;
        let total = stamp
            .model_units
            .map_or(units, |recorded| recorded.max(units));
        if stamp.model_units == Some(total) {
            return Ok(());
        }
        stamp.model_units = Some(total);
        STAMP.put(self, &mut txn, &attempt, &stamp)?;
        txn.commit()?;
        Ok(())
    }

    /// The pick `attempt`'s run woke under, if it was stamped.
    pub(crate) fn read_shape_stamp(&self, attempt: AttemptId) -> Result<Option<ReadShapeStamp>> {
        let txn = self.env.read_txn()?;
        STAMP.get(self, &txn, &attempt)
    }
}

fn read_shape_pins_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<ReadShapePins> {
    let pins = PINS.get(store, txn, &())?.unwrap_or_default();
    pins.validate()?;
    Ok(pins)
}

/// Rebuilds the read-shape posterior from the sleep pass's labelled
/// attempts: one pull per stamped attempt, whatever its run count, credited
/// to the stamp's `(model, shape)`. The reward is the mean of the attempt's
/// run rewards less the token cost term, `λ · min(1, units / median − 1)⁺`
/// against the median settled units of the model's labelled attempts (none
/// while the attempt's units are unrecorded); the weight is the mean gate
/// score. An attempt with no stamp adds no pull.
pub(crate) fn rebuild_read_shape_posterior_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempts: &BTreeMap<AttemptId, AttemptRunEvidence>,
) -> Result<ReadShapePosterior> {
    let lambda = setting_value_in_txn(store, txn, &READ_SHAPE_TOKEN_COST)?;
    let mut labelled = Vec::new();
    for (attempt, evidence) in attempts {
        if evidence.runs == 0 {
            continue;
        }
        let Some(stamp) = STAMP.get(store, txn, attempt)? else {
            continue;
        };
        let runs = f64::from(evidence.runs);
        let tokens = stamp.model_units;
        labelled.push((stamp, evidence.reward / runs, evidence.gate / runs, tokens));
    }
    let mut medians: BTreeMap<&ModelId, Vec<u64>> = BTreeMap::new();
    for (stamp, _, _, tokens) in &labelled {
        if let Some(tokens) = tokens {
            medians.entry(&stamp.model).or_default().push(*tokens);
        }
    }
    let medians: BTreeMap<&ModelId, f64> = medians
        .into_iter()
        .map(|(model, mut tokens)| (model, median(&mut tokens)))
        .collect();
    let mut posterior = ReadShapePosterior::default();
    for (stamp, reward, weight, tokens) in &labelled {
        let excess = match (tokens, medians.get(&stamp.model)) {
            (Some(tokens), Some(median)) if *median > 0.0 => {
                (*tokens as f64 / median - 1.0).clamp(0.0, 1.0)
            }
            _ => 0.0,
        };
        let shaped = (reward - lambda * excess).clamp(0.0, 1.0);
        posterior.observe(&stamp.model, stamp.shape, shaped, weight.clamp(0.0, 1.0))?;
        posterior.labeled_attempts += 1;
    }
    Ok(posterior)
}

/// Writes the rebuilt posterior inside the sleep pass's write transaction.
pub(crate) fn put_read_shape_posterior_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    posterior: &ReadShapePosterior,
) -> Result<()> {
    posterior.validate()?;
    POSTERIOR.put(store, txn, &(), posterior)
}

fn median(values: &mut [u64]) -> f64 {
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] as f64 + values[mid] as f64) / 2.0
    } else {
        values[mid] as f64
    }
}
