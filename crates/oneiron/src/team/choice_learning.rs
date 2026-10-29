//! What the planner learned under a spawn choice (FIX 3159; ARCH-0003
//! #learning-settings: a learned value beside every pin). For each value of
//! one choice, the team runs of one scope that used it: their anchored
//! outcomes, faded at the learning window, as that value's runs and its share
//! of them, ranked by the shared selector ranking (the posterior's mean plus
//! its exploration bonus). It reads the team receipts the planner learns from
//! and writes nothing: no recorder, no table, and no success but a receipt's
//! anchored outcome. A scope with none of its own reads the vault's, borrowed
//! (`parent`) and never its own runs, as the planner card does. The owner's
//! row is never one of its inputs.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::agent_dispatch::CoordinationPattern;
use crate::error::Result;
use crate::learning::estimate::{OwnTally, fold_value};
use crate::learning::ranking::rank_by_estimate;
use crate::learning::{
    ESTIMATOR_VERSION, Estimate, EstimateForm, EstimateLabels, LearningPredicate, Prior,
    PriorOrigin, Window,
};
use crate::learning_setting::SettingScope;
use crate::learning_setting_choice::{ChoiceValue, SpawnChoice};
use crate::llm::ModelId;

use super::payoff::PATTERN_EXPLORATION;
use super::receipt::{ReceiptScan, TeamReceipt, team_receipts_in_txn};

/// One choice value and what the scope's team runs measured under it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LearnedChoiceValue {
    pub(crate) value: ChoiceValue,
    /// Its anchored runs, faded at the learning window.
    pub(crate) runs: f64,
    /// Its runs over the runs of every value of the choice.
    pub(crate) share: f64,
}

/// What the planner learned under one choice in one scope.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LearnedChoice {
    /// Each value the runs used, in the shared ranking's order.
    pub(crate) values: Vec<LearnedChoiceValue>,
    /// The scope's own faded runs; zero when the vault's stand in.
    pub(crate) own_runs: f64,
    /// `shipped` over the scope's own runs or none; `parent` when the
    /// vault's runs stand in.
    pub(crate) origin: PriorOrigin,
}

/// Every team receipt as one snapshot read it, the window it fades at and
/// the time it is folded at.
pub(crate) struct ChoiceLearning {
    receipts: Vec<TeamReceipt>,
    window: Window,
    now: u64,
}

impl ChoiceLearning {
    /// Every team receipt in `txn`, folded at `now`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn read_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, now: u64) -> Result<Self> {
        Ok(Self {
            receipts: team_receipts_in_txn(vault, txn, ReceiptScan::AllScopes(None))?,
            window: crate::learning::project::window_in_txn(vault, txn)?,
            now,
        })
    }

    /// What the runs of `scope` learned under `choice`: its own runs, else
    /// the vault's. A goal keys no team receipt, so a goal row reads the
    /// vault's; a type row reads the vault's runs at its node. The planner
    /// learns no budget from a team run, so a budget reads none.
    pub(crate) fn learned(&self, choice: SpawnChoice, scope: &SettingScope) -> LearnedChoice {
        let own = self.fold(choice, |receipt| match scope {
            SettingScope::Vault => receipt.project.is_none(),
            SettingScope::Project(project) => receipt.project == Some(*project),
            SettingScope::Type(type_ref) => {
                receipt.project.is_none() && receipt.type_ref.node_id == type_ref.node_id
            }
            SettingScope::Goal(_) => false,
        });
        if own.is_empty() && *scope != SettingScope::Vault {
            let vault = self.fold(choice, |receipt| receipt.project.is_none());
            if !vault.is_empty() {
                return ranked(vault, PriorOrigin::Parent, self.window);
            }
        }
        ranked(own, PriorOrigin::Shipped, self.window)
    }

    /// The faded `(wins, losses)` under each value of `choice` over the
    /// anchored receipts `keeps` admits, by the value's label. A team on
    /// several models splits its run evenly among them.
    fn fold(
        &self,
        choice: SpawnChoice,
        keeps: impl Fn(&TeamReceipt) -> bool,
    ) -> BTreeMap<String, (ChoiceValue, f64, f64)> {
        let mut mass: BTreeMap<String, (ChoiceValue, f64, f64)> = BTreeMap::new();
        for receipt in self.receipts.iter().filter(|receipt| keeps(receipt)) {
            let Some(outcome) = &receipt.outcome else {
                continue;
            };
            let values: Vec<ChoiceValue> = match choice {
                SpawnChoice::Model => receipt
                    .models
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .filter_map(|model| ModelId::new(model.as_str()).ok())
                    .map(ChoiceValue::Model)
                    .collect(),
                SpawnChoice::Width => vec![ChoiceValue::Width(receipt.shape.width)],
                SpawnChoice::Pattern => vec![ChoiceValue::Pattern(CoordinationPattern::from_team(
                    receipt.pattern,
                ))],
                SpawnChoice::Budget => Vec::new(),
            };
            #[allow(clippy::cast_precision_loss)]
            let weight =
                self.window.decay(self.now.saturating_sub(outcome.at)) / values.len().max(1) as f64;
            for value in values {
                let cell = mass.entry(label(&value)).or_insert((value, 0.0, 0.0));
                if outcome.success {
                    cell.1 += weight;
                } else {
                    cell.2 += weight;
                }
            }
        }
        mass
    }
}

/// A value's stable label: the key ties in the ranking break by.
fn label(value: &ChoiceValue) -> String {
    match value {
        ChoiceValue::Model(model) => model.as_str().to_owned(),
        ChoiceValue::Width(width) => width.to_string(),
        ChoiceValue::Pattern(pattern) => pattern.as_str().to_owned(),
        ChoiceValue::Budget(units) => units.to_string(),
    }
}

/// `mass` ranked by the shared selector ranking, each value's success read
/// as a Beta over its faded outcomes from the shipped prior.
fn ranked(
    mass: BTreeMap<String, (ChoiceValue, f64, f64)>,
    origin: PriorOrigin,
    window: Window,
) -> LearnedChoice {
    let total: f64 = mass.values().map(|(_, wins, losses)| wins + losses).sum();
    let arms: Vec<(String, ChoiceValue, Estimate)> = mass
        .into_iter()
        .map(|(label, (value, wins, losses))| (label, value, estimate(wins, losses, window)))
        .collect();
    let values = rank_by_estimate(arms, PATTERN_EXPLORATION, |arm| &arm.2, |arm| arm.0.clone())
        .into_iter()
        .map(|((_, value, estimate), _)| LearnedChoiceValue {
            value,
            runs: estimate.runs,
            share: if total > 0.0 {
                estimate.runs / total
            } else {
                0.0
            },
        })
        .collect();
    LearnedChoice {
        values,
        own_runs: if origin == PriorOrigin::Parent {
            0.0
        } else {
            total
        },
        origin,
    }
}

/// A read-time estimate over faded outcomes; it is never stored.
fn estimate(wins: f64, losses: f64, window: Window) -> Estimate {
    let prior = Prior::shipped(EstimateForm::Beta);
    Estimate {
        value: fold_value(&prior, &OwnTally::Beta { wins, losses }),
        runs: wins + losses,
        prior,
        of: LearningPredicate::Reliability
            .default_of(EstimateForm::Beta)
            .to_owned(),
        labels: EstimateLabels::default(),
        window,
        ver: ESTIMATOR_VERSION,
    }
}
