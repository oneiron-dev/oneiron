//! The deterministic skill fit and the owner's setting that picks it (FIX
//! 9752, owner law ARCH-0053 "Everything installs; permissions ask"). A rule
//! hit does not fit; code, or a permission the caller does not hold, asks
//! with an analysis naming it; a code-free package that requests nothing new
//! is ready. No model is consulted: the same package, scan and caller give
//! the same answer. Requested permissions stay inert either way: the fit
//! only decides whether the install lands now or asks.
use super::{
    FIT_ANALYSIS_BYTES, MarketplaceFit, MarketplaceFitDecision, MarketplaceFitEvaluator,
    permission_labels,
};
use crate::consent::{AuthenticatedOwner, ComposedEffect, ConsentReceipt, EffectFacts};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::skill_hub::hub_owner::OwnerAskedSkillFit;
use crate::skill_hub::package_codec::invalid;
use crate::skill_hub::{
    HubPackage, HubRef, ScanRiskLevel, ScanVerdict, SkillGovernance, SkillScanReceipt,
};
use crate::{Vault, error::Result};

/// The owner's skill fit setting; an absent row is the rule fit.
const SKILL_FIT: SideTable<(), SkillFitSetting, Raw> =
    SideTable::new(&side_table::SKILL_HUB_MARKETPLACE_SKILL_FIT);

/// What the caller already holds, as its host judges it. A permission is a
/// request label: `verb:<name>` and `lane:<name>` for a section, and
/// `bin:`, `env:`, `mcp:` and `tool:` labels for a skill's capability
/// surface. Holding is the host's answer about the calling credential; it
/// grants nothing.
pub trait CallerPermissions {
    /// Whether the caller already holds `permission`.
    fn holds(&self, permission: &str) -> bool;
}

/// A caller whose host judged nothing: every requested permission asks.
#[derive(Debug, Clone, Copy, Default)]
pub struct HoldsNothing;

impl CallerPermissions for HoldsNothing {
    fn holds(&self, _permission: &str) -> bool {
        false
    }
}

/// Which fit an ordinary skill install runs: the owner's own setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SkillFitSetting {
    /// [`RuleSkillFit`]: a code-free package requesting no permission the
    /// caller lacks installs with undo; anything else asks.
    #[default]
    RuleFit,
    /// Every install asks the owner, whatever it requests.
    OwnerAsked,
}

impl SkillFitSetting {
    const fn byte(self) -> u8 {
        match self {
            Self::RuleFit => 0,
            Self::OwnerAsked => 1,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::RuleFit => "rule_fit",
            Self::OwnerAsked => "owner_asked",
        }
    }
}

impl RawValue for SkillFitSetting {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![self.byte()])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [0] => Ok(Self::RuleFit),
            [1] => Ok(Self::OwnerAsked),
            _ => Err(crate::error::Error::CorruptedIndex("skill fit setting").into()),
        }
    }
}

/// The deterministic skill fit over the fetched package, its static scan
/// and what the caller already holds.
pub struct RuleSkillFit<'a> {
    caller: &'a dyn CallerPermissions,
}

impl<'a> RuleSkillFit<'a> {
    #[must_use]
    pub fn new(caller: &'a dyn CallerPermissions) -> Self {
        Self { caller }
    }

    /// The same fit over a package this vault already stores, which has no
    /// hub source to bind: the rung, its analysis and every permission label
    /// the package requests.
    pub(crate) fn fit_stored(
        &self,
        package: &HubPackage,
        static_scan: &SkillScanReceipt,
    ) -> (MarketplaceFit, String, Vec<String>) {
        let (outcome, analysis) = rule_fit(package, static_scan, self.caller);
        (outcome, analysis, permission_labels(&package.capabilities))
    }
}

impl MarketplaceFitEvaluator for RuleSkillFit<'_> {
    fn evaluate(
        &self,
        source: &HubRef,
        package: &HubPackage,
        static_scan: &SkillScanReceipt,
    ) -> Result<MarketplaceFitDecision> {
        let (outcome, analysis) = rule_fit(package, static_scan, self.caller);
        MarketplaceFitDecision::new(source, package, outcome, analysis, static_scan)
    }
}

/// A rule hit is the static scan's own finding: a malicious verdict, a high
/// or critical risk, or a prohibited governance. Code is any `scripts/`
/// file, as the import's own code test reads it.
fn rule_fit(
    package: &HubPackage,
    static_scan: &SkillScanReceipt,
    caller: &dyn CallerPermissions,
) -> (MarketplaceFit, String) {
    if static_scan.verdict == ScanVerdict::Malicious
        || static_scan.risk_level >= ScanRiskLevel::High
        || static_scan.governance == SkillGovernance::Prohibited
    {
        return (
            MarketplaceFit::NoFit,
            format!(
                "a scan rule hit ({:?} verdict, {:?} risk, {:?} governance); it does not install",
                static_scan.verdict, static_scan.risk_level, static_scan.governance
            ),
        );
    }
    let code: Vec<String> = package
        .files
        .iter()
        .filter(|file| file.path.starts_with("scripts/"))
        .map(|file| file.path.clone())
        .collect();
    if !code.is_empty() {
        return (
            MarketplaceFit::Ask,
            bounded_list(
                "it carries code (",
                &code,
                "); code stays Candidate until the owner allows it",
            ),
        );
    }
    let missing: Vec<String> = permission_labels(&package.capabilities)
        .into_iter()
        .filter(|label| !caller.holds(label))
        .collect();
    if !missing.is_empty() {
        return (
            MarketplaceFit::Ask,
            bounded_list("it requests ", &missing, ", which the caller does not hold"),
        );
    }
    (
        MarketplaceFit::Ready,
        "code-free; it requests no permission the caller does not hold".to_owned(),
    )
}

/// Names `items` between `lead` and `tail` within the analysis bound; the
/// ones that do not fit are counted, never dropped silently.
fn bounded_list(lead: &str, items: &[String], tail: &str) -> String {
    // Room for the lead, the tail and an " and N more" note.
    let room = FIT_ANALYSIS_BYTES.saturating_sub(lead.len() + tail.len() + 32);
    let mut named = String::new();
    let mut shown = 0_usize;
    for item in items {
        let extra = item.len() + if named.is_empty() { 0 } else { 2 };
        if named.len() + extra > room {
            break;
        }
        if !named.is_empty() {
            named.push_str(", ");
        }
        named.push_str(item);
        shown += 1;
    }
    match (shown, items.len() - shown) {
        (_, 0) => format!("{lead}{named}{tail}"),
        (0, more) => format!("{lead}{more} items{tail}"),
        (_, more) => format!("{lead}{named} and {more} more{tail}"),
    }
}

impl Vault {
    /// The owner's skill fit setting: the rule fit unless the owner chose
    /// the owner-asked fit.
    pub fn marketplace_skill_fit(&self) -> Result<SkillFitSetting> {
        let txn = self.store.env.read_txn()?;
        Ok(SKILL_FIT.get(&self.store, &txn, &())?.unwrap_or_default())
    }

    /// The owner picks which fit an ordinary skill install runs. The change
    /// is the owner's own act, consented once and spent in the same writer.
    pub fn set_marketplace_skill_fit(
        &self,
        owner: &AuthenticatedOwner,
        setting: SkillFitSetting,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let nonce = self.store.clock.entity_id()?;
            let effect = ComposedEffect::new(EffectFacts::new(format!(
                "skill.marketplace.skill-fit:{}:{}",
                setting.as_str(),
                nonce.to_hex()
            ))?)
            .digest();
            let receipt = self.approve_once_in_txn(txn, owner, effect)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &effect)?
                    .ok_or_else(|| invalid("skill fit setting consent missing"))?;
            SKILL_FIT.put(&self.store, txn, &(), &setting)?;
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            Ok(receipt)
        })
    }

    /// The fit an ordinary skill install runs for `caller`, as the owner's
    /// setting picks it.
    pub(crate) fn chosen_skill_fit<'a>(
        &self,
        caller: &'a dyn CallerPermissions,
    ) -> Result<Box<dyn MarketplaceFitEvaluator + 'a>> {
        let fit: Box<dyn MarketplaceFitEvaluator + 'a> = match self.marketplace_skill_fit()? {
            SkillFitSetting::RuleFit => Box::new(RuleSkillFit::new(caller)),
            SkillFitSetting::OwnerAsked => Box::new(OwnerAskedSkillFit),
        };
        Ok(fit)
    }
}
