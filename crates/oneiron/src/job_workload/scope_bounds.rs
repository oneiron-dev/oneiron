//! What a launch scope can enforce (pass 34, `34-compute-general/DESIGN.md`
//! section 2.2): each bound ([`ScopeBound`]) at a strength
//! ([`BoundStrength`]: kernel, supervised or none), the report a scope's
//! probe gives ([`ScopeCapabilities`]), and the bounds a template requires
//! ([`BoundRequirement`]).
//!
//! Tree kill, the cutoff with the engine stopped, and emptiness are the
//! minimum contract: a scope without one of them runs no job. Every other
//! bound is required by the template, not by the machine; a bound that is
//! neither required nor available is recorded as unproven.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// One thing a launch scope may enforce on a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeBound {
    /// Every process of the run ends together.
    TreeKill,
    /// The cutoff holds with the engine stopped.
    CutoffWithoutEngine,
    /// The node can tell that no process of the run is left.
    Emptiness,
    MemoryCap,
    CpuCap,
    /// The run cannot read or write outside its own files.
    FileWall,
    NetworkClosed,
    /// The run opens only its leased devices, and no other account opens
    /// them.
    DeviceClosure,
    /// The run sees no other process.
    ProcessesHidden,
    WriteRateCap,
}

impl ScopeBound {
    /// Every bound, in report order.
    pub const ALL: [Self; 10] = [
        Self::TreeKill,
        Self::CutoffWithoutEngine,
        Self::Emptiness,
        Self::MemoryCap,
        Self::CpuCap,
        Self::FileWall,
        Self::NetworkClosed,
        Self::DeviceClosure,
        Self::ProcessesHidden,
        Self::WriteRateCap,
    ];

    /// The bounds a scope must give before it runs any job (invariants I4
    /// and I5): no second is spent that nobody can stop or count.
    pub const MINIMUM_CONTRACT: [Self; 3] =
        [Self::TreeKill, Self::CutoffWithoutEngine, Self::Emptiness];

    /// The bound's name in a template's `require` list, e.g. `file_wall`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::TreeKill => "tree_kill",
            Self::CutoffWithoutEngine => "cutoff_without_engine",
            Self::Emptiness => "emptiness",
            Self::MemoryCap => "memory_cap",
            Self::CpuCap => "cpu_cap",
            Self::FileWall => "file_wall",
            Self::NetworkClosed => "network_closed",
            Self::DeviceClosure => "device_closure",
            Self::ProcessesHidden => "processes_hidden",
            Self::WriteRateCap => "write_rate_cap",
        }
    }

    /// The bound a `require` name names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|bound| bound.name() == name)
    }
}

/// How strongly a scope enforces one bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundStrength {
    /// The operating system enforces it with no process of the engine's
    /// alive.
    Kernel,
    /// A privileged process that is not the engine enforces it, at most
    /// this late: its check interval plus its own restart time.
    Supervised { worst_lateness_ms: u64 },
    /// Not enforced: a run that needed it is unproven.
    None,
}

impl BoundStrength {
    /// Whether the bound is enforced at all.
    #[must_use]
    pub fn is_enforced(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// One bound as a scope reports it: its strength and one line of evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundReport {
    pub strength: BoundStrength,
    pub evidence: String,
}

/// What one launch scope can enforce on this machine now, bound by bound:
/// its probe's report, which `Node` carries and a receipt records for the
/// run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeCapabilities {
    pub tree_kill: BoundReport,
    pub cutoff_without_engine: BoundReport,
    pub emptiness: BoundReport,
    pub memory_cap: BoundReport,
    pub cpu_cap: BoundReport,
    pub file_wall: BoundReport,
    pub network_closed: BoundReport,
    pub device_closure: BoundReport,
    pub processes_hidden: BoundReport,
    pub write_rate_cap: BoundReport,
}

impl ScopeCapabilities {
    /// The report of `bound`.
    #[must_use]
    pub fn report(&self, bound: ScopeBound) -> &BoundReport {
        match bound {
            ScopeBound::TreeKill => &self.tree_kill,
            ScopeBound::CutoffWithoutEngine => &self.cutoff_without_engine,
            ScopeBound::Emptiness => &self.emptiness,
            ScopeBound::MemoryCap => &self.memory_cap,
            ScopeBound::CpuCap => &self.cpu_cap,
            ScopeBound::FileWall => &self.file_wall,
            ScopeBound::NetworkClosed => &self.network_closed,
            ScopeBound::DeviceClosure => &self.device_closure,
            ScopeBound::ProcessesHidden => &self.processes_hidden,
            ScopeBound::WriteRateCap => &self.write_rate_cap,
        }
    }

    /// Whether the scope gives tree kill, the cutoff with the engine
    /// stopped, and emptiness. A scope that does not runs no job.
    #[must_use]
    pub fn meets_minimum_contract(&self) -> bool {
        ScopeBound::MINIMUM_CONTRACT
            .into_iter()
            .all(|bound| self.report(bound).strength.is_enforced())
    }

    /// The requirements of `required` this scope does not meet: a run that
    /// requires any of them does not fit here.
    #[must_use]
    pub fn missing(&self, required: &[BoundRequirement]) -> Vec<BoundRequirement> {
        required
            .iter()
            .filter(|requirement| !requirement.is_met_by(self.report(requirement.bound).strength))
            .copied()
            .collect()
    }

    /// The bounds outside `required` that this scope does not enforce: a run
    /// here goes on, and its receipt shows each as unproven.
    #[must_use]
    pub fn unproven(&self, required: &[BoundRequirement]) -> Vec<ScopeBound> {
        ScopeBound::ALL
            .into_iter()
            .filter(|bound| {
                !required
                    .iter()
                    .any(|requirement| requirement.bound == *bound)
            })
            .filter(|bound| !self.report(*bound).strength.is_enforced())
            .collect()
    }
}

/// One bound a template requires: `file_wall` takes it at any strength,
/// `memory_cap:kernel` only from the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BoundRequirement {
    pub bound: ScopeBound,
    /// Only a kernel-enforced bound meets it.
    pub kernel: bool,
}

/// The `:kernel` suffix of a requirement's name.
const KERNEL_SUFFIX: &str = ":kernel";

impl BoundRequirement {
    /// Whether a bound enforced at `strength` meets this requirement.
    #[must_use]
    pub fn is_met_by(self, strength: BoundStrength) -> bool {
        match strength {
            BoundStrength::Kernel => true,
            BoundStrength::Supervised { .. } => !self.kernel,
            BoundStrength::None => false,
        }
    }
}

impl fmt::Display for BoundRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.bound.name())?;
        if self.kernel {
            f.write_str(KERNEL_SUFFIX)?;
        }
        Ok(())
    }
}

/// A `require` name that names no bound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("scope_bound_unknown: {0}")]
pub struct UnknownScopeBound(pub String);

impl FromStr for BoundRequirement {
    type Err = UnknownScopeBound;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (name, kernel) = match text.strip_suffix(KERNEL_SUFFIX) {
            Some(name) => (name, true),
            None => (text, false),
        };
        let bound =
            ScopeBound::from_name(name).ok_or_else(|| UnknownScopeBound(text.to_owned()))?;
        Ok(Self { bound, kernel })
    }
}

impl TryFrom<String> for BoundRequirement {
    type Error = UnknownScopeBound;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<BoundRequirement> for String {
    fn from(requirement: BoundRequirement) -> Self {
        requirement.to_string()
    }
}
