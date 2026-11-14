//! `vault.agents.optional_memory.set` (census L9-32; Engine rulings
//! L9-32-PICK-WRITER, 07:43, and L9-32-NO-PROFILE = A, 07:52, Sat 14 Nov):
//! the owner sets the optional recall one agent takes as a reader, a default
//! and the task families that differ, on the definition's next version.
//!
//! ARCH-0004 #reader-budget: held-out outcomes for the actual reader and task
//! pick the setting. The bench prints this verb's argument from its picks
//! (`beam measure --picks-for`), so the owner applies a pick in one reviewed
//! step. The Coach's retrieval slow loop is to file the same change later, as
//! a proposal in this request's shape (FIX READER-PICK-PROFILE-WRITER, L1-18).
//! The setting only narrows a pack request ([`OptionalMemory::narrow`]); it
//! carries no authority, scope or disclosure field, and the window profile,
//! its compaction and its pack budget stay as authored.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use super::{AgentDefinition, OptionalMemory, OptionalMemoryProfile};
use crate::consent::AuthenticatedOwner;
use crate::context_pack::FieldProfile;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError, MemoryResult};
use crate::{TimeRange, Vault};

/// The detail an optional recall is served at, by the pack request's `view`
/// names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OptionalMemoryView {
    Summary,
    Standard,
    Full,
}

impl From<OptionalMemoryView> for FieldProfile {
    fn from(view: OptionalMemoryView) -> Self {
        match view {
            OptionalMemoryView::Summary => Self::Minimal,
            OptionalMemoryView::Standard => Self::Standard,
            OptionalMemoryView::Full => Self::Full,
        }
    }
}

impl From<FieldProfile> for OptionalMemoryView {
    fn from(profile: FieldProfile) -> Self {
        match profile {
            FieldProfile::Minimal => Self::Summary,
            FieldProfile::Standard => Self::Standard,
            FieldProfile::Full => Self::Full,
        }
    }
}

/// One task family's optional recall, as the owner sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OptionalMemoryChoice {
    /// No optional recall.
    None,
    /// At most `tokens` of optional recall, at `view` detail or less. At
    /// least 1: a pack budget of 0 means no limit, not no recall.
    Budget {
        tokens: u64,
        view: OptionalMemoryView,
    },
}

impl OptionalMemoryChoice {
    fn to_engine(self) -> MemoryResult<OptionalMemory> {
        match self {
            Self::None => Ok(OptionalMemory::None),
            Self::Budget { tokens, view } => {
                let tokens = NonZeroU64::new(tokens).ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_BAD_REQUEST,
                        "an optional-memory budget of 0 tokens is no limit, not no recall",
                        &["Set kind none for no optional recall, or a budget of at least 1 token."],
                    )
                })?;
                Ok(OptionalMemory::Budget {
                    tokens,
                    view: view.into(),
                })
            }
        }
    }

    fn of(choice: OptionalMemory) -> Self {
        match choice {
            OptionalMemory::None => Self::None,
            OptionalMemory::Budget { tokens, view } => Self::Budget {
                tokens: tokens.get(),
                view: view.into(),
            },
        }
    }
}

/// `vault.agents.optional_memory.set`: the agent, the definition version the
/// owner read, and the optional recall it takes as a reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentOptionalMemorySetRequest {
    pub agent_def_ref: EntityId,
    /// The definition's version as `vault.agents.get` showed it; the set is
    /// refused once the definition has moved on.
    pub expected_version: String,
    /// The choice for a task family `families` does not list, and for a pack
    /// that names no family.
    pub default: OptionalMemoryChoice,
    /// The task families that differ from `default`, by the pack request's
    /// `reader.task_family` (the bench's ability label).
    #[serde(default)]
    pub families: BTreeMap<String, OptionalMemoryChoice>,
}

/// One agent's optional recall, as the setter left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentOptionalMemoryState {
    pub agent_def_ref: EntityId,
    /// The definition's version now; the next set expects it.
    pub version: String,
    pub default: OptionalMemoryChoice,
    pub families: BTreeMap<String, OptionalMemoryChoice>,
}

impl AgentOptionalMemoryState {
    fn of(agent_def_ref: EntityId, definition: &AgentDefinition) -> Self {
        let (default, families) = definition.optional_memory.as_ref().map_or(
            (OptionalMemoryChoice::None, BTreeMap::new()),
            |profile| {
                (
                    OptionalMemoryChoice::of(profile.default),
                    profile
                        .families
                        .iter()
                        .map(|(family, choice)| (family.clone(), OptionalMemoryChoice::of(*choice)))
                        .collect(),
                )
            },
        );
        Self {
            agent_def_ref,
            version: definition.version.clone(),
            default,
            families,
        }
    }
}

impl Vault {
    /// The owner sets agent definition `id`'s optional recall to
    /// `optional_memory`, when the stored definition is still at
    /// `expected_version`. The definition standing there is cloned and only
    /// its optional memory and its version change: the window profile, its
    /// compaction and its pack budget stay as authored. The new version is
    /// `optional-memory-<blake3 of the prior version and the setting>`. The
    /// owner's edit door writes it, so the proof is rechecked and the
    /// immutable-field gate runs in the same writer. A setting the definition
    /// already carries writes nothing. Returns the definition as it stands.
    ///
    /// # Errors
    ///
    /// An owner proof that does not revalidate, an id that names no row
    /// ([`Error::EntityNotFound`]) or a row that is not an agent definition
    /// (`InvalidAgentDefBody`), a definition no longer at
    /// `expected_version` ([`Error::ConcurrentWrite`]), and a family name
    /// the body codec refuses.
    pub fn set_agent_optional_memory_as(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        expected_version: &str,
        optional_memory: OptionalMemoryProfile,
    ) -> Result<AgentDefinition> {
        self.with_write_txn(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let existing = self.read_agent_definition_in_txn(txn, id)?;
            if existing.version != expected_version {
                return Err(Error::ConcurrentWrite("agent definition revision changed"));
            }
            if existing.optional_memory.as_ref() == Some(&optional_memory) {
                return Ok(existing);
            }
            let mut patched = existing.clone().with_optional_memory(Some(optional_memory));
            let setting = AgentOptionalMemoryState::of(*id, &patched);
            let seed =
                serde_json::to_vec(&(&existing.version, &setting.default, &setting.families))
                    .map_err(|_| Error::InvariantViolation("optional memory version encode"))?;
            patched.version = format!("optional-memory-{}", blake3::hash(&seed).to_hex());
            let now = crate::unix_seconds_now();
            self.update_agent_definition_as_owner_in_txn(
                txn,
                owner,
                id,
                Some(expected_version),
                &patched,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            Ok(patched)
        })
    }
}

/// [`Vault::set_agent_optional_memory_as`] from the owner door's request.
///
/// # Errors
///
/// A budget of 0 tokens, and the setter's refusals.
pub fn set_agent_optional_memory_from_request_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentOptionalMemorySetRequest,
) -> MemoryResult<AgentOptionalMemoryState> {
    let mut profile = OptionalMemoryProfile::new(input.default.to_engine()?);
    for (family, choice) in input.families {
        profile = profile.with_family(family, choice.to_engine()?);
    }
    let definition = vault.set_agent_optional_memory_as(
        owner,
        &input.agent_def_ref,
        &input.expected_version,
        profile,
    )?;
    Ok(AgentOptionalMemoryState::of(
        input.agent_def_ref,
        &definition,
    ))
}
