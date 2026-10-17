//! PEOPLE (owner ruling, ARCH-0067): one `pr` handle for every person, humans
//! and agents alike.
//!
//! A person is a PERSON entity, and its handle is the PERSON's own vault
//! short id. An agent is a person through its `actor.subject_ref` anchor; a
//! definition with no subject gets its own model PERSON when it is defined
//! ([`ensure_agent_person`]). The cached prefix holds a budgeted `people`
//! roster per vault; the live board names persons by handle, and a handle the
//! reader's cached roster does not hold carries its name inline.

use std::collections::{BTreeMap, BTreeSet};

use super::one_line_token;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::{EdgeActorClass, TimeRange, Vault, WriteActor};

/// Token budget of one vault's `people` rows in the cached prefix. Rows past
/// it page out behind `more: +N`; `vault.people.list` reads the further pages.
pub const PEOPLE_PREFIX_BUDGET_TOK: usize = 512;

/// Derivation domain of the model PERSON an agent definition is born with.
const AGENT_PERSON_DOMAIN: &[u8] = b"oneiron.people.agent-person.v1";

/// Whether a person is a human or an agent. The room roster's kind column.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PersonKind {
    Human,
    Agent,
}

impl PersonKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
        }
    }
}

/// One person the vault knows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersonRow {
    /// The PERSON entity.
    pub person: EntityId,
    /// Actors that speak as this person: the PERSON itself for a human, the
    /// anchored AGENT_DEF for an agent.
    pub actors: Vec<EntityId>,
    /// `pr<n>`, the PERSON's vault short id.
    pub handle: String,
    pub name: String,
    pub kind: PersonKind,
    /// `owner`, `member` or `contact` for a human; `preset` or `custom` for
    /// an agent.
    pub role: String,
    /// One line for the reader's sensitivity band, when the about job has
    /// written one.
    pub about: Option<String>,
}

impl PersonRow {
    /// The TOON row `pr<n>: name,kind,role,about`.
    #[must_use]
    pub fn toon_row(&self) -> String {
        format!(
            "{}: {},{},{},{}",
            self.handle,
            toon_cell(&self.name),
            self.kind.as_str(),
            toon_cell(&self.role),
            self.about.as_deref().map(toon_cell).unwrap_or_default()
        )
    }
}

/// Every person one vault knows that the reader's read admits, in handle
/// order, indexed by PERSON and by each actor that speaks as one.
#[derive(Debug, Clone, Default)]
pub struct People {
    vault: String,
    rows: Vec<PersonRow>,
    index: BTreeMap<EntityId, usize>,
}

impl People {
    /// Reads the vault's people at `at`. `admit` is the reader's read: a
    /// PERSON it does not read is not on the roster. Upkeep agents (the
    /// Dreamer, the Coach), disabled or inactive definitions and archived
    /// rows are not people.
    pub fn load(
        vault: &Vault,
        at: u64,
        admit: &mut dyn FnMut(EntityId) -> Result<bool>,
    ) -> Result<Self> {
        let agents = vault.entities_by_type(ENTITY_TYPE_AGENT_DEF)?;
        let persons = vault.entities_by_type(ENTITY_TYPE_PERSON)?;
        let fold = vault.authority_fold()?;
        let tag = fold.vault_id.map_or_else(
            || "home".to_owned(),
            |id| format!("vt{}", crate::entity_id::bytes_to_hex_lower(&id[..8])),
        );
        let members: BTreeSet<EntityId> = fold
            .actor_bindings
            .values()
            .filter(|binding| {
                binding.status == crate::authority::ActorBindingStatus::Active
                    && binding.actor_class == "human"
            })
            .map(|binding| binding.actor_ref)
            .collect();
        let rtxn = vault.store.env.read_txn()?;
        // The vault owner's row reads `owner`: the embedded owner, or a human
        // whose owner binding verifies. An unverifiable binding stays `member`.
        let mut owners = BTreeSet::new();
        for actor in members
            .iter()
            .copied()
            .chain([crate::vault::embedded_owner_actor_id()?])
        {
            if crate::memory::actor_is_vault_owner_in_txn(
                vault,
                &rtxn,
                actor,
                EdgeActorClass::Human,
            )
            .unwrap_or(false)
            {
                owners.insert(actor);
            }
        }
        let mut agent_of: BTreeMap<EntityId, (EntityId, crate::agent_def::AgentDefinition)> =
            BTreeMap::new();
        let mut hidden = BTreeSet::new();
        for agent in agents {
            let Some(anchor) =
                crate::subject_model::actor_subject_anchor_in_txn(vault, &rtxn, &agent, at)?
            else {
                continue;
            };
            match live_agent(vault, &rtxn, agent)? {
                Some(def) => {
                    agent_of.entry(anchor.subject_ref).or_insert((agent, def));
                }
                None => {
                    hidden.insert(anchor.subject_ref);
                }
            }
        }
        // Every read below the roster's own transaction opens its own, so the
        // census is taken first and the reader's read runs after it closes.
        let mut found = Vec::new();
        for person in persons {
            if hidden.contains(&person) && !agent_of.contains_key(&person) {
                continue;
            }
            if vault.archive_tombstone_in_txn(&rtxn, &person)?.is_some() {
                continue;
            }
            let crate::vault::LiveEntityRow::Live { body, .. } =
                crate::vault::live_entity_row_in_txn(&vault.store, &rtxn, &person)?
            else {
                continue;
            };
            let Some((handle, _)) = crate::ports::ShortIdStoreRead::port_short_id_reference(
                &vault.store,
                &rtxn,
                &person,
            )?
            else {
                continue;
            };
            found.push((person, handle, body));
        }
        drop(rtxn);
        let mut rows = Vec::new();
        for (person, handle, body) in found {
            if !admit(person)? {
                continue;
            }
            let row = match agent_of.get(&person) {
                Some((agent, def)) => PersonRow {
                    person,
                    actors: vec![*agent],
                    name: def
                        .display_name
                        .clone()
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or_else(|| def.agent_id.clone()),
                    handle,
                    kind: PersonKind::Agent,
                    role: if def.logical_id.is_some() {
                        "preset"
                    } else {
                        "custom"
                    }
                    .to_owned(),
                    about: None,
                },
                None => {
                    let model = matches!(
                        vault.person_substrate(&person, at),
                        Ok(Some(crate::subject_model::PersonSubstrate::Model))
                    );
                    PersonRow {
                        person,
                        actors: vec![person],
                        name: person_name(&body).unwrap_or_else(|| handle.clone()),
                        handle,
                        kind: if model {
                            PersonKind::Agent
                        } else {
                            PersonKind::Human
                        },
                        role: if model {
                            "custom"
                        } else if owners.contains(&person) {
                            "owner"
                        } else if members.contains(&person) {
                            "member"
                        } else {
                            "contact"
                        }
                        .to_owned(),
                        about: None,
                    }
                }
            };
            rows.push(row);
        }
        rows.sort_by_key(|row| (handle_number(&row.handle), row.person));
        Ok(Self::from_rows(tag, rows))
    }

    fn from_rows(vault: String, rows: Vec<PersonRow>) -> Self {
        let mut index = BTreeMap::new();
        for (at, row) in rows.iter().enumerate() {
            index.insert(row.person, at);
            for actor in &row.actors {
                index.entry(*actor).or_insert(at);
            }
        }
        Self { vault, rows, index }
    }

    /// The vault these people belong to, as the prefix groups them.
    #[must_use]
    pub fn vault(&self) -> &str {
        &self.vault
    }

    #[must_use]
    pub fn rows(&self) -> &[PersonRow] {
        &self.rows
    }

    /// The person a PERSON id or an actor id names.
    #[must_use]
    pub fn get(&self, id: EntityId) -> Option<&PersonRow> {
        self.index.get(&id).map(|at| &self.rows[*at])
    }

    /// The person a `pr<n>` handle names.
    #[must_use]
    pub fn by_handle(&self, handle: &str) -> Option<&PersonRow> {
        self.rows.iter().find(|row| row.handle == handle)
    }

    /// Sets each person's `about` line from `about(person)`.
    pub fn set_about(
        &mut self,
        about: &mut dyn FnMut(EntityId) -> Result<Option<String>>,
    ) -> Result<()> {
        for row in &mut self.rows {
            row.about = about(row.person)?;
        }
        Ok(())
    }

    /// The cached prefix's roster for this vault, chosen at an epoch boundary:
    /// `pinned` persons first, in their order, then every other person in
    /// handle order, while the rows fit [`PEOPLE_PREFIX_BUDGET_TOK`]. The
    /// rest are counted, never dropped silently.
    #[must_use]
    pub fn residence(&self, pinned: &[EntityId]) -> PeoplePrefix {
        let mut order: Vec<usize> = Vec::with_capacity(self.rows.len());
        let mut placed = BTreeSet::new();
        for id in pinned {
            if let Some(at) = self.index.get(id)
                && placed.insert(*at)
            {
                order.push(*at);
            }
        }
        order.extend((0..self.rows.len()).filter(|at| !placed.contains(at)));
        let mut rows = Vec::new();
        let mut resident = BTreeSet::new();
        let mut spent = 0_usize;
        let mut more = 0_usize;
        for at in order {
            let row = &self.rows[at];
            let line = xml_safe(&row.toon_row());
            let cost = crate::count_context_pack_tokens(&line).max(1);
            if more > 0 || spent + cost > PEOPLE_PREFIX_BUDGET_TOK {
                more += 1;
                continue;
            }
            spent += cost;
            resident.insert(row.person);
            rows.push(line);
        }
        PeoplePrefix {
            vault: self.vault.clone(),
            rows,
            more,
            resident,
        }
    }

    /// One page of the roster for `vault.people.list`: `page` counts from zero, and
    /// a page holds `size` persons in handle order.
    #[must_use]
    pub fn page(&self, page: usize, size: usize) -> (&[PersonRow], usize) {
        let size = size.max(1);
        let start = page.saturating_mul(size).min(self.rows.len());
        let end = start.saturating_add(size).min(self.rows.len());
        (&self.rows[start..end], self.rows.len() - end)
    }
}

/// The `people` block one vault contributes to the cached prefix, and the
/// persons it made resident.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeoplePrefix {
    pub vault: String,
    pub rows: Vec<String>,
    pub more: usize,
    pub resident: BTreeSet<EntityId>,
}

impl PeoplePrefix {
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("<people vault={}>", self.vault);
        for row in &self.rows {
            out.push('\n');
            out.push_str(row);
        }
        // The overflow points at the verb that pages the rest (ARCH-0067).
        if self.more > 0 {
            out.push_str(&format!(
                "\nmore: +{} \u{b7} vault.people.list({}, page)",
                self.more, self.vault
            ));
        }
        out.push_str("\n</people>");
        out
    }
}

/// How the live board names a person to one reader: the bare handle when the
/// reader's cached roster holds it, the handle with its name inline when not,
/// and the raw id for an actor that is no person.
#[derive(Debug, Clone, Copy)]
pub struct PeopleView<'a> {
    pub people: &'a People,
    pub resident: &'a BTreeSet<EntityId>,
}

impl<'a> PeopleView<'a> {
    #[must_use]
    pub const fn new(people: &'a People, resident: &'a BTreeSet<EntityId>) -> Self {
        Self { people, resident }
    }

    /// The person's board mention, or `None` for an id that is no person.
    #[must_use]
    pub fn mention(&self, id: EntityId) -> Option<String> {
        let row = self.people.get(id)?;
        Some(if self.resident.contains(&row.person) {
            row.handle.clone()
        } else {
            format!("{}({})", row.handle, one_line_token(&row.name))
        })
    }

    /// [`Self::mention`], falling back to the raw id.
    #[must_use]
    pub fn label(&self, id: EntityId) -> String {
        self.mention(id).unwrap_or_else(|| id.to_hex())
    }

    #[must_use]
    pub fn kind(&self, id: EntityId) -> Option<PersonKind> {
        self.people.get(id).map(|row| row.kind)
    }
}

/// Every agent is a person: a definition with no subject gets its own model
/// PERSON, named for it, and the anchor to it, written by the agent itself in
/// one transaction. The PERSON id derives from the agent's, so a rerun finds
/// the same person. Upkeep agents are not people and get none.
pub(crate) fn ensure_agent_person(
    vault: &Vault,
    agent: EntityId,
    name: &str,
    at: u64,
) -> Result<()> {
    if crate::dreamer_runner::authority::is_base_agent_actor(&agent)? {
        return Ok(());
    }
    let person = EntityId::derive(AGENT_PERSON_DOMAIN, &[agent.as_bytes()])?;
    let mut txn = vault.store.env.write_txn()?;
    if crate::subject_model::actor_subject_anchor_in_txn(vault, &txn, &agent, at)?.is_some() {
        return Ok(());
    }
    if vault.store.port_entity_record(&txn, &person)?.is_none() {
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(
                rmpv::Value::from("display_name"),
                rmpv::Value::from(name),
            )]),
        )
        .map_err(|_| crate::Error::InvariantViolation("agent person body encoding failed"))?;
        vault
            .batch_in()
            .put(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange { start: at, end: at },
                at,
                &body,
            )
            .apply(&mut txn)?;
    }
    let writer = WriteActor::new(agent, EdgeActorClass::Agent);
    crate::subject_model::ensure_model_person_in_txn(vault, &mut txn, person, writer, at)?;
    crate::subject_model::ensure_actor_subject_in_txn(vault, &mut txn, agent, person, writer, at)?;
    txn.commit()?;
    Ok(())
}

/// The definition of a live, enabled, active, non-upkeep agent.
fn live_agent(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
) -> Result<Option<crate::agent_def::AgentDefinition>> {
    if crate::dreamer_runner::authority::is_base_agent_actor(&agent)?
        || vault.archive_tombstone_in_txn(txn, &agent)?.is_some()
    {
        return Ok(None);
    }
    let crate::vault::LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_AGENT_DEF,
        body,
    } = crate::vault::live_entity_row_in_txn(&vault.store, txn, &agent)?
    else {
        return Ok(None);
    };
    Ok(crate::agent_def::decode_agent_definition(&body)
        .ok()
        .filter(|def| {
            def.enabled && def.lifecycle_status == crate::claim::ClaimLifecycleStatus::Active
        }))
}

/// A PERSON body's `display_name`, or its persona baseline's.
fn person_name(body: &[u8]) -> Option<String> {
    let fields = crate::companion::persona_body_fields(body).ok()?;
    let top = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("display_name"))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned);
    top.or_else(|| {
        crate::companion::validated_persona_baseline(body)
            .ok()?
            .get("display_name")?
            .as_str()
            .map(str::to_owned)
    })
    .filter(|name| !name.trim().is_empty())
}

fn handle_number(handle: &str) -> u64 {
    handle
        .trim_start_matches(|character: char| character.is_ascii_lowercase())
        .parse()
        .unwrap_or(u64::MAX)
}

/// A TOON cell: bare when it holds no delimiter, quoted JSON when it does.
fn toon_cell(value: &str) -> String {
    let value = one_line_token(value);
    let plain = !value.is_empty()
        && value.trim() == value
        && !value
            .chars()
            .any(|character| matches!(character, ',' | '"' | ':' | '\\' | '<' | '>' | '&'));
    if plain || value.is_empty() {
        value
    } else {
        serde_json::Value::String(value).to_string()
    }
}

/// Encodes XML delimiters as JSON unicode escapes so a name cannot close the
/// prefix block it sits in.
fn xml_safe(value: &str) -> String {
    value
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
}
