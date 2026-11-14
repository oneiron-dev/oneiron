//! Moved from `crates/oneiron/src/context_board/people.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

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

/// Token budget of one vault's `people` rows in the cached prefix. Rows past
/// it page out behind `more: +N`; `vault.people.list` reads the further pages.
pub const PEOPLE_PREFIX_BUDGET_TOK: usize = 512;

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

/// What a read knows of the actor behind one of its rows: a person the
/// reader reads, human or agent, or no one it can name.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ActorAttributionKind {
    Human,
    Agent,
    /// No person this reader reads: a PERSON or definition outside the
    /// reader's read, an erased or archived person, an upkeep agent, or a
    /// writer that is no person.
    Unknown,
}

impl From<PersonKind> for ActorAttributionKind {
    fn from(kind: PersonKind) -> Self {
        match kind {
            PersonKind::Human => Self::Human,
            PersonKind::Agent => Self::Agent,
        }
    }
}

/// Who made one change, as one reader may name them (FIX [UI-GATE-PREVIEW]
/// phase 3; GENUI-WIRE-GAPS section 4 item 2: "by eiri"). For an actor that
/// speaks as a person the reader reads, that person's PERSON id, `pr` handle,
/// name and kind exactly as `vault.people.list` shows them to this reader,
/// the name under the same disclosure rule; for any other actor `unknown`
/// and nothing else. The row keeps the actor's own ref either way, so a
/// change by an actor later erased still says who it was, and the person an
/// agent acts for stays its own field on the row: this names the actor alone.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActorAttribution {
    pub kind: ActorAttributionKind,
    /// The PERSON entity the actor speaks as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    /// `pr<n>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ActorAttribution {
    /// An actor this reader cannot name.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            kind: ActorAttributionKind::Unknown,
            person: None,
            handle: None,
            name: None,
        }
    }
}

pub fn person_name(body: &[u8]) -> Option<String> {
    let fields = oneiron_store::write_envelope::person_identity::body_fields(body).ok()?;
    let top = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("display_name"))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned);
    top.or_else(|| {
        oneiron_store::serialize::person_identity::validated_persona_baseline(body)
            .ok()?
            .get("display_name")?
            .as_str()
            .map(str::to_owned)
    })
    .or_else(|| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == Some("name"))
            .and_then(|(_, value)| value.as_str())
            .map(str::to_owned)
    })
    .filter(|name| !name.trim().is_empty())
}

pub fn handle_number(handle: &str) -> u64 {
    handle
        .trim_start_matches(|character: char| character.is_ascii_lowercase())
        .parse()
        .unwrap_or(u64::MAX)
}

/// Encodes XML delimiters as JSON unicode escapes so a name cannot close the
/// prefix block it sits in.
pub fn xml_safe(value: &str) -> String {
    value
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
}
