//! A site skill's folder (CUA E10): `site.json` names the skill's site by
//! exact origins and path routes, and its `traps` and `programs` (the
//! workflow refs the Coach writes) pass through as knowledge. Each
//! `programs/<name>.json` is one seed program, whose exact bytes are the
//! body a proposal of it takes; a folder with no `programs/` holds none.
//!
//! The read never refuses a folder. An origin, route or seed that does not
//! read is named in a note and left out of what the skill matches or seeds;
//! the import keeps those notes on the skill's provenance (`site_notes`),
//! and a load reads the persisted files again. A folder with no `site.json`
//! is no site skill.

use oneiron_browser::ProposeInput;
use oneiron_browser::site::{SiteOrigin, SiteSkillQuery};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::HubFile;
use crate::entity_id::bytes_to_hex_lower;

/// The file that makes a folder a site skill.
const SITE_FILE: &str = "site.json";
/// The directory a folder's seed programs sit in, one level deep.
const PROGRAMS_DIR: &str = "programs/";
const PROGRAM_SUFFIX: &str = ".json";
/// The `site.json` keys that pass through as knowledge.
const KNOWLEDGE_KEYS: [&str; 2] = ["traps", "programs"];
/// The provenance key an import's notes go under.
pub(super) const SITE_NOTES_KEY: &str = "site_notes";
/// The most notes an import keeps; the last one counts the rest.
const MAX_SITE_NOTES: usize = 16;
/// The most bytes one note keeps.
const MAX_NOTE_BYTES: usize = 256;
/// The prefix of a seed's digest: SHA-256 over its exact bytes.
pub(super) const SEED_DIGEST_PREFIX: &str = "sha256:";

/// What a folder's `site.json` names: the exact origins and routes a page
/// must be on, the knowledge it passes through, and the notes on what did
/// not read.
pub(super) struct SiteFolder {
    origins: Vec<SiteOrigin>,
    /// `None` when `site.json` named routes and none of them reads: the
    /// skill then matches no page. Empty is the whole site.
    routes: Option<Vec<String>>,
    knowledge: Map<String, Value>,
    notes: Vec<String>,
}

impl SiteFolder {
    /// The site `files` name, or `None` for a folder with no `site.json`.
    pub(super) fn read(files: &[HubFile]) -> Option<Self> {
        let file = files.iter().find(|file| file.path == SITE_FILE)?;
        let mut folder = Self {
            origins: Vec::new(),
            routes: Some(Vec::new()),
            knowledge: Map::new(),
            notes: Vec::new(),
        };
        let site = match serde_json::from_slice::<Value>(&file.content) {
            Ok(Value::Object(site)) => site,
            Ok(_) => {
                folder
                    .notes
                    .push("site.json is no JSON object; the skill matches no page".to_owned());
                return Some(folder);
            }
            Err(error) => {
                folder.notes.push(format!(
                    "site.json does not parse ({error}); the skill matches no page"
                ));
                return Some(folder);
            }
        };
        folder.read_origins(site.get("origins"));
        folder.read_routes(site.get("routes"));
        for key in KNOWLEDGE_KEYS {
            if let Some(value) = site.get(key).filter(|value| holds_knowledge(value)) {
                folder.knowledge.insert(key.to_owned(), value.clone());
            }
        }
        Some(folder)
    }

    /// Each origin canonicalised as [`SiteOrigin::parse`] reads it, once.
    /// A note names one that does not read by its place in the list, never
    /// its text, which may hold credentials.
    fn read_origins(&mut self, origins: Option<&Value>) {
        let Some(Value::Array(origins)) = origins else {
            self.notes
                .push("site.json names no list of origins; the skill matches no page".to_owned());
            return;
        };
        for (index, origin) in origins.iter().enumerate() {
            match origin.as_str().map(SiteOrigin::parse) {
                Some(Ok(origin)) => {
                    if !self.origins.contains(&origin) {
                        self.origins.push(origin);
                    }
                }
                Some(Err(error)) => self.notes.push(format!(
                    "site.json origin {index} is no site origin: {error}"
                )),
                None => self
                    .notes
                    .push(format!("site.json origin {index} is no string")),
            }
        }
        if self.origins.is_empty() {
            self.notes
                .push("site.json names no site origin; the skill matches no page".to_owned());
        }
    }

    /// The path prefixes the skill holds to, each starting with `/`. None
    /// named is the whole site. A route that does not read is left out, and
    /// when every named route is left out the skill matches no page rather
    /// than the whole site.
    fn read_routes(&mut self, routes: Option<&Value>) {
        let routes = match routes {
            None | Some(Value::Null) => return,
            Some(Value::Array(routes)) => routes,
            Some(_) => {
                self.routes = None;
                self.notes.push(
                    "site.json routes is no list of paths; the skill matches no page".to_owned(),
                );
                return;
            }
        };
        let mut kept = Vec::with_capacity(routes.len());
        for (index, route) in routes.iter().enumerate() {
            match route.as_str() {
                Some(route) if route.starts_with('/') => kept.push(route.to_owned()),
                _ => self.notes.push(format!(
                    "site.json route {index} is no path starting with /"
                )),
            }
        }
        if kept.is_empty() && !routes.is_empty() {
            self.routes = None;
            self.notes
                .push("site.json names no readable route; the skill matches no page".to_owned());
        } else {
            self.routes = Some(kept);
        }
    }

    /// Whether the page `query` names is on this site: one of its origins
    /// exactly, and a path its routes take.
    pub(super) fn matches(&self, query: &SiteSkillQuery) -> bool {
        self.origins.contains(&query.origin)
            && self
                .routes
                .as_deref()
                .is_some_and(|routes| SiteOrigin::route_matches(&query.path, routes))
    }

    /// The skill's knowledge: its `SKILL.md` text whole, then the traps and
    /// program refs `site.json` names, as JSON, when it names any.
    pub(super) fn knowledge(&self, instructions: &str) -> String {
        if self.knowledge.is_empty() {
            return instructions.to_owned();
        }
        let Ok(site) = serde_json::to_string_pretty(&self.knowledge) else {
            return instructions.to_owned();
        };
        let mut text = instructions.to_owned();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("\n## site.json\n\n```json\n");
        text.push_str(&site);
        text.push_str("\n```\n");
        text
    }
}

/// Whether a `site.json` knowledge value says anything: not null, and not
/// an empty list or map.
fn holds_knowledge(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(items) => !items.is_empty(),
        Value::Object(entries) => !entries.is_empty(),
        _ => true,
    }
}

/// One seed program as its folder holds it: the program its bytes parse
/// to, and their digest.
pub(super) struct Seed {
    pub(super) program: ProposeInput,
    pub(super) digest: String,
}

/// Whether `path` names a seed: a `.json` file directly in `programs/`.
pub(super) fn is_seed_path(path: &str) -> bool {
    path.strip_prefix(PROGRAMS_DIR)
        .and_then(|name| name.strip_suffix(PROGRAM_SUFFIX))
        .is_some_and(|stem| !stem.is_empty() && !stem.contains('/'))
}

/// The folder's seed files, in path order.
pub(super) fn seed_files(files: &[HubFile]) -> Vec<&HubFile> {
    let mut seeds: Vec<&HubFile> = files
        .iter()
        .filter(|file| is_seed_path(&file.path))
        .collect();
    seeds.sort_by(|left, right| left.path.cmp(&right.path));
    seeds
}

/// The program `file` holds, or the note that names why it holds none.
pub(super) fn read_seed(file: &HubFile) -> Result<Seed, String> {
    let program = serde_json::from_slice::<ProposeInput>(&file.content)
        .map_err(|error| format!("{} is no program: {error}", file.path))?;
    Ok(Seed {
        program,
        digest: seed_digest(&file.content),
    })
}

/// The digest of a seed's exact bytes: `sha256:` and lower-case hex.
pub(super) fn seed_digest(bytes: &[u8]) -> String {
    format!(
        "{SEED_DIGEST_PREFIX}{}",
        bytes_to_hex_lower(&Sha256::digest(bytes))
    )
}

/// The notes an import of `files` keeps: each origin, route and seed of a
/// site skill that does not read, bounded. None for a folder with no
/// `site.json`.
pub(super) fn import_notes(files: &[HubFile]) -> Vec<String> {
    let Some(folder) = SiteFolder::read(files) else {
        return Vec::new();
    };
    let mut notes = folder.notes;
    for file in seed_files(files) {
        if let Err(note) = read_seed(file) {
            notes.push(note);
        }
    }
    bounded_notes(notes)
}

/// At most [`MAX_SITE_NOTES`], each cut to [`MAX_NOTE_BYTES`] at a
/// character boundary; past the bound the last note counts the rest.
fn bounded_notes(notes: Vec<String>) -> Vec<String> {
    let total = notes.len();
    let mut kept: Vec<String> = notes
        .into_iter()
        .take(if total > MAX_SITE_NOTES {
            MAX_SITE_NOTES - 1
        } else {
            MAX_SITE_NOTES
        })
        .map(|mut note| {
            if note.len() > MAX_NOTE_BYTES {
                let mut cut = MAX_NOTE_BYTES;
                while !note.is_char_boundary(cut) {
                    cut -= 1;
                }
                note.truncate(cut);
            }
            note
        })
        .collect();
    if total > kept.len() {
        kept.push(format!("and {} more site notes", total - kept.len()));
    }
    kept
}
