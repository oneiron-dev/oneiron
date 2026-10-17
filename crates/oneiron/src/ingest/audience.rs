//! Import audience topics (OF-492). An import's extracted claims, grouped by the
//! extractor's question `topic_key`, form one cluster per topic. The host's sweep asks
//! whether a topic is sensitive; a sensitive or unsure one is asked of the owner ONCE,
//! as a Choice of only me, one of the owner's projects, or everyone the source shared it
//! with. The owner's answer becomes a standing `disclosure.import_audience` rule
//! ([`Vault::settle_import_audience`]) that applies to LATER imports only: the batch
//! that raised the ask stays private. A claim with no `topic_key` joins no cluster.
//!
//! This module keeps each cluster's operational state and the options the owner picks
//! from. The ladder runs in the host, never inside a write transaction here.

use std::collections::BTreeSet;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::llm::decision::{AnswerContract, DecisionQuestion};
use crate::side_table::{self, Named, SideTable};
use crate::workspace_roster::ProjectRole;
use crate::{EntityId, Vault};

const CLUSTERS: SideTable<EntityId, ImportAudienceCluster, Named> =
    SideTable::new(&side_table::IMPORT_AUDIENCE_CLUSTER);

const TOPIC_DOMAIN: &[u8] = b"oneiron.ingest.import_audience.topic.v1";

/// The longest topic or project label a question shows, in bytes.
const MAX_LABEL_BYTES: usize = 200;

/// The id hex a project option shows after its goal, so two projects with one goal
/// stay two options.
const PROJECT_LABEL_ID_HEX: usize = 8;

/// The most project options one ask lists: the Choice contract's 64 options, less the
/// two fixed ones. Past it, the projects first by id are listed (CALLS "OF-492 import
/// audience topics").
pub const MAX_IMPORT_AUDIENCE_PROJECTS: usize = 62;

/// The fixed option that keeps a topic's later imports private to the owner.
pub const IMPORT_AUDIENCE_ONLY_ME: &str = "Only me";

/// The fixed option that keeps a topic's later imports shared as their source shared them.
pub const IMPORT_AUDIENCE_SOURCE: &str = "Everyone the source shared it with";

/// Who a topic's later imports are shared with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportAudience {
    /// Only the owner.
    OnlyMe,
    /// Whoever the source itself shared the conversation with.
    Source,
    /// One of the owner's projects.
    Project { project: EntityId },
}

/// One option of an owner ask, frozen when it was asked: a later rename never makes
/// the same label pick another project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportAudienceOption {
    pub label: String,
    pub audience: ImportAudience,
}

/// Where one topic cluster stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportAudienceState {
    /// The sensitivity read found the topic not sensitive: no owner ask.
    Clear,
    /// The owner was asked; ask `seq` carries `question` over `evidence`, and each of
    /// the question's options maps to one audience.
    Asked {
        seq: u64,
        question: DecisionQuestion,
        evidence: Vec<EntityId>,
        options: Vec<ImportAudienceOption>,
    },
    /// The owner's answer stands as the `disclosure.import_audience` CLAIM `rule`.
    Settled {
        seq: u64,
        rule: EntityId,
        audience: ImportAudience,
    },
}

/// One topic cluster of imported claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportAudienceCluster {
    pub topic: EntityId,
    /// The topic as a question shows it.
    pub label: String,
    /// Every claim seen in the topic.
    pub claims: BTreeSet<EntityId>,
    /// Every import review those claims came from: the batches a later rule never
    /// widens.
    pub reviews: BTreeSet<String>,
    pub state: ImportAudienceState,
}

/// The topic a claim's scope names: its id, from the canonical bytes of the
/// extractor's `topic_key` (an exact match, never a semantic one), and its label.
/// `None` for a claim with no `topic_key`.
pub fn import_audience_topic(scope: Option<&Value>) -> Result<Option<(EntityId, String)>> {
    let Some(Value::Map(fields)) = scope else {
        return Ok(None);
    };
    let Some(topic) = fields
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some("topic_key")).then_some(value))
    else {
        return Ok(None);
    };
    if topic.is_nil() {
        return Ok(None);
    }
    let bytes = crate::dreamer_consolidation::topic_key_canonical_bytes(topic)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(TOPIC_DOMAIN);
    hasher.update(&bytes);
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    let id = EntityId::from_bytes(id).map_err(|_| invalid("import audience topic id"))?;
    let label = match topic.as_str() {
        Some(text) => text.trim().to_owned(),
        None => topic.to_string(),
    };
    Ok(Some((id, clipped(&label))))
}

impl Vault {
    /// One topic cluster, when the sweep has seen the topic.
    pub fn import_audience_cluster(
        &self,
        topic: &EntityId,
    ) -> Result<Option<ImportAudienceCluster>> {
        let txn = self.store.env.read_txn()?;
        CLUSTERS.get(&self.store, &txn, topic)
    }

    /// The topics whose owner ask is still waiting to settle.
    pub fn asked_import_audience_topics(&self) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        Ok(CLUSTERS
            .scan(&self.store, &txn)?
            .into_iter()
            .filter(|(_, cluster)| matches!(cluster.state, ImportAudienceState::Asked { .. }))
            .map(|(topic, _)| topic)
            .collect())
    }

    /// Records the claims and import reviews seen in one topic. A known topic keeps its
    /// state and gains the new members. A new topic opens with `opening`, either
    /// [`ImportAudienceState::Clear`] or [`ImportAudienceState::Asked`]; with no opening
    /// it is left unrecorded and `None` comes back. Only the owner's answer settles a
    /// topic ([`Vault::settle_import_audience`]).
    pub fn record_import_audience_cluster(
        &self,
        topic: &EntityId,
        label: &str,
        claims: &[EntityId],
        reviews: &[String],
        opening: Option<ImportAudienceState>,
    ) -> Result<Option<ImportAudienceCluster>> {
        if let Some(state) = &opening {
            validate_opening(state)?;
        }
        self.with_write_txn(|txn| {
            let cluster = match CLUSTERS.get(&self.store, txn, topic)? {
                Some(mut cluster) => {
                    let before = (cluster.claims.len(), cluster.reviews.len());
                    cluster.claims.extend(claims.iter().copied());
                    cluster.reviews.extend(reviews.iter().cloned());
                    if before == (cluster.claims.len(), cluster.reviews.len()) {
                        return Ok(Some(cluster));
                    }
                    cluster
                }
                None => {
                    let Some(state) = opening else {
                        return Ok(None);
                    };
                    ImportAudienceCluster {
                        topic: *topic,
                        label: clipped(label),
                        claims: claims.iter().copied().collect(),
                        reviews: reviews.iter().cloned().collect(),
                        state,
                    }
                }
            };
            CLUSTERS.put(&self.store, txn, topic, &cluster)?;
            Ok(Some(cluster))
        })
    }

    /// The options an owner ask offers now: only me, then each visible project of the
    /// vault (not its root and not a corpus) labelled by its goal and a short id, then
    /// everyone the source shared it with.
    pub fn import_audience_options(&self) -> Result<Vec<ImportAudienceOption>> {
        let root = self.root_project().ok();
        let mut projects = Vec::new();
        for id in self.entities_by_type(self.project_type_byte()?)? {
            if projects.len() == MAX_IMPORT_AUDIENCE_PROJECTS {
                break;
            }
            if Some(id) == root {
                continue;
            }
            let Some(record) = self.project(id)? else {
                continue;
            };
            if record.role == ProjectRole::Corpus {
                continue;
            }
            projects.push((id, record.goal));
        }
        let mut options = vec![ImportAudienceOption {
            label: IMPORT_AUDIENCE_ONLY_ME.to_owned(),
            audience: ImportAudience::OnlyMe,
        }];
        let mut labels: BTreeSet<String> = BTreeSet::from([
            IMPORT_AUDIENCE_ONLY_ME.to_owned(),
            IMPORT_AUDIENCE_SOURCE.to_owned(),
        ]);
        for (id, goal) in projects {
            let hex = id.to_hex();
            let goal = goal
                .as_deref()
                .map(str::trim)
                .filter(|goal| !goal.is_empty())
                .unwrap_or("Project");
            let mut label = format!("{} ({})", clipped(goal), &hex[..PROJECT_LABEL_ID_HEX]);
            if labels.contains(&label) {
                label = format!("{} ({hex})", clipped(goal));
            }
            labels.insert(label.clone());
            options.push(ImportAudienceOption {
                label,
                audience: ImportAudience::Project { project: id },
            });
        }
        options.push(ImportAudienceOption {
            label: IMPORT_AUDIENCE_SOURCE.to_owned(),
            audience: ImportAudience::Source,
        });
        Ok(options)
    }

    pub(crate) fn import_audience_cluster_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        topic: &EntityId,
    ) -> Result<Option<ImportAudienceCluster>> {
        CLUSTERS.get(&self.store, txn, topic)
    }

    pub(crate) fn put_import_audience_cluster_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        cluster: &ImportAudienceCluster,
    ) -> Result<()> {
        CLUSTERS.put(&self.store, txn, &cluster.topic, cluster)
    }
}

/// A new topic opens clear, or asked with one option per question option, in order.
fn validate_opening(state: &ImportAudienceState) -> Result<()> {
    match state {
        ImportAudienceState::Clear => Ok(()),
        ImportAudienceState::Asked {
            question, options, ..
        } => {
            question.validate()?;
            let AnswerContract::Choice { options: asked } = &question.contract else {
                return Err(invalid("an import audience ask is a choice"));
            };
            if asked.iter().ne(options.iter().map(|option| &option.label)) {
                return Err(invalid(
                    "an import audience ask's options are its question's",
                ));
            }
            Ok(())
        }
        ImportAudienceState::Settled { .. } => Err(invalid(
            "only the owner's answer settles an import audience topic",
        )),
    }
}

/// `text` cut at a char boundary to [`MAX_LABEL_BYTES`].
fn clipped(text: &str) -> String {
    if text.len() <= MAX_LABEL_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_LABEL_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
