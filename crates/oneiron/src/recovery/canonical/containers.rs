//! The same expected container rows for synchronous capture and paged validation.

use super::{CanonicalContainerManifest, CanonicalSnapshot};

#[derive(Default)]
pub(in crate::recovery) struct ExpectedContainers {
    stage: Stage,
    next: usize,
    rows: Vec<CanonicalContainerManifest>,
}

#[derive(Default)]
enum Stage {
    #[default]
    Roots,
    EntityDocuments,
    Documents,
    Sort,
    Complete,
}

impl ExpectedContainers {
    pub(in crate::recovery) fn advance_row(&mut self, snapshot: &CanonicalSnapshot) -> bool {
        loop {
            match self.stage {
                Stage::Roots => {
                    for name in [
                        "entities",
                        "edges",
                        "tombstones",
                        "retained_claim_worlds",
                        "documents",
                        "entity_documents",
                        "document_heads",
                        "head_move_receipts",
                        "note_forks",
                        "note_proposals",
                        "custody",
                        "room_turns",
                        "room_facts",
                        "document_pins",
                        "peer_origins",
                        "row_births",
                        "withdrawn_cutoffs",
                        "asset_body_refs",
                        "source_audiences",
                    ] {
                        self.rows.push(CanonicalContainerManifest {
                            container_id: name.to_owned(),
                            container_kind: "map".to_owned(),
                            schema_version: 1,
                            source_entity_id: None,
                        });
                    }
                    self.stage = Stage::EntityDocuments;
                    return false;
                }
                Stage::EntityDocuments => {
                    let Some(doc) = snapshot.entity_documents.get(self.next) else {
                        self.next = 0;
                        self.stage = Stage::Documents;
                        continue;
                    };
                    for (name, kind) in [("body", "text"), ("meta", "map")] {
                        self.rows.push(CanonicalContainerManifest {
                            container_id: format!(
                                "entity_doc/{}/{name}",
                                crate::entity_id::bytes_to_hex_lower(&doc.entity_id)
                            ),
                            container_kind: kind.to_owned(),
                            schema_version: 1,
                            source_entity_id: Some(doc.entity_id),
                        });
                    }
                    self.next += 1;
                    return false;
                }
                Stage::Documents => {
                    let Some(doc) = snapshot.doc_snapshots.get(self.next) else {
                        self.stage = Stage::Sort;
                        continue;
                    };
                    for (name, kind) in [("body", "text"), ("note", "map"), ("authorship", "map")] {
                        self.rows.push(CanonicalContainerManifest {
                            container_id: format!("{}/{name}", doc.key()),
                            container_kind: kind.to_owned(),
                            schema_version: 1,
                            source_entity_id: Some(doc.entity_id),
                        });
                    }
                    self.next += 1;
                    return false;
                }
                Stage::Sort => {
                    self.rows
                        .sort_by(|a, b| a.container_id.cmp(&b.container_id));
                    self.stage = Stage::Complete;
                    return true;
                }
                Stage::Complete => return true,
            }
        }
    }

    pub(in crate::recovery) fn rows(&self) -> &[CanonicalContainerManifest] {
        &self.rows
    }

    pub(in crate::recovery) fn position(&self) -> (&'static str, usize) {
        let stage = match self.stage {
            Stage::Roots => "container roots",
            Stage::EntityDocuments => "container entity documents",
            Stage::Documents => "container NOTE documents",
            Stage::Sort => "container sort",
            Stage::Complete => "container built",
        };
        (stage, self.next)
    }

    pub(super) fn into_rows(self) -> Vec<CanonicalContainerManifest> {
        self.rows
    }
}
