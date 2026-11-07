//! One route-grading call's question names, shared by its state and every rung.

use std::collections::BTreeMap;

use crate::EntityId;
use crate::llm::LlmRequest;
use crate::llm::decision::{DecisionQuestion, DecisionWireLabels};

const FITNESS_LABELS_VERSION: u64 = 1;
const FITNESS_LABELS_DOMAIN: &[u8] = b"oneiron:fitness-question-labels:v1";

pub(super) struct FitnessQuestionLabels {
    questions: Vec<(EntityId, u32)>,
    numbers: BTreeMap<EntityId, usize>,
}

impl FitnessQuestionLabels {
    pub(super) fn new<'q>(questions: impl IntoIterator<Item = &'q DecisionQuestion> + 'q) -> Self {
        let mut table = Self {
            questions: Vec::new(),
            numbers: BTreeMap::new(),
        };
        for question in questions {
            if !table.numbers.contains_key(&question.id) {
                table.questions.push((question.id, question.version));
                table.numbers.insert(question.id, table.questions.len());
            }
        }
        table
    }

    fn digest(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(FITNESS_LABELS_DOMAIN);
        for (id, version) in &self.questions {
            hash.update(id.as_bytes());
            hash.update(&version.to_be_bytes());
        }
        *hash.finalize().as_bytes()
    }
}

impl DecisionWireLabels for FitnessQuestionLabels {
    fn question_label(&self, question: EntityId) -> Option<String> {
        self.numbers
            .get(&question)
            .map(|number| format!("Q{number}"))
    }

    fn question_for_label(&self, label: &str) -> Option<EntityId> {
        let number = label.strip_prefix('Q')?;
        if number.starts_with('0') || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let index = number.parse::<usize>().ok()?.checked_sub(1)?;
        self.questions.get(index).map(|(id, _)| *id)
    }

    fn choice_option(&self, _question: EntityId, _index: usize, _option: &str) -> Option<String> {
        None
    }

    fn bind(&self, request: &mut LlmRequest) {
        let host = request
            .provider_options
            .entry(crate::code_run::HOST_PROVIDER_OPTIONS.to_owned())
            .or_insert_with(|| serde_json::json!({}));
        if !host.is_object() {
            *host = serde_json::json!({});
        }
        host["fitness_question_labels"] = serde_json::json!({
            "version": FITNESS_LABELS_VERSION,
            "digest": crate::entity_id::bytes_to_hex_lower(&self.digest()),
        });
    }
}
