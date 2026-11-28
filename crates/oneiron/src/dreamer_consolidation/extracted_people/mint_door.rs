//! The extraction's person mint for one declared person, for the integration
//! door `test_doors::native_person_mint`. Not API.

use super::{MintNamespace, bind_people, mint_extracted_people, original_try};
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::call_labels::{
    CallLabelMap, CallSources, LabelKind, SourceShown,
};
use crate::dreamer_consolidation::executor::extraction::ExtractedPerson;
use crate::dreamer_consolidation::resources::document_version;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_consolidation::watermark::read_turn_facts_in_txn;
use crate::error::Result;
use crate::{EntityId, Vault};

/// A call that showed one TURN, labelled `T1`, with the text stored for it.
struct OneTurnCall {
    labels: CallLabelMap,
    turn: EntityId,
    text: Option<String>,
}

impl CallSources for OneTurnCall {
    fn labels(&self) -> &CallLabelMap {
        &self.labels
    }

    fn shown(&self, id: EntityId) -> Option<SourceShown<'_>> {
        (id == self.turn).then(|| SourceShown {
            text: self.text.as_deref(),
            one_line_fenced: false,
            project: None,
        })
    }
}

/// Binds and mints the one person a reply declares as `new:P1`, named `name`
/// and citing the stored TURN `turn`, as the extraction pass does
/// ([`bind_people`], then [`mint_extracted_people`] with no fence and no
/// deadline). The namespace is the pass's: `parent` when one is given, else
/// the first try of `attempt`'s retry lineage ([`original_try`]; `attempt`
/// itself when no queue row of it retries another), with every exposure axis
/// absent. No queue row is needed for either id. Returns the id the
/// declaration bound, whether or not the writer wrote a row for it.
///
/// # Errors
///
/// A TURN that is not stored or whose stored row is shorter than its header,
/// a declaration that binds no id, and the writer's errors.
pub(crate) fn mint_named_person_for_test(
    vault: &Vault,
    attempt: AttemptId,
    parent: Option<AttemptId>,
    turn: EntityId,
    name: &str,
) -> Result<EntityId> {
    let (text, version) = {
        let txn = vault.store.env.read_txn()?;
        let raw = vault
            .get_raw_in(&txn, &turn)?
            .ok_or_else(|| invalid_consolidation("person mint door: the TURN is not stored"))?;
        let body = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .ok_or_else(|| invalid_consolidation("person mint door: the TURN's row is short"))?;
        (
            read_turn_facts_in_txn(vault, &txn, &turn)?.text,
            document_version(turn, body),
        )
    };
    let mut labels = CallLabelMap::default();
    labels.assign(LabelKind::Turn, turn);
    let call = OneTurnCall { labels, turn, text };
    let persons = [ExtractedPerson {
        id: "new:P1".to_owned(),
        name: name.to_owned(),
        evidence_turn_refs: vec!["T1".to_owned()],
    }];
    let people = bind_people(
        &persons,
        &call,
        &MintNamespace::new(original_try(vault, attempt)?, parent, None, None, None),
    );
    let id = people.subject(1)?;
    let mut scope = oneiron_model::llm::Scope::default();
    scope.readable.insert(version);
    mint_extracted_people(
        vault,
        &people,
        &[turn],
        &scope,
        vault.now_recorded_at().saturating_mul(1_000),
        None,
        None,
    )?;
    Ok(id)
}
