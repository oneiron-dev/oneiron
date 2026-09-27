//! A host-authored section recipe can lower the live report into the lens kit.
use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{Result, TimeRange};
use rmpv::Value;

#[test]
fn resident_section_recipe_renders_a_scoped_digest_atom() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let agent = entity(0x7a);
    let claim = entity(0x7b);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"resident",
    )?;
    vault.put_claim(
        &claim,
        &ClaimBody::new(
            "report.digest",
            ClaimSubject::Entity(agent),
            Value::from("changed project"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        ),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex()]);
    let recipe = [WeaveSectionSpec {
        kind: WeaveSectionKind::Digest,
        predicates: vec!["report.digest".into()],
        edge_kinds: Vec::new(),
    }];
    let report = vault
        .scoped_read(ScopedReadActorKey::new(agent.to_hex()).unwrap())
        .weave_report(WeaveReader::Agent(agent), &recipe)?;
    // The title and display shape are supplied here by the resident, not by
    // the projection. The claim ref remains available for the host's wrong action.
    let items = &report.value.sections[0].items;
    let lines = items
        .iter()
        .map(|item| match item {
            WeaveItem::Claim { id, body } => {
                assert_eq!(*id, claim);
                LensText::new(body.value.as_str().unwrap())
            }
            _ => panic!("digest item must be a scoped claim"),
        })
        .collect::<Result<Vec<_>>>()?;
    let atom = LensNode::new(
        id("resident-digest"),
        LensAtom::DossierSection(SectionAtom {
            title: LensText::new("My digest")?,
            lines,
        }),
    );
    let card = GeneratedUiCard::card(render_id("weave-card"), atom)?;
    let encoded = serde_json::to_vec(&card).unwrap();
    let decoded: GeneratedUiCard = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, card);
    Ok(())
}
