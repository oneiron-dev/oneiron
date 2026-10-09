//! Caller-observable shared-vault NOTE write-denial regressions.
use crate::edge::EdgeActorClass;
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, InitialSharedMember, ScopeAxis,
    ScopeId, decode_federation_grant_body, encode_federation_grant_body,
};
use crate::note::NoteEdit;
use crate::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_NOTE, ENTITY_TYPE_PERSON};
use crate::{EntityId, TimeRange, Vault, VaultConfig};
use std::collections::BTreeSet;

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .unwrap();
    id
}

fn replace_grant(
    vault: &Vault,
    grant_refs: &[String],
    member: EntityId,
    update: impl FnOnce(&mut FederationGrant),
) {
    let (id, mut grant) = grant_refs
        .iter()
        .find_map(|hex| {
            let id = EntityId::from_hex(hex).unwrap();
            let raw = vault.get_raw(&id).unwrap().unwrap();
            let grant =
                decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                    .unwrap();
            (grant.member_ref == member).then_some((id, grant))
        })
        .unwrap();
    update(&mut grant);
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
}

#[test]
fn shared_note_writes_refuse_viewer_out_of_scope_member_and_demoted_author() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let owner = person(&vault);
    let member = person(&vault);
    let viewer = person(&vault);
    let authenticated = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let creation = vault
        .initialize_shared_vault(
            &authenticated,
            42,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(FederationGrantRole::Owner),
                },
                InitialSharedMember {
                    member_ref: member,
                    role: Some(FederationGrantRole::Member),
                },
                InitialSharedMember {
                    member_ref: viewer,
                    role: Some(FederationGrantRole::Viewer),
                },
            ],
            1,
        )
        .unwrap();
    let note = vault
        .memory(member, EdgeActorClass::Human)
        .create_note("research", "before")
        .unwrap();
    let id = EntityId::from_hex(&note.id_hex).unwrap();
    let before_count = vault.entities_by_type(ENTITY_TYPE_NOTE).unwrap().len();
    assert!(
        vault
            .memory(viewer, EdgeActorClass::Human)
            .create_note("research", "denied")
            .is_err()
    );
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_NOTE).unwrap().len(),
        before_count
    );
    assert!(
        vault
            .memory(viewer, EdgeActorClass::Human)
            .author_take(crate::note::TakeTarget::Subject(viewer), "denied take")
            .is_err()
    );
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_NOTE).unwrap().len(),
        before_count
    );
    replace_grant(&vault, &creation.grant_refs, member, |grant| {
        grant.authority_scope.audience =
            ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]));
    });
    assert!(
        vault
            .memory(member, EdgeActorClass::Human)
            .create_note("research", "outside")
            .is_err()
    );
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_NOTE).unwrap().len(),
        before_count
    );
    replace_grant(&vault, &creation.grant_refs, member, |grant| {
        grant.role = FederationGrantRole::Viewer;
        grant.preset = FederationGrantPreset::ReadOnly;
        grant.authority_scope = crate::federation::scope_codec::read_preset();
    });
    let before = vault.note_document(id).unwrap();
    assert!(
        vault
            .memory(member, EdgeActorClass::Human)
            .edit_note(
                &note.id_hex,
                &crate::note::NoteProgramEdit::Rewrite {
                    text: "forbidden".into()
                }
            )
            .is_err()
    );
    assert!(
        vault
            .memory(member, EdgeActorClass::Human)
            .apply_note_ops(
                id,
                &before.frontier,
                &[NoteEdit {
                    start: 0,
                    delete: 0,
                    insert: "forbidden ".into()
                }]
            )
            .is_err()
    );
    assert_eq!(vault.note_document(id).unwrap(), before);
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_NOTE).unwrap().len(),
        before_count
    );
}
