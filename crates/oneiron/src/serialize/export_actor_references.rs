//! Preserve only the actor ledger's validated binary reference positions.
use super::ExportValue;
use crate::{claim::ClaimBody, entity_id::EntityId};
fn field<'a>(value: &'a mut ExportValue, name: &str) -> Option<&'a mut ExportValue> {
    let ExportValue::Map(entries) = value else {
        return None;
    };
    entries.iter_mut().find_map(|(key, value)| {
        matches!(key,ExportValue::String(key) if key==name).then_some(value)
    })
}
fn reference(id: EntityId) -> ExportValue {
    if crate::batch::secret_scan::scan_file_content("", id.as_bytes()).is_some() {
        ExportValue::Nil
    } else {
        ExportValue::EntityReference(id.as_bytes().to_vec())
    }
}
pub(super) fn export_actor_references(body: &ClaimBody, exported: &mut ExportValue) {
    let Some(refs) = crate::actor_claims::actor_archive_references(body) else {
        return;
    };
    if let Some(skill) = refs.skill
        && let Some(value) = field(exported, "scope").and_then(|scope| field(scope, "skill"))
    {
        *value = reference(skill);
    }
    if let Some((session, turns)) = refs.chat
        && let Some(evidence) = field(exported, "evid")
    {
        if let Some(value) = field(evidence, "session") {
            *value = reference(session);
        }
        if let Some(value) = field(evidence, "turns") {
            *value = ExportValue::Array(turns.into_iter().map(reference).collect());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
    use crate::serialize::ExportBody;
    use rmpv::Value;
    fn fixture() -> ClaimBody {
        let actor = EntityId::from_bytes([3; 16]).unwrap();
        let skill = EntityId::from_bytes([4; 16]).unwrap();
        let session = EntityId::from_bytes([5; 16]).unwrap();
        let turn = EntityId::from_bytes([6; 16]).unwrap();
        let mut body = ClaimBody::new(
            "actor.skill_fit",
            ClaimSubject::Entity(actor),
            Value::F32(0.6),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        body.scope = Some(Value::Map(vec![
            ("skill".into(), Value::Binary(skill.as_bytes().to_vec())),
            ("evidence_taint".into(), "generated".into()),
        ]));
        body.evidence = Some(
            crate::actor_claims::ActorClaimEvidence::chat(session, vec![turn], 9)
                .unwrap()
                .to_value(),
        );
        body
    }
    #[test]
    fn typed_actor_citations_round_trip_but_lookalikes_do_not_gain_binary_exemptions()
    -> crate::Result<()> {
        let body = fixture();
        let raw = crate::claim::encode_claim_body(&body)?;
        let exported = ExportBody::from_bytes(&raw, crate::registry::ENTITY_TYPE_CLAIM);
        exported.validate(crate::registry::ENTITY_TYPE_CLAIM)?;
        let restored = crate::claim::decode_claim_body(&exported.to_bytes()?, true)?;
        assert_eq!(restored, body);
        let mut ordinary = body.clone();
        ordinary.predicate = "profile.other".into();
        let raw = crate::claim::encode_claim_body(&ordinary)?;
        let exported = ExportBody::from_bytes(&raw, crate::registry::ENTITY_TYPE_CLAIM);
        assert_ne!(
            crate::claim::decode_claim_body(&exported.to_bytes()?, false)?.evidence,
            body.evidence
        );
        let mut extended = body;
        let Some(Value::Map(entries)) = &mut extended.evidence else {
            panic!("fixture map")
        };
        entries.push(("unvalidated_payload".into(), Value::Binary(vec![7; 16])));
        let raw = crate::claim::encode_claim_body(&extended)?;
        let ExportBody::MessagePack(mut exported) =
            ExportBody::from_bytes(&raw, crate::registry::ENTITY_TYPE_CLAIM)
        else {
            panic!("typed export")
        };
        assert_eq!(
            field(field(&mut exported, "evid").unwrap(), "session"),
            Some(&mut ExportValue::Nil)
        );
        assert_eq!(
            field(field(&mut exported, "evid").unwrap(), "unvalidated_payload"),
            Some(&mut ExportValue::Nil)
        );
        Ok(())
    }
}
