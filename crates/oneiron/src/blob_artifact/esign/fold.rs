//! Pure projection of the append-only esign claim family.
use super::model::*;
use crate::Result;
use std::collections::BTreeMap;

impl EsignState {
    pub(super) fn draft(document: EsignDocument, now: u64) -> Result<Self> {
        validate_document(&document, now)?;
        let recipients = document
            .recipients
            .iter()
            .map(|r| {
                (
                    r.id.clone(),
                    RecipientState {
                        delivery: DeliveryStatus::Unsent,
                        signing: if matches!(r.role, RecipientRole::Cc | RecipientRole::Viewer) {
                            SigningStatus::Completed
                        } else {
                            SigningStatus::Waiting
                        },
                        access: AccessStatus::Unverified,
                        expires_at: r.expires_at,
                    },
                )
            })
            .collect();
        Ok(Self {
            document,
            status: DocumentStatus::Draft,
            recipients,
            signatures: BTreeMap::new(),
            rejection: None,
            sealed_sha256: vec![],
            reseal_pending: false,
        })
    }
    pub fn ready_to_seal(&self) -> bool {
        (self.status == DocumentStatus::Pending
            && (self.rejection.is_some()
                || self
                    .recipients
                    .values()
                    .all(|r| r.signing == SigningStatus::Completed)))
            || self.reseal_pending
    }
    fn promote(&mut self, dictated: Option<&str>) -> Result<()> {
        if self.document.sequential {
            let next = if let Some(id) = dictated {
                if self
                    .recipients
                    .get(id)
                    .is_none_or(|r| r.signing != SigningStatus::Waiting)
                {
                    return Err(invalid("next signer is not waiting"));
                }
                Some(id.to_owned())
            } else {
                self.document
                    .recipients
                    .iter()
                    .filter(|r| self.recipients[&r.id].signing == SigningStatus::Waiting)
                    .min_by_key(|r| (r.order, &r.id))
                    .map(|r| r.id.clone())
            };
            if let Some(id) = next {
                self.recipients
                    .get_mut(&id)
                    .expect("selected recipient")
                    .signing = SigningStatus::Ready;
            }
        } else {
            if dictated.is_some() {
                return Err(invalid("next signer only applies to sequential documents"));
            }
            for r in self.recipients.values_mut() {
                if r.signing == SigningStatus::Waiting {
                    r.signing = SigningStatus::Ready;
                }
            }
        }
        Ok(())
    }
    fn require_turn(&self, recipient: &str, now: u64) -> Result<()> {
        let row = self
            .recipients
            .get(recipient)
            .ok_or_else(|| invalid("unknown recipient"))?;
        if self.status != DocumentStatus::Pending
            || self.rejection.is_some()
            || row.signing != SigningStatus::Ready
            || now >= row.expires_at
            || now >= self.document.expires_at
        {
            return Err(invalid("recipient turn unavailable"));
        }
        Ok(())
    }
    pub(super) fn apply(&mut self, event: &EsignEvent, now: u64) -> Result<()> {
        match event {
            EsignEvent::Drafted { document } => {
                if self.status != DocumentStatus::Draft {
                    return Err(invalid("sent content is frozen"));
                }
                *self = Self::draft(document.clone(), now)?;
            }
            EsignEvent::Sent => {
                if self.status != DocumentStatus::Draft
                    || self.document.kind != DocumentKind::Document
                    || now >= self.document.expires_at
                {
                    return Err(invalid("document cannot be sent"));
                }
                self.status = DocumentStatus::Pending;
                for r in self.recipients.values_mut() {
                    r.delivery = DeliveryStatus::Sent;
                }
                self.promote(None)?;
            }
            EsignEvent::Viewed { recipient } => {
                let progress = self
                    .recipients
                    .get(recipient)
                    .ok_or_else(|| invalid("unknown recipient"))?;
                if self.status == DocumentStatus::Draft
                    || now >= progress.expires_at
                    || now >= self.document.expires_at
                    || (self.status == DocumentStatus::Pending
                        && progress.signing == SigningStatus::Waiting)
                {
                    return Err(invalid("recipient view unavailable"));
                }
                let row = self.recipients.get_mut(recipient).expect("validated turn");
                row.delivery = DeliveryStatus::Viewed;
                row.access = AccessStatus::Verified;
            }
            EsignEvent::FieldSaved { signature } => {
                self.require_turn(&signature.recipient, now)?;
                if self.recipients[&signature.recipient].access != AccessStatus::Verified {
                    return Err(invalid("access authentication required"));
                }
                let field = self
                    .document
                    .fields
                    .iter()
                    .find(|f| f.id == signature.field && f.recipient == signature.recipient)
                    .ok_or_else(|| invalid("field is not assigned to recipient"))?;
                validate_value(field, &signature.value)?;
                self.signatures
                    .insert(signature.field.clone(), signature.clone());
            }
            EsignEvent::Signed { recipient, next } => {
                self.require_turn(recipient, now)?;
                if self.recipients[recipient].access != AccessStatus::Verified {
                    return Err(invalid("access authentication required"));
                }
                if self
                    .document
                    .fields
                    .iter()
                    .filter(|f| f.recipient == *recipient && f.required)
                    .any(|f| {
                        self.signatures.get(&f.id).is_none_or(|s| {
                            matches!(&s.value, FieldValue::Text(v) if v.trim().is_empty())
                                || matches!(s.value, FieldValue::Checked(false))
                        })
                    })
                {
                    return Err(invalid("required fields are incomplete"));
                }
                self.recipients
                    .get_mut(recipient)
                    .expect("validated turn")
                    .signing = SigningStatus::Completed;
                self.promote(next.as_deref())?;
            }
            EsignEvent::Declined { recipient, reason } => {
                self.require_turn(recipient, now)?;
                if self.recipients[recipient].access != AccessStatus::Verified
                    || reason.trim().is_empty()
                    || reason.len() > 4096
                {
                    return Err(invalid("decline requires a bounded reason"));
                }
                self.recipients
                    .get_mut(recipient)
                    .expect("validated turn")
                    .signing = SigningStatus::Rejected;
                self.rejection = Some(reason.clone());
            }
            EsignEvent::Voided { reason } => {
                if !matches!(self.status, DocumentStatus::Draft | DocumentStatus::Pending)
                    || reason.trim().is_empty()
                    || reason.len() > 4096
                {
                    return Err(invalid("document cannot be voided"));
                }
                self.status = DocumentStatus::Voided;
            }
            EsignEvent::Expired => {
                if !matches!(self.status, DocumentStatus::Draft | DocumentStatus::Pending)
                    || now < self.document.expires_at
                {
                    return Err(invalid("document has not expired"));
                }
                self.status = DocumentStatus::Expired;
            }
            EsignEvent::Sealed {
                rejected,
                item_sha256,
            } => {
                if !self.ready_to_seal()
                    || *rejected != self.rejection.is_some()
                    || item_sha256.len() != self.document.items.len()
                    || item_sha256.contains(&[0; 32])
                {
                    return Err(invalid("seal outcome is not justified"));
                }
                self.status = if *rejected {
                    DocumentStatus::Rejected
                } else {
                    DocumentStatus::Completed
                };
                self.sealed_sha256 = item_sha256.clone();
                self.reseal_pending = false;
            }
            EsignEvent::ResealRequested {
                owner,
                authorization,
            } => {
                reference(owner)?;
                if authorization.is_empty()
                    || !matches!(
                        self.status,
                        DocumentStatus::Completed | DocumentStatus::Rejected
                    )
                {
                    return Err(invalid(
                        "reseal needs owner authorization and a sealed outcome",
                    ));
                }
                self.reseal_pending = true;
            }
        }
        Ok(())
    }
}

pub(super) fn validate_value(field: &EsignField, value: &FieldValue) -> Result<()> {
    match (&field.meta, value) {
        (FieldMeta::Signature | FieldMeta::Initials, FieldValue::Signature { image_ref }) => {
            reference(image_ref)
        }
        (FieldMeta::Checkbox, FieldValue::Checked(_)) => Ok(()),
        (FieldMeta::Text { max_bytes }, FieldValue::Text(v)) if v.len() <= *max_bytes as usize => {
            Ok(())
        }
        (FieldMeta::Select { options }, FieldValue::Text(v)) if options.contains(v) => Ok(()),
        (FieldMeta::Email, FieldValue::Text(v))
            if v.len() <= 320 && v.contains('@') && !v.contains(['\r', '\n']) =>
        {
            Ok(())
        }
        (FieldMeta::Date | FieldMeta::Name, FieldValue::Text(v))
            if !v.is_empty() && v.len() <= 4096 =>
        {
            Ok(())
        }
        _ => Err(invalid("field value does not match field metadata")),
    }
}
