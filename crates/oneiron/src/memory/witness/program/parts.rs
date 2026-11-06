//! A base birth's stored parts, prepared after its guards in the same writer.

use super::*;
use crate::store::witness_message_body::StoredMessagePart;
use zeroize::Zeroizing;

#[derive(serde::Deserialize)]
struct StoredParts {
    parts: Option<Vec<StoredMessagePart>>,
}

impl Memory<'_> {
    pub(super) fn custody_witness_plan_in_txn<'t>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        plan: &WitnessPlan<'t>,
    ) -> MemoryResult<WitnessPlan<'t>> {
        let mut plan = plan.clone();
        for planned in &mut plan.messages {
            let Some(parts) = planned.envelope.parts.as_mut() else {
                continue;
            };
            match self.vault.store.port_entity_record(txn, &planned.id)? {
                Some(raw) => {
                    // Malformed or different existing bodies still meet the
                    // original full-body/topology comparison in admission.
                    let stored = rmp_serde::from_slice::<StoredParts>(&raw.body)
                        .ok()
                        .and_then(|body| body.parts);
                    if let Some(stored) = stored {
                        for (index, part) in parts.iter_mut().enumerate() {
                            let (
                                StoredMessagePart::Inline(original),
                                Some(StoredMessagePart::Custody { custody }),
                            ) = (&*part, stored.get(index))
                            else {
                                continue;
                            };
                            let bytes = Zeroizing::new(rmp_serde::to_vec_named(original).map_err(
                                |_| {
                                    Error::InvalidClaimBody(
                                        "a signed reasoning part is not encodable",
                                    )
                                },
                            )?);
                            if crate::secret_custody::message_part_original_matches_in_txn(
                                &self.vault.store,
                                txn,
                                &planned.id,
                                index,
                                custody,
                                &bytes,
                            )? {
                                *part = StoredMessagePart::Custody {
                                    custody: custody.clone(),
                                };
                            }
                        }
                    }
                }
                None => crate::batch::secret_scan::seal_message_parts_in_txn(
                    self.vault, txn, planned.id, 0, parts,
                )?,
            }
            planned.body = planned.envelope.encode_body()?;
        }
        Ok(plan)
    }
}
