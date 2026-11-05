//! Node-local recognition vectors: explicit base/public bytes or exact-world sealed bytes.

use heed::RoTxn;
use oneiron_crypto::Envelope;
use rmpv::Value;
use zeroize::Zeroizing;

use crate::Vault;
use crate::authority::EffectiveRead;
use crate::error::Result;
use crate::side_table::{CodecError, RawValue};
use crate::world_keys::{MachineSecret, WorldKey, WorldKeyId, WorldSideRowBinding};

use super::codec_core::{
    decode_entity_ref, decode_sample, decode_u64, decode_vector, encode_entity_ref, encode_sample,
    encode_vector, read_body, write_body,
};
use super::codec_records::{decode_print_metadata, encode_print_metadata};
use super::math_keys::{corrupt_voice_row, digest16, validate_voice_vector};
use super::metadata::PrintMetadata;
use super::storage_admission::sample_digest;
use super::types::{VoiceEnrollmentSampleV1, VoicePrintRecordV1};

pub(super) struct StoredPrint {
    pub(super) metadata: PrintMetadata,
    material: Material,
}

pub(super) struct StoredSample {
    material: Material,
}

enum Material {
    Base(Vec<u8>),
    Public {
        world: crate::EntityId,
        bytes: Vec<u8>,
    },
    Sealed {
        key: WorldKeyId,
        envelope: Vec<u8>,
    },
}

impl StoredPrint {
    pub(super) fn needs_world_key(&self) -> bool {
        matches!(&self.material, Material::Sealed { .. })
    }

    pub(super) fn new(
        vault: &Vault,
        txn: &RoTxn<'_>,
        record: &VoicePrintRecordV1,
        key: Option<&WorldKey>,
    ) -> Result<Self> {
        let metadata = PrintMetadata::from(record);
        let bytes = Zeroizing::new(write_body(&encode_vector(&record.centroid))?);
        let material = Material::seal(vault, txn, &metadata, None, key, &bytes)?;
        Ok(Self { metadata, material })
    }

    pub(super) fn centroid(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        secret: Option<&MachineSecret>,
    ) -> Result<Vec<f32>> {
        let bytes = self
            .material
            .open(vault, txn, &self.metadata, None, secret)?;
        let centroid = decode_vector(&read_body(&bytes)?)?;
        validate_voice_vector(&centroid, self.metadata.space.dimension)
            .map_err(|_| corrupt_voice_row())?;
        Ok(centroid)
    }
}

impl StoredSample {
    pub(super) fn needs_world_key(&self) -> bool {
        matches!(&self.material, Material::Sealed { .. })
    }

    pub(super) fn new(
        vault: &Vault,
        txn: &RoTxn<'_>,
        sample: &VoiceEnrollmentSampleV1,
        metadata: &PrintMetadata,
        key: Option<&WorldKey>,
    ) -> Result<Self> {
        let bytes = Zeroizing::new(encode_sample(sample)?);
        Ok(Self {
            material: Material::seal(vault, txn, metadata, Some(&sample.sample_id), key, &bytes)?,
        })
    }

    pub(super) fn sample(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        metadata: &PrintMetadata,
        sample_id: &str,
        secret: Option<&MachineSecret>,
    ) -> Result<VoiceEnrollmentSampleV1> {
        let bytes = self
            .material
            .open(vault, txn, metadata, Some(sample_id), secret)?;
        let sample = decode_sample(&bytes)?;
        if sample.sample_id != sample_id {
            return Err(corrupt_voice_row());
        }
        validate_voice_vector(&sample.vector, metadata.space.dimension)
            .map_err(|_| corrupt_voice_row())?;
        Ok(sample)
    }
}

impl Material {
    fn seal(
        vault: &Vault,
        txn: &RoTxn<'_>,
        metadata: &PrintMetadata,
        sample_id: Option<&str>,
        key: Option<&WorldKey>,
        bytes: &[u8],
    ) -> Result<Self> {
        match (metadata.world_ref, key) {
            (None, None) => Ok(Self::Base(bytes.to_vec())),
            (Some(world), None)
                if vault
                    .authority_view_readonly_in_txn(txn)?
                    .world_privacy(world)
                    .read
                    == EffectiveRead::Everywhere =>
            {
                Ok(Self::Public {
                    world,
                    bytes: bytes.to_vec(),
                })
            }
            (Some(world), Some(key)) if key.id().world == world => {
                let row = row_aad(metadata, sample_id)?;
                let binding = WorldSideRowBinding {
                    vault_id: *vault.vault_id().as_bytes(),
                    key: *key.id(),
                    family: family(sample_id),
                    row: &row,
                };
                let envelope = crate::world_keys::seal_side_row(&binding, key, bytes)?;
                Ok(Self::Sealed {
                    key: *key.id(),
                    envelope: envelope.to_bytes(),
                })
            }
            _ => Err(corrupt_voice_row()),
        }
    }

    fn open(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        metadata: &PrintMetadata,
        sample_id: Option<&str>,
        secret: Option<&MachineSecret>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match (self, metadata.world_ref, secret) {
            (Self::Base(bytes), None, _) => Ok(Zeroizing::new(bytes.clone())),
            (Self::Public { world, bytes }, Some(bound), _) if *world == bound => {
                Ok(Zeroizing::new(bytes.clone()))
            }
            (Self::Sealed { key, envelope }, Some(world), Some(secret)) if key.world == world => {
                let content_key = vault.world_content_key_in_txn(txn, secret, key)?;
                let row = row_aad(metadata, sample_id)?;
                let binding = WorldSideRowBinding {
                    vault_id: *vault.vault_id().as_bytes(),
                    key: *key,
                    family: family(sample_id),
                    row: &row,
                };
                let envelope = Envelope::parse(envelope).map_err(|_| corrupt_voice_row())?;
                crate::world_keys::open_side_row(&binding, &content_key, &envelope)
            }
            _ => Err(corrupt_voice_row()),
        }
    }

    fn value(&self) -> Value {
        match self {
            Self::Base(bytes) => Value::Binary(bytes.clone()),
            Self::Public { world, bytes } => {
                Value::Array(vec![encode_entity_ref(world), Value::Binary(bytes.clone())])
            }
            Self::Sealed { key, envelope } => Value::Array(vec![
                encode_entity_ref(&key.world),
                Value::from(key.generation),
                Value::Binary(key.mint.to_vec()),
                Value::Binary(envelope.clone()),
            ]),
        }
    }

    fn decode(value: &Value) -> Result<Self> {
        match value {
            Value::Binary(bytes) => Ok(Self::Base(bytes.clone())),
            Value::Array(parts) if parts.len() == 2 => {
                let Value::Binary(bytes) = &parts[1] else {
                    return Err(corrupt_voice_row());
                };
                Ok(Self::Public {
                    world: decode_entity_ref(&parts[0])?,
                    bytes: bytes.clone(),
                })
            }
            Value::Array(parts) if parts.len() == 4 => {
                let (Value::Binary(mint), Value::Binary(envelope)) = (&parts[2], &parts[3]) else {
                    return Err(corrupt_voice_row());
                };
                Envelope::parse(envelope).map_err(|_| corrupt_voice_row())?;
                Ok(Self::Sealed {
                    key: WorldKeyId {
                        world: decode_entity_ref(&parts[0])?,
                        generation: decode_u64(&parts[1])?,
                        mint: mint
                            .as_slice()
                            .try_into()
                            .map_err(|_| corrupt_voice_row())?,
                    },
                    envelope: envelope.clone(),
                })
            }
            _ => Err(corrupt_voice_row()),
        }
    }

    fn matches_world(&self, world: Option<crate::EntityId>) -> bool {
        match (self, world) {
            (Self::Base(_), None) => true,
            (Self::Public { world: held, .. }, Some(world)) => *held == world,
            (Self::Sealed { key, .. }, Some(world)) => key.world == world,
            _ => false,
        }
    }
}

fn family(sample_id: Option<&str>) -> &'static [u8] {
    match sample_id {
        None => b"voice_identity.print",
        Some(_) => b"voice_identity.sample",
    }
}

fn row_aad(metadata: &PrintMetadata, sample_id: Option<&str>) -> Result<Vec<u8>> {
    let mut header = read_body(&encode_print_metadata(metadata)?)?;
    let Value::Map(fields) = &mut header else {
        return Err(corrupt_voice_row());
    };
    // Retention acts change only these native lifecycle fields, not the enrolled
    // material. They must remain writable without opening a destroyed world key.
    fields.retain(|(key, _)| !matches!(key.as_str(), Some("updated_at" | "delete_after")));
    let key = match sample_id {
        None => {
            let mut key = metadata.subject_ref.as_bytes().to_vec();
            key.extend_from_slice(&digest16(
                b"voice_identity.space",
                metadata.space.space_id.as_bytes(),
            ));
            key
        }
        Some(id) => sample_digest(&metadata.subject_ref, id).to_vec(),
    };
    write_body(&Value::Array(vec![
        Value::Binary(key),
        header,
        sample_id.map_or(Value::Nil, |id| Value::from(id.to_owned())),
    ]))
}

impl RawValue for StoredPrint {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        if !self.material.matches_world(self.metadata.world_ref) {
            return Err(corrupt_voice_row().into());
        }
        Ok(write_body(&Value::Array(vec![
            Value::Binary(encode_print_metadata(&self.metadata)?),
            self.material.value(),
        ]))?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let value = read_body(bytes)?;
        let Value::Array(parts) = value else {
            return Err(corrupt_voice_row().into());
        };
        if parts.len() != 2 {
            return Err(corrupt_voice_row().into());
        }
        let Value::Binary(header) = &parts[0] else {
            return Err(corrupt_voice_row().into());
        };
        let metadata = decode_print_metadata(header)?;
        let material = Material::decode(&parts[1])?;
        if !material.matches_world(metadata.world_ref) {
            return Err(corrupt_voice_row().into());
        }
        Ok(Self { metadata, material })
    }
}

impl RawValue for StoredSample {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(write_body(&self.material.value())?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self {
            material: Material::decode(&read_body(bytes)?)?,
        })
    }
}
