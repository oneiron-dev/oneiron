//! Admit only issuer-seed candidates from a published custody head. No
//! source binding, control secret, other custody entry or writer epoch lands.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::{CustodyRequirement, CustodySourceAt, admit_recovery, refused};
use crate::Result;
use crate::store::host_issuer_seed::HOST_ISSUER_SEED_BYTES;
use crate::store::key_custody::head::{CustodyOpener, head_position};
use crate::store::key_custody::identity::CustodyKind;
use crate::store::key_custody::protocol::{CustodySource, Lineage};
use crate::store::restore_admission::{Rejected, RestoreAdmissionReason as R, because};

pub(crate) struct AdmittedIssuerSeeds {
    pub(crate) seeds: BTreeMap<u64, Zeroizing<[u8; HOST_ISSUER_SEED_BYTES]>>,
    pub(crate) note: Option<&'static str>,
}

// Admission and its requirement read the SAME head. Frames remain checked
// through the existing chain validator; the source cannot swap the head
// between reading its position and authenticating its contents.
struct SelectedHead<'a> {
    lineage: Lineage,
    head: Vec<u8>,
    source: &'a dyn CustodySource,
}

impl CustodySource for SelectedHead<'_> {
    fn head(&self, lineage: Lineage) -> Result<Option<Vec<u8>>> {
        Ok((lineage == self.lineage).then(|| self.head.clone()))
    }

    fn frame(&self, lineage: Lineage, seq: u64) -> Result<Option<Vec<u8>>> {
        self.source.frame(lineage, seq)
    }
}

pub(crate) fn admit_published_host_issuer_seeds(
    lineage: Lineage,
    source: &CustodySourceAt<'_>,
    data_key: Option<Zeroizing<[u8; 32]>>,
) -> std::result::Result<AdmittedIssuerSeeds, Rejected> {
    let reader = source.reader();
    let head = reader.head(lineage)?.ok_or_else(|| {
        Rejected::new(
            R::CustodyHeadInvalid,
            refused("no published custody head of the selected lineage".into()),
        )
    })?;
    // This position is unauthenticated until admit_recovery checks this
    // exact head's seal, lineage, anchor and intervening retirement log.
    let position = head_position(&head).map_err(because(R::CustodyHeadInvalid))?;
    if position.vault != lineage.vault || position.namespace != lineage.namespace {
        return Err(Rejected::new(
            R::CustodyLineageMismatch,
            refused("the selected custody head names another lineage".into()),
        ));
    }
    let required = CustodyRequirement {
        position: position.to_bytes().to_vec(),
        required: Vec::new(),
    };
    let selected = SelectedHead {
        lineage,
        head,
        source: &reader,
    };
    let opener = CustodyOpener {
        root: source.root,
        data_key,
        machine: source.machine,
    };
    let admitted = admit_recovery(&required, &selected, &opener, source.anchor)?;
    let mut seeds = BTreeMap::new();
    for (id, secret) in &admitted.live {
        if id.kind() != CustodyKind::HostIssuerSeed || admitted.retires(id) {
            continue;
        }
        if !id.subject().item().is_empty() || secret.expose().len() != HOST_ISSUER_SEED_BYTES {
            return Err(Rejected::new(
                R::CodecInvalid,
                CustodyKind::HostIssuerSeed.corrupt(),
            ));
        }
        let mut seed = Zeroizing::new([0; HOST_ISSUER_SEED_BYTES]);
        seed.copy_from_slice(secret.expose());
        seeds.insert(id.generation(), seed);
    }
    Ok(AdmittedIssuerSeeds {
        seeds,
        note: admitted.note(),
    })
}
