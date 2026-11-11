//! The side tables `feedback` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One owner-requested sweep joined running work and owes a later sweep: manual run-now
    /// or an intake enabled by the owner's standing policy. Scheduling intent only, no
    /// content or actor. Key/value: ().
    COACH_FEEDBACK_SWEEP_PENDING: VaultMeta b"coach:feedback_sweep_pending:v1" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// One note the open feedback inbox took, kept for the triage sweep. Key: u64be(sequence).
    FEEDBACK_INBOX: VaultMeta b"feedback:inbox:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// An owner feedback preview as it was shown, kept until it expires (FIX 5212): its exact
    /// bytes, encoding and digest, the digest of the bundle as built before filtering, and the
    /// owner and route it was previewed for. A send reads it back and never filters again.
    /// Key: u64be(issued at) + bytes32(approval component digest).
    FEEDBACK_PREVIEW: VaultMeta b"feedback:preview:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Open feedback-review-item queue row awaiting triage. Key: id16.
    FEEDBACK_QUEUE: VaultMeta b"feedback:queue:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Dedup index from a feedback bundle's content digest to the review item id that first recorded
    /// it. Key: hex64.
    FEEDBACK_RECEIVED_DIGEST: VaultMeta b"feedback:received:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Universal report arrivals; review lives on the ISSUE entity. Key: u64be + id16.
    FEEDBACK_REPORT_ARRIVAL: VaultMeta b"feedback:report-arrival:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each report cluster under every member ISSUE it copied a vector from (FIX 10835).
    /// Key: id16(member) + id16(root).
    FEEDBACK_REPORT_CLUSTER_BY_MEMBER: VaultMeta b"feedback:report-cluster-by-member:v1:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// One issue's publisher delivery lane (OF-420, FIX 739): the frozen ED-08 signature and its
    /// wire bytes and digest, the frozen destination and logical send, the hold, and the last
    /// send's receipt and outcome. Key: id16 (the ISSUE) + bytes32 (blake3 of the lane key).
    FEEDBACK_REPORT_DELIVERY: VaultMeta b"feedback:report-delivery:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The owner's binding of a publisher to this host's feedback destination (OF-420): its
    /// channel and exact endpoint, where that publisher's issue signatures go. Key: publisher
    /// reference.
    FEEDBACK_REPORT_PUBLISHER_ENDPOINT: VaultMeta b"feedback:report-publisher-endpoint:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Host-stamped subject provenance or owner routing policy. Key: subject reference.
    FEEDBACK_REPORT_ROUTE: VaultMeta b"feedback:report-route:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The SKILL the Coach's feedback triage runs, as the owner bound it, with the binding's
    /// revision (OF-420 T1); absent until the owner binds one. Key: ().
    FEEDBACK_TRIAGE_BINDING: VaultMeta b"feedback:triage-binding:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each acknowledged feedback triage handoff whose evidence is retained, under its evidence
    /// ASSET (FIX 7550). Key: id16(evidence) + bytes32(handoff key). Value: empty.
    FEEDBACK_TRIAGE_HANDOFF_BY_EVIDENCE: VaultMeta b"feedback:triage-handoff-by-evidence:v1:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// Each feedback triage handoff under the sweep that handed it off and the sweep that queued
    /// its current job (FIX 7550). Key: id16(sweep attempt) + bytes32(handoff key). Value: empty.
    FEEDBACK_TRIAGE_HANDOFF_BY_SWEEP: VaultMeta b"feedback:triage-handoff-by-sweep:v1:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// Each feedback triage handoff a requeue pass visits: unacknowledged, or settled erased
    /// (FIX 7550). Key: bytes32(handoff key). Value: empty.
    FEEDBACK_TRIAGE_HANDOFF_OPEN: VaultMeta b"feedback:triage-handoff-open:v1:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// One feedback revision a triage sweep handed off: its source, id and revision, the ASSET
    /// holding the exact item the triage reads, the sweeps that handed it off and queued its
    /// current job, that job, and the committed result once acknowledged. Source and result
    /// identity only; the queue holds job state. Key: bytes32 (blake3 of source, id, revision).
    FEEDBACK_TRIAGE_HANDOFF: VaultMeta b"feedback:triage-handoff:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::feedback::erase_handoff_actor_in_txn;
    /// Where the triage sweep resumes one feedback source: the open inbox's last arrival number
    /// handed off. Key: string (source name).
    FEEDBACK_TRIAGE_SOURCE: VaultMeta b"feedback:triage-source:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Publisher training custody (OF-420): ids, revisions and states of each submission and
    /// control, never text. Key: b"s" or b"c" + id16.
    PUBLISHER_TRAINING_CUSTODY: VaultMeta b"publisher_training:custody:v1:" Named
        // Restore class: Acts that already left the vault: a restore never revives a withdrawn
        // submission or replays an event number (OF-420).
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::Vault::erase_publisher_training_custody_in_txn;
    /// The publisher training outbox's private order, months used (each with its scope, next ordinal
    /// and receipt cursor), link-key flag and purge (OF-420, TRAINING-LINK = C). Key: `()`.
    PUBLISHER_TRAINING_STATE: VaultMeta b"publisher_training:state:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Hub-import receipt for one entity, keyed by (entity, source hub id, hash of the source ref
    /// string). Key: id16 + id16 + hash32.
    SKILL_HUB_IMPORT_RECEIPT: VaultMeta b"skill_hub/import-receipt/v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
}
