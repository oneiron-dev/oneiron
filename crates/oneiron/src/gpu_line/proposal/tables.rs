//! The side table `proposal` keeps. The crate's build script places it in `side_table`'s
//! catalogue.

crate::side_table::side_tables! {
    /// The standing `proposed@1` table for one period of one GPU line that has not begun
    /// (design pass 34 section 3.5): its ceilings, what was left unallocated, who proposed it
    /// and why. A later proposal for the same period replaces it; the mint copies it into the
    /// period record. Key: id16 (lane project) + u32be (period index).
    GPU_LINE_PROPOSAL: VaultMeta b"gpu_line_proposal:v1:" Named
        // Restore class: A proposal is the planner's standing ask for a period that has not
        // begun: a restore keeps the one it holds and never invents one.
        [restore: live] [family: unclassified] [tier: canonical];
}
