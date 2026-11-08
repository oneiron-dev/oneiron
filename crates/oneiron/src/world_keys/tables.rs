//! The side tables `world_keys` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One erase subject this machine sweeps from every pad object the home keeps (FIX 922, 7294,
    /// 8868): empty while only owed (a hard erase of one key's pad row stages it), else its proof:
    /// the home (16) ‖ the revision of the home's list it was made against (32) ‖ 1 and the u64be
    /// slot a pad object that did not open here held it back in, or 0 and eight zero bytes ‖
    /// u32be count ‖ each kept pad object swept, its generation (24) ‖ its digest (32). Key: "w:"
    /// hex32 (a world whose keys were destroyed here) or "k:" hex80 (one key's full id).
    SYNC_RESIDENCE_BUNDLE_SWEPT: SyncState b"rbe:" Raw;
    /// A reader's own Loro document of one sealed private-world window, which the sealed cloud
    /// bundle's world section carries whole (FIX 922). Purged with an erased world. Key: hex32
    /// (world) ":" string (window label).
    WORLD_KEY_SEALED_MIRROR: VaultMeta b"world_keys:mirror:v1:" Raw;
    /// How many actor erases rewrote the sealed mirrors here (FIX 17210): a seal or a take that
    /// read a mirror before one writes nothing after it. Key: the string `count`.
    WORLD_KEY_SEALED_MIRROR_ERASES: VaultMeta b"world_keys:mirror_erases:v1:" Named;
    /// Which version of one sealed window's mirror last landed here in full, and under which
    /// forward pass (FIX 6509), or that the window's rows here were removed since (FIX 5506): a
    /// take of that version under that pass skips its forward pass. Purged with an erased world.
    /// Key: hex32 (world) ":" string (window label).
    WORLD_KEY_SEALED_MIRROR_LANDED: VaultMeta b"world_keys:mirror_landed:v1:" Raw;
}
