//! Context Board forward test oracle — MCP surface + packaging arms, epic
//! ONE-1692, relocated from the engine crate by the ONE-1797 split so these
//! arms live in the crate that can legally link the MCP implementation.
//!
//! Contract-level red tests derived from the ticket acceptance criteria
//! (ONE-1704 / ONE-1705) and the ratified design
//! `oneiron-v1/design/out/08b-Context-Board-extension.md` (16/16, 2026-07-15).
//!
//! Shape of every test:
//! * `#[ignore = "armed by ONE-XXXX"]` — dormant until its ticket lands.
//! * An `arm_*` seam function whose body is `unimplemented!()`. Its doc
//!   comment is the fixture spec. The ARMING ticket replaces the seam body
//!   (and may freely adapt the seam signature), then removes the `#[ignore]`.
//! * Asserts are the contract: exact counts and equalities, never `any()`.
//!   Arming NEVER weakens, loosens, or removes an assert.
//!
//! Observation structs are contract shapes, not API proposals — every field
//! is asserted by at least one test.

// Contract shapes are constructed only once their arming ticket lands.
#![allow(dead_code)]

// ════════════════════════════════════════════════════════════════════════
// CB-X — MCP surface + packaging (ONE-1704 MCP 2-tool · ONE-1705 skill/CLI/
//        thin client)
// ════════════════════════════════════════════════════════════════════════
mod cb_x {
    /// Primary MCP surface observations.
    struct McpPrimarySurface {
        /// Tool names on the PRIMARY surface, sorted.
        tools: Vec<String>,
        /// True iff setup_oneiron() returns a board keyframe.
        setup_returns_board_keyframe: bool,
        /// True iff setup_oneiron() returns the typed verb grammar.
        setup_returns_verb_grammar: bool,
        /// True iff setup_oneiron() returns the instructions payload
        /// (ticket AC: "board keyframe + verb grammar + instructions
        /// payload" — F17 setup half).
        setup_returns_instructions: bool,
        /// True iff execute_code() reaches the code-mode REPL/self.oneiron.
        execute_code_reaches_repl: bool,
    }

    /// ONE-1704 fixture: enumerate the primary MCP surface and call both
    /// tools once against a small vault.
    fn arm_mcp_primary_surface() -> McpPrimarySurface {
        unimplemented!("armed by ONE-1704: 2-tool MCP surface")
    }

    /// ONE-1704 · 08b §6 (r3v2): the PRIMARY MCP surface is exactly two
    /// tools — setup_oneiron() and execute_code(); setup returns all three
    /// payload parts.
    #[test]
    #[ignore = "armed by ONE-1704"]
    fn mcp_primary_surface_is_exactly_two_tools() {
        let surface = arm_mcp_primary_surface();
        assert_eq!(surface.tools.len(), 2);
        assert_eq!(surface.tools, ["execute_code", "setup_oneiron"]);
        assert!(surface.setup_returns_board_keyframe);
        assert!(surface.setup_returns_verb_grammar);
        assert!(surface.setup_returns_instructions);
        assert!(surface.execute_code_reaches_repl);
    }

    /// Tool-first variant generation observations.
    struct GeneratedToolVariant {
        /// The fixture verb table, sorted.
        verb_table: Vec<String>,
        /// Generated tool names, sorted (F17: set-equality with the verb
        /// table — 7 duplicates of one verb must fail).
        generated_tool_names: Vec<String>,
        /// Hand-written (non-generated) tools in the variant (must be none).
        hand_written_tools: usize,
    }

    /// ONE-1704 fixture: a verb table of exactly these seven verbs —
    /// board.expand, board.refresh, tasks.ack, tasks.cancel, tasks.check,
    /// tasks.create, tasks.expand; generate the tool-first variant from it.
    fn arm_generated_tool_variant() -> GeneratedToolVariant {
        unimplemented!("armed by ONE-1704: tool-first variant generated from the verb table")
    }

    /// ONE-1704 · 08b §6: the tool-first variant is GENERATED from the verb
    /// table — the generated tool-name set equals the verb table exactly
    /// (one tool per verb, distinct), nothing hand-rolled.
    #[test]
    #[ignore = "armed by ONE-1704"]
    fn tool_first_variant_is_generated_one_tool_per_verb() {
        let variant = arm_generated_tool_variant();
        let expected = [
            "board.expand",
            "board.refresh",
            "tasks.ack",
            "tasks.cancel",
            "tasks.check",
            "tasks.create",
            "tasks.expand",
        ];
        assert_eq!(variant.verb_table, expected);
        assert_eq!(variant.generated_tool_names, expected);
        assert_eq!(variant.hand_written_tools, 0);
    }

    /// Packaging-ladder observations.
    struct PackagingLadder {
        /// Self-routing lanes the agent skill opens with.
        skill_lanes: usize,
        lane_code_mode_repl: bool,
        lane_thin_client: bool,
        lane_curl_cli: bool,
        lane_tool_first_mcp: bool,
        /// True iff a fat autogen SDK ships anywhere (must not).
        fat_autogen_sdk_shipped: bool,
        /// Distinct thin-client artifacts shipped (ticket: "ONE thin
        /// hand-rolled typed client … SAME artifact" — must be exactly 1;
        /// three independent clients must fail; F18).
        distinct_thin_client_artifacts: usize,
        /// Consumers importing THAT SAME artifact (code-mode inject, native
        /// app, npm-capable BYOA).
        consumers_importing_same_artifact: usize,
        /// True iff the thin client passes raw responses through
        /// (ticket AC: "raw-response passthrough").
        thin_client_raw_response_passthrough: bool,
        /// True iff the thin client is an autogenerated artifact (ticket:
        /// hand-rolled — must be false).
        thin_client_autogenerated: bool,
    }

    /// ONE-1705 fixture: inspect the shipped packaging artifacts — skill
    /// routing tree, thin CLI, thin typed client manifest + its consumer
    /// import table.
    fn arm_packaging_ladder() -> PackagingLadder {
        unimplemented!("armed by ONE-1705: skill + thin CLI + ONE thin typed client")
    }

    /// ONE-1705 · 08b §6 (r3v2): choose-your-own-adventure skill with four
    /// lanes; ONE hand-rolled thin client (raw-response passthrough) — the
    /// SAME artifact imported by three consumers; fat SDK never.
    #[test]
    #[ignore = "armed by ONE-1705"]
    fn packaging_ladder_four_lanes_one_thin_client_no_fat_sdk() {
        let ladder = arm_packaging_ladder();
        assert_eq!(ladder.skill_lanes, 4);
        assert!(ladder.lane_code_mode_repl);
        assert!(ladder.lane_thin_client);
        assert!(ladder.lane_curl_cli);
        assert!(ladder.lane_tool_first_mcp);
        assert!(!ladder.fat_autogen_sdk_shipped);
        assert_eq!(ladder.distinct_thin_client_artifacts, 1);
        assert_eq!(ladder.consumers_importing_same_artifact, 3);
        assert!(ladder.thin_client_raw_response_passthrough);
        assert!(!ladder.thin_client_autogenerated);
    }
}
