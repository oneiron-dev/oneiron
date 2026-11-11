---
name: rewrite-ask
description: Scoped rewrite and durable question through HTTP and MCP
version: 1.0.0
license: Apache-2.0
kind: capability
predicates: ["hooks.rewrite.http.allowed", "hooks.rewrite.http.invalid", "hooks.rewrite.http.world", "hooks.rewrite.http.facet", "hooks.rewrite.http.project", "hooks.rewrite.http.revoked", "hooks.rewrite.mcp.allowed", "hooks.rewrite.mcp.invalid", "hooks.rewrite.mcp.world", "hooks.rewrite.mcp.facet", "hooks.rewrite.mcp.project", "hooks.rewrite.mcp.revoked", "hooks.rewrite.http.live_progress", "hooks.rewrite.http.revoked_progress"]
hooks: ["scoped-rewrite", "saved-question"]
---
# Scoped write rewrite and durable question

An independent before-hook journey. The first hook rewrites the claim arguments;
the second asks whether the saved call may proceed. The engine owns the Wasm
runtime, credential checks, task settlement and committed effects.
