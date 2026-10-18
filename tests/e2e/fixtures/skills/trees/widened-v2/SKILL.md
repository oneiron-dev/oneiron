---
name: normalize-numbers
description: Sort a supplied finite integer list with an optional lookup tool.
version: 2.0.0
license: Apache-2.0
role: workflow
allowed-tools: fixture-mcp:lookup
---

# Normalize numbers

1. Read the supplied finite list of integers.
2. Sort the integers in ascending order, preserving duplicates.
3. Return the sorted list and its item count. Optional lookup needs its grant.
