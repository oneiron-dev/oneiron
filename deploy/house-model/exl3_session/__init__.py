"""Exact conversation sessions on the house EXL3 worker (DESIGN-V2 §3.2, R2
worker half): canonical checkpoints with no board attached, working branches
forked from them copy-on-write, and the suffix commit that advances them.

An in-tree override layer over the pinned exllamav3==1.6.0 (Engine ruling
10-22): it subclasses the stock Generator, PageTable and Job, forks nothing,
and leaves every session-less call as it was.

- `pages.py`: SessionPageTable, the stock table plus owners (page references
  held outside any Job), counted by defragmentation and validation.
- `generator.py`: SessionGenerator, the stock Generator over that table, and
  where this layer cannot run.
- `state.py`: recurrent snapshots at exact token positions, through the stock
  stash API; no KV is copied.
- `anchor.py`: retained pages, their tokens and snapshots, and where a prompt
  attaches to them.
- `jobs.py`: the session Job mixins (a working branch's, a suffix commit's).
- `registry.py`: sessions, branches, checkpoints, by handle.
- `layer.py`: the scheduler-thread side: plans, carries, commits, eviction,
  release, stats.
- `ops.py`: the session ops of codec v1.1, as `exl3_ipc.py` dispatches them.

Sessions live in this process's memory alone: never persisted, and never
restored as truth. A new incarnation starts with none, and its epoch makes
every old handle unknown. Startup index reconstruction therefore has nothing
to rebuild.
"""
from .generator import SessionGenerator, unsupported
from .jobs import FrontierMixin
from .layer import OPS, SCHEMA_MINOR, SessionLayer
from .ops import WITH_INPUT, answer
from .registry import Refused

__all__ = ["FrontierMixin", "OPS", "Refused", "SCHEMA_MINOR", "SessionGenerator", "SessionLayer", "WITH_INPUT",
           "answer", "unsupported"]
