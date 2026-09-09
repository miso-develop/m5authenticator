---
name: wayfinder
description: Plan a large, ambiguous, multi-session effort by mapping unresolved decisions before implementation. Use when the destination is known but the route is still foggy or depends on multiple decisions/research steps.
metadata:
  version: "1.0"
---

# Wayfinder

Wayfinder is planning only. It resolves decisions and prerequisites; it does not implement production code.

## 1. Define the destination

State what must be decided or specified when the map is complete. The destination defines scope.

## 2. Create the map

Create one GitHub Issue titled `[Map] <name>` using `agent/WORK-TRACKING.md`.

Record Destination, Decisions so far, Not yet specified, and Out of scope. Treat this Issue as an exploration map, not an Epic or implementation backlog.

## 3. Create decision issues

For each precise unresolved question, create `[Decision] <question>` with Parent map, one Question, and Blocked by.

Security, trust-boundary, secret-storage, provisioning, networking, export, reset, or signing questions must be made explicit Decisions instead of being hidden inside implementation Tasks.

Decision issues may use research, design analysis, or throwaway prototypes to gather evidence, but must not deliver production feature implementation.

## 4. Work the frontier

Resolve open Decisions whose blockers are closed. For each resolved Decision:

1. record answer and evidence,
2. identify whether it is history-only or durable repository knowledge,
3. explicitly carry durable security/architecture knowledge into the downstream Spec/Task or repository truth,
4. close the Decision,
5. link its one-line outcome from the parent Map,
6. promote newly-clear fog into new Decision issues.

## 5. Finish the map

The Map is ready to close when no unresolved in-scope Decision remains, `Not yet specified` is empty or out of scope, and a downstream `[Spec]` has been established.

Then use `to-spec`. The Map does not stay open to track implementation.

## Incomplete session

Use `handoff` on the current Map/Decision without including credentials, secret-bearing payloads, or private artifacts.

Adapted from `mattpocock/skills` `wayfinder` for the Loop Engineering GitHub Issue model.
