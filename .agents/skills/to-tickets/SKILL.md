---
name: to-tickets
description: Break a settled GitHub `[Spec]` Issue into small vertical `[Task]` implementation tickets with explicit blockers.
metadata:
  version: "1.0"
---

# To Tickets

Convert one settled Spec into implementation tickets. Do not redesign the feature while decomposing it.

## 1. Read the Spec graph

Read the Spec, references, relevant Decision outcomes, `PROJECT.md`, `SECURITY.md`, and repository current truth.

If decomposition exposes an unresolved product, architecture, or security decision, stop and route it back to planning. Do not hide a decision inside a Task.

## 2. Slice vertically

Each Task must deliver one narrow, complete, independently verifiable repository change and fit one coherent PR.

A Task may include code, configuration, durable documentation, and verification required to leave repository current truth accurate.

Security controls must not be postponed to a generic cleanup Task when they are required for the behavior being introduced. Secret-handling acceptance criteria belong in the same Task that introduces the relevant data path unless independently reviewable architecture work is intentionally split first.

## 3. Create Issues in two passes

First design the blocker graph by title. Then create each `[Task]` using `agent/WORK-TRACKING.md`. After real issue numbers exist, update blockers and the parent Spec's canonical `Implementation tasks` list.

## 4. Verify the frontier

Ensure every Spec requirement is covered, known durable knowledge work is owned, at least one Task is ready unless explicitly blocked, the graph is acyclic, and the Spec Task index exactly matches the created set.

Never include real credentials, QR payloads, dumps, or secret-bearing screenshots as Task evidence or fixtures.

Do not implement any Task in this Skill.

Adapted from `mattpocock/skills` `to-tickets` for Loop Engineering.
