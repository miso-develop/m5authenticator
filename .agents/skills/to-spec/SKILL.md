---
name: to-spec
description: Turn already-settled conversation or completed Wayfinder decisions into an implementation-ready GitHub `[Spec]` Issue.
metadata:
  version: "1.0"
---

# To Spec

Synthesize what has already been decided. Do not reopen settled choices and do not invent answers to unresolved questions.

## 1. Gather settled sources

Read `PROJECT.md`, `SECURITY.md`, the current conversation, completed Map/Decision outcomes when present, and repository current truth that materially constrains the feature.

If an unresolved choice changes observable behavior, architecture, security, cost, compatibility, or acceptance criteria, route it back through planning rather than guessing.

## 2. Write one Spec

Create/update one `[Spec] <feature>` Issue using `agent/WORK-TRACKING.md`.

Include Problem, Outcome, Requirements, Decisions, Verification, Out of scope, References, Repository knowledge, and Implementation tasks.

Requirements describe observable behavior. Tests/checks are evidence for the contract, not the contract itself.

For security-sensitive work, explicitly reference `SECURITY.md` and capture the relevant trust boundary, persistence/export/logging/network constraints without copying real credentials or payloads.

## 3. Check implementability

Verify that every requirement is observable, out-of-scope behavior is explicit where needed, references point to actual decisions/evidence, no unresolved decision is disguised as implementation freedom, and durable knowledge candidates have been identified.

Verification examples and fixtures must use public test vectors or synthetic data only.

## 4. Publish and close planning

Create/update the Spec. If it came from a Map, close the Map only after all in-scope Decisions are settled and the Spec is linked.

Do not implement repository changes. The next step is `to-tickets`.

Adapted from `mattpocock/skills` `to-spec` for Loop Engineering.
