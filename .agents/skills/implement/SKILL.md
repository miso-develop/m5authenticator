---
name: implement
description: Implement exactly one ready GitHub `[Task]` Issue through branch, code, tests, security review, PR, and merge-or-handoff.
metadata:
  version: "1.0"
---

# Implement

Implement one Task. Do not reopen planning unless the ticket is internally contradictory or missing a decision required for correctness.

## 1. Pin the exact work item

Resolve the Task by full Issue URL or `owner/repo#number`, confirm `[Task]`, then read:

- Task body/comments
- Parent Spec
- referenced Map/Decision outcomes
- `PROJECT.md`
- `SECURITY.md`
- relevant repository current truth
- existing PR/branch for the same Task
- blockers

Confirm the Task is listed in the Parent Spec's `Implementation tasks` index. Fail closed if the graph is unresolved or ambiguous.

## 2. Establish the branch

Resume an existing unfinished PR/branch for the same Task when present. Otherwise branch from latest `main`. Do not implement normal Tasks directly on `main`.

## 3. Implement the smallest complete slice

- Restate Acceptance Criteria before changing code.
- Use `codebase-design` when bounded module/interface decisions are required.
- Use `tdd` where a stable observable seam exists.
- Keep changes inside the selected Task.
- Include required code/config/documentation/tests so repository current truth is accurate.
- If implementation reveals a missing product/architecture/security decision, stop rather than inventing it.

For any credential-bearing path, explicitly inspect acquisition, decoding, memory lifetime, persistence, logging, serialization, transport, errors, cleanup, export, and deletion behavior against `SECURITY.md`.

Real user authentication material must never be used as committed test data or pasted into GitHub evidence.

## 4. Run required verification

Before closeout:

1. run repository-defined targeted and required tests/checks,
2. run `code-review` against Task, Parent Spec, `PROJECT.md`, and `SECURITY.md`,
3. fix concrete valid blocking findings,
4. re-run affected checks.

This repository does not assume a Loop Verifier or `.verifier` contract. Do not fabricate or require external verifier results unless the repository explicitly adopts them later.

Never weaken tests, Acceptance Criteria, or security rules merely to get green.

## 5. Open the PR

After local required checks are green:

1. commit the Task-scoped change,
2. push the branch,
3. create/update one PR,
4. include `Parent spec: #<spec-number>` and `Closes #<task-number>`,
5. summarize verification and security review performed without exposing secret material.

## 6. Merge or hand off

If required repository checks are green, review findings are resolved, and the PR is mergeable, merge it. The Task is complete only when merge closes the Issue.

For the final Task, re-evaluate Parent Spec requirements and durable repository knowledge. Security/trust-boundary decisions that remain current must be promoted into repository truth.

If the environment cannot reach merge state, stop making new changes and use `handoff`.

Adapted from `mattpocock/skills` `implement`; modified for Loop Engineering without Loop Verifier coupling and with mandatory project security policy.
