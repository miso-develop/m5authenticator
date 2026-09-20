# Parallel Work Coordination

This document defines the canonical coordination rules when multiple ChatGPT chats / agent sessions / human workers perform Loop Engineering concurrently in the same repository.

The goal is to determine in-flight work from observable GitHub state, without depending on centrally shared conversations or manual declarations such as "I am working on this now," and to prevent duplicate implementation of the same Task, file conflicts, semantic conflicts, and overwrites from stale bases.

These rules supplement the implementation lifecycle in `AGENTS.md` and `.agent/WORK-TRACKING.md`. If they conflict with a security rule, `SECURITY.md` takes precedence.

## Core principle

Treat each chat / agent session as an independent worker.

Before a worker begins production implementation or changes repository current truth, it MUST NOT infer other workers' state from conversation context. It MUST determine that state from the latest GitHub state.

```text
GitHub open Issues / open PRs / branches / commits / changed files
    = shared coordination surface

chat history / local assumption
    = not the coordination source of truth
```

"Another chat might be working on this, but I cannot confirm it" does not mean there is no conflict. Use observable GitHub state and fail closed.

## Terminology

- **worker**: one chat, agent session, or human implementation session.
- **candidate Task**: the open `[Task]` Issue a worker is considering starting.
- **in-flight work**: implementation work not yet merged to main, including open/draft PRs and non-main branches that can reasonably be mapped to a Task.
- **claimed Task**: a Task already occupied by in-flight work.
- **reserved surface**: files / directories / interfaces / schemas / protocols / build surfaces currently being changed or semantically owned by in-flight work.
- **hard conflict**: a conflict that prohibits parallel implementation.
- **semantic conflict**: a conflict where different file paths still modify the same contract, interface, state machine, schema, or equivalent shared behavior.

## Mandatory preflight

Before creating a branch, changing production code, or changing durable architecture/configuration, the worker MUST perform all of the following:

1. Retrieve the latest `main` HEAD SHA.
2. Review every open PR targeting `main`, including Draft PRs.
3. Review non-main branches.
4. Review open `[Task]` Issues and each Task's `Blocked by`.
5. For each open PR, inspect head branch, head SHA, base SHA, linked/closing Task, and changed files.
6. For non-main branches without a PR, infer the corresponding Task where reasonably possible from branch name, commit messages, and changes from main.
7. Review recent commits/merges on main and confirm whether Tasks that the candidate Task depends on have actually been merged.
8. Compare the candidate Task with in-flight work for dependencies, changed files, and semantic ownership.
9. Create or continue a branch only if the Parallel eligibility gate below is satisfied.

If the preflight becomes ambiguous, do not make a convenient assumption and proceed. Treat the candidate Task as blocked or choose a different Task that is clearly independent.

## How to identify in-flight work

### Open PR

Every open PR, including Draft PRs, is in-flight work.

Determine Task ownership in this order:

1. `Closes #<number>` / `Fixes #<number>` / explicit Task reference in the PR body
2. Task number in the branch name
3. match between PR title/body and Task title/scope
4. match between changed files and Task Acceptance Criteria

If step 1 identifies a Task explicitly, treat that as the canonical claim.

### Branch without PR

Do not ignore a non-main branch merely because no PR exists yet.

Combine these signals and treat the branch as an in-flight claim when the Task can reasonably be identified uniquely:

- branch names such as `task/<number>-...`, `feat/<number>-...`, or `issue-<number>-...`
- commit messages on the branch
- changed files relative to main
- scope of open Tasks

Even if Task mapping cannot be uniquely determined, treat the branch's changed files / semantic surface as reserved.

Do not treat an old or apparently abandoned branch as nonexistent unless GitHub state makes its abandonment explicit. If safe ownership cannot be determined, obtain human confirmation or clean up the branch before proceeding.

## Reservation model

In-flight work reserves three layers.

### 1. Exact file reservation

Every file changed by an open PR or branch is reserved.

If the candidate Task also needs to modify the same file, that is normally a hard conflict.

The only exception is when both changes are completely independent generated metadata or an equivalent case where safety after rebase can be proven automatically. "It will probably merge" is not proof.

### 2. Directory / ownership reservation

Do not consider only changed files. Also inspect the coherent subsystem explicitly owned by the Task.

Examples:

- provisioning protocol implementation
- account storage schema / migration
- trusted-time state machine
- TOTP core
- device input/UI behavior
- Web Serial transport/session
- release/build workflow

If another worker is modifying the public interface, state transition, or ownership boundary of the same subsystem, that is a semantic conflict even if the files differ.

### 3. Contract reservation

Treat these as especially strong shared contracts:

- protocol vocabulary / version / wire format
- storage schema / partition layout / migration behavior
- public C/C++ headers and TypeScript interfaces consumed across subsystems
- security/trust boundary
- runtime state machine
- device input mapping
- release artifact layout
- CI/build contract and shared workflow
- dependency versions / lockfiles when both branches require dependency changes

If in-flight work changes one of these contracts, downstream Tasks that consume that contract normally MUST NOT begin until the contract is merged to main.

## Hard conflict conditions

Do not begin a new implementation of the candidate Task if any of the following is true:

1. An open PR or active branch already claims the same Task.
2. The candidate Task lists an open Issue under `Blocked by`.
3. A blocker Task has a green PR but is not yet merged to main.
4. The candidate Task needs to change a file already changed by in-flight work.
5. The candidate Task changes the same shared contract as in-flight work.
6. The candidate Task depends on an interface being created or changed by in-flight work.
7. The candidate Task's correct implementation may materially depend on an unmerged design decision in another branch.
8. Main advances after candidate branch creation and the main update overlaps the candidate Task's reserved surface.
9. Branch/PR/Issue mapping is ambiguous enough that independence cannot be established safely.

When a hard conflict exists, do not commit into the conflicting branch without authorization, recreate the other worker's PR, or route around the conflict with a duplicate implementation.

## Parallel eligibility gate

A candidate Task may be implemented by another worker in parallel only when **all** of the following are true:

- the candidate Task itself is ready and every `Blocked by` entry is closed;
- no in-flight work claims the same Task;
- planned changed files do not overlap existing reserved files;
- semantic ownership does not overlap an existing reserved subsystem;
- the candidate Task does not depend on an unmerged contract;
- the candidate Task's Acceptance Criteria can be implemented and verified from main alone without assuming another in-flight branch;
- the branch can be created from latest main;
- required CI/checks can be evaluated independently.

If even one condition is false, do not parallelize.

## Planned change surface

Before implementation begins, identify at least:

- primary directories/files expected to change
- public/shared interfaces expected to change
- impact on schema/protocol/build/security contracts
- likely tests/workflows expected to change

The complete file list does not need to be fixed in advance. However, if implementation discovers a need to touch a shared area outside the planned surface, re-run GitHub preflight before expanding scope.

## Recheck points

A single preflight at iteration start is not sufficient. Recheck at each of these points.

### Before first write

After branch creation and before the first meaningful change, confirm that open PR / branch state has not changed.

### Before expanding scope

Before modifying a new directory, shared header, schema, protocol, workflow, lockfile, or similar shared surface, re-evaluate reservations.

### Before push / PR creation

Re-read latest main and other open PRs. If another worker has claimed a conflicting surface, stop before adding more pushed work and decide how to resolve ownership.

### Before merge

Immediately before PR merge, confirm at minimum:

- PR head SHA is the expected SHA
- latest main HEAD has not invalidated assumptions
- mergeability of candidate branch against latest main
- changed-file overlap with newly opened PRs
- semantic conflicts in shared contracts
- required checks are green on the exact head

If main advanced, do not merge merely because GitHub reports `mergeable`. Review the main-side change and update/rebase and reverify when required.

## Main advanced while working

If main advances during work:

1. Compare the old base with latest main.
2. Identify the Task/PR merged into latest main.
3. Check file overlap with the candidate branch.
4. Even without file overlap, check contract / dependency / behavior overlap.
5. If there is overlap or assumptions changed, update the branch to latest main and re-run required verification.
6. If there is no overlap but the PR body or verification description became stale, update that documentation.

"there was no conflict when the branch was created" is not sufficient evidence for merge.

## Conflict resolution priority

Resolve conflicts in this priority order:

1. state already merged to main
2. work that first claimed the Task through an open PR
3. active branch without a PR that clearly claims the Task
4. candidate work that has not yet created a branch

A later worker MUST NOT replace earlier work without an explicit ownership transition.

Even when earlier work appears abandoned or incorrect, do not proceed with a conflicting implementation silently. First make the ownership/state transition explicit in the Issue/PR.

## One Task, one implementation line

Do not create multiple simultaneous implementation branches/PRs for one Task.

If an existing PR is defective, normally fix that branch/PR. If a complete reimplementation is required, first close the old PR and record the ownership-transfer reason in the Issue/PR, then create the new branch.

## Cross-Task integration

Even Tasks that are safe to implement in parallel integrate through main.

Worker B MUST NOT base its branch on Worker A's unmerged branch unless an explicit Decision/Task adopts stacked PRs.

Normal:

```text
main ── Task A branch ── PR A ── merge
  └── Task B branch ── PR B ── merge
```

Forbidden implicit stack:

```text
main ── Task A branch
          └── Task B branch
```

This prevents hidden dependencies between Tasks.

## Rules for documentation / process-only changes

Agent/process documentation changes that are independent of a production Task still use the same preflight as implementation PRs.

However, if changes are limited to process-only surfaces such as `AGENTS.md` / `.agent/` and have no file or semantic conflict with an in-flight product PR, they may proceed independently of the product Task's `Blocked by` chain.

Process-rule changes should also go through a branch/PR rather than direct commits to protected `main`.

## Minimal evidence in PR

For parallel implementation, be able to explain when relevant:

- the main SHA used to create the branch
- significant in-flight PRs at that time
- why there was no file / semantic conflict
- the re-evaluation result if main advanced during the work

A long coordination report is not required every time, but important conflict decisions should leave enough durable evidence to reconstruct the reasoning.

## Fail-closed examples

### Example: safe parallel work

- PR A: firmware storage implementation
- Task B: browser-only QR parser
- changed directories are separated between firmware storage and `web/src/import`
- no shared protocol/schema changes are made concurrently
- Task B does not list Task A as a blocker

→ Parallel implementation is allowed if every Parallel eligibility gate condition is satisfied.

### Example: same file

- PR A is modifying `firmware/main/app_main.cpp`
- Task B also needs the same file for device runtime wiring

→ hard conflict. Start Task B only after PR A is merged.

### Example: different files but semantic conflict

- PR A is designing/implementing the NDJSON `time.sync` protocol
- Task B plans to implement the Web Serial `time.sync` consumer in a different file
- correct Task B behavior depends on PR A's unmerged contract

→ hard conflict despite no file overlap. Wait until the contract is merged to main.

### Example: independent process change

- PR A changes firmware trusted-time/TOTP
- a process PR adds only `.agent/PARALLEL-WORK.md`
- it does not touch product contracts or PR A's changed files

→ process PR may proceed in parallel.

## Required worker behavior summary

Workers MUST always:

1. inspect GitHub state before selecting a Task;
2. inspect branches as well as open PRs;
3. evaluate semantic conflicts as well as file conflicts;
4. treat a blocker with only a PR as unresolved until merged;
5. never build another Task on unmerged implementation;
6. re-evaluate when main advances;
7. avoid parallelization when state is unclear;
8. recheck conflicts immediately before merge.

Correctness and merge safety take precedence over parallelism. Parallelize only Tasks that can be proven safely independent.
