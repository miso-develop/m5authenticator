# Work Tracking

Loop Engineering planning / implementation state is centralized in GitHub Issues / Pull Requests. Do not create a separate progress ledger inside the repository.

## Source-of-truth boundary

```text
GitHub Issues / Pull Requests
    = planning / decision / implementation state and change history

Repository
    = current system state
```

Repository current truth should be expressed as code, configuration, durable documentation, tests/static checks, or equivalent artifacts as appropriate.

Closed Issues are important decision history, but future development MUST NOT require searching historical Issues merely to understand architecture/security/contracts that remain current. Knowledge from Maps / Decisions / Specs that is still current system truth must be promoted into the repository.

## Canonical work item flow

```text
[Map]
  ↓ resolves unknowns through [Decision]
[Decision]
  ↓ settled outcomes
[Spec]
  ↓ implementation decomposition
[Task]
  ↓ one branch / one PR / merge
repository current truth
```

Not every change requires a Map.

- Small change with already-settled requirements: may start from `[Spec]`
- One clear implementation change: create a `[Task]` under an existing `[Spec]`
- Large, ambiguous work with multiple decisions: start from `[Map]`

## Manual issue creation

When creating an Issue through the GitHub UI, use the Forms under `.github/ISSUE_TEMPLATE/`.

- `Loop Map` → `[Map]`
- `Loop Decision` → `[Decision]`
- `Loop Spec` → `[Spec]`
- `Loop Task` → `[Task]`

When an Agent/API creates an Issue directly, use the canonical body formats below.

## Dependency notation

`Blocked by` must use exactly one of these forms.

```md
## Blocked by
- None
```

or:

```md
## Blocked by
- #123
- #456
```

- Use same-repository standalone `#<number>`.
- Self-dependencies are forbidden.
- Do not create dependency cycles.
- A Task blocker references a Task; a Decision blocker references a Decision.

## Repository knowledge lifecycle

For information learned through Maps / Decisions / Specs, especially during Spec closeout, ask:

> Does this information need to remain known as the "current system state" for future development?

If YES, promote it into repository current truth. Candidate destinations include:

- `.agent/PROJECT.md`
- `SECURITY.md`
- architecture/security/design docs
- code / configuration
- durable specification
- automated tests / static checks

Do not copy an Issue body wholesale into documentation. Avoid duplicate sources of truth and promote only the currently valid contract/rationale into the appropriate durable location.

### Map knowledge

A `[Map]` is normally an Exploration Map. It is a temporary planning artifact that structures the problem space, unknowns, dependencies, and decision points; it is not an Epic or Task list.

If exploration discovers system structure that future development must continue to understand, promote only that portion into architecture documentation or another durable repository surface.

### Decision knowledge

A Decision is a work item that settles one question.

Typical knowledge that should be promoted into the repository includes:

- architecture / dependency direction
- security / trust boundary
- credential handling policy
- fail-closed policy
- compatibility policy
- subsystem ownership
- decisions whose rationale must remain understandable when they are changed in the future

Do not keep a Decision open to track implementation progress. Once the answer/evidence is settled and required promotion is complete or downstream Spec/Task ownership is explicit, close the Decision.

### Spec and verification

```text
Spec
    = contract the system must satisfy

Test / Static Check / Runtime Check / Review
    = evidence that the contract is satisfied
```

`Spec != Test`.

Architecture/security/operational rules may not be completely expressible by tests alone. In those cases, combine code/configuration/documentation/review/static checks.

### Task knowledge

A Task is an implementation unit. Do not preserve the Task Issue itself as permanent repository documentation. History remains in the Task Issue → PR → commit history chain.

## Work item types

### `[Map]`

An Exploration Map for large, ambiguous, multi-session work. Created by `wayfinder`.

Body:

```md
## Destination
<what must be decided when the map is complete>

## Decisions so far
- None yet

## Not yet specified
- <in-scope fog that is not yet clear enough to phrase as a question>

## Out of scope
- <what this map does not cover>
```

Close a Map when:

- no unresolved in-scope Decision remains;
- `Not yet specified` is empty or moved out of scope;
- a downstream `[Spec]` has been created and linked.

Do not keep the Map open until Tasks or implementation are complete.

### `[Decision]`

An Issue under a Map that resolves one question / investigation. It is not a production implementation task.

Body:

```md
## Parent map
#<map-number>

## Question
<one question this Issue decides>

## Blocked by
- None
```

When resolved:

1. record answer / evidence in a comment;
2. decide whether it is durable repository knowledge;
3. make required promotion or downstream ownership explicit;
4. close the Decision;
5. link it under the Parent Map's `Decisions so far`.

### `[Spec]`

A feature contract settled before implementation. Created by `to-spec`.

Body:

```md
## Problem
<problem from the user's perspective>

## Outcome
<result to achieve>

## Requirements
- <observable requirement>

## Decisions
- <settled decision>

## Verification
- <observable check / test seam>

## Out of scope
- <explicitly excluded work>

## References
- `.agent/PROJECT.md`
- `SECURITY.md` when applicable
- <Map / Decision / external spec>

## Repository knowledge
<initial advisory assessment>

## Implementation tasks
- [ ] #<task-number> <task title>
```

Security-sensitive features MUST include `SECURITY.md` in References.

After all Implementation Tasks are closed, re-evaluate Requirements, verification, and repository knowledge promotion before closing the Spec.

### `[Task]`

A Task is a vertical slice that can be implemented in one iteration / one coherent PR.

Body:

```md
## Parent spec
#<spec-number>

## What to build
<what this Task alone implements>

## Acceptance criteria
- [ ] <externally assessable condition>

## Blocked by
- None
```

A Task must satisfy all of the following:

- Parent Spec actually exists.
- It is listed under the Parent Spec's `Implementation tasks`.
- Production implementation MUST NOT begin until all blockers are closed.
- Acceptance Criteria are observable.
- It contains no unrelated cleanup.

## Implementation lifecycle

1. Read the exact `[Task]` and Parent `[Spec]`.
2. Read `.agent/PROJECT.md` and `SECURITY.md`.
3. Check blockers and existing PRs/branches.
4. Create the Task branch from latest `main`, or continue an existing branch.
5. Implement the smallest complete slice.
6. Run targeted tests/checks.
7. For a security-sensitive change, explicitly review credential flow, logging, artifact, and network boundaries.
8. Perform code review.
9. Create a PR containing `Parent spec: #...` and `Closes #...`.
10. Merge after required checks are green.
11. Close the Task through the merge.
12. If it is the final Task, perform Parent Spec closeout and repository-knowledge promotion review.

Verifier-specific frameworks, external Verifier repositories, and `.verifier` contracts are not part of this repository's Loop Engineering lifecycle. Only checks defined by this repository count as repository-defined required verification.

## Handoff

If a Task cannot be completed because of a session boundary or blocker, leave a checkpoint on the target Issue or PR.

At minimum include:

- branch / HEAD
- PR
- completed scope
- verification performed
- blocker
- next concrete action

**Never include secrets, credentials, QR payloads, Wi-Fi passwords, private dumps, or equivalent sensitive data in a handoff.**

## Security-specific work tracking

A security Decision must not remain only as Issue history when it constrains future implementation. Promote such decisions into `.agent/PROJECT.md` / `SECURITY.md` / a durable design document / an executable check as appropriate.

Especially strong candidates for durable knowledge include:

- secret storage / encryption architecture
- eFuse policy
- provisioning trust boundary
- Web Provisioner network policy
- secret export prohibition
- Factory Reset semantics
- firmware update secret-retention policy
- BLE authentication model
- release/signing model

## Parallel implementation lifecycle

When multiple workers implement concurrently in the same repository, step 3 of the Implementation lifecycle means the Mandatory preflight defined in `.agent/PARALLEL-WORK.md`, not merely "check whether the same Task has a PR."

### Shared coordination state

The source of truth for in-flight work is observable GitHub state:

- latest `main` HEAD
- open / draft Pull Requests
- non-main branches and branch HEADs
- open `[Task]` Issues and `Blocked by`
- closing references in PR bodies
- branch / commit naming
- changed files of PRs / branches
- recent merged commits

Conversation sharing across chats/sessions is supporting information, not the source of truth for parallel ownership.

### Task claim

If an open/draft PR references a Task with `Closes #...` or equivalent, that PR claims the Task.

A branch without a PR also counts as a claim when its Task can reasonably be identified from branch name, commits, and changed files. Do not create another branch/PR for the same Task.

### Reservation and semantic conflict

Changed files in in-flight work are reserved. The subsystem and shared contracts being changed by the Task are also reserved.

Even without file overlap, a Task has a semantic conflict if it depends on or changes an unmerged protocol/schema/public interface/state machine/security boundary/build-release contract.

Do not begin a Task with a semantic conflict until the earlier work is merged to main.

### Blocker semantics

An Issue listed under `Blocked by` is not resolved merely because its PR is green. A blocker is resolved only after its PR is merged to main and the Issue is closed.

### Re-evaluation

Parallel eligibility is not fixed at branch creation. Re-evaluate at least:

1. before the first meaningful write;
2. before expanding into a shared file/subsystem;
3. before push / PR creation;
4. immediately before merge;
5. whenever main is discovered to have advanced during the work.

If main advances, inspect dependency / semantic conflicts as well as exact file conflicts. Update to latest main and re-run required verification when necessary.

### Eligibility

A separate worker may implement concurrently only when every Parallel eligibility gate in `.agent/PARALLEL-WORK.md` is satisfied.

If information is insufficient, branch ownership is unclear, or dependence on an unmerged contract is suspected, fail closed and do not parallelize.

### Process-only changes

Process-rule-only work such as changes under `AGENTS.md` / `.agent/` is also subject to GitHub preflight. It may proceed independently of a product dependency chain only when it has no file/semantic conflict with product implementation and does not change the product Task contract.

### Atomic remote Task claim

When beginning a new production `[Task]`, after preflight succeeds and before meaningful implementation, create the **remote branch `task/<issue-number>`** from the observed latest `main` SHA to claim Task ownership.

- The canonical new Task branch name is exactly `task/<issue-number>`, without a slug. This makes GitHub ref creation fail for the later of two workers attempting to claim the same Task concurrently.
- If `task/<issue-number>` already exists, do not force-update it, create a slug variant, or otherwise bypass the claim. Inspect ownership of the existing branch/PR and either continue it or perform explicit cleanup.
- A legacy branch such as `task/<issue-number>-<slug>` or `feat/issue-<issue-number>-...` is also an existing claim when it is in flight; do not create a competing canonical branch.
- After successful branch creation and before the first meaningful write, re-read latest main / open PRs / branches. If main or ownership state changed between preflight and claim, re-evaluate.
- After the first meaningful commit is pushed, create a Draft PR as early as practical and explicitly include `Parent spec: #...` and `Closes #<task-number>`. Do not make other workers infer ownership from branch metadata for an extended period.
- Do not keep meaningful implementation only on a local branch where it is invisible to other workers. Parallel work in a shared repository should publish Task-branch ownership to the remote coordination surface early.

This remote branch claim is a coordination lock, not a Task-completion condition. Task completion still requires PR merge and Issue close.
